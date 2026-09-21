//! `list`: datasets, volumes and snapshots of a pool at a TXG.

use std::path::PathBuf;

use serde::Serialize;
use zfs_ondisk::dmu::ObjsetType;
use zfs_read::dmu::DnodeArray;
use zfs_read::dsl::{
    open_mos, read_properties, walk, Dataset, DatasetTree, Property, PropertyValue,
};
use zfs_read::pool::{select_uberblock, uberblock_candidates, TxgSelect};
use zfs_read::zio::{PoolReader, ReadError};

use zvol_common::members::{choose_pool, open_members};
use zvol_common::timefmt::{iso8601, parse_timestamp};
use zvol_common::{exit, Format, Global, PoolSpec};

/// Options of the `list` command.
pub struct Options {
    /// Exact TXG.
    pub txg: Option<u64>,
    /// Newest TXG at or before this time.
    pub before: Option<String>,
    /// Compare against this TXG.
    pub diff: Option<u64>,
    /// Include snapshots.
    pub recursive: bool,
    /// Report the properties each dataset has set (SPEC F-14).
    pub properties: bool,
}

#[derive(Debug, Serialize)]
struct DatasetOut {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    guid: String,
    object: u64,
    creation_txg: u64,
    creation_time: u64,
    created: String,
    referenced_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    volsize: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    volblocksize: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    encryption: Option<EncryptionOut>,
    /// Properties set on this dataset, when `--properties` was given.
    /// Absent and empty mean different things — nothing was asked for,
    /// and nothing is set — so an empty list is still written out.
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<Vec<PropertyOut>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PropertyOut {
    name: String,
    value: serde_json::Value,
    /// What the number means, where this build can show its working.
    #[serde(skip_serializing_if = "Option::is_none")]
    means: Option<String>,
}

#[derive(Debug, Serialize)]
struct EncryptionOut {
    suite: String,
    keyformat: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    keylocation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pbkdf2_iters: Option<u64>,
    key_guid: String,
    key_version: u64,
    encryption_root_dir_object: u64,
    crypto_key_object: u64,
}

#[derive(Debug, Serialize)]
struct DiffOut {
    txg: u64,
    time: String,
    created_since: Vec<DatasetOut>,
    destroyed_since: Vec<DatasetOut>,
}

#[derive(Debug, Serialize)]
struct ListOut {
    pool: String,
    pool_guid: String,
    members: Vec<PathBuf>,
    txg: u64,
    time: String,
    /// Verified TXGs available on the scanned members, newest first.
    available_txgs: Vec<u64>,
    datasets: Vec<DatasetOut>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diff: Option<DiffOut>,
}

fn kind_name(d: &Dataset) -> String {
    let base = match d.kind {
        Some(ObjsetType::Zfs) => "filesystem",
        Some(ObjsetType::Zvol) => "volume",
        Some(ObjsetType::Meta) => "meta",
        Some(ObjsetType::Other) => "other",
        Some(ObjsetType::None) | Some(ObjsetType::Unknown(_)) => "unknown",
        None => "unreadable",
    };
    if d.snapshot {
        format!("snapshot({base})")
    } else {
        base.to_string()
    }
}

fn property_out(p: &Property) -> PropertyOut {
    PropertyOut {
        name: p.name.clone(),
        value: match &p.value {
            PropertyValue::Number(v) => serde_json::Value::from(*v),
            other => serde_json::Value::from(other.to_display()),
        },
        means: p.meaning.clone(),
    }
}

fn dataset_out(d: &Dataset, properties: Option<Vec<Property>>) -> DatasetOut {
    DatasetOut {
        name: d.name.clone(),
        kind: kind_name(d),
        guid: format!("{:#018x}", d.guid),
        object: d.object,
        creation_txg: d.creation_txg,
        creation_time: d.creation_time,
        created: iso8601(d.creation_time),
        referenced_bytes: d.referenced_bytes,
        volsize: d.volsize,
        volblocksize: d.volblocksize,
        encryption: d.encryption.as_ref().map(|e| EncryptionOut {
            suite: e.suite_name(),
            keyformat: e.keyformat_name(),
            keylocation: e.keylocation.clone(),
            pbkdf2_iters: e.pbkdf2_iters,
            key_guid: format!("{:#018x}", e.key_guid),
            key_version: e.key_version,
            encryption_root_dir_object: e.root_ddobj,
            crypto_key_object: e.crypto_key_obj,
        }),
        properties: properties.map(|ps| ps.iter().map(property_out).collect()),
        warnings: d.warnings.clone(),
    }
}

fn human(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["", "K", "M", "G", "T", "P"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{bytes}")
    } else if v >= 100.0 {
        format!("{v:.0}{}", UNITS[u])
    } else {
        format!("{v:.1}{}", UNITS[u])
    }
}

fn print_text(out: &ListOut) {
    println!(
        "pool {:?} guid {}: txg {} ({}), {} verified txg(s) available",
        out.pool,
        out.pool_guid,
        out.txg,
        out.time,
        out.available_txgs.len()
    );
    let width = out
        .datasets
        .iter()
        .map(|d| d.name.len())
        .max()
        .unwrap_or(4)
        .max(4);
    println!(
        "{:<width$}  {:<18}  {:<18}  {:>12}  {:<20}  {:>8}  {:>8}  {:>6}  ENCRYPTION",
        "NAME", "TYPE", "GUID", "CREATED_TXG", "CREATED", "REFER", "VOLSIZE", "VOLBLK"
    );
    for d in &out.datasets {
        println!(
            "{:<width$}  {:<18}  {:<18}  {:>12}  {:<20}  {:>8}  {:>8}  {:>6}  {}",
            d.name,
            d.kind,
            d.guid,
            d.creation_txg,
            d.created,
            human(d.referenced_bytes),
            d.volsize.map_or("-".to_string(), human),
            d.volblocksize.map_or("-".to_string(), human),
            d.encryption.as_ref().map_or("-".to_string(), |e| format!(
                "{} key={}{}",
                e.suite,
                e.keyformat,
                e.keylocation
                    .as_ref()
                    .map_or(String::new(), |l| format!(" ({l})"))
            )),
        );
        for p in d.properties.iter().flatten() {
            println!(
                "{:<width$}  property: {} = {}{}",
                "",
                p.name,
                // A JSON string prints itself with quotes; a property
                // value is not quoted on the disk or in `zfs get`.
                p.value
                    .as_str()
                    .map_or_else(|| p.value.to_string(), str::to_string),
                p.means
                    .as_ref()
                    .map_or(String::new(), |m| format!(" ({m})"))
            );
        }
        for w in &d.warnings {
            println!("{:<width$}  warning: {w}", "");
        }
    }
    for e in &out.errors {
        println!("error: {e}");
    }
    if let Some(diff) = &out.diff {
        println!();
        println!("compared with txg {} ({}):", diff.txg, diff.time);
        if diff.created_since.is_empty() && diff.destroyed_since.is_empty() {
            println!("  no datasets created or destroyed");
        }
        for d in &diff.created_since {
            println!(
                "  created    {:<width$}  {}  txg {}",
                d.name, d.kind, d.creation_txg
            );
        }
        for d in &diff.destroyed_since {
            println!(
                "  destroyed  {:<width$}  {}  guid {}  -> zvolrescue dump {} … --txg {}",
                d.name, d.kind, d.guid, d.name, diff.txg
            );
        }
    }
}

fn walk_at<'r, 'a>(
    reader: &'r PoolReader<'a>,
    ub: &zfs_ondisk::uberblock::Uberblock,
    name: &str,
) -> Result<(DnodeArray<'r, 'a>, DatasetTree), ReadError> {
    let mos = open_mos(reader, ub)?;
    let tree = walk(&mos, name)?;
    Ok((mos, tree))
}

/// The properties `d` has set, or the reason there are none to show.
///
/// An unreadable properties ZAP is not a reason to fail the listing:
/// everything else about the dataset is already in hand, so the failure
/// is reported in place of the properties and the row still prints.
fn properties_of(mos: &DnodeArray<'_, '_>, d: &Dataset) -> Vec<Property> {
    match read_properties(mos, d) {
        Ok(ps) => ps,
        Err(e) => vec![Property {
            name: "(unreadable)".into(),
            value: PropertyValue::Text(e.to_string()),
            meaning: None,
        }],
    }
}

/// Run `list`.
pub fn run(g: &Global, spec: &PoolSpec, opts: &Options) -> u8 {
    let sel = match (opts.txg, &opts.before) {
        (Some(t), _) => TxgSelect::Exact(t),
        (None, Some(b)) => match parse_timestamp(b) {
            Some(ts) => TxgSelect::Before(ts),
            None => {
                eprintln!("zvolrescue: --before wants Unix seconds or YYYY-MM-DD[THH:MM[:SS]]");
                return exit::USAGE;
            }
        },
        (None, None) => TxgSelect::Newest,
    };
    let members = match open_members(spec) {
        Ok(x) => x,
        Err(code) => return zvol_common::end_early(g, "zvolrescue", spec, code),
    };
    let pool = match choose_pool(members.pools.clone(), spec.pool_guid.as_deref()) {
        Ok(p) => p,
        Err(code) => return zvol_common::end_early(g, "zvolrescue", spec, code),
    };
    let candidates = uberblock_candidates(&members.scans, &pool);
    let Some(chosen) = select_uberblock(&candidates, sel) else {
        eprintln!(
            "zvolrescue: no verified uberblock matches the requested TXG; available: {}",
            candidates
                .iter()
                .map(|c| c.ub.txg.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        );
        return zvol_common::end_early(g, "zvolrescue", spec, exit::UNRECOVERABLE);
    };
    let reader = PoolReader::new(&pool, members.devices()).with_base_offsets(&members.bases());
    let (mos, tree) = match walk_at(&reader, &chosen.ub, &pool.name) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "zvolrescue: cannot read the pool at txg {}: {e}",
                chosen.ub.txg
            );
            // The run ends the way every run ends: a device may have
            // refused a read on the way to the dataset tree, and that
            // is exit 7 and an incident on record, not a bare 3.
            let out = ListOut {
                pool: pool.name.clone(),
                pool_guid: format!("{:#018x}", pool.guid),
                members: members.paths.clone(),
                txg: chosen.ub.txg,
                time: iso8601(chosen.ub.timestamp),
                available_txgs: candidates.iter().map(|c| c.ub.txg).collect(),
                datasets: Vec::new(),
                errors: Vec::new(),
                diff: None,
            };
            let json = serde_json::to_value(&out).expect("serialisable");
            if g.format == Format::Json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json).expect("serialisable")
                );
            }
            return finish(g, &members, &json, exit::UNRECOVERABLE);
        }
    };
    let keep = |d: &Dataset| opts.recursive || !d.snapshot;
    let mut out = ListOut {
        pool: pool.name.clone(),
        pool_guid: format!("{:#018x}", pool.guid),
        members: members.paths.clone(),
        txg: chosen.ub.txg,
        time: iso8601(chosen.ub.timestamp),
        available_txgs: candidates.iter().map(|c| c.ub.txg).collect(),
        datasets: tree
            .datasets
            .iter()
            .filter(|d| keep(d))
            .map(|d| dataset_out(d, opts.properties.then(|| properties_of(&mos, d))))
            .collect(),
        errors: tree.errors.clone(),
        diff: None,
    };
    let mut code = 0;
    if let Some(other_txg) = opts.diff {
        match select_uberblock(&candidates, TxgSelect::Exact(other_txg)) {
            None => {
                eprintln!("zvolrescue: --diff txg {other_txg} has no verified uberblock");
                code = exit::UNRECOVERABLE;
            }
            Some(other) => match walk_at(&reader, &other.ub, &pool.name).map(|(_, t)| t) {
                Err(e) => {
                    eprintln!("zvolrescue: cannot read the pool at txg {other_txg}: {e}");
                    code = exit::UNRECOVERABLE;
                }
                Ok(other_tree) => {
                    let here: Vec<&Dataset> = tree.datasets.iter().filter(|d| keep(d)).collect();
                    let there: Vec<&Dataset> =
                        other_tree.datasets.iter().filter(|d| keep(d)).collect();
                    out.diff = Some(DiffOut {
                        txg: other_txg,
                        time: iso8601(other.ub.timestamp),
                        created_since: here
                            .iter()
                            .filter(|d| !there.iter().any(|o| o.guid == d.guid))
                            .map(|d| dataset_out(d, None))
                            .collect(),
                        destroyed_since: there
                            .iter()
                            .filter(|d| !here.iter().any(|o| o.guid == d.guid))
                            .map(|d| dataset_out(d, None))
                            .collect(),
                    });
                }
            },
        }
    }
    let json = serde_json::to_value(&out).expect("serialisable");
    match g.format {
        Format::Json => println!(
            "{}",
            serde_json::to_string_pretty(&json).expect("serialisable")
        ),
        Format::Text => print_text(&out),
    }
    finish(g, &members, &json, code)
}

/// The end of every `list`, early or not: the medium incidents on
/// stderr and the stop, when one stopped the run, as the exit code
/// (SPEC F-33, N-10); then the evidence record, with them. `list`
/// writes nothing but its report on stdout.
fn finish(
    g: &Global,
    members: &zvol_common::members::Members,
    json: &serde_json::Value,
    code: u8,
) -> u8 {
    let code = if code == 0 && members.any_failed() {
        exit::EVIDENCE
    } else {
        code
    };
    zvol_common::end_run(
        g,
        "zvolrescue",
        json,
        code,
        &members.inputs(),
        Vec::new(),
        &members.ledger,
    )
}

#[cfg(test)]
mod properties_tests {
    use super::*;
    use zfs_ondisk::label::LABEL_SIZE;
    use zfs_read::fixture::{build_sample_mos, Alloc, Pool};
    use zfs_read::pool::assemble;
    use zfs_read::vdev::scan_device;
    use zvolrescue_io::{BlockSource, MemSource};

    /// A properties object that cannot be read is one row saying so,
    /// not a dataset that silently has no properties and not a `list`
    /// that dies on the one dataset whose ZAP is gone.
    #[test]
    fn an_unreadable_properties_object_is_one_row_that_says_so() {
        let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
        let mut members = vec![vec![0u8; (64 * LABEL_SIZE) as usize]];
        let mut a = Alloc::new(0x20_0000);
        build_sample_mos(&mut pool, &mut members, &mut a);
        pool.write_labels(0, &mut members[0]);
        let source = MemSource::new(members.remove(0));
        let scans = vec![scan_device(&source).ok()];
        let ub = scans[0].as_ref().expect("scan").labels[0]
            .best()
            .expect("ub")
            .ub
            .clone();
        let assembly = assemble(&scans).into_iter().next().expect("one pool");
        let reader = PoolReader::new(&assembly, vec![Some(&source as &dyn BlockSource)]);
        let mos = open_mos(&reader, &ub).expect("MOS");
        let tree = walk(&mos, "tank").expect("tree");
        let disk0 = tree.get("tank/vm/disk0").expect("the volume");

        let intact = properties_of(&mos, disk0);
        assert_eq!(intact.len(), 3, "{intact:?}");
        assert_eq!(intact[0].name, "compression");

        let mut broken = disk0.clone();
        broken.props_zapobj = 999_999;
        let rows = properties_of(&mos, &broken);
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].name, "(unreadable)");
        assert!(
            matches!(&rows[0].value, PropertyValue::Text(t) if !t.is_empty()),
            "{rows:?}"
        );
        assert_eq!(rows[0].meaning, None);
    }
}
