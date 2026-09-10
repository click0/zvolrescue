//! `list`: datasets, volumes and snapshots of a pool at a TXG.

use std::path::PathBuf;

use serde::Serialize;
use zfs_ondisk::dmu::ObjsetType;
use zfs_read::bind::{bind_by_reading, Verdict};
use zfs_read::dsl::{open_mos, walk, Dataset, DatasetTree};
use zfs_read::pool::{assemble, select_uberblock, uberblock_candidates, PoolAssembly, TxgSelect};
use zfs_read::vdev::DeviceScan;
use zfs_read::zeropoint::scan_with_recovered_base;
use zfs_read::zio::{PoolReader, ReadError};
use zvolrescue_io::{BlockSource, FileSource};

use crate::timefmt::{iso8601, parse_timestamp};
use crate::{evidence, exit, Format, Global, PoolSpec};

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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
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

fn dataset_out(d: &Dataset) -> DatasetOut {
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

/// The members of a POOLSPEC after opening and scanning.
pub struct Members {
    /// Open sources, kept alive for reading (`None` where opening failed).
    pub sources: Vec<Option<FileSource>>,
    /// Scan results in the same order.
    pub scans: Vec<Option<DeviceScan>>,
    /// Pools assembled from the scans.
    pub pools: Vec<PoolAssembly>,
    /// Member paths in the same order.
    pub paths: Vec<PathBuf>,
}

impl Members {
    /// Sources as trait objects, indexed like the scans.
    pub fn devices(&self) -> Vec<Option<&dyn BlockSource>> {
        self.sources
            .iter()
            .map(|s| s.as_ref().map(|s| s as &dyn BlockSource))
            .collect()
    }

    /// Where each member's vdev begins, indexed like the scans. Non-zero
    /// only for a member whose labels were found somewhere other than the
    /// start of what was opened (SPEC F-61).
    pub fn bases(&self) -> Vec<u64> {
        self.scans
            .iter()
            .map(|s| s.as_ref().map_or(0, |s| s.base))
            .collect()
    }

    /// True when at least one member could not be opened or scanned.
    pub fn any_failed(&self) -> bool {
        self.scans.iter().any(|s| s.is_none())
    }
}

/// Apply every `--assume-member`: put a member whose labels are gone into
/// a leaf slot the configuration leaves vacant (SPEC F-62).
fn bind_assumed(
    spec: &PoolSpec,
    paths: &[PathBuf],
    pools: &mut [PoolAssembly],
    scans: &[Option<DeviceScan>],
    devices: &[Option<&dyn BlockSource>],
    bases: &[u64],
) -> Result<(), u8> {
    let assumed = spec.assumed().map_err(|e| {
        eprintln!("zvolrescue: {e}");
        exit::USAGE
    })?;
    for (path, guid) in assumed {
        let Some(device) = paths.iter().position(|p| *p == path) else {
            eprintln!(
                "zvolrescue: --assume-member {}: not among the members given",
                path.display()
            );
            return Err(exit::USAGE);
        };
        // With several pools the assertion applies to the one that is
        // short of a leaf; refuse when more than one could take it.
        let takers: Vec<usize> = pools
            .iter()
            .enumerate()
            .filter(|(_, p)| !p.vacant_leaves().is_empty())
            .map(|(i, _)| i)
            .collect();
        let pool = match takers.len() {
            1 => takers[0],
            0 => {
                eprintln!(
                    "zvolrescue: --assume-member {}: no scanned pool is missing a member",
                    path.display()
                );
                return Err(exit::USAGE);
            }
            n => {
                eprintln!(
                    "zvolrescue: --assume-member {}: {n} pools are missing members; scan them separately",
                    path.display()
                );
                return Err(exit::USAGE);
            }
        };
        // Several leaves vacant and no name given: try each of them and
        // let the checksums say which one this member is (SPEC F-62).
        // No GUID given: work out which leaf this member is by reading
        // through it. A named leaf is the user's assertion and stands as
        // given — every block read through it is checksum-verified all
        // the same.
        if guid.is_none() {
            match bind_by_reading(&mut pools[pool], scans, devices, bases, device) {
                Verdict::Bound(b, fitting) => {
                    eprintln!(
                        "zvolrescue: {}: read as leaf {:#018x} of {} — the metadata walk verifies through it{}",
                        path.display(),
                        b.guid,
                        pools[pool].tops[b.top].name,
                        if fitting > 1 {
                            format!(" ({fitting} leaves of that mirror fit; they hold the same bytes)")
                        } else {
                            String::new()
                        }
                    );
                    continue;
                }
                Verdict::Ambiguous(fits) => {
                    eprintln!(
                        "zvolrescue: --assume-member {}: {} leaves read equally well; name the right one with =GUID:",
                        path.display(),
                        fits.len()
                    );
                    for b in fits {
                        eprintln!("  {:#018x}  {}", b.guid, pools[pool].tops[b.top].name);
                    }
                    return Err(exit::USAGE);
                }
                Verdict::Nothing => {
                    eprintln!(
                        "zvolrescue: --assume-member {}: nothing reads through this member — it is not one of the {} leaves pool {:?} is missing. Name one with =GUID to assert it anyway.",
                        path.display(),
                        pools[pool].vacant_leaves().len(),
                        pools[pool].name
                    );
                    return Err(exit::USAGE);
                }
            }
        }
        match pools[pool].bind_member(device, guid) {
            Ok(g) => eprintln!(
                "zvolrescue: {}: assumed to be leaf {g:#018x} of pool {:?}; its blocks are still verified by checksum",
                path.display(),
                pools[pool].name
            ),
            Err(e) => {
                eprintln!("zvolrescue: --assume-member {}: {e}", path.display());
                return Err(exit::USAGE);
            }
        }
    }
    Ok(())
}

/// Open every member named in `spec`, scan it, and assemble pools.
pub fn open_members(spec: &PoolSpec) -> Result<Members, u8> {
    let paths = spec.members().map_err(|e| {
        eprintln!("zvolrescue: {e}");
        exit::USAGE
    })?;
    let mut sources = Vec::with_capacity(paths.len());
    let mut scans = Vec::with_capacity(paths.len());
    for p in &paths {
        let opened = FileSource::open(p).and_then(|src| {
            let scan = scan_with_recovered_base(&src)?;
            if scan.base != 0 {
                eprintln!(
                    "zvolrescue: {}: vdev starts at byte {}, confirmed by an uberblock checksum",
                    p.display(),
                    scan.base
                );
            }
            Ok((src, scan))
        });
        match opened {
            Ok((src, s)) => {
                scans.push(Some(s));
                sources.push(Some(src));
            }
            Err(e) => {
                eprintln!("zvolrescue: {}: {e}", p.display());
                scans.push(None);
                sources.push(None);
            }
        }
    }
    if scans.iter().all(|s| s.is_none()) {
        return Err(exit::EVIDENCE);
    }
    let mut pools = assemble(&scans);
    let devices: Vec<Option<&dyn BlockSource>> = sources
        .iter()
        .map(|s| s.as_ref().map(|s| s as &dyn BlockSource))
        .collect();
    let bases: Vec<u64> = scans
        .iter()
        .map(|s| s.as_ref().map_or(0, |s| s.base))
        .collect();
    bind_assumed(spec, &paths, &mut pools, &scans, &devices, &bases)?;
    drop(devices);
    Ok(Members {
        sources,
        scans,
        pools,
        paths,
    })
}

/// Pick the pool named by `--pool-guid`, or the only one found.
pub fn choose_pool(pools: Vec<PoolAssembly>, guid: Option<&str>) -> Result<PoolAssembly, u8> {
    match guid {
        Some(g) => {
            let g = g.trim_start_matches("0x");
            let want = u64::from_str_radix(g, 16).map_err(|_| {
                eprintln!("zvolrescue: --pool-guid must be hexadecimal");
                exit::USAGE
            })?;
            pools.into_iter().find(|p| p.guid == want).ok_or_else(|| {
                eprintln!("zvolrescue: no scanned member belongs to pool guid {want:#x}");
                exit::EVIDENCE
            })
        }
        None => match pools.len() {
            0 => {
                eprintln!("zvolrescue: no ZFS pool found on the given members");
                Err(exit::EVIDENCE)
            }
            1 => Ok(pools.into_iter().next().expect("one")),
            n => {
                eprintln!("zvolrescue: {n} pools found; choose one with --pool-guid:");
                for p in &pools {
                    eprintln!("  {:#018x}  {:?}", p.guid, p.name);
                }
                Err(exit::USAGE)
            }
        },
    }
}

fn walk_at(
    reader: &PoolReader<'_>,
    ub: &zfs_ondisk::uberblock::Uberblock,
    name: &str,
) -> Result<DatasetTree, ReadError> {
    let mos = open_mos(reader, ub)?;
    walk(&mos, name)
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
        Err(code) => return code,
    };
    let pool = match choose_pool(members.pools.clone(), spec.pool_guid.as_deref()) {
        Ok(p) => p,
        Err(code) => return code,
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
        return exit::UNRECOVERABLE;
    };
    let reader = PoolReader::new(&pool, members.devices()).with_base_offsets(&members.bases());
    let tree = match walk_at(&reader, &chosen.ub, &pool.name) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "zvolrescue: cannot read the pool at txg {}: {e}",
                chosen.ub.txg
            );
            return exit::UNRECOVERABLE;
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
            .map(dataset_out)
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
            Some(other) => match walk_at(&reader, &other.ub, &pool.name) {
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
                            .map(|d| dataset_out(d))
                            .collect(),
                        destroyed_since: there
                            .iter()
                            .filter(|d| !here.iter().any(|o| o.guid == d.guid))
                            .map(|d| dataset_out(d))
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
    if let Some(log) = &g.evidence_log {
        if let Err(e) = evidence::append(log, &json) {
            eprintln!(
                "zvolrescue: cannot write evidence log {}: {e}",
                log.display()
            );
            return exit::USAGE;
        }
    }
    if code == 0 && members.any_failed() {
        exit::EVIDENCE
    } else {
        code
    }
}
