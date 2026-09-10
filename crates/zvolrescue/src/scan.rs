//! `scan`: what is on these devices — labels, configuration, uberblocks,
//! TXG window, and the pools that can be assembled from them.
//!
//! Verbosity drives the detail: `-v` lists every uberblock and corrupt ring
//! slot; `-vv` prints the full configuration nvlist of each device's best
//! label.

use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{json, Map, Value as Json};
use zfs_ondisk::checksum::ChecksumStatus;
use zfs_ondisk::label::{pool_state_name, LabelConfig};
use zfs_ondisk::nvlist::{NvList, Value};
use zfs_read::pool::{assemble, PoolAssembly};
use zfs_read::vdev::{DeviceScan, LabelScan};
use zfs_read::zeropoint::{
    find as find_zero_point, partition_table, scan_with_recovered_base, Search,
};
use zvolrescue_io::{BlockSource, FileSource};

use crate::timefmt::iso8601;
use crate::{evidence, exit, Format, Global};

#[derive(Debug, Serialize)]
struct UberblockOut {
    slot: usize,
    txg: u64,
    timestamp: u64,
    time: String,
    version: u64,
    guid_sum: String,
    rootbp_birth: u64,
    endian: &'static str,
    checksum: &'static str,
    mmp: bool,
    checkpoint_txg: u64,
}

#[derive(Debug, Serialize)]
struct CorruptSlot {
    slot: usize,
    reason: String,
}

#[derive(Debug, Serialize)]
struct LabelOut {
    index: usize,
    offset: u64,
    config_checksum: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    config_error: Option<String>,
    label_txg: Option<u64>,
    slot_shift: u32,
    slots: usize,
    valid: usize,
    verified: usize,
    empty_slots: usize,
    corrupt_slots: usize,
    best_txg: Option<u64>,
    best_time: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    uberblocks: Vec<UberblockOut>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    corrupt: Vec<CorruptSlot>,
}

#[derive(Debug, Serialize)]
struct ConfigOut {
    name: Option<String>,
    pool_guid: Option<String>,
    state: Option<&'static str>,
    txg: Option<u64>,
    version: Option<u64>,
    vdev_guid: Option<String>,
    top_guid: Option<String>,
    top_vdev: Option<String>,
    ashift: Option<u64>,
    vdev_children: Option<u64>,
    hostid: Option<String>,
    hostname: Option<String>,
    features_for_read: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DeviceOut {
    path: PathBuf,
    size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    best_label: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    config: Option<ConfigOut>,
    /// Full nvlist of the best label (only with `-vv`).
    #[serde(skip_serializing_if = "Option::is_none")]
    nvlist: Option<Json>,
    labels: Vec<LabelOut>,
    /// Highest verified TXG across all labels — where `zpool import` would start.
    newest_txg: Option<u64>,
    /// Lowest verified TXG still present — how far back a rollback could reach.
    oldest_txg: Option<u64>,
    /// Zero points confirmed from uberblock checksums, best first. Filled
    /// in when the labels cannot say where the vdev starts, or on request.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    zero_point: Vec<ZeroPointOut>,
    /// Where this device's vdev begins, when that is not offset 0.
    #[serde(skip_serializing_if = "Option::is_none")]
    vdev_base: Option<u64>,
    /// How that was arrived at.
    #[serde(skip_serializing_if = "Option::is_none")]
    vdev_base_from: Option<&'static str>,
    /// The partition table of a whole-disk image, if it has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    partitions: Option<TableOut>,
}

/// How `scan` should look for a vdev's zero point (SPEC F-61).
#[derive(Debug, Default, Clone)]
pub struct ZeroPointOpts {
    /// Search every member, not only those whose labels are unusable.
    pub always: bool,
    /// Search the whole member instead of its first and last 64 MiB.
    pub whole: bool,
    /// Physical sizes to assume for the vdev when testing rear labels.
    pub psize_hints: Vec<u64>,
}

#[derive(Debug, Serialize)]
struct PartitionOut {
    index: usize,
    start: u64,
    length: u64,
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    zfs: bool,
}

#[derive(Debug, Serialize)]
struct TableOut {
    scheme: &'static str,
    sector: u64,
    partitions: Vec<PartitionOut>,
}

#[derive(Debug, Serialize)]
struct ZeroPointOut {
    /// Confirmed vdev base: subtract it from a physical offset.
    base: u64,
    /// Number of uberblocks whose checksum verified for this base.
    anchors: usize,
    /// Labels the anchors came from, e.g. `["L0", "L1"]`.
    labels: Vec<String>,
    /// TXG range the anchors cover.
    oldest_txg: u64,
    newest_txg: u64,
    /// Vdev size implied by a rear-label anchor, when one was found.
    #[serde(skip_serializing_if = "Option::is_none")]
    psize: Option<u64>,
    /// Logical birth of the root pointer in the newest anchor: the MOS
    /// this base would be read through.
    rootbp_birth: u64,
}

#[derive(Debug, Serialize)]
struct MemberOut {
    guid: String,
    path: Option<String>,
    present: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct TopOut {
    id: u64,
    guid: String,
    name: String,
    kind: String,
    nparity: Option<u64>,
    ashift: Option<u64>,
    readable: bool,
    members: Vec<MemberOut>,
}

#[derive(Debug, Serialize)]
struct PoolOut {
    name: String,
    guid: String,
    state: Option<&'static str>,
    txg: Option<u64>,
    vdev_children: Option<u64>,
    missing_tops: Vec<u64>,
    readable: bool,
    hosts: Vec<HostOut>,
    devices: Vec<PathBuf>,
    tops: Vec<TopOut>,
    stale: Vec<StaleOut>,
}

#[derive(Debug, Serialize)]
struct StaleOut {
    device: PathBuf,
    guid: Option<String>,
    txg: Option<u64>,
    reason: String,
}

#[derive(Debug, Serialize)]
struct HostOut {
    hostid: Option<String>,
    hostname: Option<String>,
}

#[derive(Debug, Serialize)]
struct ScanOut {
    devices: Vec<DeviceOut>,
    pools: Vec<PoolOut>,
}

fn hex(v: u64) -> String {
    format!("{v:#018x}")
}

/// Generic nvlist → JSON, for `-vv`.
fn nv_json(nv: &NvList) -> Json {
    let mut m = Map::new();
    for (name, v) in &nv.pairs {
        m.insert(name.clone(), value_json(v));
    }
    Json::Object(m)
}

fn value_json(v: &Value) -> Json {
    match v {
        Value::Boolean => Json::Bool(true),
        Value::Bool(b) => Json::Bool(*b),
        Value::Int(i) => json!(i),
        Value::Uint64(u) => json!(u),
        Value::Int64(i) => json!(i),
        Value::Double(d) => json!(d),
        Value::String(s) => Json::String(s.clone()),
        Value::Bytes(b) => json!(b),
        Value::IntArray(a) => json!(a),
        Value::Uint64Array(a) => json!(a),
        Value::Int64Array(a) => json!(a),
        Value::BoolArray(a) => json!(a),
        Value::StringArray(a) => json!(a),
        Value::List(l) => nv_json(l),
        Value::ListArray(a) => Json::Array(a.iter().map(nv_json).collect()),
        Value::Unknown { type_code, nelem } => json!({"unknown_type": type_code, "nelem": nelem}),
    }
}

fn config_out(c: &LabelConfig) -> ConfigOut {
    ConfigOut {
        name: c.name.clone(),
        pool_guid: c.pool_guid.map(hex),
        state: c.state.map(pool_state_name),
        txg: c.txg,
        version: c.version,
        vdev_guid: c.guid.map(hex),
        top_guid: c.top_guid.map(hex),
        top_vdev: c.tree.as_ref().map(|t| t.display_name()),
        ashift: c.ashift(),
        vdev_children: c.vdev_children,
        hostid: c.hostid.map(hex),
        hostname: c.hostname.clone(),
        features_for_read: c.features_for_read.clone(),
    }
}

fn label_out(l: &LabelScan, detail: bool) -> LabelOut {
    let best = l.best();
    let empty_slots = l.empty_slots();
    let corrupt_slots = l.invalid.len() - empty_slots;
    let corrupt = if detail {
        l.invalid
            .iter()
            .filter(|(_, e)| *e != zfs_ondisk::ParseError::BadMagic(0))
            .map(|(slot, e)| CorruptSlot {
                slot: *slot,
                reason: e.to_string(),
            })
            .collect()
    } else {
        Vec::new()
    };
    let uberblocks = if detail {
        let mut list: Vec<UberblockOut> = l
            .uberblocks
            .iter()
            .map(|s| UberblockOut {
                slot: s.slot,
                txg: s.ub.txg,
                timestamp: s.ub.timestamp,
                time: iso8601(s.ub.timestamp),
                version: s.ub.version,
                guid_sum: hex(s.ub.guid_sum),
                rootbp_birth: s.ub.rootbp_birth(),
                endian: match s.ub.endian {
                    zfs_ondisk::Endian::Little => "little",
                    zfs_ondisk::Endian::Big => "big",
                },
                checksum: s.checksum.as_str(),
                mmp: s.ub.mmp_magic != 0,
                checkpoint_txg: s.ub.checkpoint_txg,
            })
            .collect();
        list.sort_by_key(|u| std::cmp::Reverse((u.txg, u.timestamp)));
        list
    } else {
        Vec::new()
    };
    LabelOut {
        index: l.index,
        offset: l.offset,
        config_checksum: l.phys_checksum.as_str(),
        config_error: l.config_error.as_ref().map(|e| e.to_string()),
        label_txg: l.config.as_ref().and_then(|c| c.u64("txg")),
        slot_shift: l.slot_shift,
        slots: l.slots,
        valid: l.uberblocks.len(),
        verified: l
            .uberblocks
            .iter()
            .filter(|s| s.checksum == ChecksumStatus::Ok)
            .count(),
        empty_slots,
        corrupt_slots,
        best_txg: best.map(|s| s.ub.txg),
        best_time: best.map(|s| iso8601(s.ub.timestamp)),
        uberblocks,
        corrupt,
    }
}

fn device_out(
    path: &Path,
    scan: &Option<DeviceScan>,
    size: u64,
    error: Option<String>,
    verbose: u8,
) -> DeviceOut {
    let mut out = DeviceOut {
        path: path.to_path_buf(),
        size,
        error,
        best_label: None,
        config: None,
        nvlist: None,
        labels: Vec::new(),
        newest_txg: None,
        oldest_txg: None,
        zero_point: Vec::new(),
        vdev_base: None,
        vdev_base_from: None,
        partitions: None,
    };
    if let Some(s) = scan {
        out.vdev_base = (s.base != 0).then_some(s.base);
        out.vdev_base_from = s.base_source;
        out.best_label = s.best_label;
        out.config = s.config().as_ref().map(config_out);
        if verbose >= 2 {
            out.nvlist = s
                .best_label
                .and_then(|i| s.labels[i].config.as_ref())
                .map(nv_json);
        }
        out.labels = s
            .labels
            .iter()
            .map(|l| label_out(l, verbose >= 1))
            .collect();
        out.newest_txg = s.newest_txg();
        out.oldest_txg = s.oldest_txg();
    }
    out
}

fn pool_out(p: &PoolAssembly, paths: &[PathBuf]) -> PoolOut {
    PoolOut {
        name: p.name.clone(),
        guid: hex(p.guid),
        state: p.state.map(pool_state_name),
        txg: p.txg,
        vdev_children: p.vdev_children,
        missing_tops: p.missing_tops(),
        readable: p.readable(),
        hosts: p
            .hosts
            .iter()
            .map(|(id, name)| HostOut {
                hostid: id.map(hex),
                hostname: name.clone(),
            })
            .collect(),
        devices: p.devices.iter().map(|&i| paths[i].clone()).collect(),
        stale: p
            .stale
            .iter()
            .map(|m| StaleOut {
                device: paths[m.device].clone(),
                guid: m.guid.map(hex),
                txg: m.txg,
                reason: m.reason.clone(),
            })
            .collect(),
        tops: p
            .tops
            .iter()
            .map(|t| TopOut {
                id: t.id,
                guid: hex(t.guid),
                name: t.name.clone(),
                kind: t.kind.clone(),
                nparity: t.nparity,
                ashift: t.ashift,
                readable: t.readable(),
                members: t
                    .members
                    .iter()
                    .map(|m| MemberOut {
                        guid: hex(m.guid),
                        path: m.path.clone(),
                        present: m.present.map(|i| paths[i].clone()),
                    })
                    .collect(),
            })
            .collect(),
    }
}

fn print_text(out: &ScanOut, verbose: u8) {
    for d in &out.devices {
        println!("{}: {} bytes", d.path.display(), d.size);
        if let Some(e) = &d.error {
            println!("  error: {e}");
            continue;
        }
        if let Some(t) = &d.partitions {
            println!(
                "  {} table, {}-byte sectors, {} partition(s):",
                t.scheme,
                t.sector,
                t.partitions.len()
            );
            for p in &t.partitions {
                println!(
                    "    {:>2}  {:>14} + {:>14}  {}{}{}",
                    p.index,
                    p.start,
                    p.length,
                    p.kind,
                    p.name
                        .as_deref()
                        .map_or(String::new(), |n| format!("  {n:?}")),
                    if p.zfs {
                        "  <- a ZFS partition type"
                    } else {
                        ""
                    },
                );
            }
        }
        if let (Some(base), Some(from)) = (d.vdev_base, d.vdev_base_from) {
            println!("  this member's vdev begins at byte {base} ({from})");
        }
        match &d.config {
            Some(c) => {
                println!(
                    "  pool {:?} guid {}  state {}  label txg {}  host {:?} ({})",
                    c.name.as_deref().unwrap_or("?"),
                    c.pool_guid.as_deref().unwrap_or("?"),
                    c.state.unwrap_or("?"),
                    c.txg.map_or("?".to_string(), |t| t.to_string()),
                    c.hostname.as_deref().unwrap_or("?"),
                    c.hostid.as_deref().unwrap_or("?"),
                );
                println!(
                    "  vdev guid {}  ashift {}  in {} (top guid {}, pool has {} top-level vdev(s))",
                    c.vdev_guid.as_deref().unwrap_or("?"),
                    c.ashift.map_or("?".to_string(), |a| a.to_string()),
                    c.top_vdev.as_deref().unwrap_or("?"),
                    c.top_guid.as_deref().unwrap_or("?"),
                    c.vdev_children.map_or("?".to_string(), |n| n.to_string()),
                );
                if verbose >= 1 && !c.features_for_read.is_empty() {
                    println!("  features_for_read: {}", c.features_for_read.join(" "));
                }
            }
            None => println!("  no readable ZFS label configuration"),
        }
        for l in &d.labels {
            let best = match (l.best_txg, &l.best_time) {
                (Some(t), Some(ts)) => format!("best txg {t} ({ts})"),
                _ => "no valid uberblocks".to_string(),
            };
            println!(
                "  L{} @ {:>12}: config {}{}, uberblocks {}/{} valid ({} verified, {} empty, {} corrupt), {}{}",
                l.index,
                l.offset,
                l.config_checksum,
                l.label_txg.map_or(String::new(), |t| format!(" txg {t}")),
                l.valid,
                l.slots,
                l.verified,
                l.empty_slots,
                l.corrupt_slots,
                best,
                if d.best_label == Some(l.index) { "  <- best" } else { "" },
            );
            if let Some(e) = &l.config_error {
                println!("      config: {e}");
            }
            for c in &l.corrupt {
                println!("      slot {:>3}  {}", c.slot, c.reason);
            }
            for u in &l.uberblocks {
                println!(
                    "      slot {:>3}  txg {:>12}  {}  v{}  rootbp birth {}  checksum {}{}{}",
                    u.slot,
                    u.txg,
                    u.time,
                    u.version,
                    u.rootbp_birth,
                    u.checksum,
                    if u.mmp { "  mmp" } else { "" },
                    if u.checkpoint_txg != 0 {
                        format!("  checkpoint {}", u.checkpoint_txg)
                    } else {
                        String::new()
                    }
                );
            }
        }
        match (d.oldest_txg, d.newest_txg) {
            (Some(lo), Some(hi)) => println!("  verified txg window: {lo}..={hi}"),
            _ => println!("  no verified ZFS uberblocks found"),
        }
        for z in &d.zero_point {
            println!(
                "  zero point: base {} confirmed by {} uberblock checksum(s) in {}, txg {}..={}, vdev size {}, root pointer born txg {}",
                z.base,
                z.anchors,
                z.labels.join(","),
                z.oldest_txg,
                z.newest_txg,
                z.psize
                    .map_or("unknown".to_string(), |p| p.to_string()),
                z.rootbp_birth,
            );
        }
        if d.config.is_none() && d.zero_point.is_empty() && d.error.is_none() {
            println!("  zero point: no uberblock anchor found either");
        }
        if let Some(nv) = &d.nvlist {
            println!("  label nvlist (L{}):", d.best_label.unwrap_or(0));
            let pretty = serde_json::to_string_pretty(nv).expect("serialisable");
            for line in pretty.lines() {
                println!("    {line}");
            }
        }
    }
    for p in &out.pools {
        println!();
        println!(
            "pool {:?} guid {}: state {}, newest label txg {}, {} top-level vdev(s), {}",
            p.name,
            p.guid,
            p.state.unwrap_or("?"),
            p.txg.map_or("?".to_string(), |t| t.to_string()),
            p.vdev_children.map_or("?".to_string(), |n| n.to_string()),
            if p.readable() {
                "READABLE from scanned members"
            } else {
                "NOT readable from scanned members"
            }
        );
        for h in &p.hosts {
            println!(
                "  seen on host {:?} ({})",
                h.hostname.as_deref().unwrap_or("?"),
                h.hostid.as_deref().unwrap_or("?")
            );
        }
        for t in &p.tops {
            println!(
                "  {} (guid {}, ashift {}){}",
                t.name,
                t.guid,
                t.ashift.map_or("?".to_string(), |a| a.to_string()),
                if t.readable() { "" } else { "  NOT READABLE" }
            );
            for m in &t.members {
                println!(
                    "    {} {:<24} {}",
                    m.guid,
                    m.path.as_deref().unwrap_or("-"),
                    match &m.present {
                        Some(p) => format!("present: {}", p.display()),
                        None => "MISSING".to_string(),
                    }
                );
            }
        }
        for id in &p.missing_tops {
            println!("  top-level vdev #{id}: no scanned member describes it  MISSING");
        }
        for m in &p.stale {
            println!(
                "  {} {} NOT USED: {}",
                m.guid.as_deref().unwrap_or("?"),
                m.device.display(),
                m.reason
            );
        }
    }
}

impl PoolOut {
    fn readable(&self) -> bool {
        self.readable
    }
}

impl TopOut {
    fn readable(&self) -> bool {
        self.readable
    }
}

/// Look for the vdev base of one member with [`zfs_read::zeropoint`].
fn zero_points(src: &FileSource, opts: &ZeroPointOpts) -> Vec<ZeroPointOut> {
    let search = Search {
        windows: if opts.whole {
            vec![(0, src.size())]
        } else {
            Vec::new()
        },
        psize_hints: opts.psize_hints.clone(),
        ..Search::default()
    };
    let found = match find_zero_point(src, &search) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    found
        .iter()
        .map(|z| {
            let mut labels: Vec<String> = z
                .anchors
                .iter()
                .map(|a| match a.label {
                    Some(l) => format!("L{l}"),
                    None => "L?".to_string(),
                })
                .collect();
            labels.sort();
            labels.dedup();
            ZeroPointOut {
                base: z.base,
                anchors: z.anchors.len(),
                labels,
                oldest_txg: z.anchors.iter().map(|a| a.ub.txg).min().unwrap_or(0),
                newest_txg: z.newest_txg(),
                psize: z.implied_psize(),
                rootbp_birth: z.best().map(|a| a.ub.rootbp_birth()).unwrap_or(0),
            }
        })
        .collect()
}

/// What `scan --emit-label` should write (SPEC F-67).
#[derive(Debug, Default, Clone)]
pub struct EmitOpts {
    /// Layout template to build the label from.
    pub hints: Option<PathBuf>,
    /// Where to write the label image.
    pub emit_label: Option<PathBuf>,
    /// Which member of the layout, as `TOP:LEAF`.
    pub emit_for: Option<String>,
    /// Which of the four label positions to seal it for.
    pub emit_label_index: Option<usize>,
}

/// Write the label a layout describes for one member (SPEC F-67).
///
/// The bytes go where the operator asked and nowhere else: this never
/// touches an input, and the file it writes is a *template* to place on a
/// copy of the disk. It carries what the layout knows — pool name, TXG,
/// vdev type, parity, ashift, member order — with synthetic vdev GUIDs,
/// since the real ones went with the labels. Feature flags are not in it:
/// nothing surviving says which the pool had, and `zpool import` will want
/// them added by hand.
fn emit_label(
    g: &Global,
    devices: &[PathBuf],
    opts: &EmitOpts,
    txg: Option<u64>,
    psize: u64,
) -> Result<(), String> {
    let (Some(file), Some(out)) = (&opts.hints, &opts.emit_label) else {
        return Ok(());
    };
    let hints = crate::hints::load(file, devices)?;
    let (top, leaf) = match &opts.emit_for {
        None => (0usize, 0usize),
        Some(spec) => {
            let (t, l) = spec
                .split_once(':')
                .ok_or_else(|| format!("--emit-for {spec}: expected TOP:LEAF"))?;
            (
                t.trim()
                    .parse()
                    .map_err(|_| format!("--emit-for {spec}: TOP is not a number"))?,
                l.trim()
                    .parse()
                    .map_err(|_| format!("--emit-for {spec}: LEAF is not a number"))?,
            )
        }
    };
    let hint_top = hints.layout.tops.get(top).ok_or_else(|| {
        format!(
            "--emit-for: the layout has {} top-level vdev(s)",
            hints.layout.tops.len()
        )
    })?;
    if leaf >= hint_top.members.len() {
        return Err(format!(
            "--emit-for: top {top} has {} member(s)",
            hint_top.members.len()
        ));
    }
    let index = opts.emit_label_index.unwrap_or(0);
    let nv = zfs_read::hints::label_nvlist(&hints.layout, top, leaf, txg.unwrap_or(0), None);
    let img = zfs_read::hints::label_image(&nv, index, psize)?;
    std::fs::write(out, &img).map_err(|e| format!("{}: {e}", out.display()))?;
    let meta = out.with_extension("json");
    let json = json!({
        "label_index": index,
        "label_bytes": img.len(),
        "sealed_for_vdev_size": psize,
        "top": top,
        "leaf": leaf,
        "pool": hints.layout.name,
        "ashift": hints.layout.ashift,
        "txg": txg,
        "kind": hint_top.kind,
        "nparity": hint_top.nparity,
        "members": hint_top
            .members
            .iter()
            .map(|m| m.map(|i| devices[i].display().to_string()))
            .collect::<Vec<_>>(),
        "note": "template only: synthetic vdev GUIDs, no feature flags; place on a copy of the disk, never on the evidence",
    });
    std::fs::write(
        &meta,
        serde_json::to_string_pretty(&json).expect("serialisable") + "\n",
    )
    .map_err(|e| format!("{}: {e}", meta.display()))?;
    if !g.quiet {
        eprintln!(
            "zvolrescue: wrote L{index} of {}:{} to {} ({} bytes) and its geometry to {}",
            top,
            leaf,
            out.display(),
            img.len(),
            meta.display()
        );
    }
    Ok(())
}

/// Run `scan`.
pub fn run(g: &Global, devices: &[PathBuf], zp: &ZeroPointOpts, emit: &EmitOpts) -> u8 {
    let mut scans: Vec<Option<DeviceScan>> = Vec::with_capacity(devices.len());
    let mut outs: Vec<DeviceOut> = Vec::with_capacity(devices.len());
    for path in devices {
        let (scan, size, error, zero_point, table) = match FileSource::open(path) {
            Ok(src) => {
                let (scan, error) = match scan_with_recovered_base(&src) {
                    Ok(s) => (Some(s), None),
                    Err(e) => (None, Some(e.to_string())),
                };
                let table = partition_table(&src).ok().flatten();
                // A member whose four label configurations are all
                // unusable still has its uberblock rings, and one slot
                // fixes the base (SPEC F-61).
                let unusable = scan.as_ref().is_none_or(|s| s.config().is_none());
                let zero_point = if zp.always || unusable {
                    zero_points(&src, zp)
                } else {
                    Vec::new()
                };
                (scan, src.size(), error, zero_point, table)
            }
            Err(e) => (None, 0, Some(e.to_string()), Vec::new(), None),
        };
        let mut out = device_out(path, &scan, size, error, g.verbose);
        out.zero_point = zero_point;
        out.partitions = table.map(|t| TableOut {
            scheme: t.scheme,
            sector: t.sector,
            partitions: t
                .partitions
                .into_iter()
                .map(|p| PartitionOut {
                    index: p.index,
                    start: p.start,
                    length: p.length,
                    kind: p.kind,
                    name: p.name,
                    zfs: p.zfs,
                })
                .collect(),
        });
        outs.push(out);
        scans.push(scan);
    }
    let pools: Vec<PoolOut> = assemble(&scans)
        .iter()
        .map(|p| pool_out(p, devices))
        .collect();
    let out = ScanOut {
        devices: outs,
        pools,
    };

    let json = serde_json::to_value(&out).expect("serialisable");
    match g.format {
        Format::Json => println!(
            "{}",
            serde_json::to_string_pretty(&json).expect("serialisable")
        ),
        Format::Text => print_text(&out, g.verbose),
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
    if emit.emit_label.is_some() {
        // Seal it for a vdev the size of the smallest member scanned: the
        // rear labels' position depends on it, and a label sealed for the
        // wrong size verifies nowhere.
        let psize = out.devices.iter().map(|d| d.size).min().unwrap_or(0);
        // The TXG the labels would have carried: the newest any member
        // verified, whether that came from a ring inside a label or from
        // an anchor found without one.
        let txg = out
            .devices
            .iter()
            .filter_map(|d| {
                d.newest_txg
                    .into_iter()
                    .chain(d.zero_point.iter().map(|z| z.newest_txg))
                    .max()
            })
            .max();
        if let Err(e) = emit_label(g, devices, emit, txg, psize) {
            eprintln!("zvolrescue: {e}");
            return exit::USAGE;
        }
    }
    if out.devices.iter().any(|d| d.error.is_some()) {
        exit::EVIDENCE
    } else {
        0
    }
}
