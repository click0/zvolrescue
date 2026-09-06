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
use zfs_read::vdev::{scan_device, DeviceScan, LabelScan};
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
    };
    if let Some(s) = scan {
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

/// Run `scan`.
pub fn run(g: &Global, devices: &[PathBuf]) -> u8 {
    let mut scans: Vec<Option<DeviceScan>> = Vec::with_capacity(devices.len());
    let mut outs: Vec<DeviceOut> = Vec::with_capacity(devices.len());
    for path in devices {
        let (scan, size, error) = match FileSource::open(path) {
            Ok(src) => match scan_device(&src) {
                Ok(s) => (Some(s), src.size(), None),
                Err(e) => (None, src.size(), Some(e.to_string())),
            },
            Err(e) => (None, 0, Some(e.to_string())),
        };
        outs.push(device_out(path, &scan, size, error, g.verbose));
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
    if out.devices.iter().any(|d| d.error.is_some()) {
        exit::EVIDENCE
    } else {
        0
    }
}
