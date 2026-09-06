//! `scan`: label geometry and uberblock rings of single devices.
//!
//! Verbosity drives the detail: `-v` lists every uberblock and corrupt ring
//! slot; `-vv` is reserved for the label nvlists (not decoded yet).

use std::path::{Path, PathBuf};

use serde::Serialize;
use zfs_read::vdev::{scan_labels, LabelScan};
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
    mmp: bool,
    checkpoint_txg: u64,
}

#[derive(Debug, Serialize)]
struct LabelOut {
    index: usize,
    offset: u64,
    slots: usize,
    valid: usize,
    best_txg: Option<u64>,
    best_time: Option<String>,
    empty_slots: usize,
    corrupt_slots: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    uberblocks: Vec<UberblockOut>,
    /// Slots that are neither valid nor empty (only with `-v`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    corrupt: Vec<CorruptSlot>,
}

#[derive(Debug, Serialize)]
struct CorruptSlot {
    slot: usize,
    reason: String,
}

#[derive(Debug, Serialize)]
struct DeviceOut {
    path: PathBuf,
    size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    labels: Vec<LabelOut>,
    /// Highest TXG across all labels — where `zpool import` would start.
    newest_txg: Option<u64>,
    /// Lowest TXG still present — how far back a rollback could reach.
    oldest_txg: Option<u64>,
}

fn label_out(scan: &LabelScan, detail: bool, all: bool) -> LabelOut {
    let best = scan.best();
    let empty_slots = scan.empty_slots();
    let corrupt_slots = scan.invalid.len() - empty_slots;
    let corrupt = if all {
        scan.invalid
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
        let mut list: Vec<UberblockOut> = scan
            .uberblocks
            .iter()
            .map(|(slot, u)| UberblockOut {
                slot: *slot,
                txg: u.txg,
                timestamp: u.timestamp,
                time: iso8601(u.timestamp),
                version: u.version,
                guid_sum: format!("{:#018x}", u.guid_sum),
                rootbp_birth: u.rootbp_birth(),
                endian: match u.endian {
                    zfs_ondisk::Endian::Little => "little",
                    zfs_ondisk::Endian::Big => "big",
                },
                mmp: u.mmp_magic != 0,
                checkpoint_txg: u.checkpoint_txg,
            })
            .collect();
        list.sort_by_key(|u| std::cmp::Reverse((u.txg, u.timestamp)));
        list
    } else {
        Vec::new()
    };
    LabelOut {
        index: scan.index,
        offset: scan.offset,
        slots: scan.slots,
        valid: scan.uberblocks.len(),
        best_txg: best.map(|u| u.txg),
        best_time: best.map(|u| iso8601(u.timestamp)),
        empty_slots,
        corrupt_slots,
        uberblocks,
        corrupt,
    }
}

fn scan_device(path: &Path, detail: bool, all: bool) -> DeviceOut {
    let mut out = DeviceOut {
        path: path.to_path_buf(),
        size: 0,
        error: None,
        labels: Vec::new(),
        newest_txg: None,
        oldest_txg: None,
    };
    let src = match FileSource::open(path) {
        Ok(s) => s,
        Err(e) => {
            out.error = Some(e.to_string());
            return out;
        }
    };
    out.size = src.size();
    match scan_labels(&src) {
        Ok(scans) => {
            let txgs = scans
                .iter()
                .flat_map(|s| s.uberblocks.iter().map(|(_, u)| u.txg))
                .filter(|&t| t != 0);
            let (mut lo, mut hi) = (None, None);
            for t in txgs {
                lo = Some(lo.map_or(t, |l: u64| l.min(t)));
                hi = Some(hi.map_or(t, |h: u64| h.max(t)));
            }
            out.oldest_txg = lo;
            out.newest_txg = hi;
            out.labels = scans.iter().map(|s| label_out(s, detail, all)).collect();
        }
        Err(e) => out.error = Some(e.to_string()),
    }
    out
}

fn print_text(devs: &[DeviceOut], detail: bool) {
    for d in devs {
        println!("{}: {} bytes", d.path.display(), d.size);
        if let Some(e) = &d.error {
            println!("  error: {e}");
            continue;
        }
        for l in &d.labels {
            match (l.best_txg, &l.best_time) {
                (Some(txg), Some(t)) => println!(
                    "  L{} @ {:>12}: {:>3}/{} uberblocks ({} empty, {} corrupt), best txg {} ({})",
                    l.index, l.offset, l.valid, l.slots, l.empty_slots, l.corrupt_slots, txg, t
                ),
                _ => println!(
                    "  L{} @ {:>12}: no valid uberblocks ({} empty, {} corrupt)",
                    l.index, l.offset, l.empty_slots, l.corrupt_slots
                ),
            }
            for c in &l.corrupt {
                println!("      slot {:>3}  {}", c.slot, c.reason);
            }
            if detail {
                for u in &l.uberblocks {
                    println!(
                        "      slot {:>3}  txg {:>12}  {}  v{}  rootbp birth {}{}{}",
                        u.slot,
                        u.txg,
                        u.time,
                        u.version,
                        u.rootbp_birth,
                        if u.mmp { "  mmp" } else { "" },
                        if u.checkpoint_txg != 0 {
                            format!("  checkpoint {}", u.checkpoint_txg)
                        } else {
                            String::new()
                        }
                    );
                }
            }
        }
        match (d.oldest_txg, d.newest_txg) {
            (Some(lo), Some(hi)) => println!("  txg window: {lo}..={hi}"),
            _ => println!("  no ZFS uberblocks found"),
        }
    }
}

/// Run `scan`. With `-v` every label's uberblocks and corrupt slots are
/// listed; `-vv` will add nvlists once `zfs-ondisk` can decode them.
pub fn run(g: &Global, devices: &[PathBuf]) -> u8 {
    let detail = g.verbose >= 1;
    let devs: Vec<DeviceOut> = devices
        .iter()
        .map(|p| scan_device(p, detail, detail))
        .collect();
    if g.verbose >= 2 && !g.quiet {
        eprintln!(
            "zvolrescue: label nvlists are not decoded yet (-vv has no extra output in this build)"
        );
    }
    let json = serde_json::to_value(&devs).expect("serialisable");
    match g.format {
        Format::Json => println!(
            "{}",
            serde_json::to_string_pretty(&json).expect("serialisable")
        ),
        Format::Text => print_text(&devs, detail),
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
    if devs.iter().any(|d| d.error.is_some()) {
        exit::EVIDENCE
    } else {
        0
    }
}
