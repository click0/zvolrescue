//! `zvolcarve zeropoint` — where the vdev begins, from the pointers
//! alone (SPEC F-63).
//!
//! Every other route to the base needs something that survived: a label,
//! a partition table, a sibling's configuration, an uberblock, or the
//! operator's own knowledge of the layout. This is the case where none
//! of that is left.
//!
//! What is still there is that ZFS describes its own blocks. A block
//! pointer gives a position, a size and a checksum, and the position is
//! relative to the vdev's allocatable space — so the pointer is a test
//! of any candidate base: assume `B`, read at `B + 4 MiB + offset`, and
//! see whether the bytes hash to what the pointer said. A wrong base
//! hashes to nothing.
//!
//! The answer feeds `--hints` (F-65): once the base is known, every
//! other command can read the member through it.

use std::path::PathBuf;

use serde::Serialize;
use zfs_read::carve::{scan_member, Codec, Options as ScanOptions};
use zfs_read::pointers::{anchors, search, shifts, Options as SearchOptions};
use zvol_common::members::open_members;
use zvol_common::{exit, Format, Global, PoolSpec};

/// Name of the file a run writes when a workspace was given.
pub const ZEROPOINT: &str = "zeropoint.json";

/// Options of a `zeropoint` run.
pub struct Options {
    pub output: Option<PathBuf>,
    pub window: Option<String>,
    pub compressed: String,
    pub max_hits: usize,
}

/// One candidate base, as the report records it.
#[derive(Debug, Serialize)]
pub struct BaseOut {
    pub base: u64,
    /// Probes whose checksum agreed at this base.
    pub confirmed: usize,
    /// Probes read. One agreement is worth about nothing; fifty is not.
    pub tried: usize,
}

/// What one member produced.
#[derive(Debug, Serialize)]
pub struct MemberOut {
    pub member: String,
    /// Block pointers usable as probes: not holes, not embedded, not
    /// gang, and with a checksum this build can recompute without the
    /// pool's salt.
    pub probes: usize,
    /// Shifts the probes' own alignment allows, largest first.
    pub shifts: Vec<u32>,
    pub bases: Vec<BaseOut>,
    /// The scan stopped before the end of the member, having found as
    /// many probes as it was asked for.
    pub scan_stopped_early: bool,
    pub bytes_read: u64,
}

#[derive(Debug, Serialize)]
pub struct ZeroPointOut {
    pub version: u32,
    pub members: Vec<MemberOut>,
}

/// `START-END`.
fn byte_range(s: &str) -> Result<(u64, u64), String> {
    let (a, b) = s
        .split_once('-')
        .ok_or_else(|| format!("--window {s}: expected START-END"))?;
    let start: u64 = a
        .trim()
        .parse()
        .map_err(|_| format!("--window {s}: {a} is not a number"))?;
    let end: u64 = b
        .trim()
        .parse()
        .map_err(|_| format!("--window {s}: {b} is not a number"))?;
    if start >= end {
        return Err(format!("--window {s}: the range is empty"));
    }
    Ok((start, end - start))
}

pub fn run(g: &Global, spec: &PoolSpec, opts: &Options) -> u8 {
    // A surface scan is what a disk with defects survives least: a
    // block device is refused unless the operator allowed it (SPEC
    // N-10) — before it is opened, so not even its labels are read.
    if !spec.surface_scan_on_device {
        if let Some(dev) = spec
            .members()
            .ok()
            .into_iter()
            .flatten()
            .find(|p| zvol_common::evidence::Kind::of(p).is_device())
        {
            eprintln!(
                "zvolcarve: {}: a block device is not scanned (SPEC N-10): a surface scan is what a disk with defects survives least. \
                 Image it with a tool for failing media and scan the image; --surface-scan-on-device overrides.",
                dev.display()
            );
            return exit::REFUSED;
        }
    }
    let members = match open_members(spec) {
        Ok(m) => m,
        Err(code) => return code,
    };
    let codecs: Vec<Codec> = if opts.compressed == "none" {
        Vec::new()
    } else {
        let mut v = Vec::new();
        for name in opts.compressed.split(',').map(str::trim) {
            match Codec::named(name) {
                Some(c) => v.push(c),
                None => {
                    eprintln!(
                        "zvolcarve: --compressed {name}: not a compression this build knows (lz4, lzjb, gzip, zstd, none)"
                    );
                    return exit::USAGE;
                }
            }
        }
        v
    };
    let window = match &opts.window {
        Some(s) => match byte_range(s) {
            Ok(w) => Some(w),
            Err(e) => {
                eprintln!("zvolcarve: {e}");
                return exit::USAGE;
            }
        },
        None => None,
    };
    if let Some(dir) = &opts.output {
        if let Err(e) = zvolrescue_io::refuse_if_evidence(dir, &members.paths) {
            eprintln!("zvolcarve: {e}");
            return exit::REFUSED;
        }
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("zvolcarve: {}: {e}", dir.display());
            return exit::USAGE;
        }
    }

    let scan_opts = ScanOptions {
        codecs,
        // Enough probes is enough: the base is settled by a few dozen
        // agreeing pointers, and reading the rest of the member to find
        // thousands more would only cost time. A scan that stopped early
        // says so in the report.
        max_hits: opts.max_hits,
        ..ScanOptions::default()
    };

    let mut out = Vec::new();
    for (i, src) in members.sources.iter().enumerate() {
        let Some(src) = src else {
            continue;
        };
        if !g.quiet {
            eprintln!("zvolcarve: reading {}", members.paths[i].display());
        }
        let scan = match scan_member(src, i, 12, &scan_opts) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("zvolcarve: {}: {e}", members.paths[i].display());
                return exit::UNRECOVERABLE;
            }
        };
        let probes = anchors(&scan);
        let shift_list = shifts(&probes);
        let found = match search(
            src,
            &probes,
            &SearchOptions {
                window,
                ..SearchOptions::default()
            },
        ) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("zvolcarve: {}: {e}", members.paths[i].display());
                return exit::UNRECOVERABLE;
            }
        };
        out.push(MemberOut {
            member: members.paths[i].display().to_string(),
            probes: probes.len(),
            shifts: shift_list,
            bases: found
                .into_iter()
                .map(|b| BaseOut {
                    base: b.base,
                    confirmed: b.confirmed,
                    tried: b.tried,
                })
                .collect(),
            scan_stopped_early: scan.stopped_early,
            bytes_read: scan.bytes_read,
        });
    }

    let doc = ZeroPointOut {
        version: 1,
        members: out,
    };
    let json = match serde_json::to_string_pretty(&doc) {
        Ok(j) => j + "\n",
        Err(e) => {
            eprintln!("zvolcarve: {e}");
            return exit::USAGE;
        }
    };
    if let Some(dir) = &opts.output {
        let path = dir.join(ZEROPOINT);
        if let Err(e) = std::fs::write(&path, &json) {
            eprintln!("zvolcarve: {}: {e}", path.display());
            return exit::USAGE;
        }
    }
    match g.format {
        Format::Json => print!("{json}"),
        Format::Text => print(&doc),
    }
    let code = if doc.members.iter().all(|m| m.bases.is_empty()) {
        exit::UNRECOVERABLE
    } else {
        0
    };
    // A device refused a read (SPEC F-33, N-10): said, and the exit code.
    zvol_common::report_medium(&members.ledger).unwrap_or(code)
}

fn print(doc: &ZeroPointOut) {
    for m in &doc.members {
        println!(
            "{}: {} probe(s) in {} bytes{}",
            m.member,
            m.probes,
            m.bytes_read,
            if m.scan_stopped_early {
                ", scan stopped once it had enough"
            } else {
                ""
            }
        );
        if m.probes == 0 {
            println!(
                "  nothing to probe with: no block pointer this build can recompute was found"
            );
            continue;
        }
        println!(
            "  alignment allows ashift {}",
            m.shifts
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        if m.bases.is_empty() {
            println!("  no base in the window is consistent with those probes");
        }
        for b in &m.bases {
            println!(
                "  base {:#x} ({} bytes): {} of {} probe(s) agreed",
                b.base, b.base, b.confirmed, b.tried
            );
        }
    }
}
