//! `zvolcarve roots` — the MOS when no uberblock survives (SPEC F-64).
//!
//! Every other way into a pool starts at an uberblock: it carries the
//! root pointer, the root pointer names the MOS, and the MOS names
//! everything else. When all four label rings are gone there is no root
//! pointer anywhere, and the only remaining way in is to find the MOS's
//! own `objset_phys_t` in raw space.
//!
//! Finding one is cheap; believing it is not. So each header found is
//! *used*: the DSL is walked from it, and what ranks a candidate is how
//! much of a pool came out, with the birth of its pointers to separate
//! the ones that walked equally well. A header that yields no datasets
//! is still reported, with the reason it gave, because "found but
//! unreadable" and "not found" are different answers to the operator.

use std::path::PathBuf;

use serde::Serialize;
use zfs_ondisk::Endian;
use zfs_read::carve::{scan_member, Codec, Options as ScanOptions, RootHit};
use zfs_read::zio::PoolReader;
use zvol_common::evidence::FileRef;
use zvol_common::members::{choose_pool, open_members};
use zvol_common::{exit, Format, Global, PoolSpec, WriteGuard};

/// Name of the file a run writes into the workspace.
pub const ROOTS: &str = "roots.json";

/// Version of that file's shape.
pub const ROOTS_VERSION: u32 = 1;

/// Options of a `roots` run.
pub struct Options {
    pub output: PathBuf,
    pub range: Option<String>,
    pub compressed: String,
    pub max_roots: usize,
}

/// One object-set header, and what walking from it produced.
#[derive(Debug, Serialize)]
pub struct RootOut {
    /// Position in the ranking, as `dump` and a person both refer to it.
    pub id: usize,
    /// Member it was found on.
    pub member: String,
    /// Byte offset in that member.
    pub offset: u64,
    /// `plaintext`, or the compression the block was in.
    pub found: String,
    /// Highest birth transaction group among the meta-dnode's pointers.
    pub birth: u64,
    /// Block size of the dnode array under it.
    pub datablksz: u64,
    /// Depth of that array's block tree.
    pub nlevels: u8,
    /// Datasets the DSL walk produced, or 0 when it produced none.
    pub datasets: usize,
    /// Why the walk produced nothing, when it produced nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Names of the datasets, capped so a large pool does not fill the
    /// file; `datasets` is the true count either way.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sample: Vec<String>,
    /// The other members of its mirror holding the same header at the
    /// same place: one header, listed once.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub also_on: Vec<String>,
}

/// What a run writes to the workspace.
#[derive(Debug, Serialize)]
pub struct RootsOut {
    pub version: u32,
    pub members: Vec<String>,
    /// Headers found, best first.
    pub roots: Vec<RootOut>,
    /// Headers were found than the cap allowed and the rest were dropped.
    pub truncated: bool,
    pub bytes_read: u64,
}

/// How many dataset names are kept per candidate.
const SAMPLE: usize = 8;

/// `START-END`.
fn byte_range(s: &str) -> Result<(u64, u64), String> {
    let (a, b) = s
        .split_once('-')
        .ok_or_else(|| format!("--range {s}: expected START-END"))?;
    let start: u64 = a
        .trim()
        .parse()
        .map_err(|_| format!("--range {s}: {a} is not a number"))?;
    let end: u64 = b
        .trim()
        .parse()
        .map_err(|_| format!("--range {s}: {b} is not a number"))?;
    if start >= end {
        return Err(format!("--range {s}: the range is empty"));
    }
    Ok((start, end))
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
        Err(code) => return zvol_common::end_early(g, "zvolcarve", spec, code),
    };
    // A pool is not needed to *find* a header — that is the point — but
    // it is needed to read anything the header points at, because a
    // block pointer addresses a DVA and only the layout says where a DVA
    // is. Without labels that layout comes from `--hints` (SPEC F-65).
    let pool = choose_pool(members.pools.clone(), spec.pool_guid.as_deref()).ok();

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
    let range = match &opts.range {
        // Taken down to its 512-byte slot, as `scan` takes it: `--range
        // 1000-…` put every slot off by 488 bytes and found nothing.
        Some(s) => match byte_range(s) {
            Ok((a, b)) => Some((a / 512 * 512, b)),
            Err(e) => {
                eprintln!("zvolcarve: {e}");
                return exit::USAGE;
            }
        },
        None => None,
    };

    let mut reads = spec.reads();
    reads.extend(members.paths.iter().cloned());
    let guard = WriteGuard::new(g, &reads);
    for (what, path) in [
        ("-o", opts.output.clone()),
        ("to write", opts.output.join(ROOTS)),
    ] {
        if let Err(code) = guard.refuse("zvolcarve", what, &path) {
            return code;
        }
    }
    if let Err(e) = std::fs::create_dir_all(&opts.output) {
        eprintln!("zvolcarve: {}: {e}", opts.output.display());
        return exit::USAGE;
    }

    let scan_opts = ScanOptions {
        range,
        codecs,
        // Not one dnode candidate is wanted here, and the scan has to
        // run to the end of the member regardless of how many it meets.
        collect_hits: false,
        ..ScanOptions::default()
    };

    let mut found: Vec<RootHit> = Vec::new();
    let mut truncated = false;
    let mut bytes_read = 0u64;
    for (i, src) in members.sources.iter().enumerate() {
        let Some(src) = src else {
            continue;
        };
        if !g.quiet {
            eprintln!("zvolcarve: reading {}", members.paths[i].display());
        }
        let opts_here = ScanOptions {
            vdev_start: members.base_offsets.get(i).copied().unwrap_or(0),
            ..scan_opts.clone()
        };
        match scan_member(src, i, crate::member_ashift(pool.as_ref(), i), &opts_here) {
            Ok(s) => {
                bytes_read += s.bytes_read;
                truncated |= s.roots_truncated;
                found.extend(s.roots);
            }
            Err(e) => {
                eprintln!("zvolcarve: {}: {e}", members.paths[i].display());
                return exit::UNRECOVERABLE;
            }
        }
    }
    // The same header can be met twice: a resume overlaps, and a block
    // read plain is also read as the start of a compressed one.
    found.sort_by_key(|r| (r.device, r.offset));
    found.dedup_by(|a, b| (a.device, a.offset) == (b.device, b.offset));
    // And the sides of a mirror hold the same header at the same place
    // in the vdev: one header, walked once, with where else it is.
    let groups = crate::scan::mirror_groups(pool.as_ref(), members.paths.len());
    let base = |i: usize| members.base_offsets.get(i).copied().unwrap_or(0);
    let mut copies: Vec<Vec<String>> = Vec::new();
    let mut kept: Vec<RootHit> = Vec::new();
    for r in found {
        let first = groups[r.device].and_then(|g| {
            kept.iter().position(|k| {
                groups[k.device] == Some(g)
                    && k.device != r.device
                    && k.offset.saturating_sub(base(k.device))
                        == r.offset.saturating_sub(base(r.device))
                    && k.objset == r.objset
            })
        });
        match first {
            Some(k) => copies[k].push(members.paths[r.device].display().to_string()),
            None => {
                kept.push(r);
                copies.push(Vec::new());
            }
        }
    }
    let found = kept;

    // Walking is what separates a header from a coincidence, so it is
    // done for every one of them before anything is ranked.
    let mut out: Vec<RootOut> = Vec::new();
    for (r, also_on) in found.iter().zip(copies) {
        let birth = r
            .objset
            .meta_dnode
            .blkptr
            .iter()
            .map(|b| b.birth)
            .max()
            .unwrap_or(0);
        let mut row = RootOut {
            id: 0,
            member: members.paths[r.device].display().to_string(),
            offset: r.offset,
            found: r.found.as_str().to_string(),
            birth,
            datablksz: r.objset.meta_dnode.datablksz(),
            nlevels: r.objset.meta_dnode.nlevels,
            datasets: 0,
            error: None,
            sample: Vec::new(),
            also_on,
        };
        match &pool {
            None => {
                row.error = Some(
                    "no layout: the header was found, but a DVA cannot be placed without \
                     labels or --hints (SPEC F-65)"
                        .into(),
                )
            }
            Some(p) => {
                let reader =
                    PoolReader::new(p, members.devices()).with_base_offsets(&members.bases());
                match zfs_read::dsl::open_mos_objset(&reader, r.objset.clone(), Endian::Little) {
                    Err(e) => row.error = Some(e.to_string()),
                    Ok(mos) => match zfs_read::dsl::walk(&mos, &p.name) {
                        Err(e) => row.error = Some(e.to_string()),
                        Ok(tree) => {
                            row.datasets = tree.datasets.len();
                            row.sample = tree
                                .datasets
                                .iter()
                                .take(SAMPLE)
                                .map(|d| d.name.clone())
                                .collect();
                        }
                    },
                }
            }
        }
        out.push(row);
    }
    // What came out of the pool first, then how recent it is: a header
    // that yields more of the pool is better evidence than one that
    // yields less, whatever its transaction group says.
    out.sort_by(|a, b| b.datasets.cmp(&a.datasets).then(b.birth.cmp(&a.birth)));
    out.truncate(opts.max_roots);
    for (i, r) in out.iter_mut().enumerate() {
        r.id = i;
    }

    let doc = RootsOut {
        version: ROOTS_VERSION,
        members: members
            .paths
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        roots: out,
        truncated,
        bytes_read,
    };
    let path = opts.output.join(ROOTS);
    let json = match serde_json::to_string_pretty(&doc) {
        Ok(j) => j + "\n",
        Err(e) => {
            eprintln!("zvolcarve: {e}");
            return exit::USAGE;
        }
    };
    if let Err(e) = std::fs::write(&path, &json) {
        eprintln!("zvolcarve: {}: {e}", path.display());
        return exit::USAGE;
    }

    match g.format {
        Format::Json => print!("{json}"),
        Format::Text => print(&doc, &path),
    }
    // A run that found nothing is not a failure of the run; it is an
    // answer, and the exit code says which answer it was.
    let code = if doc.roots.is_empty() {
        exit::UNRECOVERABLE
    } else {
        0
    };
    // A device refused a read (SPEC F-33, N-10): said, and the exit code.
    // A member that did not open is said, and so is the code: the run
    // is of the members that did, as `zvolrescue` says it (exit 2); it
    // ended 0.
    let code = if code == 0 && members.any_failed() {
        exit::EVIDENCE
    } else {
        code
    };
    let code = zvol_common::report_medium(&members.ledger).unwrap_or(code);
    // On the record like every other run: `--evidence-log` was taken
    // and nothing was written to it.
    let written = FileRef::hashed(&path).map(|f| vec![f]).unwrap_or_default();
    g.log_evidence_with_incidents(
        "zvolcarve",
        &serde_json::to_value(&doc).expect("serialisable"),
        code,
        &members.inputs(),
        written,
        &members.ledger.incidents(),
    )
}

fn print(doc: &RootsOut, path: &std::path::Path) {
    println!(
        "{} object-set header(s) in {} bytes of {}",
        doc.roots.len(),
        doc.bytes_read,
        doc.members.join(", ")
    );
    if doc.truncated {
        println!("  more headers were found than the cap allowed; the rest were dropped");
    }
    if doc.roots.is_empty() {
        println!("  no MOS header was found: the pool's root is not in the range that was read");
    }
    for r in &doc.roots {
        println!(
            "  [{}] {} at {:#x}  {}  birth {}  {} dataset(s)",
            r.id, r.member, r.offset, r.found, r.birth, r.datasets
        );
        if !r.sample.is_empty() {
            println!("      {}", r.sample.join(", "));
        }
        if !r.also_on.is_empty() {
            println!("      also on {}", r.also_on.join(", "));
        }
        if let Some(e) = &r.error {
            println!("      {e}");
        }
    }
    println!("  index: {}", path.display());
}
