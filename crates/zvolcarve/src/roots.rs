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
use zvol_common::{errln, outln};

use serde::{Deserialize, Serialize};
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
#[derive(Debug, Clone, Serialize)]
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
    /// Where else the same header is: the MOS is written three times
    /// over, and on a raidz the parity of a block of one sector is the
    /// block again on another member. One header, listed once.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub copies: Vec<CopyOut>,
}

/// Another place a header is at.
#[derive(Debug, Clone, Serialize)]
pub struct CopyOut {
    pub member: String,
    pub offset: u64,
}

/// A dataset some header names, with the GUID a carved candidate knows
/// its dataset by.
///
/// A candidate of `scan` carries no name: names are in the DSL
/// directories of the MOS, which a carve does not reach. It may carry
/// the GUID of the dataset whose object set pointed at it, and a header
/// found here is a MOS: walked, it says what each GUID was called. A
/// volume destroyed since is named by the headers from before it was.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedOut {
    /// `ds_guid`, written as a candidate's `dataset_guid` is.
    pub guid: String,
    pub name: String,
    /// `volume` or `filesystem`; absent where its object set did not
    /// read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default)]
    pub snapshot: bool,
    pub creation_txg: u64,
    /// The size a volume was made, which its dnode cannot say.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volsize: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volblocksize: Option<u64>,
    /// The transaction group of the oldest header that names it so.
    pub first_txg: u64,
    /// And of the newest: older than the newest header of all, the
    /// dataset was destroyed, or renamed, after it.
    pub last_txg: u64,
}

/// What a `roots` run in a workspace says the datasets were called, for
/// `list` and `dump` to name a candidate by.
#[derive(Debug, Default)]
pub struct Names {
    by_guid: std::collections::HashMap<String, NamedOut>,
    newest: Option<u64>,
}

impl Names {
    /// From `roots.json` in `dir`: nothing when there is none, and why
    /// when one is there and does not read.
    pub fn load(dir: &std::path::Path) -> Result<Names, String> {
        #[derive(Deserialize)]
        struct Root {
            birth: u64,
        }
        #[derive(Deserialize)]
        struct Doc {
            #[serde(default)]
            datasets: Vec<NamedOut>,
            #[serde(default)]
            newest: Option<Root>,
        }
        let path = dir.join(ROOTS);
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Names::default()),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        let doc: Doc = serde_json::from_str(&text)
            .map_err(|e| format!("{}: not what `roots` writes: {e}", path.display()))?;
        let mut by_guid = std::collections::HashMap::<String, NamedOut>::new();
        for d in doc.datasets {
            // Renamed, a dataset has two names for one GUID: the one it
            // had last is what it is called.
            match by_guid.get(&d.guid) {
                Some(have) if have.last_txg >= d.last_txg => {}
                _ => {
                    by_guid.insert(d.guid.clone(), d);
                }
            }
        }
        Ok(Names {
            by_guid,
            newest: doc.newest.map(|r| r.birth),
        })
    }

    /// Read for a run that goes on without it: said, not fatal.
    pub fn load_or_say(dir: &std::path::Path) -> Names {
        Names::load(dir).unwrap_or_else(|e| {
            errln!("zvolcarve: {e}; candidates are not named from it");
            Names::default()
        })
    }

    /// The dataset of this GUID, as a candidate writes it.
    pub fn of(&self, guid: &str) -> Option<&NamedOut> {
        self.by_guid.get(guid)
    }

    /// The transaction group of the newest header a pool walks out of.
    pub fn newest(&self) -> Option<u64> {
        self.newest
    }
}

/// What a run writes to the workspace.
#[derive(Debug, Serialize)]
pub struct RootsOut {
    pub version: u32,
    pub members: Vec<String>,
    /// Headers found, best first, and no more of them than
    /// `--max-roots`.
    pub roots: Vec<RootOut>,
    /// More headers were found than are listed: `--max-roots` cut the
    /// list, or the scan met more than it keeps of one member.
    pub truncated: bool,
    /// Headers found, before `--max-roots` cut the list: each counted
    /// once, wherever its copies are.
    pub found: usize,
    /// The newest header a pool walked out of, wherever the ranking put
    /// it and whether or not the list was cut before it: the state the
    /// pool was last in, which is what is looked for first. Its `id` is
    /// its place in the whole ranking.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub newest: Option<RootOut>,
    /// Every dataset a header names, once per name and GUID, over all
    /// the headers found — those `--max-roots` cut from the list too:
    /// what `list` names a candidate of `scan` by.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub datasets: Vec<NamedOut>,
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
            errln!(
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
                    errln!(
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
                errln!("zvolcarve: {e}");
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
        errln!("zvolcarve: {}: {e}", opts.output.display());
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
            errln!("zvolcarve: reading {}", members.paths[i].display());
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
                errln!("zvolcarve: {}: {e}", members.paths[i].display());
                return exit::UNRECOVERABLE;
            }
        }
    }
    // The same header can be met twice: a resume overlaps, and a block
    // read plain is also read as the start of a compressed one.
    found.sort_by_key(|r| (r.device, r.offset));
    found.dedup_by(|a, b| (a.device, a.offset) == (b.device, b.offset));
    // And one header is in several places. The sides of a mirror hold
    // it at the same place in the vdev; the MOS is written three times
    // over; on a raidz the parity of a one-sector block is the block
    // again on another member. One header, walked once, with where else
    // it is: listed once per place, three rows — six on a raidz — said
    // one thing, and the 32 rows the list is cut to by default were the
    // roots of six transaction groups.
    let groups = crate::scan::mirror_groups(pool.as_ref(), members.paths.len());
    let base = |i: usize| members.base_offsets.get(i).copied().unwrap_or(0);
    let mut also_on: Vec<Vec<String>> = Vec::new();
    let mut copies: Vec<Vec<CopyOut>> = Vec::new();
    let mut kept: Vec<RootHit> = Vec::new();
    // Those kept, by what tells one header from another at a glance —
    // where its first block is, when it was born, what it hashes to —
    // so that each is compared with the few that could be it.
    let glance = |r: &RootHit| {
        r.objset
            .meta_dnode
            .blkptr
            .iter()
            .find(|b| !b.is_hole())
            .map(|b| (b.dva[0].offset, b.birth, b.cksum[0]))
    };
    let mut by_glance: std::collections::HashMap<_, Vec<usize>> = std::collections::HashMap::new();
    for r in found {
        let first = by_glance
            .get(&glance(&r))
            .and_then(|same| same.iter().copied().find(|&k| kept[k].objset == r.objset));
        match first {
            Some(k) => {
                let side_of_mirror = groups[r.device].is_some()
                    && groups[kept[k].device] == groups[r.device]
                    && kept[k].device != r.device
                    && kept[k].offset.saturating_sub(base(kept[k].device))
                        == r.offset.saturating_sub(base(r.device));
                let member = members.paths[r.device].display().to_string();
                if side_of_mirror {
                    also_on[k].push(member);
                } else {
                    copies[k].push(CopyOut {
                        member,
                        offset: r.offset,
                    });
                }
            }
            None => {
                by_glance.entry(glance(&r)).or_default().push(kept.len());
                kept.push(r);
                also_on.push(Vec::new());
                copies.push(Vec::new());
            }
        }
    }
    let found = kept;

    // Walking is what separates a header from a coincidence, so it is
    // done for every one of them before anything is ranked.
    let mut out: Vec<RootOut> = Vec::new();
    let mut named: std::collections::BTreeMap<(String, u64), NamedOut> =
        std::collections::BTreeMap::new();
    for ((r, also_on), copies) in found.iter().zip(also_on).zip(copies) {
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
            copies,
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
                            for d in &tree.datasets {
                                let e =
                                    named.entry((d.name.clone(), d.guid)).or_insert_with(|| {
                                        NamedOut {
                                            guid: format!("{:#018x}", d.guid),
                                            name: d.name.clone(),
                                            kind: None,
                                            snapshot: d.snapshot,
                                            creation_txg: d.creation_txg,
                                            volsize: None,
                                            volblocksize: None,
                                            first_txg: birth,
                                            last_txg: birth,
                                        }
                                    });
                                e.first_txg = e.first_txg.min(birth);
                                // What the newest header says of it is
                                // what it last was.
                                let newer = birth >= e.last_txg;
                                e.last_txg = e.last_txg.max(birth);
                                for (have, says, newer) in [
                                    (&mut e.volsize, d.volsize, newer),
                                    (&mut e.volblocksize, d.volblocksize, newer),
                                ] {
                                    if says.is_some() && (newer || have.is_none()) {
                                        *have = says;
                                    }
                                }
                                if let Some(k) = d.kind.filter(|_| newer || e.kind.is_none()) {
                                    e.kind = Some(k.name());
                                }
                            }
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
    for (i, r) in out.iter_mut().enumerate() {
        r.id = i;
    }
    // The pool as it last was is the newest header a pool walks out of,
    // and that ranking puts it last of all once a dataset has been
    // destroyed: the roots before the destruction yield more. Cut to
    // `--max-roots`, the list of a command meant to find the MOS did
    // not hold the pool's last one, and said nothing was cut. It is
    // named whatever its rank, and the cut is said.
    let newest = out
        .iter()
        .filter(|r| r.datasets > 0)
        .max_by_key(|r| (r.birth, std::cmp::Reverse(r.id)))
        .cloned();
    let headers = out.len();
    truncated |= headers > opts.max_roots;
    out.truncate(opts.max_roots);

    let doc = RootsOut {
        version: ROOTS_VERSION,
        members: members
            .paths
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        roots: out,
        truncated,
        found: headers,
        newest,
        datasets: named.into_values().collect(),
        bytes_read,
    };
    let path = opts.output.join(ROOTS);
    let json = match serde_json::to_string_pretty(&doc) {
        Ok(j) => j + "\n",
        Err(e) => {
            errln!("zvolcarve: {e}");
            return exit::USAGE;
        }
    };
    if let Err(e) = std::fs::write(&path, &json) {
        errln!("zvolcarve: {}: {e}", path.display());
        return exit::USAGE;
    }

    match g.format {
        Format::Json => print!("{json}"),
        Format::Text => {
            print(&doc, &path);
            // What a header is found for: the other programs read the
            // pool at it, given the file this run wrote.
            if doc.roots.iter().chain(&doc.newest).any(|r| r.datasets > 0) {
                outln!(
                    "  to read the pool at them: zvolrescue list {} --roots {}",
                    spec.as_arguments().join(" "),
                    zvol_common::shell_quote(&opts.output.display().to_string())
                );
            }
        }
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
    // The table of names is in the file, which the record names with
    // its hash; in the record itself it is how many there are.
    let mut record = serde_json::to_value(&doc).expect("serialisable");
    if let Some(o) = record.as_object_mut() {
        o.remove("datasets");
        o.insert("datasets_named".into(), doc.datasets.len().into());
    }
    g.log_evidence_with_incidents(
        "zvolcarve",
        &record,
        code,
        &members.inputs(),
        written,
        &members.ledger.incidents(),
    )
}

/// One header, as the list shows it.
fn print_root(r: &RootOut) {
    {
        outln!(
            "  [{}] {} at {:#x}  {}  birth {}  {} dataset(s)",
            r.id,
            r.member,
            r.offset,
            r.found,
            r.birth,
            r.datasets
        );
        if !r.sample.is_empty() {
            // Names are what the pool says they are, and are shown as
            // text: one with an escape sequence in it was sent to the
            // terminal as one.
            let names: Vec<_> = r
                .sample
                .iter()
                .map(|n| zvol_common::text::shown(n))
                .collect();
            outln!("      {}", names.join(", "));
        }
        if !r.also_on.is_empty() {
            outln!("      also on {}", r.also_on.join(", "));
        }
        if !r.copies.is_empty() {
            // By place, each with the members that hold it there.
            let mut places: Vec<(u64, Vec<&str>)> = Vec::new();
            for c in &r.copies {
                match places.iter_mut().find(|(at, _)| *at == c.offset) {
                    Some((_, on)) => on.push(&c.member),
                    None => places.push((c.offset, vec![&c.member])),
                }
            }
            outln!(
                "      the same header also at {}",
                places
                    .iter()
                    .map(|(at, on)| format!("{at:#x} ({})", on.join(", ")))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if let Some(e) = &r.error {
            outln!("      {}", zvol_common::text::shown(e));
        }
    }
}

fn print(doc: &RootsOut, path: &std::path::Path) {
    outln!(
        "{} object-set header(s) in {} bytes of {}",
        doc.found,
        doc.bytes_read,
        doc.members.join(", ")
    );
    if doc.found > doc.roots.len() {
        outln!(
            "  the first {} by rank are listed and {} are not: --max-roots {} lists them all",
            doc.roots.len(),
            doc.found - doc.roots.len(),
            doc.found
        );
    } else if doc.truncated {
        outln!("  more headers were met than are kept of one member; the rest were dropped");
    }
    if doc.found == 0 {
        outln!("  no MOS header was found: the pool's root is not in the range that was read");
    }
    for r in &doc.roots {
        print_root(r);
    }
    // Said apart when the ranking did not put it first: it is the state
    // the pool was last in.
    if let Some(n) = doc.newest.as_ref().filter(|n| n.id != 0) {
        outln!(
            "  the newest a pool walks out of is [{}]{}:",
            n.id,
            if n.id >= doc.roots.len() {
                ", past where the list was cut"
            } else {
                ""
            }
        );
        print_root(n);
    }
    // What a carve is usually for: the datasets the pool does not have
    // any more, with the header that named each last.
    if let Some(newest) = doc.newest.as_ref().map(|n| n.birth) {
        let gone: Vec<&NamedOut> = doc
            .datasets
            .iter()
            .filter(|d| d.last_txg < newest)
            .collect();
        if !gone.is_empty() {
            outln!(
                "  {} of the {} dataset name(s) the headers give are not in the newest (txg {newest}):",
                gone.len(),
                doc.datasets.len()
            );
            const SHOWN: usize = 16;
            for d in gone.iter().take(SHOWN) {
                outln!(
                    "      {} ({}), last named at txg {}",
                    zvol_common::text::shown(&d.name),
                    d.guid,
                    d.last_txg
                );
            }
            if gone.len() > SHOWN {
                outln!(
                    "      and {} more, in {}",
                    gone.len() - SHOWN,
                    path.display()
                );
            }
        }
    }
    outln!("  index: {}", path.display());
}
