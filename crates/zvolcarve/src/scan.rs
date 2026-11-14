//! `zvolcarve scan` — read the members through and record what could be
//! a volume (C-01, C-04, C-05, C-08, C-13…C-18).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::Ordering;

use clap::Args;
use zfs_ondisk::carve::{Profile, Reject};
use zfs_ondisk::dmu::{object_type_name, ot, DnodePhys};
use zfs_ondisk::Endian;
use zfs_read::carve::{assess_against, rank, scan_member, Codec, Options as ScanOptions};
use zfs_read::dmu::ObjectReader;
use zfs_read::zio::PoolReader;
use zvol_common::evidence::FileRef;
use zvol_common::members::{choose_pool, open_members};
use zvol_common::{exit, Format, Global, PoolSpec, WriteGuard};
use zvolrescue_io::BlockSource;

use crate::model::{
    to_hex, AssessmentOut, Bucket, Candidate, ContentsOut, Histograms, Index, ProfileOut,
    Rejection, SpaceOut, StartByPointers, State, INDEX, INDEX_VERSION, STATE,
};

/// The search profile, on the command line (C-13, C-16, C-17, C-18).
#[derive(Debug, Args)]
pub struct ProfileArgs {
    /// Data block size of the volume being looked for.
    #[arg(long, value_name = "BYTES")]
    pub volblocksize: Option<u64>,
    /// Tree depth (`dn_nlevels`) of the volume being looked for.
    #[arg(long, value_name = "N")]
    pub levels: Option<u8>,
    /// Birth transaction group window, as FROM..TO.
    #[arg(long, value_name = "FROM..TO")]
    pub txg: Option<String>,
    /// Estimated size range in bytes, as MIN..MAX.
    #[arg(long, value_name = "MIN..MAX")]
    pub size: Option<String>,
    /// Object type to look for: `zvol` (the default, unless a profile
    /// names one), `file`, or a numeric `dn_type`. `any` follows every
    /// type the scan recognises. Given here, it wins over the profile.
    #[arg(long, value_name = "TYPE")]
    pub dnode_type: Option<String>,
    /// Read the profile from a JSON file; command-line fields win.
    #[arg(long, value_name = "FILE")]
    pub profile: Option<PathBuf>,
    /// Take `volblocksize`, `levels` and `size` from a dataset that
    /// still exists in the pool: in most incidents the lost volume was
    /// made like its neighbours (C-17).
    #[arg(long, value_name = "DATASET")]
    pub like: Option<String>,
    /// Treat profile fields as hard filters, not as hints (C-18).
    #[arg(long)]
    pub strict_profile: bool,
}

/// Options of a `scan` run.
pub struct Options {
    pub output: PathBuf,
    pub profile: ProfileArgs,
    pub range: Option<String>,
    pub resume: bool,
    pub full_assess: bool,
    pub max_hits: usize,
    pub sample: Option<usize>,
    pub compressed: String,
}

/// `FROM..TO`, both optional around the dots.
fn range_pair(s: &str, what: &str) -> Result<(u64, u64), String> {
    let (a, b) = s
        .split_once("..")
        .ok_or_else(|| format!("--{what} {s}: expected FROM..TO"))?;
    let from = if a.trim().is_empty() {
        0
    } else {
        a.trim()
            .parse()
            .map_err(|_| format!("--{what} {s}: {a} is not a number"))?
    };
    let to = if b.trim().is_empty() {
        u64::MAX
    } else {
        b.trim()
            .parse()
            .map_err(|_| format!("--{what} {s}: {b} is not a number"))?
    };
    if from > to {
        return Err(format!("--{what} {s}: {from} is above {to}"));
    }
    Ok((from, to))
}

/// `START-END` for `--range`.
fn byte_range(s: &str) -> Result<(u64, u64), String> {
    let (a, b) = s
        .split_once('-')
        .ok_or_else(|| format!("--range {s}: expected START-END"))?;
    let start = a
        .trim()
        .parse()
        .map_err(|_| format!("--range {s}: {a} is not a number"))?;
    let end = b
        .trim()
        .parse()
        .map_err(|_| format!("--range {s}: {b} is not a number"))?;
    if start >= end {
        return Err(format!("--range {s}: the range is empty"));
    }
    Ok((start, end))
}

fn dnode_type_code(name: &str) -> Result<Option<u8>, String> {
    match name {
        "any" => Ok(None),
        "zvol" => Ok(Some(ot::ZVOL)),
        "file" => Ok(Some(ot::PLAIN_FILE_CONTENTS)),
        other => other
            .parse::<u8>()
            .map(Some)
            .map_err(|_| format!("--dnode-type {other}: not a known type or a number")),
    }
}

/// The profile as a JSON document, for `--profile` (C-16).
///
/// A key it does not know is refused, not passed over: `"volblocksize"`
/// misspelt searched for every block size, and said nothing.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileFile {
    volblocksize: Option<u64>,
    levels: Option<u8>,
    txg: Option<[u64; 2]>,
    size: Option<[u64; 2]>,
    dnode_type: Option<String>,
}

/// For each member, the top-level mirror whose leaf it is, if any (C-09).
pub(crate) fn mirror_groups(
    pool: Option<&zfs_read::pool::PoolAssembly>,
    n: usize,
) -> Vec<Option<u64>> {
    let mut groups = vec![None; n];
    let Some(pool) = pool else {
        return groups;
    };
    for top in &pool.tops {
        let flat = top.tree.children.iter().all(|c| c.children.is_empty());
        if matches!(top.kind.as_str(), "mirror" | "spare" | "replacing") && flat {
            for m in &top.members {
                if let Some(slot) = m.present.and_then(|i| groups.get_mut(i)) {
                    *slot = Some(top.id);
                }
            }
        }
    }
    groups
}

/// Build the profile from the file, the command line and `--like`, in
/// that order of precedence.
fn build_profile(
    args: &ProfileArgs,
    like: Option<(u64, u8, u64)>,
) -> Result<(Profile, ProfileOut), String> {
    let mut p = Profile::default();
    let mut profile_named_a_type = false;
    if let Some(path) = &args.profile {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let f: ProfileFile = serde_json::from_str(&text)
            .map_err(|e| format!("{}: not a search profile: {e}", path.display()))?;
        // A range whose start is past its end holds nothing, and a search
        // for it found nothing, exit 3, as though there were nothing to
        // find.
        for (key, range) in [("txg", f.txg), ("size", f.size)] {
            if let Some([lo, hi]) = range {
                if lo > hi {
                    return Err(format!(
                        "{}: {key} [{lo}, {hi}]: the range is empty, its start is past its end",
                        path.display()
                    ));
                }
            }
        }
        p.volblocksize = f.volblocksize;
        p.levels = f.levels;
        p.txg = f.txg.map(|t| (t[0], t[1]));
        p.size = f.size.map(|s| (s[0], s[1]));
        if let Some(t) = f.dnode_type {
            p.dnode_type = dnode_type_code(&t)?;
            profile_named_a_type = true;
        }
    }
    // A sibling that still exists knows these better than memory does.
    if let Some((bs, levels, size)) = like {
        p.volblocksize = Some(bs);
        p.levels = Some(levels);
        p.size = Some((size, size));
    }
    if let Some(bs) = args.volblocksize {
        p.volblocksize = Some(bs);
    }
    if let Some(l) = args.levels {
        p.levels = Some(l);
    }
    if let Some(t) = &args.txg {
        p.txg = Some(range_pair(t, "txg")?);
    }
    if let Some(s) = &args.size {
        p.size = Some(range_pair(s, "size")?);
    }
    // The command line wins, as for every other field: an explicit
    // `--dnode-type zvol` used to lose to a profile's `file`, being the
    // same word as the default. Without either, it is a volume that is
    // looked for — a profile that named no type searched every one.
    match &args.dnode_type {
        Some(t) => p.dnode_type = dnode_type_code(t)?,
        None if !profile_named_a_type => p.dnode_type = dnode_type_code("zvol")?,
        None => {}
    }
    let out = ProfileOut {
        dnode_type: p.dnode_type.map(object_type_name),
        volblocksize: p.volblocksize,
        levels: p.levels,
        txg: p.txg.map(|(a, b)| [a, b]),
        size: p.size.map(|(a, b)| [a, b]),
        strict: args.strict_profile,
    };
    Ok((p, out))
}

/// Run `scan`.
pub fn run(g: &Global, spec: &PoolSpec, opts: &Options) -> u8 {
    // From here a SIGINT ends the scan at the next chunk with the state
    // file saying where. One that comes while the members are still being
    // opened is acted on when the scan begins, at its first chunk; a
    // second is the default action, for a run that never gets there.
    let interrupt = zvol_common::interrupt_flag();
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
    // A carve does not need a pool to assemble — that is rather the
    // point — but when one does, its ashift and its reader are what make
    // the compressed pass and the tree walk possible.
    let pool = choose_pool(members.pools.clone(), spec.pool_guid.as_deref()).ok();

    // --like reads the numbers off a dataset that is still there.
    let like = match (&opts.profile.like, &pool) {
        (Some(name), Some(p)) => {
            let reader = PoolReader::new(p, members.devices()).with_base_offsets(&members.bases());
            match like_dataset(&reader, &members.scans, p, name) {
                Ok(v) => Some(v),
                Err(e) => {
                    eprintln!("zvolcarve: --like {name}: {e}");
                    return exit::USAGE;
                }
            }
        }
        (Some(name), None) => {
            eprintln!("zvolcarve: --like {name}: no pool assembled from these members");
            return exit::UNRECOVERABLE;
        }
        (None, _) => None,
    };

    let (mut profile, mut profile_out) = match build_profile(&opts.profile, like) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("zvolcarve: {e}");
            return exit::USAGE;
        }
    };
    // A sample is a look at what is there, not a search for something:
    // it follows every type and filters nothing, because the point is
    // to see the shape of the disk before deciding what to ask for.
    if opts.sample.is_some() {
        profile = Profile::default();
        profile_out = ProfileOut::default();
    }
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
        // Dnodes sit on 512-byte slots, and a start between two of them
        // put every slot of the range off by the difference: `--range
        // 1000-…` found nothing. The start is taken down to its slot.
        Some(s) => match byte_range(s) {
            Ok((a, b)) => Some((a / 512 * 512, b)),
            Err(e) => {
                eprintln!("zvolcarve: {e}");
                return exit::USAGE;
            }
        },
        None => None,
    };
    // A resume goes on with the range the scan was started with. One
    // given again may end elsewhere — a scan resumed to the end of a
    // range is how a long one is done in parts — but it starts where the
    // scan did, or the part between was never read and nothing said so.
    let range = if !opts.resume {
        range
    } else {
        let recorded = std::fs::read_to_string(opts.output.join(STATE))
            .ok()
            .and_then(|t| serde_json::from_str::<State>(&t).ok())
            .and_then(|s| s.range);
        match (range, recorded) {
            (None, Some([a, b])) => Some((a, b)),
            (Some((a, b)), recorded) => {
                let started = recorded.map_or(0, |[a, _]| a);
                if a != started {
                    eprintln!(
                        "zvolcarve: --resume --range {a}-{b}: the scan began at byte {started}; a resume goes on from where it got to, to the end of a range that starts there (scan into another directory for another range)"
                    );
                    return exit::USAGE;
                }
                Some((a, b))
            }
            (None, None) => None,
        }
    };
    // A range past the end of every member asks for nothing: it was
    // read as "0 bytes, nothing found" and exited 3, an answer about the
    // evidence to a question that was not about it.
    let largest = members
        .sources
        .iter()
        .flatten()
        .map(|s| s.size())
        .max()
        .unwrap_or(0);
    if let Some((a, _)) = range.filter(|(a, _)| *a >= largest) {
        eprintln!(
            "zvolcarve: --range starts at byte {a}, past the end of every member (the largest is {largest} bytes)"
        );
        return exit::USAGE;
    }

    // The workspace must never be the evidence — asked before anything
    // is created, so a workspace named after a member is refused rather
    // than failing later on some unrelated error.
    // ... and neither may anything written inside it: a member lying in
    // the workspace as `candidates.json` was replaced by the index.
    let mut reads = spec.reads();
    reads.extend(members.paths.iter().cloned());
    reads.extend(opts.profile.profile.iter().cloned());
    let guard = WriteGuard::new(g, &reads);
    for (what, path) in [
        ("-o", opts.output.clone()),
        ("to write", opts.output.join(INDEX)),
        ("to write", opts.output.join(STATE)),
    ] {
        if let Err(code) = guard.refuse("zvolcarve", what, &path) {
            return code;
        }
    }
    if let Err(e) = std::fs::create_dir_all(&opts.output) {
        eprintln!("zvolcarve: {}: {e}", opts.output.display());
        return exit::USAGE;
    }

    // What a resume goes on from. A state or an index that is there and
    // cannot be read is refused: taken as nothing, the scan began again
    // from the first byte, said nothing, and wrote its own state over the
    // one that knew where the hours of work before had got to. One that
    // is not there at all is a scan that never began, and is said.
    let state_path = opts.output.join(STATE);
    let index_path = opts.output.join(INDEX);
    let unreadable = |path: &std::path::Path, why: String| {
        eprintln!(
            "zvolcarve: --resume: {}: {why}; it says where the scan got to, and is left as it is (scan into another directory to start over)",
            path.display()
        );
        exit::USAGE
    };
    let previous: State = if !opts.resume {
        State::default()
    } else {
        match std::fs::read_to_string(&state_path) {
            Ok(t) => match serde_json::from_str(&t) {
                Ok(s) => s,
                Err(e) => return unreadable(&state_path, format!("not a scan state: {e}")),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if !g.quiet {
                    eprintln!(
                        "zvolcarve: --resume: no {} to go on from; scanning from the start",
                        state_path.display()
                    );
                }
                State::default()
            }
            Err(e) => return unreadable(&state_path, e.to_string()),
        }
    };

    // A resume adds to what the earlier run found; replacing the index
    // would throw away the part of the member that was already read.
    let earlier = if opts.resume && std::fs::symlink_metadata(&index_path).is_ok() {
        match crate::model::load_index(&opts.output) {
            Ok(i) => Some(i),
            Err(e) => {
                let shown = format!("{}: ", index_path.display());
                let why = e.strip_prefix(&shown).unwrap_or(&e).to_string();
                return unreadable(&index_path, why);
            }
        }
    } else {
        None
    };
    // And it is a resume of that scan, or nothing: resumed with another
    // pool's members it skipped as many of their bytes as the first run
    // had read of its own, and signed the index with the new pool's
    // name over the old one's candidates.
    if let Some(i) = &earlier {
        let guid = pool
            .as_ref()
            .map_or_else(|| "-".into(), |p| format!("{:#018x}", p.guid));
        let same_members = i.members.len() == members.paths.len()
            && i.members
                .iter()
                .zip(&members.paths)
                .all(|(a, b)| a == b || zvol_common::same_file(a, b));
        // The range may differ: a resume goes on from where each member
        // got to, to the end of the range it is given.
        let differs = if i.pool_guid != guid {
            Some(format!("pool {} there, {guid} here", i.pool_guid))
        } else if !same_members {
            Some("other members, or the same in another order".into())
        } else if i.profile != profile_out {
            Some("another search profile".into())
        } else {
            None
        };
        if let Some(why) = differs {
            eprintln!(
                "zvolcarve: --resume: {} is a scan of something else ({why}); resume it as it was started, or scan into another directory",
                opts.output.display()
            );
            return exit::USAGE;
        }
    }
    // What the allocator has given out, read once: a candidate whose
    // space is free is a race worth running, and one whose space went
    // elsewhere is not (C-06).
    let space = pool.as_ref().and_then(|p| {
        let reader = PoolReader::new(p, members.devices()).with_base_offsets(&members.bases());
        // The newest TXG whose object set reads: a ring slot with
        // nothing behind it (a forged txg, a sync whose MOS never
        // reached the disk) is not where the allocator's state is.
        let mos = zfs_read::pool::uberblock_candidates(&members.scans, p)
            .into_iter()
            .find_map(|c| zfs_read::dsl::open_mos(&reader, &c.ub).ok())?;
        Some(zfs_read::spacemap::read(&reader, p, &mos))
    });
    if !g.quiet {
        for w in space.iter().flat_map(|s| &s.skipped) {
            eprintln!("zvolcarve: {w}");
        }
    }

    let mut candidates: Vec<Candidate> = earlier
        .as_ref()
        .map(|i| i.candidates.clone())
        .unwrap_or_default();
    let mut rejected: std::collections::BTreeMap<Reject, u64> = std::collections::BTreeMap::new();
    if let Some(i) = &earlier {
        for r in &i.rejected {
            if let Some(reason) = Reject::ALL.iter().find(|x| x.as_str() == r.reason) {
                *rejected.entry(*reason).or_insert(0) += r.count;
            }
        }
    }
    let mut datasets_met = earlier.as_ref().map_or(0, |i| i.datasets_met);
    let mut bytes_read = earlier.as_ref().map_or(0, |i| i.bytes_read);
    let mut unreadable = earlier.as_ref().map_or(0, |i| i.unreadable_bytes);
    let mut slots = earlier.as_ref().map_or(0, |i| i.slots_examined);
    let mut reached = vec![0u64; members.paths.len()];
    let mut counted = vec![0u64; members.paths.len()];
    let mut cuts: Vec<Option<[u64; 2]>> = vec![None; members.paths.len()];
    let mut complete = true;
    // C-09: the leaves of a mirror are copies of one another, and a
    // dnode met at the same place in two of them is one candidate. It
    // was listed — and walked — once per member.
    let groups = mirror_groups(pool.as_ref(), members.paths.len());
    let base_of = |i: usize| members.base_offsets.get(i).copied().unwrap_or(0);
    // Keyed by where in the vdev and what, and holding the member it was
    // first met on. The candidates an interrupted run already listed are
    // in it: a resume that met them again on the other side of the
    // mirror listed every one twice — 2644 candidates became 5288.
    let mut seen_in_mirror: std::collections::BTreeMap<(u64, u64, u64, String), usize> =
        std::collections::BTreeMap::new();
    for c in &candidates {
        if let Some(g) = groups.get(c.device).copied().flatten() {
            seen_in_mirror
                .entry((
                    g,
                    c.offset.saturating_sub(base_of(c.device)),
                    c.slot,
                    c.dnode_hex.clone(),
                ))
                .or_insert(c.device);
        }
    }
    let mut mirror_duplicates = earlier.as_ref().map_or(0, |i| i.mirror_duplicates);
    // A member no label, uberblock or hint places is read from byte 0,
    // and a compressed block is looked for every 2^ashift bytes from
    // there: a vdev on a partition at sector 63 had none of its blocks
    // tried, and `--compressed lz4` found nothing — with no word, while
    // `zeropoint` found the start in a second. Its block pointers are
    // asked the same way here, and a start they agree on is used.
    let mut starts: Vec<u64> = (0..members.paths.len()).map(base_of).collect();
    let mut by_pointers: Vec<StartByPointers> = Vec::new();
    if spec.hints.is_none() && !codecs.is_empty() {
        for (i, src) in members.sources.iter().enumerate() {
            let placed = members
                .scans
                .get(i)
                .and_then(Option::as_ref)
                .is_none_or(|s| s.config_verified() || s.newest_txg().is_some());
            let Some(src) = src.as_ref().filter(|_| starts[i] == 0 && !placed) else {
                continue;
            };
            // A resume goes on with the start the scan it resumes found:
            // asked again, the pointers were looked for over the whole
            // member each time, gigabytes for a range of megabytes.
            if let Some(b) = earlier.as_ref().and_then(|e| {
                e.starts_by_pointers
                    .iter()
                    .find(|b| b.member == members.paths[i])
            }) {
                starts[i] = b.base;
                by_pointers.push(b.clone());
                continue;
            }
            if let Some(b) = start_by_pointers(src, i, &codecs, range, &interrupt) {
                eprintln!(
                    "zvolcarve: {}: no label says where the vdev starts; its block pointers put it at byte {} ({} of {} probes agree, as `zvolcarve zeropoint` would say), and compressed blocks are looked for from there. Reading a candidate needs the same base in --hints",
                    members.paths[i].display(),
                    b.base,
                    b.confirmed,
                    b.tried
                );
                starts[i] = b.base;
                by_pointers.push(StartByPointers {
                    member: members.paths[i].clone(),
                    base: b.base,
                    confirmed: b.confirmed,
                    tried: b.tried,
                });
            }
        }
    }

    for (i, src) in members.sources.iter().enumerate() {
        let Some(src) = src else {
            continue;
        };
        let from = previous.reached.get(i).copied().unwrap_or(0);
        let count_from = previous.counted.get(i).copied().unwrap_or(0).max(from);
        let cut_before = previous.cut.get(i).copied().flatten();
        counted[i] = count_from;
        cuts[i] = cut_before;
        // Interrupted on an earlier member: this one keeps what an
        // earlier run reached, and the state says the scan is not done.
        if interrupt.load(Ordering::Relaxed) {
            reached[i] = from;
            complete = false;
            continue;
        }
        let member_range = match (range, from) {
            (Some((a, b)), f) => Some((a.max(f), b)),
            (None, 0) => None,
            (None, f) => Some((f, src.size())),
        };
        if let Some((a, _)) = range.filter(|(a, _)| *a >= src.size()) {
            eprintln!(
                "zvolcarve: {}: --range starts at byte {a}, past its end ({} bytes); not scanned",
                members.paths[i].display(),
                src.size()
            );
            reached[i] = from;
            continue;
        }
        if !g.quiet {
            eprintln!(
                "zvolcarve: scanning {} ({} bytes){}",
                members.paths[i].display(),
                src.size(),
                member_range.map_or(String::new(), |(a, b)| format!(" from {a} to {b}"))
            );
        }
        let scan = match scan_member(
            src,
            i,
            crate::member_ashift(pool.as_ref(), i),
            &ScanOptions {
                profile: profile.clone(),
                strict_profile: opts.profile.strict_profile,
                range: member_range,
                codecs: codecs.clone(),
                max_hits: opts.sample.unwrap_or(opts.max_hits),
                stop: Some(interrupt.clone()),
                vdev_start: starts[i],
                count_from,
                ..ScanOptions::default()
            },
        ) {
            Ok(mut s) => {
                // In the order they lie on the member, so that where a
                // walk is cut short divides the walked from the rest.
                s.hits.sort_by_key(|h| (h.offset, h.slot));
                s
            }
            Err(e) => {
                eprintln!("zvolcarve: {}: {e}", members.paths[i].display());
                return exit::EVIDENCE;
            }
        };
        bytes_read += scan.bytes_read;
        unreadable += scan.unreadable_bytes;
        datasets_met += scan
            .datasets
            .iter()
            .filter(|d| d.offset >= count_from)
            .count();
        slots += scan.slots_examined;
        reached[i] = scan.resume_at;
        counted[i] = count_from.max(scan.resume_at);
        cuts[i] = None;
        if scan.stopped_early {
            complete = false;
        }
        for (r, n) in &scan.counts.0 {
            *rejected.entry(*r).or_insert(0) += n;
        }
        // Walking a candidate's tree needs a pool to read through. Where
        // none assembled, the candidates are still recorded — the scan
        // is the part that could only be done here.
        let reader = pool.as_ref().map(|p| crate::primed_reader(p, &members));
        // Which dataset each data object belonged to, worked out once per
        // member: asked of every candidate in turn, it read every dataset's
        // object set again for each — thousands of candidates by hundreds
        // of datasets on a ztest pool of 192 MiB, ten minutes of lz4, and
        // no signal heard.
        let owners = reader
            .as_ref()
            .map(|r| dataset_owners(r, &scan.datasets, &interrupt))
            .unwrap_or_default();
        // A signal that comes while the candidates are being walked
        // leaves the rest of them for the resume: listed as they were,
        // each was a candidate with nothing walked, scored as nothing,
        // and a resume — which starts past them — never looked again.
        let mut cut_at: Option<[u64; 2]> = None;
        // The limit was met in the chunk the scan stopped after: the
        // first `limit` hits past what an earlier run listed are this
        // run's, and a resume goes on from the one after them. The scan
        // used to stop inside the chunk, and its resume — from the
        // chunk's start — met the same hits, reached the same limit, and
        // never got further; the run ended 6 and said nothing.
        let limit = opts.sample.unwrap_or(opts.max_hits);
        let mut limited_at: Option<[u64; 2]> = None;
        if scan.capped {
            let listed = |h: &&zfs_read::carve::Hit| {
                cut_before.is_some_and(|[o, s]| (h.offset, h.slot) < (o, s))
            };
            limited_at = scan
                .hits
                .iter()
                .filter(|h| !listed(h))
                .nth(limit)
                .map(|h| [h.offset, h.slot]);
            if limited_at.is_some() || scan.stopped_early {
                let by = limited_at.map_or(scan.resume_at, |[o, _]| o);
                if opts.sample.is_some() {
                    if !g.quiet {
                        eprintln!(
                            "zvolcarve: {}: a sample of the first {limit} hit(s), to byte {by}",
                            members.paths[i].display()
                        );
                    }
                } else {
                    eprintln!(
                        "zvolcarve: {}: {limit} hit(s), the --max-hits limit, by byte {by}; the rest of it was not scanned, and --resume continues there (exit 6)",
                        members.paths[i].display()
                    );
                }
            }
        }
        for hit in &scan.hits {
            if limited_at.is_some_and(|[o, s]| (hit.offset, hit.slot) >= (o, s)) {
                break;
            }
            // Before where an earlier run's walk was cut: listed by it.
            if cut_before.is_some_and(|[o, s]| (hit.offset, hit.slot) < (o, s)) {
                continue;
            }
            if interrupt.load(Ordering::Relaxed) {
                cut_at = Some([hit.offset, hit.slot]);
                break;
            }
            let hex = to_hex(&dnode_bytes(&hit.dnode));
            if let Some(g) = groups[i] {
                let key = (
                    g,
                    hit.offset.saturating_sub(base_of(i)),
                    hit.slot,
                    hex.clone(),
                );
                match seen_in_mirror.get(&key) {
                    // The other side of the mirror: one candidate.
                    Some(&first) if first != i => {
                        mirror_duplicates += 1;
                        continue;
                    }
                    // This member, read again by a resume: the earlier
                    // listing stands.
                    Some(_) => continue,
                    None => {
                        seen_in_mirror.insert(key, i);
                    }
                }
            }
            let assessed = reader.as_ref().map(|r| {
                let obj = ObjectReader::new(r, hit.dnode.clone(), Endian::Little);
                assess_against(
                    &obj,
                    if opts.full_assess { 0 } else { 256 },
                    space.as_ref(),
                    Some(interrupt.as_ref()),
                )
            });
            if interrupt.load(Ordering::Relaxed) {
                // Its walk was cut short: not a verdict on it.
                cut_at = Some([hit.offset, hit.slot]);
                if let Some(g) = groups[i] {
                    seen_in_mirror.remove(&(
                        g,
                        hit.offset.saturating_sub(base_of(i)),
                        hit.slot,
                        hex,
                    ));
                }
                break;
            }
            let named = name_from_datasets(&owners, hit);
            // C-12: what is inside usually says how large the volume was
            // made, which the dnode cannot. Once a signal has come the
            // rest of the candidates are recorded as they are, at once.
            let contents = reader
                .as_ref()
                .filter(|_| !interrupt.load(Ordering::Relaxed))
                .map(|r| {
                    let obj = ObjectReader::new(r, hit.dnode.clone(), Endian::Little);
                    contents_of(&obj)
                })
                .unwrap_or_default();
            let id = format!("c{:04}", candidates.len() + 1);
            candidates.push(Candidate {
                id,
                device: hit.device,
                path: members.paths[hit.device].clone(),
                offset: hit.offset,
                slot: hit.slot,
                found: hit.found.as_str().to_string(),
                dnode_type: hit.dnode.type_name(),
                dnode_type_code: hit.dnode.object_type,
                volblocksize: hit.dnode.datablksz(),
                levels: hit.dnode.nlevels,
                maxblkid: hit.dnode.maxblkid,
                implied_size: Profile::implied_size(&hit.dnode),
                birth: Profile::birth(&hit.dnode),
                score: rank(hit, assessed.as_ref()),
                profile_misses: hit.misses.iter().map(|m| m.as_str().to_string()).collect(),
                assessment: assessed.map(|a| AssessmentOut {
                    blocks_total: a.blocks_total,
                    blocks_verified: a.blocks_verified,
                    blocks_holes: a.blocks_holes,
                    blocks_failed: a.blocks_failed,
                    birth: a.birth.map(|(x, y)| [x, y]),
                    sampled: a.sampled,
                    blocks_allocated: a.blocks_allocated,
                    blocks_free: a.blocks_free,
                    blocks_unknown: a.blocks_unknown,
                    agreement: a.agreement(),
                }),
                contents,
                dataset_guid: named.map(|(g, _)| format!("{g:#018x}")),
                dataset_creation_txg: named.map(|(_, t)| t),
                dnode_hex: hex,
            });
        }
        if let Some([at, slot]) = cut_at.or(limited_at) {
            reached[i] = reached[i].min(at / 512 * 512);
            cuts[i] = Some([at, slot]);
            complete = false;
        }
    }

    // A resumed scan re-reads the chunk it stopped inside, so the same
    // candidate can be met twice. It is one candidate.
    candidates.sort_by_key(|c| (c.device, c.offset, c.slot));
    candidates.dedup_by(|a, b| (a.device, a.offset, a.slot) == (b.device, b.offset, b.slot));
    // Best first, and by id where they tie, so two runs read the same.
    candidates.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            // And by where it was found where they tie: the order it was
            // found in is not the same for a scan done in one pass and
            // one resumed, and the ids were not either.
            .then((a.device, a.offset, a.slot).cmp(&(b.device, b.offset, b.slot)))
    });
    for (n, c) in candidates.iter_mut().enumerate() {
        c.id = format!("c{:04}", n + 1);
    }

    let histograms = opts.sample.map(|_| histograms_of(&candidates));

    let mut by_reason: Vec<Rejection> = rejected
        .iter()
        .map(|(r, n)| Rejection {
            reason: r.as_str().to_string(),
            count: *n,
            profile: r.is_profile(),
        })
        .collect();
    by_reason.sort_by(|a, b| b.count.cmp(&a.count).then(a.reason.cmp(&b.reason)));

    let index = Index {
        index_version: INDEX_VERSION,
        pool: pool.as_ref().map_or_else(|| "-".into(), |p| p.name.clone()),
        pool_guid: pool
            .as_ref()
            .map_or_else(|| "-".into(), |p| format!("{:#018x}", p.guid)),
        members: members.paths.clone(),
        profile: profile_out,
        rejected_by_profile: by_reason
            .iter()
            .filter(|r| r.profile)
            .map(|r| r.count)
            .sum(),
        rejected: by_reason,
        bytes_read,
        unreadable_bytes: unreadable,
        mirror_duplicates,
        slots_examined: slots,
        datasets_met,
        space: space.as_ref().map(|s| SpaceOut {
            vdevs_read: s.trustworthy(),
            allocated_bytes: s.vdevs.values().map(|v| v.allocated.bytes()).sum(),
            skipped: s.skipped.clone(),
            may_lag: s.may_lag,
        }),
        histograms,
        starts_by_pointers: by_pointers,
        candidates,
    };

    let json = serde_json::to_value(&index).expect("serialisable");
    let index_path = opts.output.join(INDEX);
    if let Err(e) = std::fs::write(
        &index_path,
        serde_json::to_string_pretty(&index).expect("serialisable") + "\n",
    ) {
        eprintln!("zvolcarve: {}: {e}", index_path.display());
        return exit::USAGE;
    }
    if interrupt.load(Ordering::Relaxed) {
        eprintln!(
            "zvolcarve: interrupted; the state file says where each member's scan stopped, --resume continues there (exit 6)"
        );
    }
    let state_path = opts.output.join(STATE);
    let state = State {
        index_version: INDEX_VERSION,
        reached,
        complete,
        range: range.map(|(a, b)| [a, b]),
        counted,
        cut: if cuts.iter().any(Option::is_some) {
            cuts
        } else {
            Vec::new()
        },
    };
    if let Err(e) = std::fs::write(
        &state_path,
        serde_json::to_string_pretty(&state).expect("serialisable") + "\n",
    ) {
        eprintln!("zvolcarve: {}: {e}", state_path.display());
        return exit::USAGE;
    }

    match g.format {
        Format::Json => println!(
            "{}",
            serde_json::to_string_pretty(&json).expect("serialisable")
        ),
        Format::Text => crate::list::print(&index),
    }
    // Exit 6: a scan that stopped early left a state file to go on
    // from (COMPANIONS §1.2). Exit 4: it went to the end, but not over
    // every byte — what lay in the unreadable ones was not searched.
    // Exit 3: nothing found, as the manual has always said; a scan that
    // turned up no candidate exited 0.
    // A sample that reached its size did what it was asked: it is a
    // look at the disk, not a search left half done.
    let sampled = opts.sample.is_some() && !interrupt.load(Ordering::Relaxed);
    let code = if !complete && !sampled {
        exit::INTERRUPTED
    } else if index.candidates.is_empty() {
        exit::UNRECOVERABLE
    } else if unreadable > 0 {
        exit::PARTIAL
    } else {
        0
    };
    // The code it says is the code it exits with: "(exit 4)" was said
    // over a run that found nothing and exited 3.
    if unreadable > 0 {
        eprintln!(
            "zvolcarve: {unreadable} byte(s) could not be read and were not searched; a candidate there is missed (exit {code})"
        );
    }
    let written = [index_path, state_path]
        .iter()
        .filter_map(|p| FileRef::hashed(p).ok())
        .collect();
    // A device refused a read: every incident on stderr, and the stop —
    // when one stopped the run — as the exit code (SPEC F-33, N-10).
    // A member that did not open is said, and so is the code: the run
    // is of the members that did, as `zvolrescue` says it (exit 2); it
    // ended 0.
    let code = if code == 0 && members.any_failed() {
        exit::EVIDENCE
    } else {
        code
    };
    let code = zvol_common::report_medium(&members.ledger).unwrap_or(code);
    g.log_evidence_with_incidents(
        "zvolcarve",
        &json,
        code,
        &members.inputs(),
        written,
        &members.ledger.incidents(),
    )
}

/// The dnode's own bytes, as the index stores them.
fn dnode_bytes(d: &DnodePhys) -> Vec<u8> {
    zfs_ondisk::dmu::encode::DnodeSpec {
        object_type: d.object_type,
        indblkshift: d.indblkshift,
        nlevels: d.nlevels,
        datablksz: d.datablksz(),
        maxblkid: d.maxblkid,
        blkptrs: d.blkptr.iter().map(|b| *b.raw()).collect(),
        bonus_type: d.bonus_type,
        bonus: d.bonus.clone(),
        spill: d.spill.as_ref().map(|s| *s.raw()),
        extra_slots: d.extra_slots,
    }
    .build()
}

/// `volblocksize`, `nlevels` and `volsize` of a dataset the pool still
/// has, for `--like` (C-17).
///
/// Newest transaction group first, and the first one that has the
/// dataset wins. A sibling that was itself destroyed a moment ago is
/// still a far better source for these numbers than the operator's
/// memory, and refusing to look one transaction group back would throw
/// that away for nothing.
fn like_dataset(
    reader: &PoolReader<'_>,
    scans: &[Option<zfs_read::vdev::DeviceScan>],
    pool: &zfs_read::pool::PoolAssembly,
    name: &str,
) -> Result<(u64, u8, u64), String> {
    let candidates = zfs_read::pool::uberblock_candidates(scans, pool);
    if candidates.is_empty() {
        return Err("no verified uberblock".into());
    }
    let mut looked = 0;
    for c in &candidates {
        let Ok(mos) = zfs_read::dsl::open_mos(reader, &c.ub) else {
            continue;
        };
        let Ok(tree) = zfs_read::dsl::walk(&mos, &pool.name) else {
            continue;
        };
        looked += 1;
        let Some(ds) = tree.datasets.iter().find(|d| d.name == name) else {
            continue;
        };
        let (volsize, _) = zfs_read::zvol::volume_facts(reader, ds).map_err(|e| e.to_string())?;
        let (obj, _) = zfs_read::zvol::open_volume(reader, ds).map_err(|e| e.to_string())?;
        return Ok((obj.dnode().datablksz(), obj.dnode().nlevels, volsize));
    }
    Err(format!(
        "no such dataset in any of the {looked} readable transaction group(s)"
    ))
}

/// What the sampled hits look like (C-19).
///
/// A carve on a pool that has lived for years meets far more metadata
/// than belongs to what is being looked for, and the operator often
/// does not know the block size or tree depth of the thing they lost.
/// These are the numbers actually on the disk, so a profile can be
/// picked from them instead of from memory.
fn histograms_of(candidates: &[Candidate]) -> Histograms {
    fn bars<T: Ord + std::fmt::Display>(values: impl Iterator<Item = T>) -> Vec<Bucket> {
        let mut counts: BTreeMap<T, u64> = BTreeMap::new();
        for v in values {
            *counts.entry(v).or_insert(0) += 1;
        }
        let mut out: Vec<Bucket> = counts
            .into_iter()
            .map(|(v, n)| Bucket {
                value: v.to_string(),
                count: n,
            })
            .collect();
        // Most common first, then by name, so two runs read the same.
        out.sort_by(|a, b| b.count.cmp(&a.count).then(a.value.cmp(&b.value)));
        out
    }
    Histograms {
        sampled: candidates.len(),
        dnode_type: bars(candidates.iter().map(|c| c.dnode_type.clone())),
        volblocksize: bars(candidates.iter().map(|c| c.volblocksize)),
        levels: bars(candidates.iter().map(|c| c.levels)),
        // Thousands: a pool's transaction groups run to millions, and a
        // bar per group would be a list, not a histogram.
        txg: bars(candidates.iter().map(|c| {
            let base = c.birth / 1000 * 1000;
            format!("{base}..{}", base + 999)
        })),
    }
}

/// The data object of each dataset dnode the scan met, by the first DVA
/// of its first block, with the dataset's GUID and creation TXG: what
/// [`name_from_datasets`] matches a candidate against. A dataset's bonus
/// points at its object set, and the object set's `ZVOL_OBJ` is the data
/// of a volume. Read once per member, and not past a signal.
fn dataset_owners(
    reader: &PoolReader<'_>,
    datasets: &[zfs_read::carve::Hit],
    interrupt: &std::sync::atomic::AtomicBool,
) -> Vec<(zfs_ondisk::blkptr::Dva, u64, u64)> {
    let mut out = Vec::new();
    for ds in datasets {
        if interrupt.load(Ordering::Relaxed) {
            break;
        }
        let Ok(phys) = zfs_ondisk::dsl::DslDatasetPhys::parse(&ds.dnode.bonus, Endian::Little)
        else {
            continue;
        };
        if phys.bp.is_hole() {
            continue;
        }
        let Ok(block) = reader.read_block(&phys.bp, false) else {
            continue;
        };
        let Ok(os) = zfs_ondisk::dmu::ObjsetPhys::parse(&block.data, phys.bp.endian) else {
            continue;
        };
        let objs = zfs_read::dmu::DnodeArray::new(reader, os.meta_dnode, phys.bp.endian);
        let Ok(data) = objs.get(zfs_read::dsl::ZVOL_OBJ) else {
            continue;
        };
        let Some(theirs) = data.blkptr.iter().find(|b| !b.is_hole()) else {
            continue;
        };
        out.push((theirs.dva[0], phys.guid, phys.creation_txg));
    }
    out
}

/// The dataset whose objset still points at this candidate (C-11).
///
/// A carved dnode carries no name: names live in the DSL directory
/// chain in the MOS, which is what a carve cannot reach. What can be
/// reached is a dataset dnode the scan happened to meet — its bonus
/// points at an objset, and if that objset's data object is this one,
/// the candidate belonged to that dataset. The GUID and creation
/// transaction group are enough to match it against a timeline. A head
/// dataset and its snapshots can all point at the same objset on a pool
/// this small; the newest is the one worth reporting, the first met of
/// those as new.
fn name_from_datasets(
    owners: &[(zfs_ondisk::blkptr::Dva, u64, u64)],
    candidate: &zfs_read::carve::Hit,
) -> Option<(u64, u64)> {
    let want = candidate.dnode.blkptr.iter().find(|b| !b.is_hole())?;
    owners
        .iter()
        .filter(|(dva, _, _)| *dva == want.dva[0])
        .fold(
            None,
            |best: Option<(u64, u64)>, &(_, guid, txg)| match best {
                Some((_, t)) if t >= txg => best,
                _ => Some((guid, txg)),
            },
        )
}

/// What a candidate's own bytes say it holds (C-12).
///
/// The reads go through the pool like any other, so a block that does
/// not verify is not offered as a signature. Nothing here is trusted:
/// it bounds a guess about the size, and `dump` still verifies every
/// block it writes.
fn contents_of(obj: &ObjectReader<'_, '_>) -> Vec<ContentsOut> {
    let read = |at: u64, len: usize| -> Option<Vec<u8>> { obj.read_range(at, len).ok() };
    zfs_ondisk::signature::identify(&read)
        .into_iter()
        .map(|f| ContentsOut {
            kind: f.kind.as_str().to_string(),
            at: f.at,
            size: f.size,
            label: f.label,
        })
        .collect()
}

/// Where a member's vdev starts by its own block pointers (SPEC F-63),
/// as `zvolcarve zeropoint` finds it: every sector tried, a few
/// thousand pointers read, and each candidate start tested by whether
/// the blocks they name hash right there. Only a start the probes agree
/// on — enough of them, and twice as many as on any other — and one
/// that is not 0, which is what was assumed already.
fn start_by_pointers(
    src: &dyn BlockSource,
    device: usize,
    codecs: &[Codec],
    range: Option<(u64, u64)>,
    stop: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Option<zfs_read::pointers::Base> {
    // Within the range the scan was asked for: the probes are looked for
    // where the candidates will be, and a scan of 4 MiB read the whole
    // member — 3.4 GB — to find them.
    let scan = scan_member(
        src,
        device,
        9,
        &ScanOptions {
            codecs: codecs.to_vec(),
            max_hits: 4096,
            range,
            stop: Some(stop.clone()),
            ..ScanOptions::default()
        },
    )
    .ok()?;
    let probes = zfs_read::pointers::anchors(&scan);
    let found =
        zfs_read::pointers::search(src, &probes, &zfs_read::pointers::Options::default()).ok()?;
    let best = found.first()?;
    let next = found.get(1).map_or(0, |b| b.confirmed);
    (best.base != 0 && best.confirmed >= 8 && best.confirmed >= 2 * next).then(|| best.clone())
}
