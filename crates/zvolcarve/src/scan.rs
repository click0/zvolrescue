//! `zvolcarve scan` — read the members through and record what could be
//! a volume (C-01, C-04, C-05, C-08, C-13…C-18).

use std::path::PathBuf;

use clap::Args;
use zfs_ondisk::carve::{Profile, Reject};
use zfs_ondisk::dmu::{object_type_name, ot, DnodePhys};
use zfs_ondisk::Endian;
use zfs_read::carve::{assess, rank, scan_member, Options as ScanOptions};
use zfs_read::dmu::ObjectReader;
use zfs_read::zio::PoolReader;
use zvol_common::evidence::FileRef;
use zvol_common::members::{choose_pool, open_members};
use zvol_common::{exit, Format, Global, PoolSpec};
use zvolrescue_io::BlockSource;

use crate::model::{
    to_hex, AssessmentOut, Candidate, Index, ProfileOut, Rejection, State, INDEX, INDEX_VERSION,
    STATE,
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
    /// Object type to look for: `zvol` (the default), `file`, or a
    /// numeric `dn_type`. `any` follows every type the scan recognises.
    #[arg(long, value_name = "TYPE", default_value = "zvol")]
    pub dnode_type: String,
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
#[derive(Debug, serde::Deserialize)]
struct ProfileFile {
    volblocksize: Option<u64>,
    levels: Option<u8>,
    txg: Option<[u64; 2]>,
    size: Option<[u64; 2]>,
    dnode_type: Option<String>,
}

/// Build the profile from the file, the command line and `--like`, in
/// that order of precedence.
fn build_profile(
    args: &ProfileArgs,
    like: Option<(u64, u8, u64)>,
) -> Result<(Profile, ProfileOut), String> {
    let mut p = Profile::default();
    if let Some(path) = &args.profile {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let f: ProfileFile = serde_json::from_str(&text)
            .map_err(|e| format!("{}: not a search profile: {e}", path.display()))?;
        p.volblocksize = f.volblocksize;
        p.levels = f.levels;
        p.txg = f.txg.map(|t| (t[0], t[1]));
        p.size = f.size.map(|s| (s[0], s[1]));
        if let Some(t) = f.dnode_type {
            p.dnode_type = dnode_type_code(&t)?;
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
    if args.profile.is_none() || args.dnode_type != "zvol" {
        p.dnode_type = dnode_type_code(&args.dnode_type)?;
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
    let members = match open_members(spec) {
        Ok(m) => m,
        Err(code) => return code,
    };
    // A carve does not need a pool to assemble — that is rather the
    // point — but when one does, its ashift and its reader are what make
    // the compressed pass and the tree walk possible.
    let pool = choose_pool(members.pools.clone(), spec.pool_guid.as_deref()).ok();
    // The ashift belongs to the vdev, so whichever top still states it
    // states it for every member; 12 is the modern default when none
    // survived.
    let ashift = pool
        .as_ref()
        .and_then(|p| p.tops.iter().find_map(|t| t.ashift))
        .unwrap_or(12) as u32;

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

    let (profile, profile_out) = match build_profile(&opts.profile, like) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("zvolcarve: {e}");
            return exit::USAGE;
        }
    };
    let range = match &opts.range {
        Some(s) => match byte_range(s) {
            Ok(r) => Some(r),
            Err(e) => {
                eprintln!("zvolcarve: {e}");
                return exit::USAGE;
            }
        },
        None => None,
    };

    if let Err(e) = std::fs::create_dir_all(&opts.output) {
        eprintln!("zvolcarve: {}: {e}", opts.output.display());
        return exit::USAGE;
    }
    // The workspace must never be the evidence.
    if let Err(e) = zvolrescue_io::refuse_if_evidence(&opts.output, &members.paths) {
        eprintln!("zvolcarve: {e}");
        return exit::REFUSED;
    }

    let previous: State = if opts.resume {
        std::fs::read_to_string(opts.output.join(STATE))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    } else {
        State::default()
    };

    // A resume adds to what the earlier run found; replacing the index
    // would throw away the part of the member that was already read.
    let earlier = if opts.resume {
        crate::model::load_index(&opts.output).ok()
    } else {
        None
    };
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
    let mut bytes_read = earlier.as_ref().map_or(0, |i| i.bytes_read);
    let mut slots = earlier.as_ref().map_or(0, |i| i.slots_examined);
    let mut reached = vec![0u64; members.paths.len()];
    let mut complete = true;

    for (i, src) in members.sources.iter().enumerate() {
        let Some(src) = src else {
            continue;
        };
        let from = previous.reached.get(i).copied().unwrap_or(0);
        let member_range = match (range, from) {
            (Some((a, b)), f) => Some((a.max(f), b)),
            (None, 0) => None,
            (None, f) => Some((f, src.size())),
        };
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
            ashift,
            &ScanOptions {
                profile: profile.clone(),
                strict_profile: opts.profile.strict_profile,
                range: member_range,
                max_hits: opts.max_hits,
                ..ScanOptions::default()
            },
        ) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("zvolcarve: {}: {e}", members.paths[i].display());
                return exit::EVIDENCE;
            }
        };
        bytes_read += scan.bytes_read;
        slots += scan.slots_examined;
        reached[i] = scan.resume_at;
        if scan.stopped_early {
            complete = false;
        }
        for (r, n) in &scan.counts.0 {
            *rejected.entry(*r).or_insert(0) += n;
        }
        // Walking a candidate's tree needs a pool to read through. Where
        // none assembled, the candidates are still recorded — the scan
        // is the part that could only be done here.
        let reader = pool
            .as_ref()
            .map(|p| PoolReader::new(p, members.devices()).with_base_offsets(&members.bases()));
        for hit in &scan.hits {
            let assessed = reader.as_ref().map(|r| {
                let obj = ObjectReader::new(r, hit.dnode.clone(), Endian::Little);
                assess(&obj, if opts.full_assess { 0 } else { 256 })
            });
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
                    agreement: a.agreement(),
                }),
                dnode_hex: to_hex(&dnode_bytes(&hit.dnode)),
            });
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
            .then(a.id.cmp(&b.id))
    });
    for (n, c) in candidates.iter_mut().enumerate() {
        c.id = format!("c{:04}", n + 1);
    }

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
        slots_examined: slots,
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
    let state_path = opts.output.join(STATE);
    let state = State {
        index_version: INDEX_VERSION,
        reached,
        complete,
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
    // from (COMPANIONS §1.2).
    let code = if complete { 0 } else { exit::INTERRUPTED };
    let written = [index_path, state_path]
        .iter()
        .filter_map(|p| FileRef::hashed(p).ok())
        .collect();
    g.log_evidence("zvolcarve", &json, code, &members.paths, written)
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
