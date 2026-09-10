//! Opening the members of a POOLSPEC, with every recovery path the tool
//! has for labels that are not where they should be.
//!
//! One place decides how a member is found: labels at offset 0, a
//! partition table, the zero point an uberblock confirms (SPEC F-61), a
//! member asserted into a leaf its siblings name (F-62), or a layout
//! given by hand (F-65, F-66). Every binary opens members through here,
//! so a companion cannot end up reading a pool differently from the tool
//! that found it.

use std::path::PathBuf;

use zfs_read::bind::{bind_by_reading, Verdict};
use zfs_read::hints::{search_order, LayoutHints};
use zfs_read::pool::{assemble, PoolAssembly};
use zfs_read::vdev::DeviceScan;
use zfs_read::zeropoint::scan_with_recovered_base;
use zvolrescue_io::{BlockSource, FileSource};

use crate::{exit, hints, PoolSpec};

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
    /// Where each member's vdev begins, indexed like the scans.
    pub base_offsets: Vec<u64>,
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
    /// for a member whose labels were found somewhere other than the start
    /// of what was opened (SPEC F-61), or as a layout hint states.
    pub fn bases(&self) -> Vec<u64> {
        self.base_offsets.clone()
    }

    /// True when at least one member could not be opened or scanned.
    pub fn any_failed(&self) -> bool {
        self.scans.iter().any(|s| s.is_none())
    }
}

/// Try the orders a layout leaves open and keep the one the checksums
/// accept (SPEC F-66).
fn search_layout(
    layout: &LayoutHints,
    scans: &[Option<DeviceScan>],
    devices: &[Option<&dyn BlockSource>],
    bases: &[u64],
) -> Result<LayoutHints, u8> {
    let mut out = layout.clone();
    for (top, hint) in layout.tops.iter().enumerate() {
        if !matches!(hint.kind.as_str(), "raidz" | "draid") || hint.members.len() < 2 {
            continue;
        }
        let trials = search_order(&out, top, scans, devices, bases).map_err(|e| {
            eprintln!("zvolrescue: --search-order: {e}");
            exit::USAGE
        })?;
        match trials.split_first() {
            None => {
                eprintln!(
                    "zvolrescue: --search-order: no order of {} members reads this pool at all",
                    hint.members.len()
                );
                return Err(exit::UNRECOVERABLE);
            }
            Some((best, rest)) => {
                let ties = rest
                    .iter()
                    .filter(|t| t.mismatches == best.mismatches)
                    .count();
                eprintln!(
                    "zvolrescue: --search-order: {} order(s) read, best has {} checksum mismatch(es){}",
                    trials.len(),
                    best.mismatches,
                    if ties > 0 {
                        format!(" — {ties} other order(s) are just as good, taking the first")
                    } else {
                        String::new()
                    }
                );
                out = best.layout.clone();
            }
        }
    }
    Ok(out)
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
            0 if pools.is_empty() => {
                // Nothing at all could be assembled: the assertion has no
                // configuration to attach to, which is unreadable
                // evidence rather than a mistake by the operator.
                eprintln!(
                    "zvolrescue: --assume-member {}: no ZFS pool found on the given members — at least one member whose labels survive is needed to say what the pool looks like",
                    path.display()
                );
                return Err(exit::EVIDENCE);
            }
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
                    // Every one of them reads, so the pool comes back
                    // whichever is chosen and each block is still
                    // checksum-verified. Take the first, and say plainly
                    // that the evidence did not choose — if this member
                    // is later needed in its true slot, =GUID pins it.
                    let first = fits[0].guid;
                    eprintln!(
                        "zvolrescue: {}: {} leaves of {} read equally well; taking {:#018x}. Name one with =GUID to pin it. Candidates:",
                        path.display(),
                        fits.len(),
                        pools[pool].tops[fits[0].top].name,
                        first
                    );
                    for b in &fits {
                        eprintln!("  {:#018x}  {}", b.guid, pools[pool].tops[b.top].name);
                    }
                    if pools[pool].bind_member(device, Some(first)).is_err() {
                        return Err(exit::USAGE);
                    }
                    continue;
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
                    "zvolrescue: {}: vdev starts at byte {} ({})",
                    p.display(),
                    scan.base,
                    scan.base_source.unwrap_or("confirmed by checksum")
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
    let mut bases: Vec<u64> = scans
        .iter()
        .map(|s| s.as_ref().map_or(0, |s| s.base))
        .collect();
    // A hand-written layout replaces the labels' account of the topology
    // (SPEC F-65). The uberblocks still come from the members themselves:
    // where no label survives, they are the ones the zero-point search
    // confirmed by their own checksums.
    let mut pools = match &spec.hints {
        Some(file) => {
            let hints = hints::load(file, &paths).map_err(|e| {
                eprintln!("zvolrescue: {e}");
                exit::USAGE
            })?;
            for (i, b) in hints.bases.iter().enumerate() {
                if *b != 0 {
                    bases[i] = *b;
                }
            }
            let mut layout = hints.layout;
            if spec.search_order {
                let devices: Vec<Option<&dyn BlockSource>> = sources
                    .iter()
                    .map(|s| s.as_ref().map(|s| s as &dyn BlockSource))
                    .collect();
                layout = search_layout(&layout, &scans, &devices, &bases)?;
            }
            let pool = layout.assemble();
            eprintln!(
                "zvolrescue: reading through the layout in {}: {}",
                file.display(),
                pool.tops
                    .iter()
                    .map(|t| format!("{} of {}", t.name, t.members.len()))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            vec![pool]
        }
        None => assemble(&scans),
    };
    let devices: Vec<Option<&dyn BlockSource>> = sources
        .iter()
        .map(|s| s.as_ref().map(|s| s as &dyn BlockSource))
        .collect();
    bind_assumed(spec, &paths, &mut pools, &scans, &devices, &bases)?;
    drop(devices);
    Ok(Members {
        sources,
        scans,
        pools,
        paths,
        base_offsets: bases,
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
