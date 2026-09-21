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
use zfs_read::dsl::removed_tops_of;
use zfs_read::hints::{search_order, LayoutHints};
use zfs_read::pool::{assemble, PoolAssembly};
use zfs_read::vdev::DeviceScan;
use zfs_read::zeropoint::scan_with_recovered_base_opts;
use zvolrescue_io::medium::Ledger;
use zvolrescue_io::{BlockSource, FileSource};

use crate::{evidence, exit, hints, PoolSpec};

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
    /// Files read besides the members: the imagers' maps (SPEC F-72).
    pub map_files: Vec<PathBuf>,
    /// The run's ledger of refused device reads (SPEC F-33, N-10):
    /// what to report, and whether the run was stopped.
    pub ledger: std::sync::Arc<Ledger>,
}

impl Members {
    /// Everything read from disk for the evidence record: the members,
    /// and any imager's map read alongside one (SPEC F-72).
    pub fn inputs(&self) -> Vec<PathBuf> {
        let mut v = self.paths.clone();
        v.extend(self.map_files.iter().cloned());
        v
    }

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
    bases: &mut [u64],
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
                // "No pool is missing a member" is only true when no pool
                // is missing a whole top-level vdev either. A leaf slot
                // exists to be filled because some present member's
                // configuration describes it; a vdev nothing describes
                // has no slots at all, and saying nothing is missing is
                // the one answer that is certainly wrong — the labels
                // carry `vdev_children`, so the count is known.
                if let Some((name, tops)) = pool_missing_a_whole_top(pools) {
                    let which = tops
                        .iter()
                        .map(|id| format!("#{id}"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    eprintln!(
                        "zvolrescue: --assume-member {}: pool \"{name}\" is missing top-level vdev {which} entirely, not a member of one",
                        path.display()
                    );
                    eprintln!(
                        "zvolrescue: nothing present describes that vdev, so there is no leaf to place this member in. Give a member whose labels survive from it, or describe it with --hints (SPEC F-65)."
                    );
                    // The same reasoning as the branch above: the
                    // operator's assertion is sound and the command line
                    // is well formed. What is short is the evidence, so
                    // this is exit 2 and not a usage error.
                    return Err(exit::EVIDENCE);
                }
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
                        "zvolrescue: {}: read as leaf {:#018x} of {} — the metadata walk verifies through it{}{}",
                        path.display(),
                        b.guid,
                        pools[pool].tops[b.top].name,
                        if fitting > 1 {
                            format!(" ({fitting} leaves of that mirror fit; they hold the same bytes)")
                        } else {
                            String::new()
                        },
                        if b.base != bases[device] {
                            format!(
                                ", with its vdev at byte {} (nothing on the member confirmed a base; the siblings' asize bounded the search and the walk confirmed this one — SPEC F-62)",
                                b.base
                            )
                        } else {
                            String::new()
                        }
                    );
                    bases[device] = b.base;
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
                    bases[device] = fits[0].base;
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

/// The first assembled pool that is short of a whole top-level vdev,
/// with the ids of the ones nothing describes.
///
/// The difference this draws is the whole of the message it feeds. A
/// *leaf* slot exists because some present member's configuration names
/// it, so a member can be asserted into it (SPEC F-62). A top-level vdev
/// that nothing present describes has no slots at all — and the labels
/// carry `vdev_children`, so "nothing is missing" is knowably false.
fn pool_missing_a_whole_top(pools: &[PoolAssembly]) -> Option<(String, Vec<u64>)> {
    pools.iter().find_map(|p| {
        let tops = p.missing_tops();
        (!tops.is_empty()).then(|| (p.name.clone(), tops))
    })
}

/// Open every member named in `spec`, scan it, and assemble pools.
/// Refuse a pool whose active read-incompatible features this build
/// cannot account for (SPEC F-70).
///
/// The label lists, under `features_for_read`, the read-incompatible
/// features that are *in use* — the pool itself saying what a reader
/// must understand. A feature named there and not implemented here
/// means the bytes may be read under assumptions that no longer hold,
/// and the checksums will not object: they are the checksums of
/// whatever blocks the wrong geometry lands on, and those agree with
/// themselves. So this refuses rather than warns.
///
/// `scan` is deliberately not routed through here. Its job is to survey
/// a disk and say what is on it, which includes saying this.
fn refuse_unaccounted_features(
    scans: &[Option<zfs_read::vdev::DeviceScan>],
    ignore: bool,
) -> Result<(), u8> {
    let mut active: Vec<String> = scans
        .iter()
        .flatten()
        .filter_map(|s| s.config())
        .flat_map(|c| c.features_for_read)
        .collect();
    active.sort();
    active.dedup();
    let unaccounted = zfs_ondisk::features::unaccounted(&active);
    if unaccounted.is_empty() {
        return Ok(());
    }
    for (name, s) in &unaccounted {
        match s {
            zfs_ondisk::features::Support::No(why) => {
                eprintln!("zvolrescue: {name}: not implemented.");
                eprintln!("zvolrescue:   {why}.");
            }
            _ => eprintln!(
                "zvolrescue: {name}: unknown to this build, and the pool says it is in use."
            ),
        }
    }
    if ignore {
        eprintln!("zvolrescue: reading anyway (--ignore-unknown-features).");
        eprintln!("zvolrescue:   what comes out may be wrong in a way no checksum catches.");
        return Ok(());
    }
    eprintln!(
        "zvolrescue: refusing this pool: {} active feature(s) above are unaccounted for.",
        unaccounted.len()
    );
    eprintln!("zvolrescue:   reading past them would answer confidently and perhaps wrongly.");
    eprintln!("zvolrescue:   `scan` still reports what is on the disk.");
    eprintln!("zvolrescue:   --ignore-unknown-features reads anyway.");
    Err(exit::UNRECOVERABLE)
}

/// Open every member named in `spec`, scan it, and assemble pools.
pub fn open_members(spec: &PoolSpec) -> Result<Members, u8> {
    let paths = spec.members().map_err(|e| {
        eprintln!("zvolrescue: {e}");
        exit::USAGE
    })?;
    // F-68: this tool reads a device and a copy of one the same way,
    // and writes to neither. The next tool the operator reaches for —
    // `zpool import -F`, a filesystem repair — does write, so it is
    // worth saying once which of the two is on the table (SPEC §4.1).
    let devices = paths
        .iter()
        .filter(|p| evidence::Kind::of(p).is_device())
        .count();
    if devices > 0 {
        eprintln!(
            "zvolrescue: {devices} of {} input(s) are devices, not images. \
             Nothing here writes to them; the next tool might.",
            paths.len()
        );
    }
    let open = spec.open_opts().map_err(|e| {
        eprintln!("zvolrescue: {e}");
        exit::USAGE
    })?;
    for (member, file) in &open.maps {
        if !paths.contains(member) {
            eprintln!(
                "zvolrescue: --map {}={}: {} is not among the members given",
                member.display(),
                file.display(),
                member.display()
            );
            return Err(exit::USAGE);
        }
    }
    let mut sources = Vec::with_capacity(paths.len());
    let mut scans = Vec::with_capacity(paths.len());
    for p in &paths {
        let opened = open.open(p).and_then(|src| {
            if let Some(m) = src.map() {
                eprintln!(
                    "zvolrescue: {}: the imager's map says {} byte(s) in {} range(s) were never read; they are refused, not trusted (SPEC F-72)",
                    p.display(),
                    m.unreadable_bytes(),
                    m.unreadable().len()
                );
            }
            let scan = scan_with_recovered_base_opts(&src, open.surface_scan_on_device)?;
            if scan.surface_scan_refused {
                eprintln!(
                    "zvolrescue: {}: labels do not verify, and a block device is not searched for anchors (SPEC N-10) — \
                     image it and scan the image, or --surface-scan-on-device",
                    p.display()
                );
            }
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
        // A device that refused a label read has stopped the run
        // already (SPEC F-33, N-10): go no further. The caller ends the
        // run through `end_early`, which reports the incident once and
        // writes the record; nothing is printed here so that it is not
        // printed twice.
        if open.ledger.stopped().is_some() {
            return Err(exit::MEDIUM);
        }
    }
    if scans.iter().all(|s| s.is_none()) {
        return Err(exit::EVIDENCE);
    }
    refuse_unaccounted_features(&scans, spec.ignore_unknown_features)?;
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
    // A top-level vdev no label describes is missing, unless the pool
    // itself says it was removed (SPEC F-69). Asked before anything
    // judges what is missing, so that `--assume-member` does not refuse
    // a leaf on account of a vdev that is gone on purpose.
    for pool in &mut pools {
        let removed = removed_tops_of(&scans, devices.clone(), &bases, pool);
        pool.note_removed_tops(removed);
    }
    bind_assumed(spec, &paths, &mut pools, &scans, &devices, &mut bases)?;
    drop(devices);
    Ok(Members {
        sources,
        scans,
        pools,
        paths,
        base_offsets: bases,
        map_files: open.map_files(),
        ledger: open.ledger.clone(),
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

#[cfg(test)]
mod assume_member_tests {
    use super::pool_missing_a_whole_top;
    use zfs_read::pool::PoolAssembly;

    fn pool(name: &str, children: Option<u64>, tops_present: &[u64]) -> PoolAssembly {
        PoolAssembly {
            name: name.into(),
            guid: 1,
            state: None,
            txg: None,
            vdev_children: children,
            features_for_read: Vec::new(),
            tops: tops_present
                .iter()
                .map(|id| zfs_read::pool::TopVdev {
                    id: *id,
                    guid: 0,
                    name: format!("mirror-{id}"),
                    kind: "mirror".into(),
                    nparity: None,
                    ashift: Some(12),
                    members: Vec::new(),
                    tree: Default::default(),
                })
                .collect(),
            removed_tops: Vec::new(),
            hosts: Vec::new(),
            devices: Vec::new(),
            stale: Vec::new(),
        }
    }

    /// The case the damage matrix found: a pool whose labels say it has
    /// two top-level vdevs, with members for one. Answering "no pool is
    /// missing a member" there is knowably false — the count is in the
    /// labels that were read.
    #[test]
    fn a_pool_short_of_a_whole_top_is_named() {
        let pools = [pool("tank", Some(2), &[1])];
        assert_eq!(
            pool_missing_a_whole_top(&pools),
            Some(("tank".to_string(), vec![0]))
        );
    }

    /// A pool with every top accounted for says nothing, whatever is
    /// wrong inside those tops: that is a vacant *leaf*, which is a
    /// different message and a different answer.
    #[test]
    fn a_pool_with_every_top_present_is_not_named() {
        let pools = [pool("tank", Some(2), &[0, 1])];
        assert_eq!(pool_missing_a_whole_top(&pools), None);
    }

    /// Labels that do not carry `vdev_children` cannot say anything is
    /// missing, and must not pretend to.
    #[test]
    fn without_a_count_nothing_is_claimed() {
        let pools = [pool("tank", None, &[0])];
        assert_eq!(pool_missing_a_whole_top(&pools), None);
    }

    /// With several pools the one that is short is the one named.
    #[test]
    fn the_pool_that_is_short_is_the_one_named() {
        let pools = [pool("whole", Some(1), &[0]), pool("short", Some(3), &[2])];
        assert_eq!(
            pool_missing_a_whole_top(&pools),
            Some(("short".to_string(), vec![0, 1]))
        );
    }
}

/// The refusal on a feature this build cannot account for (SPEC F-70),
/// on scans of real fixture members rather than on strings.
#[cfg(test)]
mod unaccounted_feature_tests {
    use super::refuse_unaccounted_features;
    use zfs_ondisk::label::LABEL_SIZE;
    use zfs_read::fixture::{build_sample_mos, Alloc, Pool};
    use zfs_read::vdev::{scan_device, DeviceScan};
    use zvolrescue_io::MemSource;

    const SIZE: u64 = 64 * LABEL_SIZE;

    fn scans_claiming(features: &[&str]) -> Vec<Option<DeviceScan>> {
        let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
        for f in features {
            pool = pool.with_feature(f);
        }
        let mut members = vec![vec![0u8; SIZE as usize]];
        let mut a = Alloc::new(0x20_0000);
        build_sample_mos(&mut pool, &mut members, &mut a);
        pool.write_labels(0, &mut members[0]);
        let src = MemSource::new(members.remove(0));
        vec![scan_device(&src).ok()]
    }

    #[test]
    fn a_pool_whose_features_are_all_accounted_for_is_not_refused() {
        assert_eq!(
            refuse_unaccounted_features(&scans_claiming(&[]), false),
            Ok(())
        );
    }

    #[test]
    fn a_known_but_unimplemented_feature_is_refused() {
        let scans = scans_claiming(&["org.openzfs:raidz_expansion"]);
        assert_eq!(
            refuse_unaccounted_features(&scans, false),
            Err(crate::exit::UNRECOVERABLE)
        );
    }

    #[test]
    fn a_feature_this_build_has_never_heard_of_is_refused_too() {
        let scans = scans_claiming(&["org.example:not_a_real_feature"]);
        assert_eq!(
            refuse_unaccounted_features(&scans, false),
            Err(crate::exit::UNRECOVERABLE)
        );
    }

    /// The override reads anyway; the cost is stated on stderr, which
    /// is not what this checks.
    #[test]
    fn the_override_reads_anyway() {
        let scans = scans_claiming(&["org.openzfs:raidz_expansion", "org.example:unknown"]);
        assert_eq!(refuse_unaccounted_features(&scans, true), Ok(()));
    }

    /// A member that could not be scanned contributes nothing to the
    /// list and does not by itself refuse the pool.
    #[test]
    fn an_unscanned_member_says_nothing_about_features() {
        let mut scans = scans_claiming(&[]);
        scans.push(None);
        assert_eq!(refuse_unaccounted_features(&scans, false), Ok(()));
    }
}
