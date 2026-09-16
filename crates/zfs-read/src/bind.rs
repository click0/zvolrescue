//! Working out which leaf a member without labels is (SPEC F-62).
//!
//! A member whose four labels are gone says nothing about itself. Its
//! siblings' configuration, however, names every leaf of the pool, and the
//! leaves that no scanned device carries are exactly the slots it could
//! fill. Which one is settled the only way anything is settled here — by
//! reading through the candidate and checking the checksums.
//!
//! For the test to mean something the candidate must actually be needed,
//! so one present sibling of the same top-level vdev is withheld while the
//! metadata is walked. A wrong slot then yields garbage where parity
//! reconstruction expects data, and the walk fails. A right slot walks the
//! whole DSL exactly as an intact pool does.

use crate::dsl::{open_mos, walk};
use crate::pool::{uberblock_candidates, PoolAssembly};
use crate::vdev::DeviceScan;
use crate::zio::PoolReader;
use zfs_ondisk::blkptr::LABEL_START_SIZE;
use zfs_ondisk::label::{VdevNode, LABEL_SIZE};
use zvolrescue_io::{trace, BlockSource};

/// The alignment partitioning tools put a member at: `gpart`, `sgdisk`
/// and `zpool create` on a whole disk all start it on a 1 MiB boundary.
const BASE_ALIGN: u64 = 1 << 20;
/// How many bases are tried for a member nothing on it confirms: the
/// first and the last this many multiples of [`BASE_ALIGN`] that leave
/// room for the member. A member is at the front of its disk or, less
/// often, its tail is at the disk's end; the middle of a large disk is
/// where a base is not.
const BASE_TRIALS_EACH_END: usize = 512;

/// A leaf a device was found to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// Index of the device in the scanned list.
    pub device: usize,
    /// Index of the top-level vdev in [`PoolAssembly::tops`].
    pub top: usize,
    /// Index of the leaf within that top's members.
    pub leaf: usize,
    /// GUID of that leaf.
    pub guid: u64,
    /// Whether the pool could *not* be walked without this member. A
    /// binding that reads either way is consistent, not proven: the
    /// vdev's redundancy answered for the slot.
    pub used: bool,
    /// Where the member's vdev begins on the device, confirmed by the
    /// walk. What the member's own scan found, or — when nothing on the
    /// member confirmed a base — the one of the candidates the
    /// siblings' `asize` bounded that read (SPEC F-62).
    pub base: u64,
}

/// Bytes a leaf of `top` occupies, as its siblings' labels put it: the
/// top's `asize`, shared out for raidz and dRAID, plus the labels at
/// both ends. `None` when the labels do not say.
fn leaf_psize(pool: &PoolAssembly, top: usize) -> Option<u64> {
    let t = &pool.tops[top];
    let asize = t.tree.asize?;
    let per_leaf = match t.kind.as_str() {
        "raidz" | "draid" => asize / t.members.len().max(1) as u64,
        _ => asize,
    };
    Some(per_leaf + LABEL_START_SIZE + 2 * LABEL_SIZE)
}

/// Bases worth trying for a member of `top` on a device of `size`
/// bytes when nothing on the member confirms one (SPEC F-62): 0, and
/// every multiple of [`BASE_ALIGN`] that leaves room for the leaf the
/// siblings describe — the first and the last [`BASE_TRIALS_EACH_END`]
/// of them when there are more. Each is confirmed or refused by
/// reading through it, never assumed.
pub fn base_candidates(pool: &PoolAssembly, top: usize, size: u64) -> Vec<u64> {
    let need = leaf_psize(pool, top).unwrap_or(LABEL_START_SIZE + 2 * LABEL_SIZE);
    let last = size.saturating_sub(need) / BASE_ALIGN;
    let mut out = vec![0];
    let count = last as usize;
    let mut push = |k: u64| {
        let b = k * BASE_ALIGN;
        if out.last() != Some(&b) {
            out.push(b);
        }
    };
    if count <= 2 * BASE_TRIALS_EACH_END {
        (1..=last).for_each(&mut push);
    } else {
        (1..=BASE_TRIALS_EACH_END as u64).for_each(&mut push);
        (last - BASE_TRIALS_EACH_END as u64 + 1..=last).for_each(&mut push);
    }
    out
}

/// Try `device` in each leaf the pool's configuration leaves vacant and
/// return the ones the pool can be read *through*.
///
/// A binding only means something when the candidate is needed: with
/// enough redundancy left, a wrong slot is simply treated as a corrupt
/// column and reconstructed around, and the walk succeeds either way. So
/// as many present siblings of the same top are withheld as the vdev can
/// spare, and the walk is then run twice — with the candidate and
/// without it. Only a candidate that makes the difference is reported.
pub fn candidates_for(
    pool: &PoolAssembly,
    scans: &[Option<DeviceScan>],
    devices: &[Option<&dyn BlockSource>],
    bases: &[u64],
    device: usize,
) -> Vec<Binding> {
    let mut out = Vec::new();
    // A member whose scan confirmed nothing — no label, no uberblock
    // anchor — has no base of its own to be read at. The siblings'
    // asize bounds where its vdev can begin, and each candidate base is
    // tried the way a leaf is.
    let unanchored = scans.get(device).and_then(Option::as_ref).is_none_or(|s| {
        !s.config_verified() && s.newest_txg().is_none() && s.base_source.is_none()
    });
    let own_base = bases.get(device).copied().unwrap_or(0);
    for (top, leaf) in pool.vacant_leaves() {
        let guid = pool.tops[top].members[leaf].guid;
        let mut trial = pool.clone();
        if trial.bind_member(device, Some(guid)).is_err() {
            continue;
        }
        let trial_bases: Vec<u64> = if unanchored && own_base == 0 {
            let size = devices
                .get(device)
                .copied()
                .flatten()
                .map_or(0, |d| d.size());
            base_candidates(pool, top, size)
        } else {
            vec![own_base]
        };
        // Withhold as many siblings as the redundancy allows, so what is
        // left leans on the candidate as hard as it can.
        let siblings: Vec<(usize, usize)> = trial.tops[top]
            .members
            .iter()
            .enumerate()
            .filter(|(i, m)| *i != leaf && m.present.is_some())
            .map(|(i, m)| (i, m.present.expect("present")))
            .collect();
        let mut masked: Vec<Option<&dyn BlockSource>> = devices.to_vec();
        let mut withheld = Vec::new();
        for (i, dev) in siblings {
            let mut without = trial.clone();
            without.tops[top].members[i].present = None;
            if !without.tops[top].readable() {
                continue;
            }
            trial = without;
            if let Some(slot) = masked.get_mut(dev) {
                *slot = None;
            }
            withheld.push(dev);
        }
        trace!(
            "pool",
            "trying device {device} as leaf {guid:#x}, withholding {withheld:?}, {} base(s)",
            trial_bases.len()
        );
        let mut at_base = bases.to_vec();
        let Some(base) = trial_bases.iter().copied().find(|&b| {
            if let Some(slot) = at_base.get_mut(device) {
                *slot = b;
            }
            walks(&trial, scans, masked.clone(), &at_base).is_some()
        }) else {
            trace!(
                "pool",
                "device {device} is not leaf {guid:#x} at any base tried"
            );
            continue;
        };
        if let Some(slot) = at_base.get_mut(device) {
            *slot = base;
        }
        let bases = at_base.as_slice();
        if base != own_base {
            trace!(
                "pool",
                "device {device} reads as leaf {guid:#x} with its vdev at byte {base}"
            );
        }
        // Does the walk depend on what this member *holds*, or merely on
        // the slot being occupied? Put a device of zeros in its place: if
        // the walk still succeeds, redundancy was answering all along and
        // the trial says nothing about this member.
        let zeros = ZeroSource(
            devices
                .get(device)
                .copied()
                .flatten()
                .map_or(0, |d| d.size()),
        );
        let mut blanked = masked.clone();
        if let Some(slot) = blanked.get_mut(device) {
            *slot = Some(&zeros);
        }
        let needed = walks(&trial, scans, blanked, bases).is_none();
        trace!(
            "pool",
            "device {device} works as leaf {guid:#x} ({})",
            if needed {
                "and its contents are what made the walk work"
            } else {
                "but a blank device in that slot reads just as well: no evidence"
            }
        );
        out.push(Binding {
            device,
            top,
            leaf,
            guid,
            used: needed,
            base,
        });
    }
    out
}

/// A device of the right size holding nothing: used to tell a slot that
/// merely needs to be occupied from one whose contents matter.
struct ZeroSource(u64);

impl BlockSource for ZeroSource {
    fn size(&self) -> u64 {
        self.0
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        if offset + buf.len() as u64 > self.0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "past the end of the device",
            ));
        }
        buf.fill(0);
        Ok(())
    }
}

/// Walk the DSL of `pool`; `None` when anything on the way fails.
fn walks(
    pool: &PoolAssembly,
    scans: &[Option<DeviceScan>],
    devices: Vec<Option<&dyn BlockSource>>,
    bases: &[u64],
) -> Option<()> {
    let candidates = uberblock_candidates(scans, pool);
    let ub = &candidates.first()?.ub;
    let reader = PoolReader::new(pool, devices).with_base_offsets(bases);
    let mos = open_mos(&reader, ub).ok()?;
    walk(&mos, &pool.name).ok()?;
    Some(())
}

/// What the trials concluded about a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// One leaf, or several that are interchangeable by construction —
    /// the leaves of a mirror hold the same bytes, so any of them is as
    /// true an answer as the others. The count says how many fitted.
    Bound(Binding, usize),
    /// Several leaves fit and they are not interchangeable: the evidence
    /// does not choose between them, so nothing is bound.
    Ambiguous(Vec<Binding>),
    /// No vacant leaf reads as this member.
    Nothing,
}

/// Kind of the vdev a leaf hangs under: `mirror`, `raidz`, `draid`, …
fn parent_kind(node: &VdevNode, guid: u64) -> Option<&str> {
    if node.children.iter().any(|c| c.guid == guid) {
        return Some(&node.kind);
    }
    node.children.iter().find_map(|c| parent_kind(c, guid))
}

/// Bind `device` into the leaf the pool reads as, when the trials point
/// at one.
///
/// Two kinds of evidence count. A leaf whose *contents* the walk depended
/// on is proven outright. Failing that, a leaf that works when every
/// other vacant leaf fails is settled by elimination.
pub fn bind_by_reading(
    pool: &mut PoolAssembly,
    scans: &[Option<DeviceScan>],
    devices: &[Option<&dyn BlockSource>],
    bases: &[u64],
    device: usize,
) -> Verdict {
    let consistent = candidates_for(pool, scans, devices, bases, device);
    let decisive: Vec<Binding> = consistent.iter().filter(|b| b.used).cloned().collect();
    let fitting = if decisive.is_empty() {
        consistent
    } else {
        decisive
    };
    let interchangeable = |b: &Binding| {
        matches!(
            parent_kind(&pool.tops[b.top].tree, b.guid),
            Some("mirror") | Some("replacing") | Some("spare")
        )
    };
    let pick = match fitting.len() {
        0 => return Verdict::Nothing,
        1 => fitting[0].clone(),
        _ if fitting.iter().all(interchangeable) => fitting[0].clone(),
        _ => return Verdict::Ambiguous(fitting),
    };
    let count = fitting.len();
    match pool.bind_member(device, Some(pick.guid)) {
        Ok(_) => Verdict::Bound(pick, count),
        Err(_) => Verdict::Nothing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{destroyed_zvol_members, Pool};
    use crate::pool::assemble;
    use crate::vdev::scan_device;
    use zfs_ondisk::label::{LABEL_SIZE, VDEV_PHYS_OFFSET, VDEV_PHYS_SIZE};
    use zvolrescue_io::MemSource;

    const SIZE: u64 = 64 * 262_144;

    /// Erase the four label configurations of one member: what is left is
    /// a device that reads as data with nothing saying whose it is.
    fn wipe_configs(img: &mut [u8]) {
        let aligned = img.len() as u64 & !(LABEL_SIZE - 1);
        for off in [
            0,
            LABEL_SIZE,
            aligned - 2 * LABEL_SIZE,
            aligned - LABEL_SIZE,
        ] {
            let at = (off + VDEV_PHYS_OFFSET) as usize;
            img[at..at + VDEV_PHYS_SIZE as usize].fill(0);
        }
    }

    fn setup(
        mut pool: Pool,
        wipe: &[usize],
    ) -> (Vec<MemSource>, Vec<Option<crate::vdev::DeviceScan>>) {
        let (mut members, _, _) = destroyed_zvol_members(&mut pool, SIZE);
        for &i in wipe {
            wipe_configs(&mut members[i]);
        }
        let sources: Vec<MemSource> = members.into_iter().map(MemSource::new).collect();
        let scans = sources.iter().map(|s| scan_device(s).ok()).collect();
        (sources, scans)
    }

    fn as_dyn(sources: &[MemSource]) -> Vec<Option<&dyn BlockSource>> {
        sources
            .iter()
            .map(|s| Some(s as &dyn BlockSource))
            .collect()
    }

    #[test]
    fn a_mirror_leaf_without_labels_is_found_by_reading() {
        let pool = Pool::mirror("tank", 0x1000, 12).txgs(&[(100, 1), (200, 2)]);
        let (sources, scans) = setup(pool, &[0]);
        let mut assembly = assemble(&scans).into_iter().next().expect("one pool");
        assert_eq!(assembly.vacant_leaves().len(), 1);

        let devices = as_dyn(&sources);
        let bases = vec![0u64; sources.len()];
        let found = candidates_for(&assembly, &scans, &devices, &bases, 0);
        assert_eq!(found.len(), 1);
        // Its sibling is withheld, so the walk leans on it entirely and a
        // blank device in its place would fail.
        assert!(found[0].used);

        match bind_by_reading(&mut assembly, &scans, &devices, &bases, 0) {
            Verdict::Bound(b, 1) => assert_eq!(b.guid, assembly.tops[0].members[0].guid),
            other => panic!("{other:?}"),
        }
        assert!(assembly.vacant_leaves().is_empty());
    }

    /// A three-way mirror with one leaf gone and another's labels wiped:
    /// the third describes the topology, and the wiped member is bound
    /// by reading — the shape the damage matrix produces when ztest has
    /// attached a third side.
    #[test]
    fn a_wider_mirror_with_a_leaf_missing_still_binds_the_wiped_one() {
        let mut pool = Pool::mirror("tank", 0x1000, 12).txgs(&[(100, 1), (200, 2)]);
        pool.members.push(crate::fixture::Member {
            guid: crate::fixture::Member::guid_for(0x1000, 2),
            path: "/dev/gpt/tank-d2".into(),
        });
        let (sources, mut scans) = setup(pool, &[0]);
        assert_eq!(sources.len(), 3);
        // Leaf 1 is absent from the run altogether.
        scans[1] = None;
        let mut devices = as_dyn(&sources);
        devices[1] = None;
        let mut assembly = assemble(&scans).into_iter().next().expect("one pool");
        assert_eq!(assembly.vacant_leaves().len(), 2);
        let bases = vec![0u64; sources.len()];
        let found = candidates_for(&assembly, &scans, &devices, &bases, 0);
        assert!(!found.is_empty(), "the wiped member reads as a leaf");
        match bind_by_reading(&mut assembly, &scans, &devices, &bases, 0) {
            Verdict::Bound(_, _) => {}
            other => panic!("{other:?}"),
        }
    }

    /// All four labels gone — rings and all, so no anchor — and the
    /// member 1 MiB into a larger image with nothing saying so: the
    /// siblings' asize bounds where it can begin, and the walk finds
    /// the one base it reads at.
    #[test]
    fn a_member_with_no_anchor_is_found_at_the_base_its_siblings_bound() {
        use zfs_ondisk::blkptr::LABEL_START_SIZE;
        let mut pool = Pool::mirror("tank", 0x1000, 12).txgs(&[(100, 1), (200, 2)]);
        pool.asize = Some((SIZE - LABEL_START_SIZE - 2 * LABEL_SIZE) & !((1u64 << 12) - 1));
        let (mut members, _, _) = destroyed_zvol_members(&mut pool, SIZE);
        // Every label, whole: nothing left to confirm a base with.
        let aligned = SIZE & !(LABEL_SIZE - 1);
        for off in [
            0,
            LABEL_SIZE,
            aligned - 2 * LABEL_SIZE,
            aligned - LABEL_SIZE,
        ] {
            members[0][off as usize..(off + LABEL_SIZE) as usize].fill(0);
        }
        let shift = 1u64 << 20;
        let mut image = vec![0x5au8; shift as usize];
        image.extend_from_slice(&members[0]);
        image.extend_from_slice(&vec![0u8; 8 << 20]);
        members[0] = image;
        let sources: Vec<MemSource> = members.into_iter().map(MemSource::new).collect();
        let scans: Vec<_> = sources
            .iter()
            .map(|s| crate::zeropoint::scan_with_recovered_base(s).ok())
            .collect();
        assert!(
            scans[0].as_ref().unwrap().newest_txg().is_none(),
            "no anchor"
        );
        let mut assembly = assemble(&scans).into_iter().next().expect("one pool");
        let devices = as_dyn(&sources);
        let bases = vec![0u64; sources.len()];
        let candidates = base_candidates(&assembly, 0, sources[0].size());
        assert!(candidates.contains(&shift), "{candidates:?}");
        assert!(candidates.len() < 32, "{}", candidates.len());
        match bind_by_reading(&mut assembly, &scans, &devices, &bases, 0) {
            Verdict::Bound(b, 1) => {
                assert_eq!(b.guid, assembly.tops[0].members[0].guid);
                assert_eq!(b.base, shift);
                assert!(b.used);
            }
            other => panic!("{other:?}"),
        }
    }

    /// The candidate list is bounded whatever the disk's size: a huge
    /// image yields the first and last few hundred, not millions.
    #[test]
    fn base_candidates_stay_a_handful_on_a_huge_disk() {
        let pool = Pool::mirror("tank", 0x1000, 12).txgs(&[(100, 1), (200, 2)]);
        let (_, scans) = setup(pool, &[]);
        let assembly = assemble(&scans).into_iter().next().expect("one pool");
        let many = base_candidates(&assembly, 0, 4 << 40);
        assert_eq!(many.len(), 1 + 2 * BASE_TRIALS_EACH_END);
        assert_eq!(many[0], 0);
        assert_eq!(many[1], BASE_ALIGN);
        assert!(many.windows(2).all(|w| w[0] < w[1]));
        // Too small for the leaf at all: only 0 is left to try.
        assert_eq!(base_candidates(&assembly, 0, 1 << 20), vec![0]);
    }

    #[test]
    fn a_device_that_does_not_hold_the_pools_data_reads_as_no_leaf() {
        let pool = Pool::mirror("tank", 0x1000, 12).txgs(&[(100, 1), (200, 2)]);
        let (mut members, _, _) = destroyed_zvol_members(&mut pool.clone(), SIZE);
        wipe_configs(&mut members[0]);
        // The member is the right size and shape but its data area is
        // not this pool's: the walk through it cannot verify a thing.
        let start = 4 * 1024 * 1024;
        for b in &mut members[0][start..] {
            *b ^= 0xa5;
        }
        let sources: Vec<MemSource> = members.into_iter().map(MemSource::new).collect();
        let scans: Vec<_> = sources.iter().map(|s| scan_device(s).ok()).collect();
        let assembly = assemble(&scans).into_iter().next().expect("one pool");
        let devices = as_dyn(&sources);
        let bases = vec![0u64; sources.len()];
        assert!(candidates_for(&assembly, &scans, &devices, &bases, 0).is_empty());
    }
}
