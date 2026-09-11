//! Scanning raw vdev space for metadata nothing points at any more
//! (COMPANIONS C-01, C-03, C-04, C-08, C-10).
//!
//! When the uberblock ring has rolled past the last transaction group
//! that referenced a dataset, no walk can reach it: there is no path
//! from any uberblock down to its dnode. The blocks are usually still
//! there, though, and a dnode is recognisable on its own. This module
//! streams a member from end to end and hands every slot that could be
//! a dnode to the recogniser in `zfs-ondisk`.
//!
//! Two passes over the same bytes, because metadata is usually
//! compressed:
//!
//! * **plaintext** — every 512-byte slot, which is where a dnode sits
//!   inside a dnode block that was written uncompressed;
//! * **lz4** — every block-sized offset tried as the start of a
//!   compressed block, since OpenZFS compresses metadata with lz4 by
//!   default and a compressed dnode block matches nothing in plaintext.
//!
//! Read-only, streaming and bounded: one buffer, whatever the member's
//! size, and nothing is written anywhere.

use std::collections::BTreeMap;

use zfs_ondisk::blkptr;
use zfs_ondisk::carve::{plausible_dnode, plausible_head, Profile, Reject, MAX_BLOCKSIZE};
use zfs_ondisk::compress;
use zfs_ondisk::dmu::{DnodePhys, DNODE_SIZE};
use zfs_ondisk::Endian;
use zvolrescue_io::{trace, BlockSource};

/// How the bytes of a hit were found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Found {
    /// The dnode was on disk as it is in memory.
    Plaintext,
    /// It came out of an lz4-compressed block at this offset.
    Lz4,
}

impl Found {
    /// Stable name for the report.
    pub fn as_str(self) -> &'static str {
        match self {
            Found::Plaintext => "plaintext",
            Found::Lz4 => "lz4",
        }
    }
}

/// One dnode the scan found.
#[derive(Debug, Clone)]
pub struct Hit {
    /// Index of the member it was found on.
    pub device: usize,
    /// Offset in that member where the dnode's first slot starts. For a
    /// compressed hit this is the start of the compressed block, plus
    /// the slot's offset inside it in `slot`.
    pub offset: u64,
    /// Slot index inside the block, for a compressed hit.
    pub slot: u64,
    /// How it was found.
    pub found: Found,
    /// The dnode itself.
    pub dnode: DnodePhys,
    /// Profile fields it failed, empty when it matched everything asked
    /// for. A soft profile keeps these; a strict one never records them.
    pub misses: Vec<Reject>,
}

/// How many hits each reason accounted for (C-14, C-15).
#[derive(Debug, Clone, Default)]
pub struct Counts(pub BTreeMap<Reject, u64>);

impl Counts {
    fn bump(&mut self, r: Reject) {
        *self.0.entry(r).or_insert(0) += 1;
    }

    /// Reasons that rejected at least one candidate, most first, then by
    /// name so two runs of the same evidence read the same.
    pub fn ranked(&self) -> Vec<(Reject, u64)> {
        let mut v: Vec<(Reject, u64)> = self.0.iter().map(|(r, n)| (*r, *n)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v
    }

    /// Rejections that came from the profile rather than from the bytes.
    /// This is the number that tells "the filter is too tight" from
    /// "there is nothing here" (C-14).
    pub fn by_profile(&self) -> u64 {
        self.0
            .iter()
            .filter(|(r, _)| r.is_profile())
            .map(|(_, n)| n)
            .sum()
    }
}

/// What to scan and what to look for.
#[derive(Debug, Clone)]
pub struct Options {
    /// The search profile (C-13).
    pub profile: Profile,
    /// Profile fields are hard filters rather than hints (C-18).
    pub strict_profile: bool,
    /// Byte range of the member to read; the whole member when absent.
    pub range: Option<(u64, u64)>,
    /// Also try to decompress each block-aligned offset as lz4 (C-10).
    pub lz4: bool,
    /// Block sizes to try when decompressing, largest first.
    pub lz4_sizes: Vec<u64>,
    /// Stop after this many hits, so a wide search can be bounded.
    pub max_hits: usize,
    /// Read this many bytes at a time.
    pub chunk: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            profile: Profile::default(),
            strict_profile: false,
            range: None,
            lz4: true,
            // The sizes a dnode block is written at: `dnodesize` blocks
            // are 16 KiB by default, 32 KiB and 128 KiB for large dnodes
            // and busy objsets.
            lz4_sizes: vec![16384, 32768, 131072],
            max_hits: 100_000,
            chunk: 4 << 20,
        }
    }
}

/// What one pass over one member found.
#[derive(Debug, Clone, Default)]
pub struct Scan {
    /// Candidates that survived both tests, in the order they were met.
    pub hits: Vec<Hit>,
    /// How many candidates each reason accounted for.
    pub counts: Counts,
    /// Bytes read from the member.
    pub bytes_read: u64,
    /// 512-byte slots the cheap test looked at.
    pub slots_examined: u64,
    /// Offset the scan reached, so it can be resumed from there (C-08).
    pub resume_at: u64,
    /// The scan stopped before the end of the range.
    pub stopped_early: bool,
    /// Dataset dnodes met along the way, whatever the profile asked for
    /// (C-11). A candidate whose DSL metadata survived somewhere on the
    /// disk can be named from these, and a search for volumes would
    /// otherwise throw them away.
    pub datasets: Vec<Hit>,
}

/// Judge one candidate dnode and, if it survives, record it.
///
/// The structural test comes first and is absolute; the profile comes
/// second and, unless it was made strict, only annotates.
fn consider(
    scan: &mut Scan,
    opts: &Options,
    device: usize,
    offset: u64,
    slot: u64,
    found: Found,
    dnode: DnodePhys,
) {
    if let Err(r) = plausible_dnode(&dnode) {
        scan.counts.bump(r);
        return;
    }
    // A dataset dnode is kept whatever was asked for: it is not a
    // candidate, it is what lets one be named (C-11).
    if dnode.object_type == zfs_ondisk::dmu::ot::DSL_DATASET && scan.datasets.len() < opts.max_hits
    {
        scan.datasets.push(Hit {
            device,
            offset,
            slot,
            found,
            dnode: dnode.clone(),
            misses: Vec::new(),
        });
    }
    let misses = opts.profile.misses(&dnode);
    for m in &misses {
        scan.counts.bump(*m);
    }
    if opts.strict_profile && !misses.is_empty() {
        return;
    }
    if scan.hits.len() >= opts.max_hits {
        scan.stopped_early = true;
        return;
    }
    trace!(
        "carve",
        "hit: device {device} offset {offset:#x} slot {slot} {} type {} datablksz {} nlevels {} maxblkid {}",
        found.as_str(),
        dnode.type_name(),
        dnode.datablksz(),
        dnode.nlevels,
        dnode.maxblkid
    );
    scan.hits.push(Hit {
        device,
        offset,
        slot,
        found,
        dnode,
        misses,
    });
}

/// Every 512-byte slot of `buf` that could be a dnode.
fn plaintext_pass(scan: &mut Scan, opts: &Options, device: usize, base: u64, buf: &[u8]) {
    let mut at = 0usize;
    while at + DNODE_SIZE <= buf.len() {
        scan.slots_examined += 1;
        match plausible_head(&buf[at..]) {
            Err(r) => {
                scan.counts.bump(r);
            }
            Ok(()) => match DnodePhys::parse(&buf[at..], Endian::Little) {
                Ok(d) => consider(scan, opts, device, base + at as u64, 0, Found::Plaintext, d),
                Err(_) => scan.counts.bump(Reject::BonusLen),
            },
        }
        at += DNODE_SIZE;
    }
}

/// Try `buf` at `at` as the start of an lz4-compressed block.
///
/// OpenZFS frames lz4 with a big-endian four-byte compressed length, so
/// a length that does not fit the block is settled without decompressing
/// anything — which is what keeps this pass affordable.
fn lz4_pass(scan: &mut Scan, opts: &Options, device: usize, base: u64, buf: &[u8], at: usize) {
    let Some(head) = buf.get(at..at + 4) else {
        return;
    };
    let clen = u32::from_be_bytes(head.try_into().expect("4 bytes")) as usize;
    if clen == 0 || clen as u64 > MAX_BLOCKSIZE {
        return;
    }
    if at + 4 + clen > buf.len() {
        return;
    }
    for lsize in &opts.lz4_sizes {
        // A compressed block never claims to be larger than what it
        // decompresses to.
        if clen as u64 >= *lsize {
            continue;
        }
        let Ok(out) = compress::lz4(&buf[at..], *lsize as usize) else {
            continue;
        };
        let mut slot = 0u64;
        let mut off = 0usize;
        while off + DNODE_SIZE <= out.len() {
            scan.slots_examined += 1;
            if plausible_head(&out[off..]).is_ok() {
                if let Ok(d) = DnodePhys::parse(&out[off..], Endian::Little) {
                    consider(scan, opts, device, base + at as u64, slot, Found::Lz4, d);
                }
            }
            off += DNODE_SIZE;
            slot += 1;
        }
        // One size that decompressed cleanly is enough; trying the rest
        // would report the same block again under another name.
        break;
    }
}

/// Scan one member.
///
/// `ashift` sets the granularity of the compressed pass: a block starts
/// at an allocation boundary, so nothing in between needs trying.
pub fn scan_member(
    src: &dyn BlockSource,
    device: usize,
    ashift: u32,
    opts: &Options,
) -> std::io::Result<Scan> {
    let size = src.size();
    let (start, end) = opts.range.unwrap_or((0, size));
    let end = end.min(size);
    let step = 1u64 << ashift.clamp(9, 17);
    let mut scan = Scan {
        resume_at: start,
        ..Scan::default()
    };
    // A block that starts near the end of a chunk has to be readable
    // whole, so each read carries a tail past its own chunk. The tail is
    // the largest thing that is actually looked at — the biggest
    // compressed block tried, or one dnode's worth of slots — not the
    // largest block ZFS can write: an overlap of 16 MiB on a 4 MiB chunk
    // would read every byte of the member five times.
    let overlap = opts
        .lz4_sizes
        .iter()
        .copied()
        .max()
        .unwrap_or(0)
        .max(DNODE_SIZE as u64 * 256) as usize
        + 4;
    let mut at = start;
    let mut buf = vec![0u8; opts.chunk + overlap];
    while at < end {
        let want = ((end - at) as usize + overlap).min(buf.len());
        let readable = (size - at).min(want as u64) as usize;
        if readable < DNODE_SIZE {
            break;
        }
        let window = &mut buf[..readable];
        if let Err(e) = src.read_at(at, window) {
            // A member with a bad sector is not a reason to lose the
            // rest of it: skip the chunk and say so.
            trace!(
                "carve",
                "device {device} offset {at:#x}: {e}; skipping chunk"
            );
            at += opts.chunk as u64;
            scan.resume_at = at;
            continue;
        }
        scan.bytes_read += readable as u64;
        // Only offsets that start inside this chunk are examined; the
        // overlap belongs to the next one.
        let own = (opts.chunk).min((end - at) as usize);
        plaintext_pass(&mut scan, opts, device, at, &window[..own.min(readable)]);
        if opts.lz4 {
            let mut off = 0usize;
            while off < own && off < readable {
                lz4_pass(&mut scan, opts, device, at, window, off);
                off += step as usize;
            }
        }
        if scan.stopped_early {
            // Stop where this chunk began. The rest of it was never
            // looked at, and a resume that started after it would lose
            // whatever is there; seeing a few candidates twice is the
            // cheaper mistake.
            scan.resume_at = at;
            break;
        }
        at += opts.chunk as u64;
        scan.resume_at = at.min(end);
    }
    Ok(scan)
}

/// A candidate's final rank, once its tree has been walked (C-05).
///
/// The profile decides the half of the range a candidate lands in, and
/// the evidence decides where in that half. A candidate that matched
/// everything asked for scores 0.5 or above and one that did not scores
/// below 0.5 — always, whatever else it has going for it. That is what
/// C-18 asks for: a hint that was wrong costs ranking rather than the
/// recovery, and a hint that was right is not outvoted by a well-formed
/// dnode of something else. The two bands are disjoint, so 0.5 reads as
/// a line between them and not as a score anything can have.
///
/// Within a half: the structure says whether the slot could be a dnode,
/// the walk says whether what it points at is really there, and the
/// second is much the stronger evidence — a slot can look perfect and
/// address nothing — so the two weigh equally once a walk has happened.
pub fn rank(hit: &Hit, assessed: Option<&Assessment>) -> f64 {
    let base = match assessed {
        None => score(hit),
        Some(a) => 0.5 * score(hit) + 0.5 * a.agreement(),
    };
    // The two bands do not touch, so 0.5 reads as a dividing line
    // rather than as a value a candidate can land on from either side.
    let base = base.clamp(0.0, 1.0);
    if hit.misses.is_empty() {
        0.55 + 0.45 * base
    } else {
        0.45 * base
    }
}

/// How good a candidate looks, in 0.0..=1.0 (C-05).
///
/// Not a probability: a ranking. What it weighs, and why:
///
/// * how much of the tree the dnode claims is actually addressable —
///   pointers that address nothing are the commonest sign of a slot that
///   only resembles a dnode;
/// * whether the births are consistent — a real tree's children are no
///   younger than their parents;
/// * whether the shape is possible at all — a single-level tree cannot
///   hold more blocks than the dnode has pointers.
///
/// Whether the profile matched is not weighed here; [`rank`] does that,
/// and decisively. The extraction itself trusts none of it: every block
/// `dump` reads is verified by its own checksum.
pub fn score(hit: &Hit) -> f64 {
    let d = &hit.dnode;
    let live: Vec<&blkptr::BlkPtr> = d.blkptr.iter().filter(|b| !b.is_hole()).collect();
    if live.is_empty() {
        return 0.0;
    }
    let addressable = live
        .iter()
        .filter(|b| b.dva[0].asize != 0 && b.lsize > 0)
        .count() as f64
        / live.len() as f64;
    let births: Vec<u64> = live.iter().map(|b| b.birth).collect();
    let consistent = if births.iter().all(|b| *b > 0) {
        let (lo, hi) = (
            births.iter().copied().min().unwrap_or(0),
            births.iter().copied().max().unwrap_or(0),
        );
        // Pointers of one object are written over a window of
        // transaction groups, not all at once; a spread of more than a
        // few thousand is a sign of pointers that never belonged
        // together.
        if hi.saturating_sub(lo) <= 4096 {
            1.0
        } else {
            0.5
        }
    } else {
        0.0
    };
    // A tree that says it has more levels than one indirect block could
    // hold is describing something real; a single-level dnode with a
    // huge maxblkid is not.
    let shape = {
        let per = d.ptrs_per_indirect().max(1);
        let capacity = (d.nblkptr as u64)
            .saturating_mul(per.saturating_pow(u32::from(d.nlevels.saturating_sub(1)).min(6)));
        if capacity > d.maxblkid {
            1.0
        } else {
            0.0
        }
    };
    (0.5 * addressable + 0.25 * consistent + 0.25 * shape).clamp(0.0, 1.0)
}

/// What walking a candidate's tree found (C-04).
///
/// This is the part that separates a dnode-shaped slot from a volume
/// that is really there: the tree is walked, every block that is not a
/// hole is read, and the checksum decides. Nothing is kept — only the
/// counts — so assessing a 300 GB candidate costs the reads and no
/// memory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Assessment {
    /// Blocks the dnode claims (`maxblkid + 1`, capped by the walk).
    pub blocks_total: u64,
    /// Blocks that read and whose checksum verified.
    pub blocks_verified: u64,
    /// Blocks the tree says are holes: never written, not lost.
    pub blocks_holes: u64,
    /// Blocks that could not be read or did not verify.
    pub blocks_failed: u64,
    /// Oldest and newest birth transaction group met in the tree.
    pub birth: Option<(u64, u64)>,
    /// Blocks whose space the allocator still has given out (C-06): the
    /// candidate is either live somewhere or its space went to something
    /// else.
    pub blocks_allocated: u64,
    /// Blocks whose space has been released. The likeliest state for
    /// something destroyed, and the one a recovery is racing.
    pub blocks_free: u64,
    /// Blocks the space maps say nothing about.
    pub blocks_unknown: u64,
    /// The walk stopped before the end of the tree.
    pub sampled: bool,
}

impl Assessment {
    /// Share of the blocks that are either present and verified or
    /// honestly absent, in 0.0..=1.0.
    pub fn agreement(&self) -> f64 {
        let looked = self.blocks_verified + self.blocks_holes + self.blocks_failed;
        if looked == 0 {
            return 0.0;
        }
        (self.blocks_verified + self.blocks_holes) as f64 / looked as f64
    }
}

/// Walk a candidate's tree and see how much of it is really there.
///
/// `sample` bounds the walk: a candidate is ranked, not extracted, so
/// there is no reason to read a terabyte to decide whether to offer it.
/// Blocks are taken evenly across the whole tree rather than from the
/// front, because the front of an overwritten volume is the part most
/// likely to still look intact.
pub fn assess(obj: &crate::dmu::ObjectReader<'_, '_>, sample: u64) -> Assessment {
    assess_against(obj, sample, None)
}

/// Like [`assess`], and also asking the space maps about each block it
/// finds (C-06).
///
/// The space maps say whether the allocator still has that space given
/// out. They are not a verdict on the data — the checksum is — but they
/// tell "released, and still there until something overwrites it" from
/// "handed to something else", which is the difference between a
/// recovery worth starting now and one that is already too late.
pub fn assess_against(
    obj: &crate::dmu::ObjectReader<'_, '_>,
    sample: u64,
    space: Option<&crate::spacemap::Space>,
) -> Assessment {
    let d = obj.dnode();
    let total = d.maxblkid.saturating_add(1);
    let step = if sample == 0 || total <= sample {
        1
    } else {
        total.div_ceil(sample)
    };
    let mut a = Assessment {
        blocks_total: total,
        sampled: step > 1,
        ..Assessment::default()
    };
    let mut blkid = 0u64;
    while blkid <= d.maxblkid {
        match obj.locate(blkid) {
            Err(_) => a.blocks_failed += 1,
            Ok(None) => a.blocks_holes += 1,
            Ok(Some(bp)) => {
                if let Some(space) = space {
                    let dva = &bp.dva[0];
                    match space.allocated(dva.vdev.into(), dva.offset, dva.asize) {
                        Some(true) => a.blocks_allocated += 1,
                        Some(false) => a.blocks_free += 1,
                        None => a.blocks_unknown += 1,
                    }
                }
                a.birth = Some(match a.birth {
                    None => (bp.birth, bp.birth),
                    Some((lo, hi)) => (lo.min(bp.birth), hi.max(bp.birth)),
                });
                // read_blkid verifies the checksum; a block that comes
                // back is a block that was really written here.
                match obj.read_blkid(blkid) {
                    Ok(_) => a.blocks_verified += 1,
                    Err(_) => a.blocks_failed += 1,
                }
            }
        }
        blkid = blkid.saturating_add(step);
        if step > 1 && blkid > d.maxblkid {
            break;
        }
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{carved_zvol_members, Pool};
    use crate::pool::assemble;
    use crate::vdev::scan_device;
    use crate::zio::PoolReader;
    use zfs_ondisk::dmu::ot;
    use zvolrescue_io::MemSource;

    const SIZE: u64 = 64 * 1024 * 1024;

    fn carved() -> Vec<Vec<u8>> {
        let mut pool = Pool::mirror("tank", 0x5eed_0000_0000_0001, 12).txgs(&[
            (4816228, 1757100000),
            (4816229, 1757100005),
            (4816230, 1757100010),
        ]);
        carved_zvol_members(&mut pool, SIZE)
    }

    /// The volume nothing points at is found by scanning for it, and its
    /// dnode says what it was: 8 KiB blocks, four of them.
    #[test]
    fn a_volume_no_uberblock_leads_to_is_found_by_scanning() {
        let members = carved();
        let src = MemSource::new(members[0].clone());
        let opts = Options {
            profile: Profile {
                dnode_type: Some(ot::ZVOL),
                ..Profile::default()
            },
            strict_profile: true,
            ..Options::default()
        };
        let scan = scan_member(&src, 0, 12, &opts).expect("scan");
        assert!(
            !scan.hits.is_empty(),
            "no zvol dnode found; counts {:?}",
            scan.counts.ranked()
        );
        assert!(scan.hits.iter().all(|h| h.dnode.object_type == ot::ZVOL));
        let best = scan
            .hits
            .iter()
            .max_by(|a, b| score(a).partial_cmp(&score(b)).expect("finite"))
            .expect("a hit");
        assert_eq!(best.dnode.datablksz(), 8192);
        assert_eq!(best.dnode.maxblkid, 3);
    }

    /// C-14: a profile that matches nothing must be visibly a rejection.
    /// "0 candidates, all of them rejected by volblocksize" is a
    /// different fact from "there is nothing on this disk", and the
    /// operator has to be able to tell which one they are looking at.
    #[test]
    fn a_profile_that_matches_nothing_says_which_field_rejected_what() {
        let members = carved();
        let src = MemSource::new(members[0].clone());
        let opts = Options {
            profile: Profile {
                dnode_type: Some(ot::ZVOL),
                volblocksize: Some(1 << 20),
                ..Profile::default()
            },
            strict_profile: true,
            ..Options::default()
        };
        let scan = scan_member(&src, 0, 12, &opts).expect("scan");
        assert!(scan.hits.is_empty());
        assert!(scan.counts.by_profile() > 0, "{:?}", scan.counts.ranked());
        let named: Vec<&str> = scan
            .counts
            .ranked()
            .iter()
            .map(|(r, _)| r.as_str())
            .collect();
        assert!(named.contains(&"profile_volblocksize"), "{named:?}");
    }

    /// A soft profile costs ranking, not the recovery: the hit is still
    /// recorded, with the field it failed named (C-18).
    #[test]
    fn a_soft_profile_records_what_it_would_have_dropped() {
        let members = carved();
        let src = MemSource::new(members[0].clone());
        let wrong = Profile {
            dnode_type: Some(ot::ZVOL),
            volblocksize: Some(1 << 20),
            ..Profile::default()
        };
        let soft = scan_member(
            &src,
            0,
            12,
            &Options {
                profile: wrong.clone(),
                strict_profile: false,
                ..Options::default()
            },
        )
        .expect("scan");
        let kept: Vec<&Hit> = soft
            .hits
            .iter()
            .filter(|h| h.dnode.object_type == ot::ZVOL)
            .collect();
        assert!(!kept.is_empty(), "a soft profile dropped the volume");
        assert!(kept
            .iter()
            .all(|h| h.misses.contains(&Reject::ProfileVolBlockSize)));
        // And it ranks below what a right profile would have matched —
        // decisively: no amount of structural quality lifts a candidate
        // that failed the profile above one that passed it.
        let hit = kept[0];
        let mut matched = hit.clone();
        matched.misses.clear();
        assert!(rank(&matched, None) > 0.5);
        assert!(rank(hit, None) < 0.5);
        assert!(rank(&matched, None) > rank(hit, None));
    }

    /// C-04: the tree of the carved volume is really there — every block
    /// the dnode claims either reads and verifies, or is a hole.
    #[test]
    fn the_carved_volume_walks_and_verifies() {
        let members = carved();
        let sources: Vec<MemSource> = members.iter().map(|m| MemSource::new(m.clone())).collect();
        let scans: Vec<_> = sources
            .iter()
            .map(|s| Some(scan_device(s).expect("scan")))
            .collect();
        let pools = assemble(&scans);
        let devices: Vec<Option<&dyn BlockSource>> = sources
            .iter()
            .map(|s| Some(s as &dyn BlockSource))
            .collect();
        let reader = PoolReader::new(&pools[0], devices);

        let opts = Options {
            profile: Profile {
                dnode_type: Some(ot::ZVOL),
                ..Profile::default()
            },
            strict_profile: true,
            ..Options::default()
        };
        let scan = scan_member(&sources[0], 0, 12, &opts).expect("scan");
        let best = scan
            .hits
            .iter()
            .max_by(|a, b| score(a).partial_cmp(&score(b)).expect("finite"))
            .expect("a hit");
        let obj = crate::dmu::ObjectReader::new(&reader, best.dnode.clone(), Endian::Little);
        let a = assess(&obj, 0);
        assert_eq!(a.blocks_total, 4);
        assert_eq!(a.blocks_failed, 0, "{a:?}");
        assert_eq!(a.blocks_verified + a.blocks_holes, 4, "{a:?}");
        assert_eq!(a.agreement(), 1.0);
    }

    /// The counters are what makes an empty result readable, so every
    /// slot the scan looked at has to be accounted for by exactly one.
    #[test]
    fn a_blank_member_rejects_everything_as_free() {
        let src = MemSource::new(vec![0u8; 4 << 20]);
        let scan = scan_member(&src, 0, 12, &Options::default()).expect("scan");
        assert!(scan.hits.is_empty());
        assert_eq!(scan.counts.by_profile(), 0);
        assert_eq!(
            scan.counts.0.get(&Reject::Free).copied().unwrap_or(0),
            scan.slots_examined
        );
    }
}
