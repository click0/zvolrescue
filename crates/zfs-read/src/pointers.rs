//! The vdev zero point from pointer self-consistency (SPEC F-63).
//!
//! Every other way to find where a vdev begins needs something that
//! survived: a label, a partition table, a sibling's configuration, an
//! uberblock, or the operator's own knowledge. F-63 is the case where
//! none of that is left — a bare device, all four labels gone, nothing
//! to go on but the bytes.
//!
//! What is still there is ZFS's own redundancy of *description*. A block
//! pointer says where its block is, how large it is, and what its
//! checksum comes to. The position it gives is relative to the vdev's
//! allocatable space, so it is only an address once the base is known —
//! which turns the pointer into a test of a candidate base: assume `B`,
//! read the bytes at `B + 4 MiB + offset`, and see whether they hash to
//! what the pointer said. A wrong base hashes to nothing; the right one
//! hashes to all of them.
//!
//! Nothing here is believed on its own. A base is reported with how many
//! independent pointers confirmed it and how many were tried, so a
//! reader can tell one checksum's luck from a hundred agreeing.

use std::io;

use zfs_ondisk::blkptr::{BlkPtr, Checksum, LABEL_START_SIZE};
use zfs_ondisk::checksum::{verify_block, Verify};
use zfs_ondisk::Endian;
use zvolrescue_io::{trace, BlockSource};

use crate::carve::Scan;

/// The largest physical block ZFS writes, and so the largest read this
/// will make for one probe.
const MAX_PSIZE: u64 = 16 * 1024 * 1024;

/// One block pointer, used as a probe for the vdev's zero point.
#[derive(Debug, Clone)]
pub struct Anchor {
    /// Offset the pointer gives, relative to the vdev's allocatable space.
    pub offset: u64,
    /// Physical size of the block in bytes: what has to be hashed.
    pub psize: u64,
    /// Checksum algorithm the pointer names.
    pub checksum: Checksum,
    /// The checksum it carries.
    pub cksum: [u64; 4],
    /// Byte order the block was written in.
    pub endian: Endian,
    /// The block is encrypted, so the stored checksum covers only part
    /// of the value and `verify_block` compares it accordingly.
    pub encrypted: bool,
}

/// Whether a pointer can be used as a probe, and why not when it cannot.
///
/// The restrictions are all of the same kind: a probe is only useful if
/// this code can reproduce the number the pointer carries, knowing
/// nothing but the bytes on the disk.
fn as_anchor(bp: &BlkPtr) -> Option<Anchor> {
    if bp.is_hole() || bp.embedded {
        return None;
    }
    let dva = &bp.dva[0];
    // A gang pointer's checksum covers the gang header, whose verifier
    // is the DVA itself — which is what is being solved for here.
    if dva.gang || dva.asize == 0 {
        return None;
    }
    // The salted algorithms need the pool's checksum salt, and the salt
    // lives in the MOS object directory — which cannot be read until the
    // base is known. Using one would be circular, so they are left out;
    // fletcher4 is the default for metadata and there is never a
    // shortage of it.
    match bp.checksum {
        Checksum::Fletcher2 | Checksum::Fletcher4 | Checksum::Sha256 | Checksum::Sha512 => {}
        _ => return None,
    }
    if bp.psize == 0 || bp.psize > MAX_PSIZE {
        return None;
    }
    Some(Anchor {
        offset: dva.offset,
        psize: bp.psize,
        checksum: bp.checksum,
        cksum: bp.cksum,
        endian: bp.endian,
        encrypted: bp.encrypted,
    })
}

/// Every usable probe a scan met, nearest the front of the vdev first.
///
/// Order matters for cost, not for correctness: a low offset can be read
/// whatever the base turns out to be, while a probe near the end of the
/// vdev falls off the device for every base but the right one and is
/// settled without a read.
pub fn anchors(scan: &Scan) -> Vec<Anchor> {
    let mut out: Vec<Anchor> = Vec::new();
    let from_dnode = |d: &zfs_ondisk::dmu::DnodePhys| -> Vec<Anchor> {
        d.blkptr.iter().filter_map(as_anchor).collect()
    };
    for h in scan.hits.iter().chain(scan.datasets.iter()) {
        out.extend(from_dnode(&h.dnode));
    }
    for r in &scan.roots {
        out.extend(from_dnode(&r.objset.meta_dnode));
    }
    out.sort_by_key(|a| (a.offset, a.psize));
    out.dedup_by(|a, b| a.offset == b.offset && a.psize == b.psize && a.cksum == b.cksum);
    out
}

/// Shifts consistent with every offset and size the probes carry
/// (SPEC F-63: "`ashift` itself follows from the smallest DVA offset
/// step and `asize` granularity"), largest first.
///
/// Every allocation is a multiple of `1 << ashift`, so every offset is
/// too: the shift cannot be larger than the alignment they share. It can
/// be smaller — a pool whose blocks all happen to be 8 KiB-aligned says
/// nothing against `ashift` 9 — which is why this returns candidates in
/// the order worth trying rather than one answer.
pub fn shifts(anchors: &[Anchor]) -> Vec<u32> {
    let common = anchors
        .iter()
        .map(|a| a.offset)
        .filter(|o| *o != 0)
        .fold(0u64, gcd);
    let limit = if common == 0 {
        17
    } else {
        common.trailing_zeros().min(17)
    };
    (9..=limit.max(9)).rev().collect()
}

fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 {
        a
    } else {
        gcd(b, a % b)
    }
}

/// One candidate base and the evidence for it.
#[derive(Debug, Clone)]
pub struct Base {
    /// Subtract this from a physical offset to get a vdev offset.
    pub base: u64,
    /// Probes whose checksum agreed at this base.
    pub confirmed: usize,
    /// Probes read and checked. The pair is the point: one agreement is
    /// a coincidence worth about nothing, and fifty is not.
    pub tried: usize,
}

/// Check `anchors` against one candidate base, stopping after `at_most`
/// reads. Returns how many agreed and how many were read.
///
/// A probe whose block would fall outside the device is not counted
/// either way: it says nothing about this base, because it was never
/// read.
pub fn confirm(
    dev: &dyn BlockSource,
    base: u64,
    anchors: &[Anchor],
    at_most: usize,
) -> (usize, usize) {
    let size = dev.size();
    let mut buf = Vec::new();
    let (mut ok, mut tried) = (0usize, 0usize);
    for a in anchors {
        if tried >= at_most {
            break;
        }
        let Some(at) = base
            .checked_add(LABEL_START_SIZE)
            .and_then(|p| p.checked_add(a.offset))
        else {
            continue;
        };
        if at.saturating_add(a.psize) > size {
            continue;
        }
        buf.clear();
        buf.resize(a.psize as usize, 0);
        if dev.read_at(at, &mut buf).is_err() {
            continue;
        }
        tried += 1;
        if verify_block(a.checksum, &buf, a.endian, &a.cksum, None, a.encrypted) == Verify::Ok {
            ok += 1;
        }
    }
    (ok, tried)
}

/// Bases from `start` to `end`, `step` apart, at which one of the first
/// `at_most` probes that fit agrees — what [`confirm`] would say of each
/// with `at_most` probes, without asking it base by base.
///
/// Asked base by base, every probe's block was read again at each step:
/// a 128 KiB block 256 times over for every 512 bytes of window, and a
/// search of the first 64 MiB read 3.4 GB. Here each probe is read once
/// for a run of bases, as one span from where its block lies at the
/// first base of the run to where it ends at the last, and every base is
/// checked from memory. A span that cannot be read is asked base by
/// base, as before, so that one bad sector costs only the bases it is
/// under.
fn screen(
    dev: &dyn BlockSource,
    start: u64,
    end: u64,
    step: u64,
    anchors: &[Anchor],
    at_most: usize,
) -> Vec<u64> {
    const RUN: u64 = 16 << 20;
    let size = dev.size();
    let mut out = Vec::new();
    let per_run = (RUN / step).max(1);
    let mut first = start;
    while first < end {
        let n = per_run.min((end - first).div_ceil(step)) as usize;
        let base = |k: usize| first + k as u64 * step;
        let mut tried = vec![0usize; n];
        let mut ok = vec![false; n];
        let mut buf = Vec::new();
        for a in anchors {
            if tried.iter().all(|t| *t >= at_most) {
                break;
            }
            // Where this probe's block lies at a base, if the device has
            // all of it there.
            let place = |b: u64| {
                b.checked_add(LABEL_START_SIZE)
                    .and_then(|p| p.checked_add(a.offset))
                    .filter(|at| at.saturating_add(a.psize) <= size)
            };
            let wanted: Vec<usize> = (0..n)
                .filter(|&k| tried[k] < at_most && place(base(k)).is_some())
                .collect();
            let (Some(&lo), Some(&hi)) = (wanted.first(), wanted.last()) else {
                continue;
            };
            let from = place(base(lo)).expect("placed");
            let to = place(base(hi)).expect("placed") + a.psize;
            let psize = a.psize as usize;
            buf.clear();
            buf.resize((to - from) as usize, 0);
            let whole = dev.read_at(from, &mut buf).is_ok();
            let mut one = Vec::new();
            for k in wanted {
                let at = place(base(k)).expect("placed");
                let block = if whole {
                    let o = (at - from) as usize;
                    &buf[o..o + psize]
                } else {
                    one.clear();
                    one.resize(psize, 0);
                    if dev.read_at(at, &mut one).is_err() {
                        continue;
                    }
                    &one[..]
                };
                tried[k] += 1;
                if !ok[k]
                    && verify_block(a.checksum, block, a.endian, &a.cksum, None, a.encrypted)
                        == Verify::Ok
                {
                    ok[k] = true;
                }
            }
        }
        out.extend((0..n).filter(|&k| ok[k]).map(base));
        first = first.saturating_add(per_run * step);
    }
    out
}

/// How the search is bounded.
#[derive(Debug, Clone)]
pub struct Options {
    /// Byte range of the device to consider as a base, as `(start, len)`.
    /// The base is where the vdev *begins*, so this is a head window.
    pub window: Option<(u64, u64)>,
    /// Shifts to step by; empty means the ones the probes imply.
    pub shifts: Vec<u32>,
    /// Probes read per candidate while screening. A wrong base fails the
    /// first one almost always, so this is small on purpose.
    pub screen: usize,
    /// Probes read per candidate that survived screening.
    pub confirm: usize,
    /// Keep at most this many bases.
    pub keep: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            window: None,
            shifts: Vec::new(),
            screen: 4,
            confirm: 64,
            keep: 8,
        }
    }
}

/// Find the bases the probes agree with, best first (SPEC F-63).
pub fn search(dev: &dyn BlockSource, anchors: &[Anchor], opts: &Options) -> io::Result<Vec<Base>> {
    if anchors.is_empty() {
        return Ok(Vec::new());
    }
    let size = dev.size();
    let (start, len) = opts.window.unwrap_or((0, (64 * 1024 * 1024).min(size)));
    let end = start.saturating_add(len).min(size);
    let shifts = if opts.shifts.is_empty() {
        shifts(anchors)
    } else {
        opts.shifts.clone()
    };
    let mut seen: std::collections::BTreeMap<u64, Base> = std::collections::BTreeMap::new();
    // Screening is where the time goes, so it is the smallest question
    // that can be asked: did even one probe agree? It is asked once, at
    // the finest step: what a base answers does not depend on the step
    // it was reached by, and every coarser step's bases are among the
    // finest one's. Asked again for each shift, the same spans were read
    // four times over.
    let finest = shifts.iter().copied().min().unwrap_or(9);
    trace!(
        "pointers",
        "base search: window {start:#x}..{end:#x} step {} ({} probe(s))",
        1u64 << finest,
        anchors.len()
    );
    let screened = screen(dev, start, end, 1u64 << finest, anchors, opts.screen);
    for shift in shifts {
        let step = 1u64 << shift;
        for at in screened.iter().copied().filter(|b| (b - start) % step == 0) {
            let (ok, tried) = confirm(dev, at, anchors, opts.confirm);
            trace!("pointers", "base {at:#x}: {ok} of {tried} probe(s) agreed");
            seen.entry(at).or_insert(Base {
                base: at,
                confirmed: ok,
                tried,
            });
        }
        // A coarser shift finds the same bases a finer one does, so once
        // anything has been found there is nothing left for the finer
        // steps to add but time.
        if !seen.is_empty() {
            break;
        }
    }
    let mut out: Vec<Base> = seen.into_values().collect();
    out.sort_by(|a, b| b.confirmed.cmp(&a.confirmed).then(a.base.cmp(&b.base)));
    out.truncate(opts.keep);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::carve::{scan_member, Options as ScanOptions};
    use crate::fixture::{zpl_members, Pool};
    use zvolrescue_io::MemSource;

    const LABEL: usize = 256 << 10;

    /// A member with every label gone, placed at a known offset inside a
    /// larger device — the F-63 case, and nothing else left to go on.
    fn bare(at: usize) -> (Vec<u8>, u64) {
        let mut pool = Pool::mirror("tank", 0x5eed_0000_0000_0007, 12)
            .txgs(&[(4816228, 1757100000), (4816229, 1757100005)]);
        let members = zpl_members(&mut pool, 48 * 1024 * 1024);
        let mut m = members.into_iter().next().expect("a member");
        let tail = (m.len() / LABEL) * LABEL;
        for base in [0, LABEL, tail - 2 * LABEL, tail - LABEL] {
            m[base..base + LABEL].fill(0);
        }
        let mut disk = vec![0u8; at];
        disk.extend_from_slice(&m);
        disk.extend_from_slice(&vec![0u8; 2 << 20]);
        (disk, at as u64)
    }

    /// Screening reads each probe once for a run of bases, and answers
    /// for every base what asking it alone does: the same bases, at the
    /// boundary of a run and at the end of the device too.
    #[test]
    fn screening_in_runs_is_screening_base_by_base() {
        let (disk, _) = bare(63 * 512);
        let src = MemSource::new(disk);
        let scan = scan_member(&src, 0, 9, &ScanOptions::default()).expect("scan");
        let probes = anchors(&scan);
        assert!(!probes.is_empty());
        let size = src.size();
        for (start, end, step) in [(0, 64 << 20, 512), (size - (3 << 20), size, 4096)] {
            let one_by_one: Vec<u64> = (start..end)
                .step_by(step as usize)
                .filter(|&b| confirm(&src, b, &probes, 4).0 > 0)
                .collect();
            assert_eq!(screen(&src, start, end, step, &probes, 4), one_by_one);
        }
    }

    /// SPEC F-63: the base comes out of the pointers alone.
    #[test]
    fn the_vdev_base_is_found_with_nothing_but_the_pointers() {
        let (disk, want) = bare(1 << 20);
        let src = MemSource::new(disk);
        let scan = scan_member(&src, 0, 12, &ScanOptions::default()).expect("scan");
        let probes = anchors(&scan);
        assert!(!probes.is_empty(), "the member has pointers to probe with");
        // Every allocation is a multiple of `1 << ashift`, so the
        // alignment the probes share cannot be finer than the pool's 12.
        assert!(shifts(&probes).contains(&12), "{:?}", shifts(&probes));

        let found = search(&src, &probes, &Options::default()).expect("search");
        let best = found.first().expect("a base");
        assert_eq!(best.base, want, "{found:?}");
        assert!(best.confirmed > 1, "{best:?}");
        // Ranked above anything else that agreed at all: a wrong base can
        // line a probe up with a *different* block of identical content —
        // a sparse member is mostly zeros — so the count is the evidence,
        // not the mere fact that something matched.
        for other in found.iter().skip(1) {
            assert!(other.confirmed < best.confirmed, "{found:?}");
        }
    }

    /// And a device with no pool on it at all yields no base, rather than
    /// the first offset whose bytes happened to hash to something.
    #[test]
    fn a_device_with_nothing_on_it_yields_no_base() {
        let src = MemSource::new(vec![0u8; 8 << 20]);
        let scan = scan_member(&src, 0, 12, &ScanOptions::default()).expect("scan");
        let probes = anchors(&scan);
        let found = search(&src, &probes, &Options::default()).expect("search");
        assert!(found.is_empty(), "{found:?}");
    }
}
