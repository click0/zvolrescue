//! Searching a member for uberblock anchors and deriving its zero point.
//!
//! The pure part — what an uberblock slot proves about where its vdev
//! starts — lives in [`zfs_ondisk::zeropoint`]. This module drives it over
//! a device: it looks for the uberblock magic, confirms every hit by its
//! embedded checksum, and groups the confirmations by the base they imply.
//!
//! Nothing here needs a label. It is the answer to "all four `vdev_phys`
//! areas are gone and I do not know where the partition began".

use std::collections::BTreeMap;
use std::io;

use zfs_ondisk::uberblock::{self, MAX_UBERBLOCK_SHIFT};
use zfs_ondisk::zeropoint::{
    confirm_against_base, confirm_slot, confirm_slot_thorough, plausible_shifts, Anchor,
};
use zfs_ondisk::Endian;
use zvolrescue_io::{trace, BlockSource};

/// Largest uberblock slot, and so the tail every read window must overlap.
const MAX_SLOT: u64 = 1 << MAX_UBERBLOCK_SHIFT;
/// Read granularity of the search.
const CHUNK: u64 = 4 * 1024 * 1024;

/// How much of a member to search, and how finely.
#[derive(Debug, Clone)]
pub struct Search {
    /// Byte ranges to look in, as `(start, length)`. Empty means the
    /// default: the head and tail windows, where labels live.
    pub windows: Vec<(u64, u64)>,
    /// Step between candidate positions. Uberblock slots are at least
    /// 1 KiB and aligned to their size relative to the vdev base, but the
    /// base itself is what is unknown, so the default is a 512-byte step.
    pub stride: u64,
    /// Physical sizes to assume for the vdev when testing the rear label
    /// pair. Empty means the default: the member's own size, i.e. a vdev
    /// that starts at offset 0 and runs to the end — true for a whole
    /// image file, not for a partition whose base is what we are looking
    /// for. Rear labels float with the vdev's *end*, so they pin a base
    /// only together with a size; the front pair needs no hypothesis.
    pub psize_hints: Vec<u64>,
    /// Stop once this many anchors have been confirmed. 0 means no limit.
    pub max_anchors: usize,
}

impl Default for Search {
    fn default() -> Self {
        Search {
            windows: Vec::new(),
            stride: 512,
            psize_hints: Vec::new(),
            max_anchors: 0,
        }
    }
}

impl Search {
    /// Sizes to assume for the vdev when testing rear labels.
    pub fn psize_hints_for(&self, size: u64) -> Vec<u64> {
        if self.psize_hints.is_empty() {
            vec![size]
        } else {
            self.psize_hints.clone()
        }
    }

    /// Default windows for a device of `size` bytes: the first and last
    /// 64 MiB, which cover a front label pair wherever a partition with
    /// conventional alignment began, and the rear pair of a vdev that ends
    /// at the end of the device.
    pub fn windows_for(&self, size: u64) -> Vec<(u64, u64)> {
        if !self.windows.is_empty() {
            return self.windows.clone();
        }
        let edge = (64 * 1024 * 1024).min(size);
        if size <= 2 * edge {
            return vec![(0, size)];
        }
        vec![(0, edge), (size - edge, edge)]
    }
}

/// One candidate zero point and the anchors that confirmed it.
#[derive(Debug, Clone)]
pub struct ZeroPoint {
    /// Vdev base: subtract it from a physical offset to get a vdev offset.
    pub base: u64,
    /// Every confirmed anchor for this base, in the order they were found.
    pub anchors: Vec<Anchor>,
}

impl ZeroPoint {
    /// Highest TXG among the confirmed uberblocks.
    pub fn newest_txg(&self) -> u64 {
        self.anchors.iter().map(|a| a.ub.txg).max().unwrap_or(0)
    }

    /// The uberblock to import from: highest TXG, then latest timestamp.
    pub fn best(&self) -> Option<&Anchor> {
        self.anchors
            .iter()
            .max_by_key(|a| (a.ub.txg, a.ub.timestamp))
    }

    /// Physical size implied by any rear-label anchor, if one was found.
    pub fn implied_psize(&self) -> Option<u64> {
        self.anchors.iter().find_map(|a| a.implied_psize())
    }
}

/// Search `dev` for uberblock anchors and group them by the base they fix.
///
/// Bases with more confirmations come first; ties go to the newer TXG. A
/// single anchor is already proof — a wrong base cannot produce a matching
/// SHA-256 — so a lone result is not a weak one, but a whole ring pointing
/// at the same base is what an intact front label looks like.
pub fn find(dev: &dyn BlockSource, opts: &Search) -> io::Result<Vec<ZeroPoint>> {
    let size = dev.size();
    let mut by_base: BTreeMap<u64, Vec<Anchor>> = BTreeMap::new();
    let psize_hints = opts.psize_hints_for(size);
    let mut buf = vec![0u8; (CHUNK + MAX_SLOT) as usize];
    let mut total = 0usize;

    for (start, length) in opts.windows_for(size) {
        let end = (start + length).min(size);
        let mut pos = start;
        while pos < end {
            let want = (CHUNK + MAX_SLOT).min(size - pos);
            let chunk = &mut buf[..want as usize];
            dev.read_at(pos, chunk)?;
            let last = if want > MAX_SLOT { want - MAX_SLOT } else { 1 };
            let mut off = 0u64;
            while off < last && pos + off < end {
                let at = &chunk[off as usize..];
                if has_magic(at) {
                    let physical = pos + off;
                    let anchors = confirm(at, physical, size, &by_base, &psize_hints);
                    for a in anchors {
                        trace!(
                            "zeropoint",
                            "uberblock at {physical} verifies for vdev offset {} -> base {} (L{:?} slot {}, txg {})",
                            a.vdev_offset,
                            a.base,
                            a.label,
                            a.slot,
                            a.ub.txg
                        );
                        by_base.entry(a.base).or_default().push(a);
                        total += 1;
                    }
                    if opts.max_anchors != 0 && total >= opts.max_anchors {
                        return Ok(ranked(by_base));
                    }
                }
                off += opts.stride;
            }
            pos += CHUNK;
        }
    }
    Ok(ranked(by_base))
}

/// Confirm one hit: cheaply against bases already found, then in full.
fn confirm(
    at: &[u8],
    physical: u64,
    size: u64,
    by_base: &BTreeMap<u64, Vec<Anchor>>,
    psize_hints: &[u64],
) -> Vec<Anchor> {
    for &base in by_base.keys() {
        // Any size hypothesis only decides which rear label a hit came
        // from; the base is confirmed either way. A vdev that runs to the
        // end of the member is the ordinary case, so try that too.
        let mut sizes: Vec<Option<u64>> = psize_hints.iter().copied().map(Some).collect();
        sizes.push(Some(size - base.min(size)));
        sizes.push(None);
        let mut best: Option<Anchor> = None;
        for psize in sizes {
            match confirm_against_base(at, physical, base, psize) {
                Some(a) if a.label.is_some() => return vec![a],
                Some(a) => best = Some(a),
                None => break,
            }
        }
        if let Some(a) = best {
            return vec![a];
        }
    }
    if plausible_shifts(at).is_empty() {
        // Uberblock magic with no `zio_eck_t` behind it: not a slot, and
        // not worth a single SHA-256.
        return Vec::new();
    }
    let mut hints: Vec<Option<u64>> = vec![None];
    hints.extend(psize_hints.iter().copied().map(Some));
    for psize in hints {
        let found = confirm_slot(at, physical, psize);
        if !found.is_empty() {
            return found;
        }
        // A ring written outside the `txg & (slots - 1)` convention still
        // verifies, it just has to be looked for slot by slot.
        let found = confirm_slot_thorough(at, physical, psize);
        if !found.is_empty() {
            return found;
        }
    }
    Vec::new()
}

fn has_magic(buf: &[u8]) -> bool {
    match Endian::Little.u64_at(buf, 0) {
        Some(raw) => raw == uberblock::MAGIC || raw.swap_bytes() == uberblock::MAGIC,
        None => false,
    }
}

fn ranked(by_base: BTreeMap<u64, Vec<Anchor>>) -> Vec<ZeroPoint> {
    let mut out: Vec<ZeroPoint> = by_base
        .into_iter()
        .map(|(base, anchors)| ZeroPoint { base, anchors })
        .collect();
    out.sort_by_key(|z| {
        (
            std::cmp::Reverse(z.anchors.len()),
            std::cmp::Reverse(z.newest_txg()),
        )
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::Pool;
    use zfs_ondisk::label::{label_offsets, VDEV_PHYS_OFFSET, VDEV_PHYS_SIZE};
    use zvolrescue_io::MemSource;

    fn member(size: u64) -> Vec<u8> {
        let pool =
            Pool::mirror("zp", 0x5150, 12).txgs(&[(100, 1_700_000_000), (101, 1_700_000_100)]);
        pool.member_image(0, size)
    }

    /// Erase every `vdev_phys` area, leaving only the uberblock rings —
    /// the case F-61 exists for.
    fn wipe_configs(img: &mut [u8], base: u64) {
        for off in label_offsets(img.len() as u64 - base).expect("large enough") {
            let at = (base + off + VDEV_PHYS_OFFSET) as usize;
            img[at..at + VDEV_PHYS_SIZE as usize].fill(0);
        }
    }

    #[test]
    fn a_whole_file_member_without_configs_still_yields_its_base() {
        let size = 16 * 1024 * 1024;
        let mut img = member(size);
        wipe_configs(&mut img, 0);
        let dev = MemSource::new(img);

        let found = find(&dev, &Search::default()).expect("search");
        assert_eq!(found.len(), 1, "one base, not a scatter of candidates");
        let z = &found[0];
        assert_eq!(z.base, 0);
        assert_eq!(z.newest_txg(), 101);
        // Two uberblocks in each of the four rings.
        assert_eq!(z.anchors.len(), 8);
        assert_eq!(z.best().map(|a| a.ub.txg), Some(101));
        assert_eq!(z.implied_psize(), Some(size));
    }

    #[test]
    fn a_partition_that_moved_is_found_by_its_front_labels() {
        // The member sits 3 MiB into the device: a partition table that
        // was rewritten with a different start, the classic case where
        // every DVA in the pool would otherwise be read 3 MiB off.
        let base = 3 * 1024 * 1024;
        let psize = 16 * 1024 * 1024;
        let inner = member(psize);
        let mut img = vec![0x5au8; base as usize];
        img.extend_from_slice(&inner);
        wipe_configs(&mut img, base);
        let dev = MemSource::new(img);

        let found = find(&dev, &Search::default()).expect("search");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].base, base);
        assert_eq!(found[0].anchors.len(), 8);
        // The front pair is what fixed the base; the rear pair then falls
        // into place because the vdev ends where the device does.
        assert!(found[0]
            .anchors
            .iter()
            .take(4)
            .all(|a| matches!(a.label, Some(0) | Some(1))));
        assert_eq!(found[0].implied_psize(), Some(psize));

        // On their own the rear labels do not pin a base: they are placed
        // against the vdev's size, so searching only their region finds
        // nothing until that size is supplied.
        let rear_only = Search {
            windows: vec![(base + psize - 512 * 1024, 512 * 1024)],
            ..Search::default()
        };
        assert!(find(&dev, &rear_only).expect("search").is_empty());
        let with_size = Search {
            psize_hints: vec![psize],
            ..rear_only
        };
        let found = find(&dev, &with_size).expect("search");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].base, base);
        assert!(found[0]
            .anchors
            .iter()
            .all(|a| matches!(a.label, Some(2) | Some(3))));
    }

    #[test]
    fn garbage_and_a_blank_device_anchor_nothing() {
        let blank = MemSource::new(vec![0u8; 8 * 1024 * 1024]);
        assert!(find(&blank, &Search::default()).expect("search").is_empty());

        // Uberblock magic everywhere, no valid checksum behind any of it.
        let mut noise = vec![0u8; 8 * 1024 * 1024];
        for off in (0..noise.len()).step_by(512) {
            noise[off..off + 8].copy_from_slice(&uberblock::MAGIC.to_le_bytes());
        }
        let dev = MemSource::new(noise);
        assert!(find(&dev, &Search::default()).expect("search").is_empty());
    }

    #[test]
    fn the_search_can_be_limited_to_a_window_and_a_count() {
        let mut img = member(16 * 1024 * 1024);
        wipe_configs(&mut img, 0);
        let dev = MemSource::new(img);

        // Only L1's ring: one label's worth of anchors, all from L1.
        let opts = Search {
            windows: vec![(256 * 1024, 256 * 1024)],
            ..Search::default()
        };
        let found = find(&dev, &opts).expect("search");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].base, 0);
        assert!(found[0].anchors.iter().all(|a| a.label == Some(1)));

        let opts = Search {
            max_anchors: 1,
            ..Search::default()
        };
        let found = find(&dev, &opts).expect("search");
        assert_eq!(found[0].anchors.len(), 1);
    }
}
