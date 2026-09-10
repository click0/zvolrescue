//! Recovering a vdev's zero point from label material (F-61).
//!
//! Every DVA is relative: *physical = vdev base + 4 MiB + offset*. When the
//! `vdev_phys` areas of all four labels are gone, the base is unknown, and
//! nothing in a block pointer says where the vdev starts. One surviving
//! uberblock slot settles it.
//!
//! An uberblock is a self-checksumming block: its `zio_eck_t` holds a
//! SHA-256 taken with the verifier `[vdev-relative offset, 0, 0, 0]`
//! (`zio_checksum_label_verifier`). A slot found by magic at physical
//! offset `P` therefore confirms base `B` if and only if the checksum
//! verifies with `P - B`, and no wrong base can produce a match. Which
//! offsets are worth trying follows from the on-disk layout: the ring sits
//! at +128 KiB of each label, the slot size is `1 << ub_shift`, and
//! `vdev_uberblock_sync` writes the uberblock of transaction group `txg`
//! into slot `txg & (slots - 1)`.
//!
//! The front labels (L0, L1) sit at fixed offsets, so a hit inside them
//! pins the base with no further assumptions. The rear pair (L2, L3) is
//! placed relative to the vdev's physical size, so a hit there confirms a
//! base only together with a size hypothesis — see [`slot_offsets`].

use crate::checksum::{verify_label, ChecksumStatus, ECK_SIZE, ZEC_MAGIC};
use crate::label::{LABEL_SIZE, UBERBLOCK_RING_OFFSET, UBERBLOCK_RING_SIZE};
use crate::uberblock::{Uberblock, MAX_UBERBLOCK_SHIFT, UBERBLOCK_SHIFT};
use crate::Endian;

/// A zero point confirmed by an uberblock checksum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    /// Byte offset of the slot in the file or device that was scanned.
    pub physical: u64,
    /// Confirmed vdev base: `physical - vdev_offset`.
    pub base: u64,
    /// Vdev-relative offset the checksum verified for.
    pub vdev_offset: u64,
    /// Which of the four labels the slot belongs to, when that is known.
    /// A hit confirmed against an already known base tells L2 from L3 only
    /// with a size hypothesis, and is then `None`.
    pub label: Option<usize>,
    /// Slot index inside that label's uberblock ring.
    pub slot: usize,
    /// `ub_shift`: the ring's slot size is `1 << shift`.
    pub shift: u32,
    /// The uberblock itself — it also carries the root pointer (F-64).
    pub ub: Uberblock,
}

impl Anchor {
    /// Physical size the vdev must have had for a rear-label anchor to sit
    /// where it does, or `None` for the front labels, which say nothing
    /// about the size.
    pub fn implied_psize(&self) -> Option<u64> {
        let label = self.label?;
        if label < 2 {
            return None;
        }
        let ring = self.vdev_offset - UBERBLOCK_RING_OFFSET - (self.slot as u64) * self.slot_size();
        Some(ring + (4 - label as u64) * LABEL_SIZE)
    }

    /// Size of one ring slot in bytes.
    pub fn slot_size(&self) -> u64 {
        1u64 << self.shift
    }
}

/// Number of uberblock slots in a ring whose slot size is `1 << shift`.
pub fn slots_per_ring(shift: u32) -> usize {
    (UBERBLOCK_RING_SIZE >> shift.clamp(UBERBLOCK_SHIFT, MAX_UBERBLOCK_SHIFT)) as usize
}

/// Vdev-relative offset of one ring slot.
///
/// `psize` is the vdev's physical size, needed only for the rear labels
/// (L2, L3), which OpenZFS places at `align_down(psize, 256 KiB)` minus two
/// and one label respectively. Returns `None` when the label is out of
/// range, the slot does not exist for this shift, or a rear label was asked
/// for without a size (or with one too small to hold four labels).
pub fn slot_offset(label: usize, slot: usize, shift: u32, psize: Option<u64>) -> Option<u64> {
    let shift = shift.clamp(UBERBLOCK_SHIFT, MAX_UBERBLOCK_SHIFT);
    if label >= 4 || slot >= slots_per_ring(shift) {
        return None;
    }
    let label_start = if label < 2 {
        label as u64 * LABEL_SIZE
    } else {
        let aligned = psize? & !(LABEL_SIZE - 1);
        if aligned < 4 * LABEL_SIZE {
            return None;
        }
        aligned - (4 - label as u64) * LABEL_SIZE
    };
    Some(label_start + UBERBLOCK_RING_OFFSET + (slot as u64) * (1u64 << shift))
}

/// Vdev-relative offsets where the uberblock of `txg` can sit, as
/// `(label, slot, offset)` triples.
///
/// `vdev_uberblock_sync` writes into slot `txg & (slots - 1)`, so a parsed
/// uberblock names its own slot; only the label is left open. Pass `psize`
/// to include the rear pair.
pub fn slot_offsets(txg: u64, shift: u32, psize: Option<u64>) -> Vec<(usize, usize, u64)> {
    let slots = slots_per_ring(shift);
    let slot = (txg & (slots as u64 - 1)) as usize;
    (0..4)
        .filter_map(|label| slot_offset(label, slot, shift, psize).map(|off| (label, slot, off)))
        .collect()
}

/// Slot shifts whose end-of-slot `zio_eck_t` magic is present in `buf`.
///
/// The eck sits in the last 40 bytes of the slot, so the magic's position
/// identifies the slot size without trying every SHA-256.
pub fn plausible_shifts(buf: &[u8]) -> Vec<u32> {
    (UBERBLOCK_SHIFT..=MAX_UBERBLOCK_SHIFT)
        .filter(|shift| {
            let size = 1usize << shift;
            if buf.len() < size {
                return false;
            }
            let at = size - ECK_SIZE;
            match Endian::Little.u64_at(buf, at) {
                Some(raw) => raw == ZEC_MAGIC || raw.swap_bytes() == ZEC_MAGIC,
                None => false,
            }
        })
        .collect()
}

/// Confirm a candidate uberblock slot read at `physical`.
///
/// `buf` must start at `physical` and hold at least one slot; 8 KiB covers
/// every slot size. `psize` is an optional hypothesis for the vdev's
/// physical size, which brings the rear labels into play — without it only
/// L0 and L1 are considered, and those need no hypothesis at all.
///
/// Returns every anchor whose checksum verified. More than one is possible
/// only for a device that carries several copies of the same slot content
/// at different offsets, which a real pool does not.
pub fn confirm_slot(buf: &[u8], physical: u64, psize: Option<u64>) -> Vec<Anchor> {
    confirm_slot_at(buf, physical, psize, false)
}

/// Like [`confirm_slot`], but tries every slot index instead of the one the
/// uberblock's TXG implies. Use when a ring was written by something that
/// does not follow `txg & (slots - 1)`; it costs one SHA-256 per slot.
pub fn confirm_slot_thorough(buf: &[u8], physical: u64, psize: Option<u64>) -> Vec<Anchor> {
    confirm_slot_at(buf, physical, psize, true)
}

fn confirm_slot_at(buf: &[u8], physical: u64, psize: Option<u64>, thorough: bool) -> Vec<Anchor> {
    let Ok(ub) = Uberblock::parse(buf) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for shift in plausible_shifts(buf) {
        let slot_bytes = &buf[..1usize << shift];
        let candidates: Vec<(usize, usize, u64)> = if thorough {
            (0..4)
                .flat_map(|label| {
                    (0..slots_per_ring(shift)).filter_map(move |slot| {
                        slot_offset(label, slot, shift, psize).map(|off| (label, slot, off))
                    })
                })
                .collect()
        } else {
            slot_offsets(ub.txg, shift, psize)
        };
        for (label, slot, vdev_offset) in candidates {
            if vdev_offset > physical {
                continue;
            }
            if verify_label(slot_bytes, vdev_offset) != ChecksumStatus::Ok {
                continue;
            }
            found.push(Anchor {
                physical,
                base: physical - vdev_offset,
                vdev_offset,
                label: Some(label),
                slot,
                shift,
                ub: ub.clone(),
            });
        }
    }
    found
}

/// Confirm a slot against bases that are already known, one checksum each.
///
/// Once the first anchor has fixed the base, every further hit is a single
/// verification: the vdev-relative offset is `physical - base`.
pub fn confirm_against_base(buf: &[u8], physical: u64, base: u64) -> Option<Anchor> {
    let ub = Uberblock::parse(buf).ok()?;
    let vdev_offset = physical.checked_sub(base)?;
    for shift in plausible_shifts(buf) {
        let slot_bytes = &buf[..1usize << shift];
        if verify_label(slot_bytes, vdev_offset) != ChecksumStatus::Ok {
            continue;
        }
        let ring_relative = vdev_offset % LABEL_SIZE;
        if ring_relative < UBERBLOCK_RING_OFFSET {
            continue;
        }
        let label = (vdev_offset / LABEL_SIZE) as usize;
        let slot = ((ring_relative - UBERBLOCK_RING_OFFSET) >> shift) as usize;
        return Some(Anchor {
            physical,
            base,
            vdev_offset,
            label: (label < 2).then_some(label),
            slot,
            shift,
            ub,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum::seal_label;

    /// One sealed uberblock slot as `vdev_uberblock_sync` would write it.
    fn slot_bytes(txg: u64, shift: u32, vdev_offset: u64) -> Vec<u8> {
        let mut v = vec![0u8; 1usize << shift];
        let put = |v: &mut Vec<u8>, off: usize, x: u64| {
            v[off..off + 8].copy_from_slice(&x.to_le_bytes());
        };
        put(&mut v, 0, crate::uberblock::MAGIC);
        put(&mut v, 8, 5000);
        put(&mut v, 16, txg);
        put(&mut v, 32, 1_700_000_000);
        put(&mut v, 40 + 80, txg); // rootbp birth
        seal_label(&mut v, vdev_offset);
        v
    }

    #[test]
    fn ring_geometry_matches_the_on_disk_layout() {
        assert_eq!(slots_per_ring(UBERBLOCK_SHIFT), 128);
        assert_eq!(slots_per_ring(13), 16);
        // L0 ring starts at +128 KiB, L1 one label later.
        assert_eq!(slot_offset(0, 0, 10, None), Some(128 * 1024));
        assert_eq!(
            slot_offset(1, 3, 10, None),
            Some(256 * 1024 + 128 * 1024 + 3072)
        );
        // Rear labels need a size, and follow align_down(psize, 256 KiB).
        assert_eq!(slot_offset(2, 0, 10, None), None);
        let psize = 8 * LABEL_SIZE + 999;
        assert_eq!(
            slot_offset(2, 0, 10, Some(psize)),
            Some(6 * LABEL_SIZE + UBERBLOCK_RING_OFFSET)
        );
        assert_eq!(
            slot_offset(3, 0, 10, Some(psize)),
            Some(7 * LABEL_SIZE + UBERBLOCK_RING_OFFSET)
        );
        // Out of range: no such label, no such slot, device too small.
        assert_eq!(slot_offset(4, 0, 10, None), None);
        assert_eq!(slot_offset(0, 128, 10, None), None);
        assert_eq!(slot_offset(2, 0, 10, Some(3 * LABEL_SIZE)), None);
    }

    #[test]
    fn a_front_label_slot_pins_the_base_with_no_hypothesis() {
        // A vdev starting 2 MiB into the device (a 1 MiB-aligned partition
        // that was moved), its labels gone except this one slot.
        let base = 2 * 1024 * 1024;
        let txg = 4242;
        let shift = 12;
        let offset = slot_offset(
            1,
            (txg % slots_per_ring(shift) as u64) as usize,
            shift,
            None,
        )
        .expect("front label offset");
        let buf = slot_bytes(txg, shift, offset);

        let anchors = confirm_slot(&buf, base + offset, None);
        assert_eq!(anchors.len(), 1);
        let a = &anchors[0];
        assert_eq!(a.base, base);
        assert_eq!(a.label, Some(1));
        assert_eq!(a.shift, shift);
        assert_eq!(a.vdev_offset, offset);
        assert_eq!(a.ub.txg, txg);
        assert_eq!(a.implied_psize(), None);
    }

    #[test]
    fn a_rear_label_slot_confirms_a_size_hypothesis() {
        let base = 1024 * 1024;
        let psize = 64 * LABEL_SIZE + 4096; // not label-aligned on purpose
        let txg = 9;
        let shift = 10;
        let slot = (txg % slots_per_ring(shift) as u64) as usize;
        let offset = slot_offset(2, slot, shift, Some(psize)).expect("rear label offset");
        let buf = slot_bytes(txg, shift, offset);

        // Without a size hypothesis the rear pair is not even considered.
        assert!(confirm_slot(&buf, base + offset, None).is_empty());
        // A wrong size puts the ring somewhere else: no match.
        assert!(confirm_slot(&buf, base + offset, Some(psize + LABEL_SIZE)).is_empty());

        let anchors = confirm_slot(&buf, base + offset, Some(psize));
        assert_eq!(anchors.len(), 1);
        assert_eq!(anchors[0].base, base);
        assert_eq!(anchors[0].label, Some(2));
        assert_eq!(anchors[0].implied_psize(), Some(psize & !(LABEL_SIZE - 1)));
    }

    #[test]
    fn a_wrong_base_never_verifies() {
        let base = 4 * 1024 * 1024;
        let txg = 77;
        let shift = 11;
        let slot = (txg % slots_per_ring(shift) as u64) as usize;
        let offset = slot_offset(0, slot, shift, None).unwrap();
        let buf = slot_bytes(txg, shift, offset);

        // What the checksum pins is the slot's *vdev-relative* offset; the
        // base is then wherever the slot was found minus that offset. Read
        // the same bytes 512 further along and the answer moves with them,
        // and it names only the label the slot really came from.
        let moved = confirm_slot(&buf, base + offset + 512, None);
        assert_eq!(moved.len(), 1);
        assert_eq!((moved[0].base, moved[0].label), (base + 512, Some(0)));

        // Given a base, the check is a verdict on that base: only the right
        // one produces the offset the checksum was taken with.
        assert!(confirm_against_base(&buf, base + offset, base + 512).is_none());
        assert!(confirm_against_base(&buf, base + offset, base - 4096).is_none());
        assert_eq!(
            confirm_against_base(&buf, base + offset, base).map(|a| a.vdev_offset),
            Some(offset)
        );
    }

    #[test]
    fn a_slot_written_off_its_txg_index_needs_the_thorough_pass() {
        let base = 0;
        let shift = 10;
        let txg = 5;
        // Slot 40 does not match txg 5 & 127: the quick pass misses it.
        let offset = slot_offset(0, 40, shift, None).unwrap();
        let buf = slot_bytes(txg, shift, offset);
        assert!(confirm_slot(&buf, base + offset, None).is_empty());
        let anchors = confirm_slot_thorough(&buf, base + offset, None);
        assert_eq!(anchors.len(), 1);
        assert_eq!((anchors[0].base, anchors[0].slot), (0, 40));
    }

    #[test]
    fn garbage_and_short_buffers_are_not_anchors() {
        assert!(confirm_slot(&[0u8; 8192], 0, None).is_empty());
        assert!(confirm_slot(&[0xa5u8; 8192], 1 << 20, None).is_empty());
        // An uberblock magic with no valid eck: no shift is plausible.
        let mut v = vec![0u8; 8192];
        v[..8].copy_from_slice(&crate::uberblock::MAGIC.to_le_bytes());
        assert!(plausible_shifts(&v).is_empty());
        assert!(confirm_slot(&v, 0, None).is_empty());
    }
}
