//! Reading labels and uberblock rings from a single vdev member.

use std::io;

use zfs_ondisk::label::{
    label_offsets, LABELS_PER_VDEV, LABEL_SIZE, UBERBLOCK_RING_OFFSET, UBERBLOCK_RING_SIZE,
};
use zfs_ondisk::uberblock::{self, Uberblock, UBERBLOCK_SHIFT};
use zfs_ondisk::ParseError;
use zvolrescue_io::BlockSource;

/// What one of the four labels on a device contained.
#[derive(Debug, Clone)]
pub struct LabelScan {
    /// Label index 0..=3.
    pub index: usize,
    /// Byte offset of the label on the device.
    pub offset: u64,
    /// Uberblocks with a valid magic, as `(slot index, uberblock)` in slot order.
    pub uberblocks: Vec<(usize, Uberblock)>,
    /// Slots that did not parse, as `(slot index, reason)`; zeroed slots are
    /// `ParseError::BadMagic(0)`.
    pub invalid: Vec<(usize, ParseError)>,
    /// Number of ring slots examined.
    pub slots: usize,
}

impl LabelScan {
    /// The uberblock OpenZFS would import from, if any.
    pub fn best(&self) -> Option<&Uberblock> {
        uberblock::best(self.uberblocks.iter().map(|(_, u)| u))
    }

    /// Number of slots that are simply empty (never written).
    pub fn empty_slots(&self) -> usize {
        self.invalid
            .iter()
            .filter(|(_, e)| *e == ParseError::BadMagic(0))
            .count()
    }
}

/// Read all four labels of `dev` and decode their uberblock rings.
///
/// The ring is walked with the minimum slot size (1 KiB); a pool with a
/// larger `ashift` simply leaves the intermediate slots empty, so every
/// real uberblock is still found. Slot indices are therefore relative to
/// 1 KiB slots until the nvlist parser provides the real `ashift`.
pub fn scan_labels(dev: &dyn BlockSource) -> io::Result<Vec<LabelScan>> {
    let offsets = label_offsets(dev.size()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "device is {} bytes, smaller than {} labels of {} bytes",
                dev.size(),
                LABELS_PER_VDEV,
                LABEL_SIZE
            ),
        )
    })?;
    let mut ring = vec![0u8; UBERBLOCK_RING_SIZE as usize];
    let mut out = Vec::with_capacity(LABELS_PER_VDEV);
    for (index, &offset) in offsets.iter().enumerate() {
        dev.read_at(offset + UBERBLOCK_RING_OFFSET, &mut ring)?;
        let mut uberblocks = Vec::new();
        let mut invalid = Vec::new();
        let mut slots = 0;
        for (slot, parsed) in uberblock::ring_slots(&ring, UBERBLOCK_SHIFT) {
            slots += 1;
            match parsed {
                Ok(ub) => uberblocks.push((slot, ub)),
                Err(e) => invalid.push((slot, e)),
            }
        }
        out.push(LabelScan {
            index,
            offset,
            uberblocks,
            invalid,
            slots,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zfs_ondisk::Endian;
    use zvolrescue_io::MemSource;

    fn put_uberblock(img: &mut [u8], at: usize, txg: u64, ts: u64) {
        let w = |img: &mut [u8], off: usize, x: u64| {
            img[off..off + 8].copy_from_slice(&x.to_le_bytes());
        };
        w(img, at, uberblock::MAGIC);
        w(img, at + 8, 5000);
        w(img, at + 16, txg);
        w(img, at + 32, ts);
    }

    #[test]
    fn finds_uberblocks_in_all_labels() {
        let size = 8 * LABEL_SIZE as usize;
        let mut img = vec![0u8; size];
        let ring = UBERBLOCK_RING_OFFSET as usize;
        for off in label_offsets(size as u64).unwrap() {
            let base = off as usize + ring;
            put_uberblock(&mut img, base, 100, 1);
            put_uberblock(&mut img, base + 4096, 101, 2); // ashift=12 spacing
        }
        let scans = scan_labels(&MemSource::new(img)).unwrap();
        assert_eq!(scans.len(), 4);
        for s in &scans {
            assert_eq!(s.slots, 128);
            assert_eq!(s.uberblocks.len(), 2);
            assert_eq!(s.uberblocks[1].0, 4); // 4096 / 1024
            assert_eq!(s.empty_slots(), 126);
            let b = s.best().unwrap();
            assert_eq!(b.txg, 101);
            assert_eq!(b.endian, Endian::Little);
        }
    }

    #[test]
    fn rejects_tiny_device() {
        let err = scan_labels(&MemSource::new(vec![0u8; 1024])).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
