//! Vdev label geometry.
//!
//! Every vdev carries four 256 KiB labels: two at the front of the device
//! and two at the back. Each label holds a blank area, a boot header, the
//! XDR-encoded nvlist configuration (`vdev_phys`), and a 128 KiB ring of
//! uberblocks.

/// Size of one label in bytes.
pub const LABEL_SIZE: u64 = 256 * 1024;
/// Number of labels per vdev.
pub const LABELS_PER_VDEV: usize = 4;
/// Offset of the nvlist area (`vdev_phys`) inside a label.
pub const VDEV_PHYS_OFFSET: u64 = 16 * 1024;
/// Size of the nvlist area, including its trailing embedded checksum.
pub const VDEV_PHYS_SIZE: u64 = 112 * 1024;
/// Offset of the uberblock ring inside a label.
pub const UBERBLOCK_RING_OFFSET: u64 = 128 * 1024;
/// Size of the uberblock ring.
pub const UBERBLOCK_RING_SIZE: u64 = 128 * 1024;

/// Byte offsets of the four labels on a device of `psize` bytes.
///
/// Mirrors `vdev_label_offset()` in OpenZFS: `psize` is first aligned down
/// to a label boundary, then L0/L1 sit at the start and L2/L3 at the end.
/// Returns `None` when the device is too small to hold four labels.
pub fn label_offsets(psize: u64) -> Option<[u64; LABELS_PER_VDEV]> {
    let aligned = psize & !(LABEL_SIZE - 1);
    if aligned < LABEL_SIZE * LABELS_PER_VDEV as u64 {
        return None;
    }
    Some([
        0,
        LABEL_SIZE,
        aligned - 2 * LABEL_SIZE,
        aligned - LABEL_SIZE,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets_for_aligned_device() {
        let o = label_offsets(1 << 30).unwrap();
        assert_eq!(o, [0, 262_144, (1 << 30) - 524_288, (1 << 30) - 262_144]);
    }

    #[test]
    fn offsets_align_down_unaligned_size() {
        let size = (1 << 30) + 12_345;
        let o = label_offsets(size).unwrap();
        assert_eq!(o[3], (1 << 30) - 262_144);
    }

    #[test]
    fn too_small_device() {
        assert_eq!(label_offsets(3 * LABEL_SIZE), None);
        assert!(label_offsets(4 * LABEL_SIZE).is_some());
    }
}
