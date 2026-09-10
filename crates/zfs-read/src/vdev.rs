//! Reading labels and uberblock rings from a single vdev member.

use std::io;

use zfs_ondisk::checksum::{verify_label, ChecksumStatus};
use zfs_ondisk::label::{
    label_offsets, parse_vdev_phys, LabelConfig, LABELS_PER_VDEV, LABEL_SIZE,
    UBERBLOCK_RING_OFFSET, UBERBLOCK_RING_SIZE, VDEV_PHYS_OFFSET, VDEV_PHYS_SIZE,
};
use zfs_ondisk::nvlist::NvList;
use zfs_ondisk::uberblock::{self, Uberblock, MAX_UBERBLOCK_SHIFT, UBERBLOCK_SHIFT};
use zfs_ondisk::ParseError;
use zvolrescue_io::trace::hexdump;
use zvolrescue_io::{trace, BlockSource};

/// One slot of an uberblock ring that carried a valid magic.
#[derive(Debug, Clone)]
pub struct UberblockSlot {
    /// Slot index within the ring (slot size is `1 << slot_shift`).
    pub slot: usize,
    /// The decoded uberblock.
    pub ub: Uberblock,
    /// Embedded SHA-256 verification of the whole slot.
    pub checksum: ChecksumStatus,
}

/// What one of the four labels on a device contained.
#[derive(Debug, Clone)]
pub struct LabelScan {
    /// Label index 0..=3.
    pub index: usize,
    /// Byte offset of the label on the device.
    pub offset: u64,
    /// Checksum state of the configuration nvlist area.
    pub phys_checksum: ChecksumStatus,
    /// Raw configuration nvlist, if it parsed.
    pub config: Option<NvList>,
    /// Why the configuration did not parse, if it did not.
    pub config_error: Option<ParseError>,
    /// Slot size used to walk the ring, from the label's `ashift`.
    pub slot_shift: u32,
    /// Uberblocks with a valid magic, in slot order.
    pub uberblocks: Vec<UberblockSlot>,
    /// Slots that did not parse, as `(slot index, reason)`; zeroed slots are
    /// `ParseError::BadMagic(0)`.
    pub invalid: Vec<(usize, ParseError)>,
    /// Number of ring slots examined.
    pub slots: usize,
}

impl LabelScan {
    /// Typed view of the configuration.
    pub fn typed(&self) -> Option<LabelConfig> {
        self.config.as_ref().map(LabelConfig::from_nvlist)
    }

    /// The uberblock OpenZFS would import from: among checksum-verified
    /// slots, highest TXG then latest timestamp. Falls back to unverified
    /// slots when none verified, flagged by the returned status.
    pub fn best(&self) -> Option<&UberblockSlot> {
        let verified = self
            .uberblocks
            .iter()
            .filter(|s| s.checksum == ChecksumStatus::Ok);
        uberblock::best(verified.clone().map(|s| &s.ub))
            .and_then(|b| self.uberblocks.iter().find(|s| std::ptr::eq(&s.ub, b)))
            .or_else(|| {
                let any = self.uberblocks.iter().map(|s| &s.ub);
                uberblock::best(any)
                    .and_then(|b| self.uberblocks.iter().find(|s| std::ptr::eq(&s.ub, b)))
            })
    }

    /// Number of slots that are simply empty (never written).
    pub fn empty_slots(&self) -> usize {
        self.invalid
            .iter()
            .filter(|(_, e)| *e == ParseError::BadMagic(0))
            .count()
    }
}

/// Everything read from one member device.
#[derive(Debug, Clone)]
pub struct DeviceScan {
    /// Device size in bytes.
    pub size: u64,
    /// Byte offset at which the vdev begins. Zero unless the labels were
    /// found somewhere other than the start of what was opened — see
    /// [`scan_device_at`].
    pub base: u64,
    /// How that base was arrived at: `"partition table"` when a table
    /// pointed at it, `"uberblock checksum"` when the anchor search did,
    /// `None` when the labels were simply where they should be.
    pub base_source: Option<&'static str>,
    /// The four labels.
    pub labels: Vec<LabelScan>,
    /// Index into `labels` of the label to trust: checksum-verified with
    /// the highest `txg`, else the highest `txg` of any parsed config.
    pub best_label: Option<usize>,
}

impl DeviceScan {
    /// Typed configuration from the best label.
    pub fn config(&self) -> Option<LabelConfig> {
        self.best_label.and_then(|i| self.labels[i].typed())
    }

    /// Whether any label holds a configuration whose embedded checksum
    /// verified at the offset it was read from. A configuration that
    /// parses but does not verify is the signature of a member read at
    /// the wrong base: the nvlist is intact, the offset it was sealed
    /// with is not the one it was found at.
    pub fn config_verified(&self) -> bool {
        self.labels
            .iter()
            .any(|l| l.config.is_some() && l.phys_checksum == ChecksumStatus::Ok)
    }

    /// Highest TXG of any checksum-verified uberblock across all labels.
    pub fn newest_txg(&self) -> Option<u64> {
        self.verified_txgs().max()
    }

    /// Lowest TXG of any checksum-verified uberblock across all labels.
    pub fn oldest_txg(&self) -> Option<u64> {
        self.verified_txgs().min()
    }

    fn verified_txgs(&self) -> impl Iterator<Item = u64> + '_ {
        self.labels
            .iter()
            .flat_map(|l| l.uberblocks.iter())
            .filter(|s| s.checksum == ChecksumStatus::Ok && s.ub.txg != 0)
            .map(|s| s.ub.txg)
    }
}

/// Slot shift for an uberblock ring given the vdev's `ashift`.
pub fn slot_shift_for(ashift: Option<u64>) -> u32 {
    let a = ashift
        .and_then(|a| u32::try_from(a).ok())
        .unwrap_or(UBERBLOCK_SHIFT);
    a.clamp(UBERBLOCK_SHIFT, MAX_UBERBLOCK_SHIFT)
}

/// Read all four labels of `dev`: configuration nvlists with their
/// checksums, and uberblock rings walked at the real slot size.
pub fn scan_device(dev: &dyn BlockSource) -> io::Result<DeviceScan> {
    scan_device_at(dev, 0)
}

/// Read the four labels of a vdev that begins at byte `base` of `dev`.
///
/// Everything about a label — where the rear pair sits, and the offset
/// each embedded checksum was taken with — is relative to the vdev, not
/// to the file. A member whose partition was re-created with a different
/// start therefore scans as blank at base 0 and reads normally once the
/// base recovered from its uberblocks (SPEC F-61) is passed here.
pub fn scan_device_at(dev: &dyn BlockSource, base: u64) -> io::Result<DeviceScan> {
    scan_device_range(dev, base, dev.size().saturating_sub(base))
}

/// Read the four labels of a vdev that occupies `psize` bytes from `base`.
///
/// The rear label pair is placed against the vdev's own size, so a member
/// inside a whole-disk image has to be scanned with the length its
/// partition declares, not with everything to the end of the disk.
pub fn scan_device_range(dev: &dyn BlockSource, base: u64, psize: u64) -> io::Result<DeviceScan> {
    let psize = psize.min(dev.size().saturating_sub(base));
    let offsets = label_offsets(psize).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "device is {} bytes, smaller than {} labels of {} bytes",
                psize, LABELS_PER_VDEV, LABEL_SIZE
            ),
        )
    })?;
    // `ashift` belongs to the vdev, not to one copy of its label: a label
    // whose configuration is gone still has a ring, and it was written
    // with the same slot size as the others. Take it from whichever label
    // still says so before walking any ring.
    let mut vdev_ashift = None;
    let mut probe = vec![0u8; VDEV_PHYS_SIZE as usize];
    for &offset in offsets.iter() {
        dev.read_at(base + offset + VDEV_PHYS_OFFSET, &mut probe)?;
        if let Ok(c) = parse_vdev_phys(&probe, offset).config {
            if let Some(a) = c.list("vdev_tree").and_then(|t| t.u64("ashift")) {
                vdev_ashift = Some(a);
                break;
            }
        }
    }
    let mut label = vec![0u8; LABEL_SIZE as usize];
    let mut labels = Vec::with_capacity(LABELS_PER_VDEV);
    for (index, &offset) in offsets.iter().enumerate() {
        dev.read_at(base + offset, &mut label)?;
        let phys_start = VDEV_PHYS_OFFSET as usize;
        let phys = parse_vdev_phys(
            &label[phys_start..phys_start + VDEV_PHYS_SIZE as usize],
            offset,
        );
        let (config, config_error) = match phys.config {
            Ok(c) => {
                trace!(
                    "label",
                    "L{index} @ {offset}: config checksum {}, nvlist ok: pool {:?} guid {:#x} txg {:?} vdev guid {:#x}",
                    phys.checksum.as_str(),
                    c.str("name").unwrap_or("?"),
                    c.u64("pool_guid").unwrap_or(0),
                    c.u64("txg"),
                    c.u64("guid").unwrap_or(0)
                );
                (Some(c), None)
            }
            Err(e) => {
                trace!(
                    "label",
                    "L{index} @ {offset}: config checksum {}, nvlist error: {e}; first bytes of vdev_phys:\n{}",
                    phys.checksum.as_str(),
                    hexdump(&label[phys_start..phys_start + 64], offset + VDEV_PHYS_OFFSET, 64)
                );
                (None, Some(e))
            }
        };
        let ashift = config
            .as_ref()
            .and_then(|c| c.list("vdev_tree"))
            .and_then(|t| t.u64("ashift"))
            .or(vdev_ashift);
        let slot_shift = slot_shift_for(ashift);
        trace!(
            "label",
            "L{index}: ashift {ashift:?} -> uberblock slot shift {slot_shift}"
        );
        let ring_start = UBERBLOCK_RING_OFFSET as usize;
        let ring = &label[ring_start..ring_start + UBERBLOCK_RING_SIZE as usize];
        let mut uberblocks = Vec::new();
        let mut invalid = Vec::new();
        let mut slots = 0;
        for (slot, parsed) in uberblock::ring_slots(ring, slot_shift) {
            slots += 1;
            match parsed {
                Ok(ub) => {
                    let size = 1usize << slot_shift;
                    let slot_buf = &ring[slot * size..(slot + 1) * size];
                    let vdev_offset = offset + UBERBLOCK_RING_OFFSET + (slot * size) as u64;
                    let checksum = verify_label(slot_buf, vdev_offset);
                    trace!(
                        "uberblock",
                        "L{index} slot {slot} @ {vdev_offset}: txg {} ts {} version {} checksum {} rootbp birth {}",
                        ub.txg,
                        ub.timestamp,
                        ub.version,
                        checksum.as_str(),
                        ub.rootbp_birth()
                    );
                    uberblocks.push(UberblockSlot { slot, ub, checksum });
                }
                Err(e) => {
                    if e != ParseError::BadMagic(0) {
                        trace!("uberblock", "L{index} slot {slot}: {e}");
                    }
                    invalid.push((slot, e));
                }
            }
        }
        labels.push(LabelScan {
            index,
            offset,
            phys_checksum: phys.checksum,
            config,
            config_error,
            slot_shift,
            uberblocks,
            invalid,
            slots,
        });
    }
    let best_label = pick_best_label(&labels);
    trace!("label", "best label: {best_label:?}");
    Ok(DeviceScan {
        size: dev.size(),
        base,
        base_source: None,
        labels,
        best_label,
    })
}

fn pick_best_label(labels: &[LabelScan]) -> Option<usize> {
    let key = |l: &LabelScan| l.config.as_ref().and_then(|c| c.u64("txg")).unwrap_or(0);
    let verified = labels
        .iter()
        .enumerate()
        .filter(|(_, l)| l.config.is_some() && l.phys_checksum == ChecksumStatus::Ok)
        .max_by_key(|(_, l)| key(l));
    verified
        .or_else(|| {
            labels
                .iter()
                .enumerate()
                .filter(|(_, l)| l.config.is_some())
                .max_by_key(|(_, l)| key(l))
        })
        .map(|(i, _)| i)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{Member, Pool};
    use zvolrescue_io::MemSource;

    #[test]
    fn scans_a_sealed_member() {
        let pool = Pool::mirror("tank", 0x1000, 12).txgs(&[(100, 1), (101, 2)]);
        let img = pool.member_image(0, 8 * LABEL_SIZE);
        let scan = scan_device(&MemSource::new(img)).unwrap();
        assert_eq!(scan.labels.len(), 4);
        for l in &scan.labels {
            assert_eq!(l.phys_checksum, ChecksumStatus::Ok);
            assert_eq!(l.slot_shift, 12);
            assert_eq!(l.slots, 32);
            assert_eq!(l.uberblocks.len(), 2);
            assert!(l
                .uberblocks
                .iter()
                .all(|s| s.checksum == ChecksumStatus::Ok));
            assert_eq!(l.best().unwrap().ub.txg, 101);
        }
        let cfg = scan.config().unwrap();
        assert_eq!(cfg.name.as_deref(), Some("tank"));
        assert_eq!(cfg.guid, Some(Member::guid_for(0x1000, 0)));
        assert_eq!(scan.newest_txg(), Some(101));
        assert_eq!(scan.oldest_txg(), Some(100));
    }

    #[test]
    fn corrupt_uberblock_is_flagged_and_not_chosen() {
        let pool = Pool::mirror("tank", 0x1000, 12).txgs(&[(100, 1), (101, 2)]);
        let mut img = pool.member_image(0, 8 * LABEL_SIZE);
        // Flip a byte inside the txg-101 uberblock of L0 (slot 1 at ashift 12).
        let off = UBERBLOCK_RING_OFFSET as usize + 4096 + 100;
        img[off] ^= 0xff;
        let scan = scan_device(&MemSource::new(img)).unwrap();
        let l0 = &scan.labels[0];
        assert_eq!(l0.uberblocks[1].checksum, ChecksumStatus::Bad);
        assert_eq!(l0.best().unwrap().ub.txg, 100);
        // Other labels still have a good copy of txg 101.
        assert_eq!(scan.labels[1].best().unwrap().ub.txg, 101);
        assert_eq!(scan.newest_txg(), Some(101));
    }

    #[test]
    fn best_label_prefers_verified_config() {
        let pool = Pool::mirror("tank", 0x1000, 12).txgs(&[(100, 1)]);
        let mut img = pool.member_image(0, 8 * LABEL_SIZE);
        // Damage the nvlist area of L0 (checksum bad, config may still parse).
        let off = VDEV_PHYS_OFFSET as usize + 3000;
        img[off] ^= 0xff;
        let scan = scan_device(&MemSource::new(img)).unwrap();
        assert_eq!(scan.labels[0].phys_checksum, ChecksumStatus::Bad);
        assert_ne!(scan.best_label, Some(0));
    }

    #[test]
    fn rejects_tiny_device() {
        let err = scan_device(&MemSource::new(vec![0u8; 1024])).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
