//! Synthetic vdev members for tests and smoke runs.
//!
//! Builds images that carry real label structures — XDR nvlists with
//! embedded SHA-256 checksums and sealed uberblock slots — without any
//! data blocks. Enough for `scan` and pool assembly; the tool itself never
//! writes evidence, so nothing here is reachable from the binaries except
//! through explicit fixture generation.

use zfs_ondisk::checksum::seal_label;
use zfs_ondisk::label::{
    label_offsets, LABEL_SIZE, UBERBLOCK_RING_OFFSET, VDEV_PHYS_OFFSET, VDEV_PHYS_SIZE,
};
use zfs_ondisk::nvlist::encode::{list, pack};
use zfs_ondisk::nvlist::{NvList, Value};
use zfs_ondisk::uberblock::{MAGIC, MAX_UBERBLOCK_SHIFT, UBERBLOCK_SHIFT};

/// A leaf member of the fixture pool.
#[derive(Debug, Clone)]
pub struct Member {
    /// Leaf GUID.
    pub guid: u64,
    /// `path` recorded in the label.
    pub path: String,
}

impl Member {
    /// Deterministic leaf GUID for member `i` of pool `pool_guid`.
    pub fn guid_for(pool_guid: u64, i: usize) -> u64 {
        pool_guid
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .wrapping_add(i as u64 + 1)
    }
}

/// A single-top-level-vdev fixture pool.
#[derive(Debug, Clone)]
pub struct Pool {
    /// Pool name.
    pub name: String,
    /// Pool GUID.
    pub guid: u64,
    /// `ashift` of the top-level vdev.
    pub ashift: u32,
    /// Top-level vdev type: `mirror`, `raidz`, or `disk`.
    pub kind: String,
    /// `nparity` for raidz.
    pub nparity: Option<u64>,
    /// Leaves.
    pub members: Vec<Member>,
    /// `(txg, timestamp)` pairs to record as uberblocks, oldest first.
    pub uberblocks: Vec<(u64, u64)>,
    /// `vdev_children` to claim.
    pub vdev_children: u64,
    /// `hostname`.
    pub hostname: String,
    /// `hostid`.
    pub hostid: u64,
    /// `state`.
    pub state: u64,
}

impl Pool {
    /// A two-way mirror.
    pub fn mirror(name: &str, guid: u64, ashift: u32) -> Pool {
        Pool {
            name: name.into(),
            guid,
            ashift,
            kind: "mirror".into(),
            nparity: None,
            members: (0..2)
                .map(|i| Member {
                    guid: Member::guid_for(guid, i),
                    path: format!("/dev/fixture{i}"),
                })
                .collect(),
            uberblocks: Vec::new(),
            vdev_children: 1,
            hostname: "fixture-host".into(),
            hostid: 0x1234_5678,
            state: 0,
        }
    }

    /// A raidz vdev with `width` leaves and `nparity` parity.
    pub fn raidz(name: &str, guid: u64, ashift: u32, width: usize, nparity: u64) -> Pool {
        let mut p = Pool::mirror(name, guid, ashift);
        p.kind = "raidz".into();
        p.nparity = Some(nparity);
        p.members = (0..width)
            .map(|i| Member {
                guid: Member::guid_for(guid, i),
                path: format!("/dev/fixture{i}"),
            })
            .collect();
        p
    }

    /// Set the uberblocks to record.
    pub fn txgs(mut self, txgs: &[(u64, u64)]) -> Pool {
        self.uberblocks = txgs.to_vec();
        self
    }

    /// The top-level vdev tree as it appears in every member's label.
    fn tree(&self) -> NvList {
        let top_guid = self.guid ^ 0xf0f0;
        let children: Vec<NvList> = self
            .members
            .iter()
            .enumerate()
            .map(|(i, m)| {
                list(vec![
                    ("type", Value::String("disk".into())),
                    ("id", Value::Uint64(i as u64)),
                    ("guid", Value::Uint64(m.guid)),
                    ("path", Value::String(m.path.clone())),
                    ("whole_disk", Value::Uint64(0)),
                    ("create_txg", Value::Uint64(4)),
                ])
            })
            .collect();
        let mut pairs = vec![
            ("type", Value::String(self.kind.clone())),
            ("id", Value::Uint64(0)),
            ("guid", Value::Uint64(top_guid)),
            ("metaslab_array", Value::Uint64(65)),
            ("metaslab_shift", Value::Uint64(29)),
            ("ashift", Value::Uint64(self.ashift as u64)),
            ("asize", Value::Uint64(1 << 36)),
            ("is_log", Value::Uint64(0)),
            ("create_txg", Value::Uint64(4)),
        ];
        if let Some(p) = self.nparity {
            pairs.push(("nparity", Value::Uint64(p)));
        }
        if self.kind == "disk" {
            pairs.push(("path", Value::String(self.members[0].path.clone())));
        } else {
            pairs.push(("children", Value::ListArray(children)));
        }
        list(pairs)
    }

    /// The label configuration nvlist for member `i`.
    pub fn config(&self, i: usize) -> NvList {
        let txg = self.uberblocks.last().map(|u| u.0).unwrap_or(0);
        list(vec![
            ("version", Value::Uint64(5000)),
            ("name", Value::String(self.name.clone())),
            ("state", Value::Uint64(self.state)),
            ("txg", Value::Uint64(txg)),
            ("pool_guid", Value::Uint64(self.guid)),
            ("errata", Value::Uint64(0)),
            ("hostid", Value::Uint64(self.hostid)),
            ("hostname", Value::String(self.hostname.clone())),
            ("top_guid", Value::Uint64(self.guid ^ 0xf0f0)),
            ("guid", Value::Uint64(self.members[i].guid)),
            ("vdev_children", Value::Uint64(self.vdev_children)),
            ("vdev_tree", Value::List(self.tree())),
            (
                "features_for_read",
                Value::List(list(vec![
                    ("com.delphix:hole_birth", Value::Boolean),
                    ("com.delphix:embedded_data", Value::Boolean),
                ])),
            ),
        ])
    }

    /// Build the image of member `i` with `size` bytes: four sealed labels,
    /// nothing else.
    pub fn member_image(&self, i: usize, size: u64) -> Vec<u8> {
        let mut img = vec![0u8; size as usize];
        let packed = pack(&self.config(i));
        assert!(packed.len() + 40 <= VDEV_PHYS_SIZE as usize);
        let shift = (self.ashift).clamp(UBERBLOCK_SHIFT, MAX_UBERBLOCK_SHIFT);
        let slot = 1usize << shift;
        for label_off in label_offsets(size).expect("fixture large enough") {
            let phys_off = (label_off + VDEV_PHYS_OFFSET) as usize;
            let phys = &mut img[phys_off..phys_off + VDEV_PHYS_SIZE as usize];
            phys[..packed.len()].copy_from_slice(&packed);
            seal_label(phys, label_off + VDEV_PHYS_OFFSET);

            for (n, (txg, ts)) in self.uberblocks.iter().enumerate() {
                let ring_off = label_off + UBERBLOCK_RING_OFFSET + (n * slot) as u64;
                let ub = &mut img[ring_off as usize..ring_off as usize + slot];
                let w = |ub: &mut [u8], off: usize, x: u64| {
                    ub[off..off + 8].copy_from_slice(&x.to_le_bytes())
                };
                w(ub, 0, MAGIC);
                w(ub, 8, 5000);
                w(ub, 16, *txg);
                w(
                    ub,
                    24,
                    self.members
                        .iter()
                        .map(|m| m.guid)
                        .fold(self.guid ^ 0xf0f0, u64::wrapping_add),
                );
                w(ub, 32, *ts);
                w(ub, 40 + 80, *txg); // rootbp logical birth
                w(ub, 40 + 128, 5000); // software version
                seal_label(ub, ring_off);
            }
        }
        assert!(size >= 4 * LABEL_SIZE);
        img
    }
}
