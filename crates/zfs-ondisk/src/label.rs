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

// ---------------------------------------------------------------------------
// vdev_phys: the packed configuration nvlist and its embedded checksum
// ---------------------------------------------------------------------------

use crate::checksum::{verify_label, ChecksumStatus, ECK_SIZE};
use crate::nvlist::{parse_packed, NvList};
use crate::ParseError;

/// Decoded `vdev_phys`: the configuration nvlist plus its checksum state.
#[derive(Debug, Clone)]
pub struct VdevPhys {
    /// Result of parsing the packed nvlist (independent of the checksum).
    pub config: Result<NvList, ParseError>,
    /// Embedded SHA-256 verification over the whole 112 KiB area.
    pub checksum: ChecksumStatus,
}

/// Parse the 112 KiB `vdev_phys` area of a label stored at byte offset
/// `label_offset` on its vdev.
pub fn parse_vdev_phys(buf: &[u8], label_offset: u64) -> VdevPhys {
    let checksum = if buf.len() == VDEV_PHYS_SIZE as usize {
        verify_label(buf, label_offset + VDEV_PHYS_OFFSET)
    } else {
        ChecksumStatus::Missing
    };
    let nv_end = buf.len().saturating_sub(ECK_SIZE);
    VdevPhys {
        config: parse_packed(&buf[..nv_end]),
        checksum,
    }
}

/// Name of a `pool_state_t` value.
pub fn pool_state_name(state: u64) -> &'static str {
    match state {
        0 => "ACTIVE",
        1 => "EXPORTED",
        2 => "DESTROYED",
        3 => "SPARE",
        4 => "L2CACHE",
        5 => "UNINITIALIZED",
        6 => "UNAVAIL",
        7 => "POTENTIALLY_ACTIVE",
        _ => "UNKNOWN",
    }
}

/// One node of the `vdev_tree` stored in a label: the top-level vdev this
/// device belongs to, with its children down to the leaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VdevNode {
    /// `type`: `disk`, `file`, `mirror`, `raidz`, `draid`, `root`, …
    pub kind: String,
    /// `id`: index among siblings.
    pub id: u64,
    /// `guid`.
    pub guid: u64,
    /// `path` for leaves.
    pub path: Option<String>,
    /// `ashift` (top-level vdevs).
    pub ashift: Option<u64>,
    /// `asize` (top-level vdevs).
    pub asize: Option<u64>,
    /// `nparity` for raidz/draid.
    pub nparity: Option<u64>,
    /// `draid_ndata`: data columns per dRAID group.
    pub draid_ndata: Option<u64>,
    /// `draid_nspares`: distributed spares of a dRAID.
    pub draid_nspares: Option<u64>,
    /// `draid_ngroups`: groups per dRAID slice.
    pub draid_ngroups: Option<u64>,
    /// `is_log`.
    pub is_log: bool,
    /// `children`, in order.
    pub children: Vec<VdevNode>,
}

impl VdevNode {
    /// Build from a `vdev_tree` (or child) nvlist.
    pub fn from_nvlist(nv: &NvList) -> VdevNode {
        VdevNode {
            kind: nv.str("type").unwrap_or("?").to_string(),
            id: nv.u64("id").unwrap_or(0),
            guid: nv.u64("guid").unwrap_or(0),
            path: nv.str("path").map(str::to_string),
            ashift: nv.u64("ashift"),
            asize: nv.u64("asize"),
            nparity: nv.u64("nparity"),
            draid_ndata: nv.u64("draid_ndata"),
            draid_nspares: nv.u64("draid_nspares"),
            draid_ngroups: nv.u64("draid_ngroups"),
            is_log: nv.u64("is_log").unwrap_or(0) != 0,
            children: nv
                .list_array("children")
                .map(|c| c.iter().map(VdevNode::from_nvlist).collect())
                .unwrap_or_default(),
        }
    }

    /// Leaves of this subtree in order (the node itself if it has no children).
    pub fn leaves(&self) -> Vec<&VdevNode> {
        if self.children.is_empty() {
            vec![self]
        } else {
            self.children.iter().flat_map(|c| c.leaves()).collect()
        }
    }

    /// `mirror-0`, `raidz2-1`, or the leaf path/guid for a single-disk top.
    pub fn display_name(&self) -> String {
        match self.kind.as_str() {
            "mirror" | "raidz" | "draid" => {
                let parity = self.nparity.filter(|_| self.kind != "mirror");
                match parity {
                    Some(p) => format!("{}{}-{}", self.kind, p, self.id),
                    None => format!("{}-{}", self.kind, self.id),
                }
            }
            _ => self
                .path
                .clone()
                .unwrap_or_else(|| format!("{}-{:#x}", self.kind, self.guid)),
        }
    }
}

/// The fields of a label configuration that recovery needs, pulled out of
/// the raw nvlist. Anything absent is `None`; nothing here is fatal.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LabelConfig {
    /// `version` (5000 for feature-flag pools).
    pub version: Option<u64>,
    /// `name` of the pool.
    pub name: Option<String>,
    /// `state` (`pool_state_t`).
    pub state: Option<u64>,
    /// `txg` in which this label was written.
    pub txg: Option<u64>,
    /// `pool_guid`.
    pub pool_guid: Option<u64>,
    /// `guid` of this leaf vdev.
    pub guid: Option<u64>,
    /// `top_guid` of the top-level vdev this leaf belongs to.
    pub top_guid: Option<u64>,
    /// `vdev_children`: number of top-level vdevs in the pool.
    pub vdev_children: Option<u64>,
    /// `hostid` of the last importing host.
    pub hostid: Option<u64>,
    /// `hostname` of the last importing host.
    pub hostname: Option<String>,
    /// Names under `features_for_read`.
    pub features_for_read: Vec<String>,
    /// The top-level vdev subtree containing this device.
    pub tree: Option<VdevNode>,
}

impl LabelConfig {
    /// Extract from a parsed label nvlist.
    pub fn from_nvlist(nv: &NvList) -> LabelConfig {
        LabelConfig {
            version: nv.u64("version"),
            name: nv.str("name").map(str::to_string),
            state: nv.u64("state"),
            txg: nv.u64("txg"),
            pool_guid: nv.u64("pool_guid"),
            guid: nv.u64("guid"),
            top_guid: nv.u64("top_guid"),
            vdev_children: nv.u64("vdev_children"),
            hostid: nv.u64("hostid"),
            hostname: nv.str("hostname").map(str::to_string),
            features_for_read: nv
                .list("features_for_read")
                .map(|l| l.pairs.iter().map(|(n, _)| n.clone()).collect())
                .unwrap_or_default(),
            tree: nv.list("vdev_tree").map(VdevNode::from_nvlist),
        }
    }

    /// `ashift` of the top-level vdev, if recorded.
    pub fn ashift(&self) -> Option<u64> {
        self.tree.as_ref().and_then(|t| t.ashift)
    }
}

#[cfg(test)]
mod phys_tests {
    use super::*;
    use crate::checksum::seal_label;
    use crate::nvlist::encode::{list, pack};
    use crate::nvlist::Value;

    fn config() -> NvList {
        list(vec![
            ("version", Value::Uint64(5000)),
            ("name", Value::String("tank".into())),
            ("state", Value::Uint64(0)),
            ("txg", Value::Uint64(77)),
            ("pool_guid", Value::Uint64(0x1111)),
            ("guid", Value::Uint64(0xaa)),
            ("top_guid", Value::Uint64(0x10)),
            ("vdev_children", Value::Uint64(1)),
            ("hostname", Value::String("h1".into())),
            (
                "features_for_read",
                Value::List(list(vec![("com.delphix:hole_birth", Value::Boolean)])),
            ),
            (
                "vdev_tree",
                Value::List(list(vec![
                    ("type", Value::String("mirror".into())),
                    ("id", Value::Uint64(0)),
                    ("guid", Value::Uint64(0x10)),
                    ("ashift", Value::Uint64(12)),
                    (
                        "children",
                        Value::ListArray(vec![
                            list(vec![
                                ("type", Value::String("disk".into())),
                                ("id", Value::Uint64(0)),
                                ("guid", Value::Uint64(0xaa)),
                                ("path", Value::String("/dev/ada0p3".into())),
                            ]),
                            list(vec![
                                ("type", Value::String("disk".into())),
                                ("id", Value::Uint64(1)),
                                ("guid", Value::Uint64(0xbb)),
                                ("path", Value::String("/dev/ada1p3".into())),
                            ]),
                        ]),
                    ),
                ])),
            ),
        ])
    }

    #[test]
    fn vdev_phys_roundtrip_with_checksum() {
        let mut phys = vec![0u8; VDEV_PHYS_SIZE as usize];
        let packed = pack(&config());
        phys[..packed.len()].copy_from_slice(&packed);
        seal_label(&mut phys, LABEL_SIZE + VDEV_PHYS_OFFSET);
        let p = parse_vdev_phys(&phys, LABEL_SIZE);
        assert_eq!(p.checksum, ChecksumStatus::Ok);
        let cfg = LabelConfig::from_nvlist(p.config.as_ref().unwrap());
        assert_eq!(cfg.name.as_deref(), Some("tank"));
        assert_eq!(cfg.ashift(), Some(12));
        assert_eq!(cfg.features_for_read, vec!["com.delphix:hole_birth"]);
        let tree = cfg.tree.unwrap();
        assert_eq!(tree.display_name(), "mirror-0");
        let leaves = tree.leaves();
        assert_eq!(leaves.len(), 2);
        assert_eq!(leaves[1].path.as_deref(), Some("/dev/ada1p3"));
        // Wrong label offset => checksum bad, config still parses.
        let p = parse_vdev_phys(&phys, 0);
        assert_eq!(p.checksum, ChecksumStatus::Bad);
        assert!(p.config.is_ok());
    }

    #[test]
    fn empty_phys() {
        let p = parse_vdev_phys(&vec![0u8; VDEV_PHYS_SIZE as usize], 0);
        assert_eq!(p.checksum, ChecksumStatus::Missing);
        assert!(p.config.is_err());
        assert_eq!(pool_state_name(2), "DESTROYED");
    }
}
