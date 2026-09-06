//! DSL (Dataset and Snapshot Layer) bonus structures.
//!
//! `dsl_dir_phys_t` lives in the bonus of a `DMU_OT_DSL_DIR` dnode and
//! names the directory's children ZAP, properties ZAP and head dataset.
//! `dsl_dataset_phys_t` lives in the bonus of a `DMU_OT_DSL_DATASET` dnode
//! and points at the dataset's objset plus its snapshot chain. Layouts
//! from OpenZFS `dsl_dir.h` and `dsl_dataset.h`.

use crate::blkptr::{self, BlkPtr};
use crate::{Endian, ParseError};

/// Minimum bonus length of a `dsl_dir_phys_t` this reader needs.
pub const DSL_DIR_MIN_LEN: usize = 128;
/// Minimum bonus length of a `dsl_dataset_phys_t` this reader needs.
pub const DSL_DATASET_MIN_LEN: usize = 320;

/// `dsl_dir_phys_t`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DslDirPhys {
    /// `dd_creation_time`.
    pub creation_time: u64,
    /// `dd_head_dataset_obj`: the live dataset (0 for the `$MOS` dir etc.).
    pub head_dataset_obj: u64,
    /// `dd_parent_obj`.
    pub parent_obj: u64,
    /// `dd_origin_obj`: the snapshot this is a clone of, if any.
    pub origin_obj: u64,
    /// `dd_child_dir_zapobj`: ZAP of child directory name → object.
    pub child_dir_zapobj: u64,
    /// `dd_used_bytes`.
    pub used_bytes: u64,
    /// `dd_compressed_bytes`.
    pub compressed_bytes: u64,
    /// `dd_uncompressed_bytes`.
    pub uncompressed_bytes: u64,
    /// `dd_quota`.
    pub quota: u64,
    /// `dd_reserved`.
    pub reserved: u64,
    /// `dd_props_zapobj`: ZAP of local properties.
    pub props_zapobj: u64,
    /// `dd_deleg_zapobj`.
    pub deleg_zapobj: u64,
    /// `dd_flags`.
    pub flags: u64,
    /// `dd_used_breakdown[5]`: head, snap, child, child rsrv, refrsrv.
    pub used_breakdown: [u64; 5],
    /// `dd_clones`: ZAP of clone dataset objects (0 when absent).
    pub clones: u64,
}

impl DslDirPhys {
    /// Parse from a bonus buffer.
    pub fn parse(bonus: &[u8], endian: Endian) -> Result<DslDirPhys, ParseError> {
        if bonus.len() < DSL_DIR_MIN_LEN {
            return Err(ParseError::Truncated {
                needed: DSL_DIR_MIN_LEN,
                got: bonus.len(),
            });
        }
        let w = |i: usize| endian.u64_at(bonus, i * 8).unwrap_or(0);
        Ok(DslDirPhys {
            creation_time: w(0),
            head_dataset_obj: w(1),
            parent_obj: w(2),
            origin_obj: w(3),
            child_dir_zapobj: w(4),
            used_bytes: w(5),
            compressed_bytes: w(6),
            uncompressed_bytes: w(7),
            quota: w(8),
            reserved: w(9),
            props_zapobj: w(10),
            deleg_zapobj: w(11),
            flags: w(12),
            used_breakdown: [w(13), w(14), w(15), w(16), w(17)],
            clones: w(18),
        })
    }
}

/// `dsl_dataset_phys_t`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DslDatasetPhys {
    /// `ds_dir_obj`: owning DSL directory.
    pub dir_obj: u64,
    /// `ds_prev_snap_obj`: previous snapshot in the chain (0 = none).
    pub prev_snap_obj: u64,
    /// `ds_prev_snap_txg`.
    pub prev_snap_txg: u64,
    /// `ds_next_snap_obj`: next snapshot (0 for a head dataset).
    pub next_snap_obj: u64,
    /// `ds_snapnames_zapobj`: ZAP of snapshot name → dataset object.
    pub snapnames_zapobj: u64,
    /// `ds_num_children`: number of clones + 1 for snapshots.
    pub num_children: u64,
    /// `ds_creation_time` (Unix seconds).
    pub creation_time: u64,
    /// `ds_creation_txg`.
    pub creation_txg: u64,
    /// `ds_deadlist_obj`.
    pub deadlist_obj: u64,
    /// `ds_referenced_bytes`.
    pub referenced_bytes: u64,
    /// `ds_compressed_bytes`.
    pub compressed_bytes: u64,
    /// `ds_uncompressed_bytes`.
    pub uncompressed_bytes: u64,
    /// `ds_unique_bytes`.
    pub unique_bytes: u64,
    /// `ds_fsid_guid`.
    pub fsid_guid: u64,
    /// `ds_guid`: stable dataset identity across renames.
    pub guid: u64,
    /// `ds_flags`.
    pub flags: u64,
    /// `ds_bp`: the dataset's objset block.
    pub bp: BlkPtr,
    /// `ds_next_clones_obj`.
    pub next_clones_obj: u64,
    /// `ds_props_obj`: snapshot-local properties ZAP.
    pub props_obj: u64,
    /// `ds_userrefs_obj`.
    pub userrefs_obj: u64,
}

impl DslDatasetPhys {
    /// Parse from a bonus buffer.
    pub fn parse(bonus: &[u8], endian: Endian) -> Result<DslDatasetPhys, ParseError> {
        if bonus.len() < DSL_DATASET_MIN_LEN {
            return Err(ParseError::Truncated {
                needed: DSL_DATASET_MIN_LEN,
                got: bonus.len(),
            });
        }
        let w = |i: usize| endian.u64_at(bonus, i * 8).unwrap_or(0);
        Ok(DslDatasetPhys {
            dir_obj: w(0),
            prev_snap_obj: w(1),
            prev_snap_txg: w(2),
            next_snap_obj: w(3),
            snapnames_zapobj: w(4),
            num_children: w(5),
            creation_time: w(6),
            creation_txg: w(7),
            deadlist_obj: w(8),
            referenced_bytes: w(9),
            compressed_bytes: w(10),
            uncompressed_bytes: w(11),
            unique_bytes: w(12),
            fsid_guid: w(13),
            guid: w(14),
            flags: w(15),
            bp: BlkPtr::parse(&bonus[128..128 + blkptr::SIZE], endian)?,
            next_clones_obj: w(32),
            props_obj: w(33),
            userrefs_obj: w(34),
        })
    }

    /// A snapshot has a next pointer; a head dataset does not.
    pub fn is_snapshot(&self) -> bool {
        self.next_snap_obj != 0
    }
}

/// Builders for fixtures.
pub mod encode {
    use super::*;

    /// Serialise a `dsl_dir_phys_t` (little-endian, 256 bytes).
    pub fn dsl_dir(d: &DslDirPhys) -> Vec<u8> {
        let words = [
            d.creation_time,
            d.head_dataset_obj,
            d.parent_obj,
            d.origin_obj,
            d.child_dir_zapobj,
            d.used_bytes,
            d.compressed_bytes,
            d.uncompressed_bytes,
            d.quota,
            d.reserved,
            d.props_zapobj,
            d.deleg_zapobj,
            d.flags,
            d.used_breakdown[0],
            d.used_breakdown[1],
            d.used_breakdown[2],
            d.used_breakdown[3],
            d.used_breakdown[4],
            d.clones,
        ];
        let mut b = vec![0u8; 256];
        for (i, w) in words.iter().enumerate() {
            b[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        b
    }

    /// Serialise a `dsl_dataset_phys_t` (little-endian, 320 bytes).
    pub fn dsl_dataset(d: &DslDatasetPhys) -> Vec<u8> {
        let words = [
            d.dir_obj,
            d.prev_snap_obj,
            d.prev_snap_txg,
            d.next_snap_obj,
            d.snapnames_zapobj,
            d.num_children,
            d.creation_time,
            d.creation_txg,
            d.deadlist_obj,
            d.referenced_bytes,
            d.compressed_bytes,
            d.uncompressed_bytes,
            d.unique_bytes,
            d.fsid_guid,
            d.guid,
            d.flags,
        ];
        let mut b = vec![0u8; DSL_DATASET_MIN_LEN];
        for (i, w) in words.iter().enumerate() {
            b[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        b[128..256].copy_from_slice(d.bp.raw());
        b[256..264].copy_from_slice(&d.next_clones_obj.to_le_bytes());
        b[264..272].copy_from_slice(&d.props_obj.to_le_bytes());
        b[272..280].copy_from_slice(&d.userrefs_obj.to_le_bytes());
        b
    }
}

#[cfg(test)]
mod tests {
    use super::encode::{dsl_dataset, dsl_dir};
    use super::*;
    use crate::blkptr::encode::Builder;

    #[test]
    fn dir_roundtrip() {
        let d = DslDirPhys {
            creation_time: 1_700_000_000,
            head_dataset_obj: 54,
            parent_obj: 2,
            child_dir_zapobj: 55,
            props_zapobj: 56,
            used_bytes: 1 << 30,
            used_breakdown: [1, 2, 3, 4, 5],
            clones: 99,
            ..Default::default()
        };
        let raw = dsl_dir(&d);
        assert_eq!(DslDirPhys::parse(&raw, Endian::Little).unwrap(), d);
        assert!(matches!(
            DslDirPhys::parse(&raw[..100], Endian::Little),
            Err(ParseError::Truncated { .. })
        ));
    }

    #[test]
    fn dataset_roundtrip() {
        let bp = Builder::new()
            .dva(0, 0, 0x8000, 4096, false)
            .sizes(4096, 4096)
            .props(2, 7, 11, 0)
            .births(0, 500, 1)
            .bytes(Endian::Little);
        let d = DslDatasetPhys {
            dir_obj: 53,
            prev_snap_obj: 70,
            prev_snap_txg: 400,
            next_snap_obj: 0,
            snapnames_zapobj: 57,
            num_children: 1,
            creation_time: 1_700_000_000,
            creation_txg: 100,
            deadlist_obj: 58,
            referenced_bytes: 10,
            compressed_bytes: 11,
            uncompressed_bytes: 12,
            unique_bytes: 13,
            fsid_guid: 14,
            guid: 0xabcd,
            flags: 0,
            bp: BlkPtr::parse(&bp, Endian::Little).unwrap(),
            next_clones_obj: 0,
            props_obj: 0,
            userrefs_obj: 0,
        };
        let raw = dsl_dataset(&d);
        let parsed = DslDatasetPhys::parse(&raw, Endian::Little).unwrap();
        assert_eq!(parsed, d);
        assert!(!parsed.is_snapshot());
        assert_eq!(parsed.bp.dva[0].offset, 0x8000);
        assert_eq!(parsed.bp.birth, 500);
        let snap = DslDatasetPhys {
            next_snap_obj: 54,
            ..d
        };
        assert!(DslDatasetPhys::parse(&dsl_dataset(&snap), Endian::Little)
            .unwrap()
            .is_snapshot());
        assert!(DslDatasetPhys::parse(&raw[..200], Endian::Little).is_err());
    }
}
