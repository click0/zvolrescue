//! DMU on-disk structures: `dnode_phys_t` and `objset_phys_t`.
//!
//! Layouts from OpenZFS `include/sys/dnode.h` and `dmu_objset.h`. A dnode
//! is 512 bytes (more with `dn_extra_slots` for large dnodes): a 64-byte
//! core, one to three block pointers, the bonus buffer, and optionally a
//! spill block pointer in the last 128 bytes.

use crate::blkptr::{self, BlkPtr};
use crate::{Endian, ParseError};

/// `DNODE_SHIFT`: size of one dnode slot.
pub const DNODE_SHIFT: u32 = 9;
/// Size of one dnode slot in bytes.
pub const DNODE_SIZE: usize = 1 << DNODE_SHIFT;
/// Bytes before the first block pointer.
pub const DNODE_CORE_SIZE: usize = 64;
/// `DNODE_FLAG_USED_BYTES`: `dn_used` counts bytes, not sectors.
pub const FLAG_USED_BYTES: u8 = 1;
/// `DNODE_FLAG_USERUSED_ACCOUNTED`.
pub const FLAG_USERUSED_ACCOUNTED: u8 = 2;
/// `DNODE_FLAG_SPILL_BLKPTR`: the last 128 bytes hold a spill pointer.
pub const FLAG_SPILL_BLKPTR: u8 = 4;
/// Size of `objset_phys_t` with the project-used dnode (`OBJSET_PHYS_SIZE_V3`).
pub const OBJSET_PHYS_SIZE: usize = 4096;
/// `DMU_OT_NEWTYPE` bit: the type byte encodes a byteswap class and flags
/// instead of a legacy enumerator.
pub const OT_NEWTYPE: u8 = 0x80;
/// `DMU_OT_METADATA` flag inside a new-style type.
pub const OT_METADATA: u8 = 0x40;
/// `DMU_OT_ENCRYPTED` flag inside a new-style type.
pub const OT_ENCRYPTED: u8 = 0x20;

/// Legacy `dmu_object_type_t` values this reader cares about.
pub mod ot {
    /// Free dnode.
    pub const NONE: u8 = 0;
    /// The MOS object directory ZAP.
    pub const OBJECT_DIRECTORY: u8 = 1;
    /// Packed nvlist (pool config, history).
    pub const PACKED_NVLIST: u8 = 3;
    /// Space map.
    pub const SPACE_MAP: u8 = 8;
    /// Dnode array (the meta-dnode's data).
    pub const DNODE: u8 = 10;
    /// Object set.
    pub const OBJSET: u8 = 11;
    /// DSL directory (bonus: `dsl_dir_phys_t`).
    pub const DSL_DIR: u8 = 12;
    /// DSL directory child map ZAP.
    pub const DSL_DIR_CHILD_MAP: u8 = 13;
    /// Snapshot name → dataset ZAP.
    pub const DSL_DS_SNAP_MAP: u8 = 14;
    /// DSL properties ZAP.
    pub const DSL_PROPS: u8 = 15;
    /// DSL dataset (bonus: `dsl_dataset_phys_t`).
    pub const DSL_DATASET: u8 = 16;
    /// ZPL file contents.
    pub const PLAIN_FILE_CONTENTS: u8 = 19;
    /// ZPL directory ZAP.
    pub const DIRECTORY_CONTENTS: u8 = 20;
    /// ZPL master node ZAP.
    pub const MASTER_NODE: u8 = 21;
    /// zvol data.
    pub const ZVOL: u8 = 23;
    /// zvol properties ZAP.
    pub const ZVOL_PROP: u8 = 24;
    /// System attributes.
    pub const SA: u8 = 44;
    /// Deadlist.
    pub const DEADLIST: u8 = 50;

    /// `DMU_OT_IS_ENCRYPTED`: whether level-0 blocks of this type are
    /// stored as ciphertext in an encrypted dataset. Other types (MOS
    /// bookkeeping, indirect blocks) are only authenticated with a MAC and
    /// stay readable without the key. Objset blocks are a special case:
    /// plaintext with two MACs embedded (`zio_crypt_do_objset_hmacs`).
    pub fn is_encrypted(t: u8) -> bool {
        if t & super::OT_NEWTYPE != 0 {
            return t & super::OT_ENCRYPTED != 0;
        }
        // ot_encrypt column of dmu_ot[] (module/zfs/dmu.c). Notably NOT
        // encrypted: znode (17), master node (21), zvol prop (24), other
        // ZAP (27), FUID size (36): those are only authenticated.
        matches!(
            t,
            9 | 10 | 18 | 19 | 20 | 22 | 23 | 25 | 26 | 33 | 34 | 35 | 39 | 40 | 44..=47 | 49
        )
    }
}

/// Human name of a `dmu_object_type_t` byte.
pub fn object_type_name(t: u8) -> String {
    if t & OT_NEWTYPE != 0 {
        let bswap = match t & 0x1f {
            0 => "uint8",
            1 => "uint16",
            2 => "uint32",
            3 => "uint64",
            4 => "zap",
            5 => "dnode",
            6 => "objset",
            7 => "znode",
            8 => "oldacl",
            9 => "acl",
            _ => "?",
        };
        return format!(
            "newtype({bswap}{}{})",
            if t & OT_METADATA != 0 {
                ",metadata"
            } else {
                ""
            },
            if t & OT_ENCRYPTED != 0 {
                ",encrypted"
            } else {
                ""
            }
        );
    }
    let names = [
        "none",
        "object directory",
        "object array",
        "packed nvlist",
        "packed nvlist size",
        "bpobj",
        "bpobj header",
        "SPA space map header",
        "SPA space map",
        "ZIL intent log",
        "DMU dnode",
        "DMU objset",
        "DSL directory",
        "DSL directory child map",
        "DSL dataset snap map",
        "DSL props",
        "DSL dataset",
        "ZFS znode",
        "ZFS V0 ACL",
        "ZFS plain file",
        "ZFS directory",
        "ZFS master node",
        "ZFS delete queue",
        "zvol object",
        "zvol prop",
        "other uint8[]",
        "other uint64[]",
        "other ZAP",
        "persistent error log",
        "SPA history",
        "SPA history offsets",
        "Pool properties",
        "DSL permissions",
        "ZFS ACL",
        "ZFS SYSACL",
        "FUID table",
        "FUID table size",
        "DSL dataset next clones",
        "scan work queue",
        "ZFS user/group/project used",
        "ZFS user/group/project quota",
        "snapshot refcount tags",
        "DDT ZAP algorithm",
        "DDT statistics",
        "System attributes",
        "SA master node",
        "SA attr registration",
        "SA attr layouts",
        "scan translations",
        "deduplicated block",
        "DSL deadlist map",
        "DSL deadlist map hdr",
        "DSL dir clones",
        "bpobj subobj",
    ];
    names
        .get(t as usize)
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("unknown-{t}"))
}

/// A decoded dnode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnodePhys {
    /// `dn_type`.
    pub object_type: u8,
    /// `dn_indblkshift`: log2 of the indirect block size.
    pub indblkshift: u8,
    /// `dn_nlevels`: 1 = block pointers point at data.
    pub nlevels: u8,
    /// `dn_nblkptr`: 1..=3 block pointers in the dnode.
    pub nblkptr: u8,
    /// `dn_bonustype`.
    pub bonus_type: u8,
    /// `dn_checksum` (0 = inherit from dataset).
    pub checksum: u8,
    /// `dn_compress` (0 = inherit from dataset).
    pub compress: u8,
    /// `dn_flags`.
    pub flags: u8,
    /// `dn_datablkszsec`: data block size in 512-byte sectors.
    pub datablkszsec: u16,
    /// `dn_bonuslen`.
    pub bonuslen: u16,
    /// `dn_extra_slots`: additional 512-byte slots this dnode occupies.
    pub extra_slots: u8,
    /// `dn_maxblkid`: highest block id ever written.
    pub maxblkid: u64,
    /// `dn_used`: bytes (or sectors if `FLAG_USED_BYTES` is clear).
    pub used: u64,
    /// The block pointers (`nblkptr` of them).
    pub blkptr: Vec<BlkPtr>,
    /// Bonus buffer contents (`bonuslen` bytes).
    pub bonus: Vec<u8>,
    /// Spill block pointer when `FLAG_SPILL_BLKPTR` is set.
    pub spill: Option<BlkPtr>,
}

impl DnodePhys {
    /// Parse a dnode from the start of `buf`, which must hold all of its
    /// slots (`512 * (1 + extra_slots)` bytes).
    pub fn parse(buf: &[u8], endian: Endian) -> Result<DnodePhys, ParseError> {
        if buf.len() < DNODE_SIZE {
            return Err(ParseError::Truncated {
                needed: DNODE_SIZE,
                got: buf.len(),
            });
        }
        let u16_at = |o: usize| {
            let b = [buf[o], buf[o + 1]];
            match endian {
                Endian::Little => u16::from_le_bytes(b),
                Endian::Big => u16::from_be_bytes(b),
            }
        };
        let extra_slots = buf[12];
        let total = DNODE_SIZE * (1 + extra_slots as usize);
        if buf.len() < total {
            return Err(ParseError::Truncated {
                needed: total,
                got: buf.len(),
            });
        }
        let nblkptr = buf[3];
        if !(1..=3).contains(&nblkptr) && buf[0] != ot::NONE {
            return Err(ParseError::Malformed {
                what: "dn_nblkptr outside 1..=3",
                at: 3,
            });
        }
        let nbp = nblkptr.clamp(0, 3) as usize;
        let mut blkptr = Vec::with_capacity(nbp);
        for i in 0..nbp {
            let at = DNODE_CORE_SIZE + i * blkptr::SIZE;
            blkptr.push(BlkPtr::parse(&buf[at..at + blkptr::SIZE], endian)?);
        }
        let flags = buf[7];
        let bonus_start = DNODE_CORE_SIZE + nbp * blkptr::SIZE;
        let spill_start = if flags & FLAG_SPILL_BLKPTR != 0 {
            total - blkptr::SIZE
        } else {
            total
        };
        let bonuslen = u16_at(10);
        let bonus_end = bonus_start + bonuslen as usize;
        if bonus_end > spill_start {
            return Err(ParseError::Malformed {
                what: "dn_bonuslen overlaps spill pointer or dnode end",
                at: 10,
            });
        }
        let spill = if flags & FLAG_SPILL_BLKPTR != 0 {
            Some(BlkPtr::parse(
                &buf[spill_start..spill_start + blkptr::SIZE],
                endian,
            )?)
        } else {
            None
        };
        Ok(DnodePhys {
            object_type: buf[0],
            indblkshift: buf[1],
            nlevels: buf[2],
            nblkptr,
            bonus_type: buf[4],
            checksum: buf[5],
            compress: buf[6],
            flags,
            datablkszsec: u16_at(8),
            bonuslen,
            extra_slots,
            maxblkid: endian.u64_at(buf, 16).expect("length checked"),
            used: endian.u64_at(buf, 24).expect("length checked"),
            blkptr,
            bonus: buf[bonus_start..bonus_end].to_vec(),
            spill,
        })
    }

    /// A free slot (`DMU_OT_NONE`).
    pub fn is_free(&self) -> bool {
        self.object_type == ot::NONE
    }

    /// Data block size in bytes.
    pub fn datablksz(&self) -> u64 {
        u64::from(self.datablkszsec) << blkptr::MINBLOCKSHIFT
    }

    /// Indirect block size in bytes.
    pub fn indblksz(&self) -> u64 {
        1u64 << self.indblkshift.min(63)
    }

    /// Block pointers per indirect block.
    pub fn ptrs_per_indirect(&self) -> u64 {
        self.indblksz() / blkptr::SIZE as u64
    }

    /// Bytes this dnode occupies in the dnode array.
    pub fn slot_bytes(&self) -> usize {
        DNODE_SIZE * (1 + self.extra_slots as usize)
    }

    /// `dn_used` normalised to bytes.
    pub fn used_bytes(&self) -> u64 {
        if self.flags & FLAG_USED_BYTES != 0 {
            self.used
        } else {
            self.used << blkptr::MINBLOCKSHIFT
        }
    }

    /// Human name of the object type.
    pub fn type_name(&self) -> String {
        object_type_name(self.object_type)
    }
}

/// `dmu_objset_type_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjsetType {
    /// `DMU_OST_NONE`.
    None,
    /// `DMU_OST_META`: the MOS.
    Meta,
    /// `DMU_OST_ZFS`: a filesystem.
    Zfs,
    /// `DMU_OST_ZVOL`: a volume.
    Zvol,
    /// `DMU_OST_OTHER`.
    Other,
    /// Any other value.
    Unknown(u64),
}

impl ObjsetType {
    /// Decode `os_type`.
    pub fn from_raw(v: u64) -> ObjsetType {
        match v {
            0 => ObjsetType::None,
            1 => ObjsetType::Meta,
            2 => ObjsetType::Zfs,
            3 => ObjsetType::Zvol,
            4 => ObjsetType::Other,
            other => ObjsetType::Unknown(other),
        }
    }

    /// Short lowercase name.
    pub fn name(&self) -> String {
        match self {
            ObjsetType::None => "none".into(),
            ObjsetType::Meta => "meta".into(),
            ObjsetType::Zfs => "filesystem".into(),
            ObjsetType::Zvol => "volume".into(),
            ObjsetType::Other => "other".into(),
            ObjsetType::Unknown(v) => format!("unknown-{v}"),
        }
    }
}

/// A decoded object set header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjsetPhys {
    /// `os_meta_dnode`: the dnode whose data is the dnode array.
    pub meta_dnode: DnodePhys,
    /// `zh_log`: head of the intent log chain.
    pub zil_log: BlkPtr,
    /// `zh_claim_txg`.
    pub zil_claim_txg: u64,
    /// `os_type`.
    pub os_type: ObjsetType,
    /// `os_flags`.
    pub flags: u64,
    /// `os_userused_dnode` when the buffer is large enough.
    pub userused_dnode: Option<DnodePhys>,
    /// `os_groupused_dnode` when the buffer is large enough.
    pub groupused_dnode: Option<DnodePhys>,
    /// `os_projectused_dnode` when the buffer is large enough.
    pub projectused_dnode: Option<DnodePhys>,
}

impl ObjsetPhys {
    /// Parse an objset block (1024, 2048 or 4096 bytes).
    pub fn parse(buf: &[u8], endian: Endian) -> Result<ObjsetPhys, ParseError> {
        if buf.len() < 1024 {
            return Err(ParseError::Truncated {
                needed: 1024,
                got: buf.len(),
            });
        }
        let dnode_at = |o: usize| {
            buf.get(o..o + DNODE_SIZE)
                .map(|b| DnodePhys::parse(b, endian))
                .transpose()
        };
        Ok(ObjsetPhys {
            meta_dnode: DnodePhys::parse(&buf[..DNODE_SIZE], endian)?,
            zil_claim_txg: endian.u64_at(buf, 512).expect("length checked"),
            zil_log: BlkPtr::parse(&buf[528..528 + blkptr::SIZE], endian)?,
            os_type: ObjsetType::from_raw(endian.u64_at(buf, 704).expect("length checked")),
            flags: endian.u64_at(buf, 712).expect("length checked"),
            userused_dnode: dnode_at(1024)?,
            groupused_dnode: dnode_at(1536)?,
            projectused_dnode: dnode_at(2048)?,
        })
    }
}

/// Builders for fixtures.
pub mod encode {
    use super::*;

    /// Everything needed to serialise one dnode for a fixture.
    #[derive(Debug, Clone)]
    pub struct DnodeSpec {
        /// `dn_type`.
        pub object_type: u8,
        /// `dn_indblkshift`.
        pub indblkshift: u8,
        /// `dn_nlevels`.
        pub nlevels: u8,
        /// Data block size in bytes.
        pub datablksz: u64,
        /// `dn_maxblkid`.
        pub maxblkid: u64,
        /// One to three block pointers.
        pub blkptrs: Vec<[u8; blkptr::SIZE]>,
        /// `dn_bonustype`.
        pub bonus_type: u8,
        /// Bonus contents.
        pub bonus: Vec<u8>,
        /// Spill pointer, sets `FLAG_SPILL_BLKPTR`.
        pub spill: Option<[u8; blkptr::SIZE]>,
        /// `dn_extra_slots`.
        pub extra_slots: u8,
    }

    impl Default for DnodeSpec {
        fn default() -> Self {
            DnodeSpec {
                object_type: ot::NONE,
                indblkshift: 17,
                nlevels: 1,
                datablksz: 512,
                maxblkid: 0,
                blkptrs: vec![[0u8; blkptr::SIZE]],
                bonus_type: 0,
                bonus: Vec::new(),
                spill: None,
                extra_slots: 0,
            }
        }
    }

    impl DnodeSpec {
        /// Serialise into `512 * (1 + extra_slots)` little-endian bytes.
        pub fn build(&self) -> Vec<u8> {
            assert!((1..=3).contains(&self.blkptrs.len()));
            let total = DNODE_SIZE * (1 + self.extra_slots as usize);
            let mut b = vec![0u8; total];
            b[0] = self.object_type;
            b[1] = self.indblkshift;
            b[2] = self.nlevels;
            b[3] = self.blkptrs.len() as u8;
            b[4] = self.bonus_type;
            b[7] = FLAG_USED_BYTES
                | if self.spill.is_some() {
                    FLAG_SPILL_BLKPTR
                } else {
                    0
                };
            b[8..10]
                .copy_from_slice(&((self.datablksz >> blkptr::MINBLOCKSHIFT) as u16).to_le_bytes());
            b[10..12].copy_from_slice(&(self.bonus.len() as u16).to_le_bytes());
            b[12] = self.extra_slots;
            b[16..24].copy_from_slice(&self.maxblkid.to_le_bytes());
            for (i, bp) in self.blkptrs.iter().enumerate() {
                let at = DNODE_CORE_SIZE + i * blkptr::SIZE;
                b[at..at + blkptr::SIZE].copy_from_slice(bp);
            }
            let bonus_at = DNODE_CORE_SIZE + self.blkptrs.len() * blkptr::SIZE;
            b[bonus_at..bonus_at + self.bonus.len()].copy_from_slice(&self.bonus);
            if let Some(s) = &self.spill {
                b[total - blkptr::SIZE..].copy_from_slice(s);
            }
            b
        }
    }

    /// Serialise a 4096-byte objset block around `meta_dnode`.
    pub fn objset(meta_dnode: &[u8], os_type: u64) -> Vec<u8> {
        let mut b = vec![0u8; OBJSET_PHYS_SIZE];
        b[..DNODE_SIZE].copy_from_slice(&meta_dnode[..DNODE_SIZE]);
        b[704..712].copy_from_slice(&os_type.to_le_bytes());
        b
    }
}

#[cfg(test)]
mod tests {
    use super::encode::{objset, DnodeSpec};
    use super::*;
    use crate::blkptr::encode::Builder;

    fn bp(offset: u64) -> [u8; blkptr::SIZE] {
        Builder::new()
            .dva(0, 0, offset, 0x4000, false)
            .sizes(0x4000, 0x4000)
            .props(2, 7, ot::ZVOL, 0)
            .births(0, 9, 1)
            .bytes(Endian::Little)
    }

    #[test]
    fn dnode_roundtrip_with_spill() {
        let bonus: Vec<u8> = (0..100u8).collect();
        let raw = DnodeSpec {
            object_type: ot::ZVOL,
            indblkshift: 17,
            nlevels: 2,
            datablksz: 8192,
            maxblkid: 1000,
            blkptrs: vec![bp(0x1000)],
            bonus_type: ot::ZVOL_PROP,
            bonus: bonus.clone(),
            spill: Some(bp(0x2000)),
            extra_slots: 0,
        }
        .build();
        let d = DnodePhys::parse(&raw, Endian::Little).unwrap();
        assert_eq!(d.object_type, ot::ZVOL);
        assert_eq!(d.type_name(), "zvol object");
        assert_eq!((d.indblkshift, d.nlevels, d.nblkptr), (17, 2, 1));
        assert_eq!(d.datablksz(), 8192);
        assert_eq!(d.indblksz(), 128 * 1024);
        assert_eq!(d.ptrs_per_indirect(), 1024);
        assert_eq!(d.maxblkid, 1000);
        assert_eq!(d.bonus, bonus);
        assert_eq!(d.blkptr[0].dva[0].offset, 0x1000);
        assert_eq!(d.spill.as_ref().unwrap().dva[0].offset, 0x2000);
        assert_eq!(d.slot_bytes(), 512);
        assert!(!d.is_free());
    }

    #[test]
    fn large_dnode_and_three_pointers() {
        // 64 core + 3 * 128 pointers + 500 bonus = 948 <= 1024 (two slots).
        let raw = DnodeSpec {
            object_type: ot::DSL_DATASET,
            indblkshift: 14,
            blkptrs: vec![bp(1), bp(2), bp(3)],
            bonus: vec![7u8; 500],
            extra_slots: 1,
            ..DnodeSpec::default()
        }
        .build();
        assert_eq!(raw.len(), 1024);
        let d = DnodePhys::parse(&raw, Endian::Little).unwrap();
        assert_eq!(d.blkptr.len(), 3);
        assert_eq!(d.bonus.len(), 500);
        assert_eq!(d.slot_bytes(), 1024);
        assert!(d.spill.is_none());
        // Only the first slot given: truncated.
        assert!(matches!(
            DnodePhys::parse(&raw[..512], Endian::Little),
            Err(ParseError::Truncated { needed: 1024, .. })
        ));
    }

    #[test]
    fn free_and_malformed_dnodes() {
        let free = DnodePhys::parse(&[0u8; 512], Endian::Little).unwrap();
        assert!(free.is_free());
        assert_eq!(free.blkptr.len(), 0);
        let plain = DnodeSpec {
            object_type: ot::ZVOL,
            blkptrs: vec![bp(1)],
            ..DnodeSpec::default()
        };
        let mut bad = plain.build();
        bad[3] = 5; // nblkptr
        assert!(matches!(
            DnodePhys::parse(&bad, Endian::Little),
            Err(ParseError::Malformed { .. })
        ));
        let mut bad = DnodeSpec {
            spill: Some(bp(2)),
            ..plain
        }
        .build();
        bad[10..12].copy_from_slice(&400u16.to_le_bytes()); // bonus into spill
        assert!(matches!(
            DnodePhys::parse(&bad, Endian::Little),
            Err(ParseError::Malformed { .. })
        ));
    }

    #[test]
    fn objset_roundtrip() {
        let meta = DnodeSpec {
            object_type: ot::DNODE,
            nlevels: 3,
            datablksz: 16384,
            maxblkid: 5,
            blkptrs: vec![bp(0x100), bp(0x200), bp(0x300)],
            ..DnodeSpec::default()
        }
        .build();
        let raw = objset(&meta, 3);
        let os = ObjsetPhys::parse(&raw, Endian::Little).unwrap();
        assert_eq!(os.os_type, ObjsetType::Zvol);
        assert_eq!(os.os_type.name(), "volume");
        assert_eq!(os.meta_dnode.blkptr.len(), 3);
        assert_eq!(os.meta_dnode.datablksz(), 16384);
        assert!(os.zil_log.is_hole());
        assert!(os.userused_dnode.unwrap().is_free());
        assert!(os.projectused_dnode.is_some());
        let short = ObjsetPhys::parse(&raw[..2048], Endian::Little).unwrap();
        assert!(short.projectused_dnode.is_none());
        assert!(ObjsetPhys::parse(&raw[..1000], Endian::Little).is_err());
    }

    #[test]
    fn type_names() {
        assert_eq!(object_type_name(ot::DSL_DIR), "DSL directory");
        assert_eq!(object_type_name(0x80 | 0x40 | 4), "newtype(zap,metadata)");
        assert_eq!(
            object_type_name(0x80 | 0x20 | 3),
            "newtype(uint64,encrypted)"
        );
        assert_eq!(object_type_name(77), "unknown-77");
    }
}
