//! Telling a dnode from 512 bytes that merely look like one (COMPANIONS
//! C-02), and the profile that narrows which of them is worth following
//! (C-13…C-15).
//!
//! A carve reads raw vdev space, so most of what it looks at is not
//! metadata at all, and much of what is is metadata of something else.
//! Two separate questions therefore have to be answered about every
//! candidate, and kept apart:
//!
//! * *Could this be a dnode?* — structure only: every field inside the
//!   range OpenZFS's `dnode.h` allows it. This is a fact about the bytes.
//! * *Could this be the object being looked for?* — the search profile:
//!   block size, tree depth, birth window, size. This is the operator's
//!   knowledge, and it is a filter, never an assumption. Nothing that
//!   passes it is trusted for having passed: every block is still
//!   verified by its own checksum before a byte of it is used.
//!
//! Nothing here does I/O or knows about vdevs; the DVA-inside-a-member
//! test lives where the vdev tree does.

use crate::blkptr::{self, BlkPtr, Checksum, Compression};
use crate::dmu::{DnodePhys, OT_NEWTYPE};

/// Why a candidate was rejected.
///
/// One variant per reason so a run can count them (C-15): the operator
/// needs to see which single field is too tight, not that "nothing
/// matched".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reject {
    /// A free slot: `dn_type` is `DMU_OT_NONE`.
    Free,
    /// `dn_type` is not an object type this build knows.
    UnknownType,
    /// `dn_indblkshift` outside 9..=17.
    IndBlkShift,
    /// `dn_nlevels` outside 1..=7.
    NLevels,
    /// `dn_nblkptr` outside 1..=3.
    NBlkPtr,
    /// `dn_datablkszsec` is zero, not a power of two, or too large.
    DataBlkSz,
    /// `dn_bonuslen` does not fit in the slots the dnode claims.
    BonusLen,
    /// The checksum code is not one OpenZFS defines.
    ChecksumCode,
    /// The compression code is not one OpenZFS defines.
    CompressCode,
    /// Every block pointer is a hole: nothing to follow.
    NoBlocks,
    /// A block pointer's sizes or birth cannot be right.
    BadBlkptr,
    /// A block pointer addresses a place no member of this pool has.
    DvaOutside,
    /// The profile asked for another object type.
    ProfileType,
    /// The profile asked for another data block size.
    ProfileVolBlockSize,
    /// The profile asked for another tree depth.
    ProfileLevels,
    /// The birth TXG is outside the window the profile allows.
    ProfileTxg,
    /// The estimated size is outside the range the profile allows.
    ProfileSize,
}

impl Reject {
    /// Stable name, as counted on stderr and in JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            Reject::Free => "free",
            Reject::UnknownType => "dnode_type",
            Reject::IndBlkShift => "indblkshift",
            Reject::NLevels => "nlevels",
            Reject::NBlkPtr => "nblkptr",
            Reject::DataBlkSz => "datablksz",
            Reject::BonusLen => "bonuslen",
            Reject::ChecksumCode => "checksum_code",
            Reject::CompressCode => "compress_code",
            Reject::NoBlocks => "no_blocks",
            Reject::BadBlkptr => "blkptr",
            Reject::DvaOutside => "dva_outside",
            Reject::ProfileType => "profile_dnode_type",
            Reject::ProfileVolBlockSize => "profile_volblocksize",
            Reject::ProfileLevels => "profile_levels",
            Reject::ProfileTxg => "profile_txg",
            Reject::ProfileSize => "profile_size",
        }
    }

    /// Whether this rejection came from the search profile rather than
    /// from the bytes. A soft profile records these instead of dropping
    /// the hit (C-18).
    pub fn is_profile(self) -> bool {
        matches!(
            self,
            Reject::ProfileType
                | Reject::ProfileVolBlockSize
                | Reject::ProfileLevels
                | Reject::ProfileTxg
                | Reject::ProfileSize
        )
    }

    /// Every reason, for initialising counters in a fixed order.
    pub const ALL: [Reject; 17] = [
        Reject::Free,
        Reject::UnknownType,
        Reject::IndBlkShift,
        Reject::NLevels,
        Reject::NBlkPtr,
        Reject::DataBlkSz,
        Reject::BonusLen,
        Reject::ChecksumCode,
        Reject::CompressCode,
        Reject::NoBlocks,
        Reject::BadBlkptr,
        Reject::DvaOutside,
        Reject::ProfileType,
        Reject::ProfileVolBlockSize,
        Reject::ProfileLevels,
        Reject::ProfileSize,
        Reject::ProfileTxg,
    ];
}

/// The largest block OpenZFS will write (`SPA_MAXBLOCKSIZE`, 16 MiB with
/// `large_blocks`).
pub const MAX_BLOCKSIZE: u64 = 1 << 24;

/// Object types a carve will follow. Anything outside this is either a
/// type this build does not know or a byte that is not a type at all.
fn known_type(t: u8) -> bool {
    // The high bits are the new-type encoding: metadata, encrypted, and
    // the DMU_OTN_ marker. The low bits are the type proper.
    if t & OT_NEWTYPE != 0 {
        return true;
    }
    // DMU_OT_NUMTYPES is 54 in OpenZFS 2.2; leave room for a type a
    // newer pool may carry rather than calling its dnodes garbage.
    t <= 60
}

/// Could these bytes be a dnode? Structure only (C-02).
///
/// Every bound is the one OpenZFS's `dnode.h` enforces when it writes
/// one, so a slot that fails any of them was not written by ZFS as a
/// dnode — whatever else it may be.
pub fn plausible_dnode(d: &DnodePhys) -> Result<(), Reject> {
    if d.is_free() {
        return Err(Reject::Free);
    }
    if !known_type(d.object_type) {
        return Err(Reject::UnknownType);
    }
    if !(9..=17).contains(&d.indblkshift) {
        return Err(Reject::IndBlkShift);
    }
    if !(1..=7).contains(&d.nlevels) {
        return Err(Reject::NLevels);
    }
    if !(1..=3).contains(&d.nblkptr) {
        return Err(Reject::NBlkPtr);
    }
    let dbs = d.datablksz();
    if dbs == 0 || !dbs.is_power_of_two() || dbs > MAX_BLOCKSIZE {
        return Err(Reject::DataBlkSz);
    }
    let core = crate::dmu::DNODE_CORE_SIZE + d.nblkptr as usize * blkptr::SIZE;
    if core + d.bonuslen as usize > d.slot_bytes() {
        return Err(Reject::BonusLen);
    }
    let live: Vec<&BlkPtr> = d.blkptr.iter().filter(|b| !b.is_hole()).collect();
    if live.is_empty() {
        return Err(Reject::NoBlocks);
    }
    for b in live {
        if matches!(b.checksum, Checksum::Unknown(_)) {
            return Err(Reject::ChecksumCode);
        }
        if matches!(b.compression, Compression::Unknown(_)) {
            return Err(Reject::CompressCode);
        }
        if !plausible_blkptr(b) {
            return Err(Reject::BadBlkptr);
        }
    }
    Ok(())
}

/// Could this be a block pointer ZFS wrote?
///
/// An embedded pointer carries its payload instead of an address, so it
/// is judged on its sizes alone; everything else must have a first DVA,
/// sizes inside the block-size range, and a birth transaction group.
pub fn plausible_blkptr(b: &BlkPtr) -> bool {
    if b.is_hole() {
        return false;
    }
    if b.lsize == 0 || b.lsize > MAX_BLOCKSIZE {
        return false;
    }
    if b.embedded {
        return b.psize <= b.lsize;
    }
    if b.psize == 0 || b.psize > b.lsize {
        return false;
    }
    if b.birth == 0 {
        return false;
    }
    b.dva[0].asize != 0
}

/// An array of block pointers that could be an indirect block (C-03).
///
/// A real one is mostly holes near the end and otherwise consistent: the
/// pointers that are there address something, and none of them was born
/// after the block that holds them. `birth` is that block's own birth
/// transaction group; children are always at least as old.
pub fn plausible_indirect(bps: &[BlkPtr], birth: u64) -> bool {
    let live: Vec<&BlkPtr> = bps.iter().filter(|b| !b.is_hole()).collect();
    if live.is_empty() {
        return false;
    }
    live.iter()
        .all(|b| plausible_blkptr(b) && (birth == 0 || b.birth <= birth))
}

/// What the operator knows about the object being looked for (C-13).
///
/// Every field is optional and independent; an absent field filters
/// nothing. Applied at recognition time, before any tree is walked: a
/// search for one 300 GB volume must not pay to walk the trees of
/// everything else in the pool.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Profile {
    /// `dn_type` to look for. `None` means any known type.
    pub dnode_type: Option<u8>,
    /// Data block size in bytes (`volblocksize`).
    pub volblocksize: Option<u64>,
    /// Tree depth, `dn_nlevels`.
    pub levels: Option<u8>,
    /// Birth transaction group window, inclusive.
    pub txg: Option<(u64, u64)>,
    /// Estimated size range in bytes, inclusive.
    pub size: Option<(u64, u64)>,
}

impl Profile {
    /// Nothing is being asked for.
    pub fn is_empty(&self) -> bool {
        *self == Profile::default()
    }

    /// Size a dnode implies: one more block than the largest block id.
    ///
    /// It is what the dnode says, not what a `zvol_prop` ZAP would say,
    /// so it is an estimate — a volume whose tail was never written is
    /// smaller here than it was created.
    pub fn implied_size(d: &DnodePhys) -> u64 {
        d.datablksz().saturating_mul(d.maxblkid.saturating_add(1))
    }

    /// The newest transaction group any of the dnode's own pointers was
    /// born in: when the object was last written to.
    pub fn birth(d: &DnodePhys) -> u64 {
        d.blkptr
            .iter()
            .filter(|b| !b.is_hole())
            .map(|b| b.birth)
            .max()
            .unwrap_or(0)
    }

    /// Which of the profile's fields this dnode fails, in a fixed order.
    ///
    /// Empty means it matches everything asked for. The caller decides
    /// what to do with a failure: drop the hit, or record it with the
    /// field named and rank it below the ones that matched (C-18).
    pub fn misses(&self, d: &DnodePhys) -> Vec<Reject> {
        let mut out = Vec::new();
        if let Some(t) = self.dnode_type {
            if d.object_type != t {
                out.push(Reject::ProfileType);
            }
        }
        if let Some(bs) = self.volblocksize {
            if d.datablksz() != bs {
                out.push(Reject::ProfileVolBlockSize);
            }
        }
        if let Some(l) = self.levels {
            if d.nlevels != l {
                out.push(Reject::ProfileLevels);
            }
        }
        if let Some((from, to)) = self.txg {
            let birth = Profile::birth(d);
            if birth < from || birth > to {
                out.push(Reject::ProfileTxg);
            }
        }
        if let Some((min, max)) = self.size {
            let size = Profile::implied_size(d);
            if size < min || size > max {
                out.push(Reject::ProfileSize);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blkptr::encode::Builder;
    use crate::dmu::encode::DnodeSpec;
    use crate::dmu::ot;
    use crate::Endian;

    /// A block pointer to somewhere, born at `birth`.
    fn bp(birth: u64, lsize: u64) -> [u8; blkptr::SIZE] {
        Builder::new()
            .dva(0, 0, 0x20_0000, lsize, false)
            .sizes(lsize, lsize)
            .props(0, 2, ot::ZVOL, 0)
            .births(0, birth, 1)
            .bytes(Endian::Little)
    }

    /// A zvol dnode: 8 KiB blocks, two levels, one pointer, 64 blocks.
    fn zvol() -> DnodeSpec {
        DnodeSpec {
            object_type: ot::ZVOL,
            indblkshift: 17,
            nlevels: 2,
            datablksz: 8192,
            maxblkid: 63,
            blkptrs: vec![bp(4816229, 131072)],
            ..DnodeSpec::default()
        }
    }

    fn parse(spec: &DnodeSpec) -> DnodePhys {
        DnodePhys::parse(&spec.build(), Endian::Little).expect("built dnode parses")
    }

    #[test]
    fn a_zvol_dnode_is_plausible() {
        assert_eq!(plausible_dnode(&parse(&zvol())), Ok(()));
    }

    #[test]
    fn a_free_slot_is_not_a_hit() {
        let d = parse(&DnodeSpec::default());
        assert_eq!(plausible_dnode(&d), Err(Reject::Free));
    }

    /// Random bytes are rejected, and this is the property that matters:
    /// a carve looks at far more of them than of metadata.
    #[test]
    fn noise_is_not_a_dnode() {
        // A cheap deterministic generator: no dependency, and the point
        // is volume, not cryptographic quality.
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut accepted = 0;
        for _ in 0..20_000 {
            let mut buf = [0u8; crate::dmu::DNODE_SIZE];
            for chunk in buf.chunks_mut(8) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let b = state.to_le_bytes();
                chunk.copy_from_slice(&b[..chunk.len()]);
            }
            if let Ok(d) = DnodePhys::parse(&buf, Endian::Little) {
                if plausible_dnode(&d).is_ok() {
                    accepted += 1;
                }
            }
        }
        assert_eq!(
            accepted, 0,
            "{accepted} of 20000 random slots looked like dnodes"
        );
    }

    #[test]
    fn every_structural_bound_is_checked() {
        let cases: [(&str, DnodeSpec, Reject); 5] = [
            (
                "indblkshift",
                DnodeSpec {
                    indblkshift: 8,
                    ..zvol()
                },
                Reject::IndBlkShift,
            ),
            (
                "nlevels",
                DnodeSpec {
                    nlevels: 9,
                    ..zvol()
                },
                Reject::NLevels,
            ),
            (
                "datablksz not a power of two",
                DnodeSpec {
                    datablksz: 1536,
                    ..zvol()
                },
                Reject::DataBlkSz,
            ),
            (
                "datablksz too large",
                DnodeSpec {
                    datablksz: 1 << 25,
                    ..zvol()
                },
                Reject::DataBlkSz,
            ),
            (
                "every pointer a hole",
                DnodeSpec {
                    blkptrs: vec![[0u8; blkptr::SIZE]],
                    ..zvol()
                },
                Reject::NoBlocks,
            ),
        ];
        for (what, spec, want) in cases {
            assert_eq!(plausible_dnode(&parse(&spec)), Err(want), "{what}");
        }
    }

    #[test]
    fn an_unknown_checksum_code_is_not_followed() {
        let bad = Builder::new()
            .dva(0, 0, 0x20_0000, 8192, false)
            .sizes(8192, 8192)
            .props(0, 99, ot::ZVOL, 0)
            .births(0, 5, 1)
            .bytes(Endian::Little);
        let d = parse(&DnodeSpec {
            blkptrs: vec![bad],
            ..zvol()
        });
        assert_eq!(plausible_dnode(&d), Err(Reject::ChecksumCode));
    }

    #[test]
    fn an_empty_profile_filters_nothing() {
        assert!(Profile::default().is_empty());
        assert!(Profile::default().misses(&parse(&zvol())).is_empty());
    }

    #[test]
    fn each_profile_field_names_itself_when_it_fails() {
        let d = parse(&zvol());
        let cases = [
            (
                Profile {
                    volblocksize: Some(4096),
                    ..Profile::default()
                },
                Reject::ProfileVolBlockSize,
            ),
            (
                Profile {
                    levels: Some(3),
                    ..Profile::default()
                },
                Reject::ProfileLevels,
            ),
            (
                Profile {
                    txg: Some((1, 100)),
                    ..Profile::default()
                },
                Reject::ProfileTxg,
            ),
            (
                Profile {
                    size: Some((1 << 30, 1 << 40)),
                    ..Profile::default()
                },
                Reject::ProfileSize,
            ),
            (
                Profile {
                    dnode_type: Some(ot::PLAIN_FILE_CONTENTS),
                    ..Profile::default()
                },
                Reject::ProfileType,
            ),
        ];
        for (p, want) in cases {
            assert_eq!(p.misses(&d), vec![want], "{p:?}");
        }
    }

    /// The profile that describes the object matches it, and every field
    /// it names is one the dnode really carries.
    #[test]
    fn a_profile_taken_from_the_object_matches_it() {
        let d = parse(&zvol());
        let p = Profile {
            dnode_type: Some(ot::ZVOL),
            volblocksize: Some(8192),
            levels: Some(2),
            txg: Some((4816000, 4816300)),
            size: Some((64 * 8192, 64 * 8192)),
        };
        assert!(p.misses(&d).is_empty(), "{:?}", p.misses(&d));
        assert_eq!(Profile::implied_size(&d), 64 * 8192);
        assert_eq!(Profile::birth(&d), 4816229);
    }

    #[test]
    fn a_profile_rejection_is_told_from_a_structural_one() {
        assert!(Reject::ProfileLevels.is_profile());
        assert!(!Reject::NLevels.is_profile());
        // Every reason has a name, and no two share one.
        let mut names: Vec<&str> = Reject::ALL.iter().map(|r| r.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before);
    }

    #[test]
    fn an_indirect_block_is_consistent_with_its_own_birth() {
        let bps: Vec<BlkPtr> = [bp(90, 8192), bp(80, 8192)]
            .iter()
            .map(|b| BlkPtr::parse(b, Endian::Little).expect("parses"))
            .collect();
        assert!(plausible_indirect(&bps, 100));
        // A child born after the block that points at it cannot be one.
        assert!(!plausible_indirect(&bps, 85));
        assert!(!plausible_indirect(&[], 100));
    }
}
