//! Synthetic vdev members for tests and smoke runs.
//!
//! Builds images that carry real label structures — XDR nvlists with
//! embedded SHA-256 checksums and sealed uberblock slots — without any
//! data blocks. Enough for `scan` and pool assembly; the tool itself never
//! writes evidence, so nothing here is reachable from the binaries except
//! through explicit fixture generation.

use zfs_ondisk::blkptr::{self, encode::Builder, Compression, LABEL_START_SIZE};
use zfs_ondisk::checksum::seal_label;
use zfs_ondisk::dmu::encode::{objset, DnodeSpec};
use zfs_ondisk::dmu::{ot, DNODE_CORE_SIZE, DNODE_SIZE};
use zfs_ondisk::dsl::encode::{dsl_dataset, dsl_dir};
use zfs_ondisk::dsl::{DslDatasetPhys, DslDirPhys};
use zfs_ondisk::indirect;
use zfs_ondisk::label::{
    label_offsets, LABEL_SIZE, UBERBLOCK_RING_OFFSET, VDEV_PHYS_OFFSET, VDEV_PHYS_SIZE,
};
use zfs_ondisk::nvlist::encode::{list, pack};
use zfs_ondisk::nvlist::{NvList, Value};
use zfs_ondisk::uberblock::{MAGIC, MAX_UBERBLOCK_SHIFT, UBERBLOCK_SHIFT};
use zfs_ondisk::zap::encode::micro;
use zfs_ondisk::Endian;

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

/// One top-level vdev of a fixture pool, with everything a label of one
/// of its members says about the pool. A pool with several top-level
/// vdevs is several of these sharing name, GUID and uberblocks, one per
/// top, each with its own `top_id` — which is also how real labels
/// work: a member's label describes its own top-level vdev and nothing
/// of the others. [`two_top_mirror_members`] builds such a pool.
#[derive(Debug, Clone)]
pub struct Pool {
    /// Pool name.
    pub name: String,
    /// Pool GUID.
    pub guid: u64,
    /// `id` of this top-level vdev among the pool's; its guid is derived
    /// from it so that two tops never share one.
    pub top_id: u64,
    /// `asize` to write for the top-level vdev. `None` writes a large
    /// round number, as fixtures always have; a test that needs the
    /// labels to say how big the members really are sets it.
    pub asize: Option<u64>,
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
    /// Root block pointer to record in every uberblock (128 bytes); when
    /// `None` only the logical birth is filled in.
    pub rootbp: Option<[u8; blkptr::SIZE]>,
    /// Per-TXG root block pointers that override `rootbp` for that TXG,
    /// so different TXGs can describe different dataset trees.
    pub rootbp_by_txg: Vec<(u64, [u8; blkptr::SIZE])>,
    /// Active read-incompatible features to name in every label
    /// (SPEC F-70). The two a real pool always carries, unless a test
    /// adds one to see the tool refuse.
    pub features_for_read: Vec<String>,
}

impl Pool {
    /// A two-way mirror.
    pub fn mirror(name: &str, guid: u64, ashift: u32) -> Pool {
        Pool::mirror_of(name, guid, ashift, 2)
    }

    /// A mirror of `width` leaves. Three or four is what `zpool attach`
    /// leaves behind, and what the damage matrix meets when `ztest` has
    /// attached a side during its run.
    pub fn mirror_of(name: &str, guid: u64, ashift: u32, width: usize) -> Pool {
        Pool {
            name: name.into(),
            guid,
            top_id: 0,
            asize: None,
            ashift,
            kind: "mirror".into(),
            nparity: None,
            // Named the way a FreeBSD administrator names them: by the
            // GPT label, `/dev/gpt/<pool>-d<n>`, which is what F-71
            // matches a bare member against.
            members: (0..width)
                .map(|i| Member {
                    guid: Member::guid_for(guid, i),
                    path: format!("/dev/gpt/{name}-d{i}"),
                })
                .collect(),
            uberblocks: Vec::new(),
            vdev_children: 1,
            hostname: "fixture-host".into(),
            hostid: 0x1234_5678,
            state: 0,
            rootbp: None,
            rootbp_by_txg: Vec::new(),
            // What every pool in the cross-check carries, so a fixture
            // is refused for the same reasons a real pool would be and
            // for no others.
            features_for_read: vec![
                "com.delphix:hole_birth".into(),
                "com.delphix:embedded_data".into(),
            ],
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
                path: format!("/dev/gpt/{name}-d{i}"),
            })
            .collect();
        p
    }

    /// Set the uberblocks to record.
    pub fn txgs(mut self, txgs: &[(u64, u64)]) -> Pool {
        self.uberblocks = txgs.to_vec();
        self
    }

    /// Claim one more active read-incompatible feature (SPEC F-70).
    pub fn with_feature(mut self, name: &str) -> Pool {
        self.features_for_read.push(name.to_string());
        self
    }

    /// The top-level vdev tree as it appears in every member's label.
    /// The guid of this top-level vdev: distinct per `top_id`, and what
    /// `top_guid` in every member's label names.
    pub fn top_guid(&self) -> u64 {
        self.guid ^ 0xf0f0 ^ (self.top_id << 20)
    }

    fn tree(&self) -> NvList {
        let top_guid = self.top_guid();
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
            ("id", Value::Uint64(self.top_id)),
            ("guid", Value::Uint64(top_guid)),
            ("metaslab_array", Value::Uint64(65)),
            ("metaslab_shift", Value::Uint64(29)),
            ("ashift", Value::Uint64(self.ashift as u64)),
            ("asize", Value::Uint64(self.asize.unwrap_or(1 << 36))),
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
            ("top_guid", Value::Uint64(self.top_guid())),
            ("guid", Value::Uint64(self.members[i].guid)),
            ("vdev_children", Value::Uint64(self.vdev_children)),
            ("vdev_tree", Value::List(self.tree())),
            (
                "features_for_read",
                Value::List(list(
                    self.features_for_read
                        .iter()
                        .map(|n| (n.as_str(), Value::Boolean))
                        .collect::<Vec<_>>(),
                )),
            ),
        ])
    }

    /// Build the image of member `i` with `size` bytes: four sealed labels,
    /// nothing else.
    pub fn member_image(&self, i: usize, size: u64) -> Vec<u8> {
        let mut img = vec![0u8; size as usize];
        self.write_labels(i, &mut img);
        img
    }

    /// (Re)write the four labels of member `i` into an existing image,
    /// leaving everything else untouched.
    pub fn write_labels(&self, i: usize, img: &mut [u8]) {
        let size = img.len() as u64;
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
                        .fold(self.top_guid(), u64::wrapping_add),
                );
                w(ub, 32, *ts);
                let per_txg = self
                    .rootbp_by_txg
                    .iter()
                    .find(|(t, _)| t == txg)
                    .map(|(_, bp)| bp);
                match per_txg.or(self.rootbp.as_ref()) {
                    Some(bp) => ub[40..40 + blkptr::SIZE].copy_from_slice(bp),
                    None => w(ub, 40 + 80, *txg), // rootbp logical birth only
                }
                w(ub, 40 + 128, 5000); // software version
                seal_label(ub, ring_off);
            }
        }
        assert!(size >= 4 * LABEL_SIZE);
    }
}

/// Place `bytes` at DVA offset `offset` (relative to the allocatable
/// area) inside a member image, as a stripe/mirror leaf would store them.
pub fn write_at_dva(img: &mut [u8], offset: u64, bytes: &[u8]) {
    let start = (LABEL_START_SIZE + offset) as usize;
    img[start..start + bytes.len()].copy_from_slice(bytes);
}

/// How the fixture allocator lays blocks onto the members.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Every member holds the same bytes (stripe of one, or mirror).
    Mirror,
    /// RAIDZ with `nparity` parity columns over all members.
    Raidz {
        /// `ashift` of the top-level vdev.
        ashift: u32,
        /// Parity columns.
        nparity: u64,
    },
}

/// A bump allocator that stores uncompressed, fletcher4-checksummed
/// blocks on the member images of top-level vdev 0 and hands back the
/// block pointers.
#[derive(Debug)]
pub struct Alloc {
    next: u64,
    layout: Layout,
    /// Checksum algorithm recorded in the pointers written from now on.
    pub checksum: zfs_ondisk::blkptr::Checksum,
    /// Pool salt for salted algorithms; also written into the sample
    /// object directory when set.
    pub salt: Option<zfs_ondisk::checksum::Salt>,
    /// When set, blocks put through [`Alloc::put_removed`] are addressed
    /// on this top-level vdev — one the pool has since had removed —
    /// while their bytes are written where they always were. That is
    /// the shape `zpool remove` leaves behind: the pointers are never
    /// rewritten, so they go on naming a vdev that is gone (SPEC F-69).
    pub removed_vdev: Option<u32>,
    /// What it takes to translate those addresses back, in source order.
    pub mapping: Vec<indirect::Entry>,
    /// Next address to hand out in the removed vdev's own space.
    removed_next: u64,
    /// Top-level vdev the pointers handed out name.
    pub vdev: u32,
    /// Which of the member images this allocator writes to: the leaves
    /// of its top-level vdev. `None` is all of them.
    pub members: Option<std::ops::Range<usize>>,
    /// An allocator for another top-level vdev, which the sample builder
    /// uses for the volume's data blocks: with it set, the MOS lands on
    /// this allocator's top and the data on that one, so a read has to
    /// go through both.
    pub data: Option<Box<Alloc>>,
    /// Build the sample volume dense (SPEC N-03, N-08): every block
    /// present under a real indirect tree, of this size, block size and
    /// compression, in place of the two-block sample.
    pub dense: Option<Dense>,
    /// `fill` written into the pointers from now on: the number of
    /// non-hole level-0 blocks beneath. One for a data block; the dense
    /// builder sets it to the sum of a chunk's fills for the indirect
    /// pointer above the chunk, as ZFS keeps it, so `zdb`'s block
    /// accounting on the dense fixtures adds up.
    pub fill: u64,
    /// Build the sample volume deduplicated (SPEC F-28): its data
    /// pointers carry the dedup bit and a dedup-capable checksum
    /// (sha256), and its properties ZAP says `dedup=sha256,verify`.
    /// A reader that resolved anything through the DDT would need a
    /// table this fixture has none of; one that reads the pointers as
    /// the pointers they are needs nothing more.
    pub dedup: bool,
}

/// A dense volume for measurements (SPEC N-03, N-08): `bytes` of data
/// in blocks of `blocksize`, every one present, compressed as said.
#[derive(Debug, Clone)]
pub struct Dense {
    /// Volume size; a whole number of blocks.
    pub bytes: u64,
    /// `volblocksize`.
    pub blocksize: usize,
    /// `off`, `lz4` or `gzip-N`; anything else is not encoded here.
    pub compression: Compression,
}

impl Dense {
    /// Bytes of block `blkid`: incompressible noise for `off`, so the
    /// measurement reads what it reads; text-like bytes otherwise, so
    /// the decompressor has work to do.
    pub fn block(&self, blkid: u64) -> Vec<u8> {
        let mut out = vec![0u8; self.blocksize];
        let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ (blkid.wrapping_mul(0x2545_f491_4f6c_dd1d) | 1);
        if self.compression == Compression::Off {
            for chunk in out.chunks_mut(8) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
            }
        } else {
            let words: [&[u8]; 8] = [
                b"the quick ",
                b"brown fox ",
                b"jumps over ",
                b"the lazy ",
                b"dog while ",
                b"the pool ",
                b"resilvers ",
                b"quietly. ",
            ];
            let mut at = 0;
            let mut n = 0u64;
            while at < out.len() {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let piece = if n % 16 == 0 {
                    format!("[{blkid}:{n}] ").into_bytes()
                } else {
                    words[(state % 8) as usize].to_vec()
                };
                let take = piece.len().min(out.len() - at);
                out[at..at + take].copy_from_slice(&piece[..take]);
                at += take;
                n += 1;
            }
        }
        out
    }

    /// How many blocks the volume has.
    pub fn blocks(&self) -> u64 {
        self.bytes.div_ceil(self.blocksize as u64)
    }

    /// SHA-256 of the whole volume image, for the run that extracts it
    /// to be checked against.
    pub fn sha256(&self) -> String {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        let mut left = self.bytes;
        for b in 0..self.blocks() {
            let block = self.block(b);
            let take = (left as usize).min(block.len());
            h.update(&block[..take]);
            left -= take as u64;
        }
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// MOS object holding the properties set on `tank/vm/disk0`.
pub const SAMPLE_PROPS_OBJECT: u64 = 15;

/// MOS object the sample pool's configuration nvlist lives in — the
/// number its object directory has always named.
pub const CONFIG_OBJECT: u64 = 11;

/// MOS object the sample pool's removed-vdev mapping lives in.
pub const MAPPING_OBJECT: u64 = 14;

/// `DMU_OTN_UINT64_METADATA`: what a real pool's mapping object is, and
/// what `zdb` prints for one as `uint64`.
const MAPPING_OT: u8 = zfs_ondisk::dmu::OT_NEWTYPE | zfs_ondisk::dmu::OT_METADATA | 3;

/// Where the removed vdev's own address space starts in fixtures. It
/// bears no relation to where the bytes are: a reader that ignored the
/// mapping, or applied half of it, cannot land on them by luck.
pub const REMOVED_BASE: u64 = 0x40_0000;

/// Space left between one fixture mapping entry and the next, so that a
/// lookup which merely lands in the right neighbourhood is not the same
/// as one that lands in the right entry.
const REMOVED_GAP: u64 = 0x1_0000;

impl Alloc {
    /// Start allocating at DVA offset `start` on a mirror.
    pub fn new(start: u64) -> Alloc {
        Alloc::with_layout(start, Layout::Mirror)
    }

    /// Start allocating at DVA offset `start` with `layout`.
    pub fn with_layout(start: u64, layout: Layout) -> Alloc {
        Alloc {
            next: start,
            layout,
            checksum: zfs_ondisk::blkptr::Checksum::Fletcher4,
            salt: None,
            removed_vdev: None,
            mapping: Vec::new(),
            removed_next: REMOVED_BASE,
            vdev: 0,
            members: None,
            data: None,
            dense: None,
            fill: 1,
            dedup: false,
        }
    }

    /// The same, for top-level vdev `vdev`, writing to `members[range]`.
    pub fn for_top(start: u64, vdev: u32, range: std::ops::Range<usize>) -> Alloc {
        let mut a = Alloc::new(start);
        a.vdev = vdev;
        a.members = Some(range);
        a
    }

    /// The images this allocator writes to.
    fn mine<'m>(&self, members: &'m mut [Vec<u8>]) -> &'m mut [Vec<u8>] {
        match &self.members {
            Some(r) => &mut members[r.clone()],
            None => members,
        }
    }

    /// Store `data` as [`Alloc::put`] does, but hand back a pointer that
    /// addresses it on the removed vdev when one is set, recording what
    /// it takes to find the bytes again.
    ///
    /// With no removed vdev set this is exactly `put`, so a fixture that
    /// does not ask for one is byte-identical to what it was.
    pub fn put_removed(
        &mut self,
        members: &mut [Vec<u8>],
        data: &[u8],
        otype: u8,
        level: u8,
        txg: u64,
    ) -> [u8; blkptr::SIZE] {
        let dst = self.next;
        let mut bytes = self.put(members, data, otype, level, txg);
        let Some(vdev) = self.removed_vdev else {
            return bytes;
        };
        let asize = self.next - dst;
        let src = self.removed_next;
        self.removed_next += asize + REMOVED_GAP;
        // A range the removal copied in pieces is several entries, and
        // the reader has to join them. On a mirror anything big enough to
        // have been split is split, so both cases are covered by one
        // fixture. On a raidz destination the block stays one entry: a
        // stripe's column rotation depends on its offset, so half a block
        // read from the middle of a stripe is not the tail of that
        // stripe, and ZFS's removal copies allocated ranges whole there.
        let first = if asize >= 8192 && self.layout == Layout::Mirror {
            asize / 2
        } else {
            asize
        };
        self.mapping.push(indirect::Entry {
            src,
            size: first,
            dst_vdev: 0,
            dst_offset: dst,
        });
        if first < asize {
            self.mapping.push(indirect::Entry {
                src: src + first,
                size: asize - first,
                dst_vdev: 0,
                dst_offset: dst + first,
            });
        }
        // Only the address changes; the checksum is of the same bytes,
        // which is what makes a mistranslation show up as a mismatch.
        bytes[0..8].copy_from_slice(&(((vdev as u64) << 32) | (asize >> 9)).to_le_bytes());
        bytes[8..16].copy_from_slice(&(src >> 9).to_le_bytes());
        bytes
    }

    /// The mapping object's bonus for the entries handed out so far.
    pub fn mapping_phys(&self) -> Vec<u8> {
        let max = self.mapping.last().map(indirect::Entry::end).unwrap_or(0);
        let mut bonus = Vec::new();
        bonus.extend_from_slice(&max.to_le_bytes());
        bonus.extend_from_slice(
            &self
                .mapping
                .iter()
                .map(|e| e.size)
                .sum::<u64>()
                .to_le_bytes(),
        );
        bonus.extend_from_slice(&(self.mapping.len() as u64).to_le_bytes());
        // No obsolete-counts object: nothing here has been condensed.
        bonus.extend_from_slice(&0u64.to_le_bytes());
        bonus
    }

    /// The mapping object's data: the entries in their on-disk form.
    pub fn mapping_entries(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.mapping.len() * indirect::ENTRY_SIZE);
        for e in &self.mapping {
            out.extend_from_slice(&(e.src >> 9).to_le_bytes());
            out.extend_from_slice(&(((e.dst_vdev as u64) << 32) | (e.size >> 9)).to_le_bytes());
            out.extend_from_slice(&(e.dst_offset >> 9).to_le_bytes());
        }
        out
    }

    /// Checksum words for `padded` under the current algorithm and salt.
    fn cksum(&self, padded: &[u8]) -> [u64; 4] {
        zfs_ondisk::checksum::compute_salted(
            self.checksum,
            padded,
            Endian::Little,
            self.salt.as_ref(),
        )
        .expect("fixture checksum algorithm implemented")
    }

    /// Store `data` on `members`; return a block pointer with the given
    /// object type and level, born in `txg`.
    pub fn put(
        &mut self,
        members: &mut [Vec<u8>],
        data: &[u8],
        otype: u8,
        level: u8,
        txg: u64,
    ) -> [u8; blkptr::SIZE] {
        self.put_raw(members, data, data.len() as u64, 2, otype, level, txg)
    }

    /// [`put`](Self::put), with `data` compressed as `comp` first —
    /// `lz4` in ZFS's framing (a big-endian length, then the block) or
    /// `gzip` as the zlib stream ZFS stores — and the pointer carrying
    /// the logical size and the compression code. A block that does not
    /// shrink is stored as it is, as ZFS stores it.
    pub fn put_compressed(
        &mut self,
        members: &mut [Vec<u8>],
        data: &[u8],
        comp: Compression,
        otype: u8,
        level: u8,
        txg: u64,
    ) -> [u8; blkptr::SIZE] {
        let (payload, code) = match comp {
            Compression::Off => (data.to_vec(), 2u8),
            Compression::Lz4 => {
                let block = lz4_flex::block::compress(data);
                let mut v = (block.len() as u32).to_be_bytes().to_vec();
                v.extend_from_slice(&block);
                (v, 15)
            }
            Compression::Gzip(level) => {
                use std::io::Write;
                let mut enc = flate2::write::ZlibEncoder::new(
                    Vec::new(),
                    flate2::Compression::new(u32::from(level)),
                );
                enc.write_all(data).expect("in-memory");
                (enc.finish().expect("in-memory"), 4 + level)
            }
            other => panic!("the fixture does not encode {other:?}"),
        };
        if payload.len() >= data.len() {
            return self.put_raw(members, data, data.len() as u64, 2, otype, level, txg);
        }
        self.put_raw(
            members,
            &payload,
            data.len() as u64,
            code,
            otype,
            level,
            txg,
        )
    }

    /// Write `data` as one block and return its pointer, with `lsize`
    /// as the logical size and `comp` as the compression code.
    #[allow(clippy::too_many_arguments)]
    fn put_raw(
        &mut self,
        members: &mut [Vec<u8>],
        data: &[u8],
        lsize: u64,
        comp: u8,
        otype: u8,
        level: u8,
        txg: u64,
    ) -> [u8; blkptr::SIZE] {
        match self.layout {
            Layout::Mirror => {
                let size = data.len().div_ceil(512) * 512;
                // An uncompressed block is as long as what was written,
                // padding included; only a compressed one has a logical
                // size of its own.
                let lsize = if comp == 2 { size as u64 } else { lsize };
                let mut padded = data.to_vec();
                padded.resize(size, 0);
                let offset = self.next;
                self.next += size as u64;
                for m in self.mine(members).iter_mut() {
                    write_at_dva(m, offset, &padded);
                }
                self.bp(
                    offset,
                    size as u64,
                    size as u64,
                    lsize,
                    comp,
                    &padded,
                    otype,
                    level,
                    txg,
                )
            }
            Layout::Raidz { ashift, nparity } => {
                let unit = 1usize << ashift;
                let size = data.len().div_ceil(unit) * unit;
                let lsize = if comp == 2 { size as u64 } else { lsize };
                let mut padded = data.to_vec();
                padded.resize(size, 0);
                let offset = self.next;
                let members = self.mine(members);
                let m = zfs_ondisk::raidz::map(
                    offset,
                    size as u64,
                    ashift,
                    members.len() as u64,
                    nparity,
                );
                let mut cols: Vec<Vec<u8>> = Vec::new();
                let mut at = 0usize;
                for c in m.data() {
                    let n = c.size as usize;
                    cols.push(padded[at..at + n].to_vec());
                    at += n;
                }
                let parity = zfs_ondisk::raidz::generate_parity(&cols, nparity as usize);
                for (c, bytes) in m.parity().iter().zip(parity.iter()) {
                    write_at_dva(
                        &mut members[c.devidx as usize],
                        c.offset,
                        &bytes[..c.size as usize],
                    );
                }
                for (c, bytes) in m.data().iter().zip(cols.iter()) {
                    write_at_dva(&mut members[c.devidx as usize], c.offset, bytes);
                }
                self.next += m.asize;
                self.bp(
                    offset,
                    m.asize,
                    size as u64,
                    lsize,
                    comp,
                    &padded,
                    otype,
                    level,
                    txg,
                )
            }
        }
    }

    /// Store `data` as a gang block: the pieces become ordinary blocks,
    /// and a sealed 512-byte gang header at the returned pointer's DVA
    /// (gang bit set) lists them. `pieces` gives the byte length of each
    /// of up to three children (they must sum to `data.len()`). On a
    /// raidz layout the header is striped like any block of its size —
    /// one data column padded to the unit, plus parity — which is how
    /// ZFS allocates a gang header there.
    pub fn put_gang(
        &mut self,
        members: &mut [Vec<u8>],
        data: &[u8],
        pieces: &[usize],
        otype: u8,
        txg: u64,
    ) -> [u8; blkptr::SIZE] {
        assert!(
            pieces.len() <= blkptr::GANG_NBLKPTRS && pieces.iter().sum::<usize>() == data.len()
        );
        let mut children = Vec::new();
        let mut at = 0usize;
        for &n in pieces {
            children.push(self.put(members, &data[at..at + n], otype, 0, txg));
            at += n;
        }
        let offset = self.next;
        let mut header = vec![0u8; blkptr::GANG_HEADER_SIZE];
        for (i, c) in children.iter().enumerate() {
            header[i * blkptr::SIZE..(i + 1) * blkptr::SIZE].copy_from_slice(c);
        }
        zfs_ondisk::checksum::seal_embedded(&mut header, [0, offset, txg, 0]);
        let asize = match self.layout {
            Layout::Mirror => {
                for m in members.iter_mut() {
                    write_at_dva(m, offset, &header);
                }
                blkptr::GANG_HEADER_SIZE as u64
            }
            Layout::Raidz { ashift, nparity } => {
                let unit = 1usize << ashift;
                let mut row = header.clone();
                row.resize(unit, 0);
                let members = self.mine(members);
                let m = zfs_ondisk::raidz::map(
                    offset,
                    unit as u64,
                    ashift,
                    members.len() as u64,
                    nparity,
                );
                let cols: Vec<Vec<u8>> = m
                    .data()
                    .iter()
                    .scan(0usize, |at, c| {
                        let n = c.size as usize;
                        let col = row[*at..*at + n].to_vec();
                        *at += n;
                        Some(col)
                    })
                    .collect();
                let parity = zfs_ondisk::raidz::generate_parity(&cols, nparity as usize);
                for (c, bytes) in m.parity().iter().zip(parity.iter()) {
                    write_at_dva(
                        &mut members[c.devidx as usize],
                        c.offset,
                        &bytes[..c.size as usize],
                    );
                }
                for (c, bytes) in m.data().iter().zip(cols.iter()) {
                    write_at_dva(&mut members[c.devidx as usize], c.offset, bytes);
                }
                m.asize
            }
        };
        self.next += asize;
        let size = data.len().div_ceil(512) * 512;
        let mut padded = data.to_vec();
        padded.resize(size, 0);
        Builder::new()
            .dva(0, 0, offset, asize, true)
            .sizes(size as u64, size as u64)
            .props(2, self.checksum.code(), otype, 0)
            .births(0, txg, 1)
            .cksum(self.cksum(&padded))
            .bytes(Endian::Little)
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    fn bp(
        &self,
        offset: u64,
        asize: u64,
        psize: u64,
        lsize: u64,
        comp: u8,
        padded: &[u8],
        otype: u8,
        level: u8,
        txg: u64,
    ) -> [u8; blkptr::SIZE] {
        Builder::new()
            .dva(0, self.vdev, offset, asize, false)
            .sizes(lsize, psize)
            .props(comp, self.checksum.code(), otype, level)
            .flags(false, self.dedup && otype == ot::ZVOL && level == 0)
            .births(0, txg, self.fill)
            .cksum(self.cksum(padded))
            .bytes(Endian::Little)
    }
}

/// A `dsl_dataset_phys_t` for fixtures.
pub fn dataset_phys(
    dir: u64,
    next_snap: u64,
    bp: &[u8; blkptr::SIZE],
    txg: u64,
    guid: u64,
    snapnames: u64,
) -> DslDatasetPhys {
    DslDatasetPhys {
        dir_obj: dir,
        prev_snap_obj: 0,
        prev_snap_txg: 0,
        next_snap_obj: next_snap,
        snapnames_zapobj: snapnames,
        num_children: 1,
        creation_time: 1_700_000_000 + txg,
        creation_txg: txg,
        deadlist_obj: 0,
        referenced_bytes: 1 << 20,
        compressed_bytes: 0,
        uncompressed_bytes: 0,
        unique_bytes: 0,
        fsid_guid: 0,
        guid,
        flags: 0,
        bp: blkptr::BlkPtr::parse(bp, Endian::Little).expect("valid pointer"),
        next_clones_obj: 0,
        props_obj: 0,
        userrefs_obj: 0,
    }
}

/// DVA offset of the sample volume's block 0 when `build_sample_mos` runs
/// on an allocator started at `0x20_0000`: the filesystem objset block
/// (4 KiB) comes first.
pub const SAMPLE_ZVOL_BLOCK0_OFFSET: u64 = 0x20_0000 + 4096;

/// Contents of block `blkid` of the sample volume (8 KiB).
pub fn zvol_pattern(blkid: u64) -> Vec<u8> {
    let mut block: Vec<u8> = (0..8192u64)
        .map(|i| ((blkid * 97 + i * 7) % 251) as u8)
        .collect();
    if blkid == 0 {
        // A real volume holds a filesystem, and its superblock is what
        // says how large the volume was made for — the one number a
        // carved dnode cannot know (COMPANIONS C-12). This one says the
        // 32 MiB the volume's properties also say, in 8192 blocks of
        // 4096 bytes.
        let put = |b: &mut Vec<u8>, at: usize, bytes: &[u8]| {
            b[at..at + bytes.len()].copy_from_slice(bytes);
        };
        put(&mut block, 1024 + 0x38, &0xef53u16.to_le_bytes()); // s_magic
        put(&mut block, 1024 + 0x18, &2u32.to_le_bytes()); // 1024 << 2
        put(&mut block, 1024 + 0x04, &8192u32.to_le_bytes()); // s_blocks_count_lo
        put(&mut block, 1024 + 0x150, &0u32.to_le_bytes()); // s_blocks_count_hi
        put(&mut block, 1024 + 0x78, b"fixture\0\0\0\0\0\0\0\0\0"); // s_volume_name
    }
    block
}

/// Write a small MOS onto `members` describing `tank` (filesystem),
/// `tank/vm` (filesystem), `tank/vm/disk0` (32 MiB volume, 8 KiB blocks)
/// with snapshot `@before`, plus a `$MOS` bookkeeping directory, and
/// point `pool.rootbp` at it. Call `pool.write_labels()` afterwards.
pub fn build_sample_mos(pool: &mut Pool, members: &mut [Vec<u8>], a: &mut Alloc) {
    pool.rootbp = Some(build_sample_mos_variant(members, a, true));
}

/// Like [`build_sample_mos`] but returns the root pointer instead of
/// setting it, and with `with_disk0 = false` describes the tree *after*
/// `zfs destroy tank/vm/disk0`: the `vm` children ZAP is empty and the
/// volume's objects are gone.
pub fn build_sample_mos_variant(
    members: &mut [Vec<u8>],
    a: &mut Alloc,
    with_disk0: bool,
) -> [u8; blkptr::SIZE] {
    let m = members;
    let empty_meta = DnodeSpec {
        object_type: ot::DNODE,
        ..DnodeSpec::default()
    }
    .build();
    let os_fs = a.put(m, &objset(&empty_meta, 2), ot::OBJSET, 0, 100);
    let mut zvol_dnodes = vec![0u8; 4096];
    // Data blocks 0 and 2 of the volume; 1 and 3 are holes.
    if with_disk0 && a.layout == Layout::Mirror && a.data.is_none() && a.dense.is_none() {
        assert_eq!(
            a.next, SAMPLE_ZVOL_BLOCK0_OFFSET,
            "sample layout changed: update SAMPLE_ZVOL_BLOCK0_OFFSET"
        );
    }
    // With a salt, the volume's own blocks use blake3 like a dataset with
    // checksum=blake3 would; MOS metadata stays fletcher4.
    let plain = a.checksum;
    if a.salt.is_some() {
        a.checksum = zfs_ondisk::blkptr::Checksum::Blake3;
    } else if a.dedup {
        // Deduplicated blocks carry a dedup-capable checksum, as
        // `dedup=sha256` makes them (SPEC F-28).
        a.checksum = zfs_ondisk::blkptr::Checksum::Sha256;
    }
    // On another top-level vdev when the fixture has one for data.
    let (blk0, blk2) = match a.data.as_mut() {
        Some(d) => (
            d.put_removed(m, &zvol_pattern(0), ot::ZVOL, 0, 100),
            d.put_removed(m, &zvol_pattern(2), ot::ZVOL, 0, 100),
        ),
        None => (
            a.put_removed(m, &zvol_pattern(0), ot::ZVOL, 0, 100),
            a.put_removed(m, &zvol_pattern(2), ot::ZVOL, 0, 100),
        ),
    };
    a.checksum = plain;
    let (data_obj, volsize, volblocksize) = match a.dense.clone() {
        // The dense volume (SPEC N-03, N-08): every block present, and
        // an indirect tree of 128 KiB blocks above them, as many levels
        // as it takes for one pointer to hold the lot. Indirect blocks
        // are compressed the way the data is, as ZFS would.
        Some(d) if with_disk0 => {
            let mut bps: Vec<[u8; blkptr::SIZE]> = (0..d.blocks())
                .map(|b| a.put_compressed(m, &d.block(b), d.compression, ot::ZVOL, 0, 100))
                .collect();
            // Every data block is present, so each pointer's fill is
            // the number of level-0 blocks beneath it: 1 here, and the
            // sum of a chunk's fills for the pointer above the chunk.
            let mut fills: Vec<u64> = vec![1; bps.len()];
            let indblkshift = 17u8;
            let per = (1usize << indblkshift) / blkptr::SIZE;
            let mut level = 0u8;
            while bps.len() > 1 {
                level += 1;
                let (next_bps, next_fills): (Vec<_>, Vec<_>) = bps
                    .chunks(per)
                    .zip(fills.chunks(per))
                    .map(|(chunk, chunk_fills)| {
                        let mut blk = vec![0u8; 1 << indblkshift];
                        for (i, bp) in chunk.iter().enumerate() {
                            blk[i * blkptr::SIZE..(i + 1) * blkptr::SIZE].copy_from_slice(bp);
                        }
                        let comp = if d.compression == Compression::Off {
                            Compression::Off
                        } else {
                            Compression::Lz4
                        };
                        let fill: u64 = chunk_fills.iter().sum();
                        a.fill = fill;
                        let bp = a.put_compressed(m, &blk, comp, ot::ZVOL, level, 100);
                        a.fill = 1;
                        (bp, fill)
                    })
                    .unzip();
                bps = next_bps;
                fills = next_fills;
            }
            let obj = DnodeSpec {
                object_type: ot::ZVOL,
                indblkshift,
                nlevels: level + 1,
                datablksz: d.blocksize as u64,
                maxblkid: d.blocks() - 1,
                blkptrs: bps,
                ..DnodeSpec::default()
            }
            .build();
            (obj, d.bytes, d.blocksize as u64)
        }
        _ => (
            DnodeSpec {
                object_type: ot::ZVOL,
                datablksz: 8192,
                maxblkid: 3,
                blkptrs: vec![blk0, [0u8; blkptr::SIZE], blk2],
                ..DnodeSpec::default()
            }
            .build(),
            32 << 20,
            8192,
        ),
    };
    zvol_dnodes[DNODE_SIZE..2 * DNODE_SIZE].copy_from_slice(&data_obj);
    let props_blk = a.put(
        m,
        &micro(4096, &[("size", volsize), ("volblocksize", volblocksize)]),
        ot::ZVOL_PROP,
        0,
        100,
    );
    let props_obj = DnodeSpec {
        object_type: ot::ZVOL_PROP,
        datablksz: 4096,
        blkptrs: vec![props_blk],
        ..DnodeSpec::default()
    }
    .build();
    zvol_dnodes[2 * DNODE_SIZE..3 * DNODE_SIZE].copy_from_slice(&props_obj);
    let zvol_dnode_blk = a.put(m, &zvol_dnodes, ot::DNODE, 0, 100);
    let zvol_meta = DnodeSpec {
        object_type: ot::DNODE,
        datablksz: 4096,
        blkptrs: vec![zvol_dnode_blk],
        ..DnodeSpec::default()
    }
    .build();
    let os_zvol = a.put(m, &objset(&zvol_meta, 3), ot::OBJSET, 0, 100);

    let mut dnodes = vec![0u8; 16384];
    let mut put = |obj: u64, bytes: Vec<u8>| {
        let at = obj as usize * DNODE_SIZE;
        dnodes[at..at + bytes.len()].copy_from_slice(&bytes);
    };
    let zap_obj = |a: &mut Alloc, m: &mut [Vec<u8>], entries: &[(&str, u64)]| {
        let blk = a.put(m, &micro(4096, entries), ot::DSL_DIR_CHILD_MAP, 0, 100);
        DnodeSpec {
            object_type: ot::DSL_DIR_CHILD_MAP,
            datablksz: 4096,
            blkptrs: vec![blk],
            ..DnodeSpec::default()
        }
        .build()
    };
    let dir_obj_with = |head: u64, children: u64, parent: u64, props: u64| {
        DnodeSpec {
            object_type: ot::DSL_DIR,
            bonus_type: ot::DSL_DIR,
            bonus: dsl_dir(&DslDirPhys {
                head_dataset_obj: head,
                child_dir_zapobj: children,
                parent_obj: parent,
                props_zapobj: props,
                ..Default::default()
            }),
            ..DnodeSpec::default()
        }
        .build()
    };
    let dir_obj = |head: u64, children: u64, parent: u64| dir_obj_with(head, children, parent, 0);
    let ds_obj = |d: &DslDatasetPhys| {
        DnodeSpec {
            object_type: ot::DSL_DATASET,
            bonus_type: ot::DSL_DATASET,
            bonus: dsl_dataset(d),
            ..DnodeSpec::default()
        }
        .build()
    };
    if let Some(salt) = a.salt {
        // A byte-array entry forces a fatzap: header block + one leaf.
        let hdr = zfs_ondisk::zap::encode::fat_header(4096, 1, 3);
        let lf = zfs_ondisk::zap::encode::leaf(
            4096,
            &[
                ("root_dataset", 8, 2u64.to_be_bytes().to_vec()),
                ("config", 8, 11u64.to_be_bytes().to_vec()),
                (crate::dsl::CHECKSUM_SALT, 1, salt.to_vec()),
            ],
        );
        let b0 = a.put(m, &hdr, ot::OBJECT_DIRECTORY, 0, 100);
        let b1 = a.put(m, &lf, ot::OBJECT_DIRECTORY, 0, 100);
        put(
            1,
            DnodeSpec {
                object_type: ot::OBJECT_DIRECTORY,
                datablksz: 4096,
                maxblkid: 1,
                blkptrs: vec![b0, b1],
                ..DnodeSpec::default()
            }
            .build(),
        );
    } else {
        put(1, zap_obj(a, m, &[("root_dataset", 2), ("config", 11)]));
    }
    put(2, dir_obj(3, 4, 0));
    put(3, ds_obj(&dataset_phys(2, 0, &os_fs, 4, 0xa1, 0)));
    put(4, zap_obj(a, m, &[("vm", 5), ("$MOS", 9)]));
    put(5, dir_obj(6, 7, 2));
    put(6, ds_obj(&dataset_phys(5, 0, &os_fs, 20, 0xa2, 0)));
    put(9, dir_obj(0, 0, 2));
    if with_disk0 {
        put(7, zap_obj(a, m, &[("disk0", 12)]));
        // Properties set on the volume (SPEC F-14). A byte-array value
        // forces a fatzap, which is what a ZAP holding a user property
        // really is: a microzap entry is one 64-bit integer and cannot
        // hold a string at all.
        let mut entries = vec![
            ("compression", 8, 15u64.to_be_bytes().to_vec()),
            ("checksum", 8, 12u64.to_be_bytes().to_vec()),
            ("org.example:ticket", 1, b"RT-4471\0".to_vec()),
        ];
        if a.dedup {
            // `dedup=sha256,verify`: the zio_checksum code with the
            // verify flag above it (SPEC F-14, F-28).
            entries.push((
                "dedup",
                8,
                (8u64 | zfs_ondisk::props::DEDUP_VERIFY)
                    .to_be_bytes()
                    .to_vec(),
            ));
        }
        let hdr = zfs_ondisk::zap::encode::fat_header(4096, 1, entries.len() as u64);
        let lf = zfs_ondisk::zap::encode::leaf(4096, &entries);
        let h = a.put(m, &hdr, ot::DSL_PROPS, 0, 100);
        let l = a.put(m, &lf, ot::DSL_PROPS, 0, 100);
        put(
            SAMPLE_PROPS_OBJECT,
            DnodeSpec {
                object_type: ot::DSL_PROPS,
                datablksz: 4096,
                maxblkid: 1,
                blkptrs: vec![h, l],
                ..DnodeSpec::default()
            }
            .build(),
        );
        put(12, dir_obj_with(13, 0, 5, SAMPLE_PROPS_OBJECT));
        put(13, ds_obj(&dataset_phys(12, 0, &os_zvol, 30, 0xa3, 8)));
        put(8, zap_obj(a, m, &[("before", 10)]));
        put(10, ds_obj(&dataset_phys(12, 13, &os_zvol, 25, 0xa4, 0)));
    } else {
        put(7, zap_obj(a, m, &[]));
    }

    // A pool a top-level vdev was removed from (SPEC F-69). The volume's
    // data blocks above are addressed on it; these two objects are what
    // says where those bytes actually went.
    //
    // The configuration object carries the removed vdev and nothing
    // else. It is the only account of one — removal takes its members
    // away, so no label describes it — but the live vdevs are described
    // by the labels already, and writing a second, unchecked account of
    // them here would be inventing evidence rather than providing it.
    if let Some(vdev) = a.removed_vdev {
        let entries = a.mapping_entries();
        let bonus = a.mapping_phys();
        let blk = a.put(m, &entries, MAPPING_OT, 0, 100);
        put(
            MAPPING_OBJECT,
            DnodeSpec {
                object_type: MAPPING_OT,
                datablksz: 4096,
                blkptrs: vec![blk],
                bonus_type: MAPPING_OT,
                bonus,
                ..DnodeSpec::default()
            }
            .build(),
        );
        let config = pack(&list(vec![(
            "vdev_tree",
            Value::List(list(vec![
                ("type", Value::String("root".into())),
                ("id", Value::Uint64(0)),
                (
                    "children",
                    Value::ListArray(vec![list(vec![
                        ("type", Value::String("indirect".into())),
                        ("id", Value::Uint64(u64::from(vdev))),
                        ("guid", Value::Uint64(0x1de_0000 + u64::from(vdev))),
                        ("com.delphix:indirect_object", Value::Uint64(MAPPING_OBJECT)),
                    ])]),
                ),
            ])),
        )]));
        assert!(
            config.len() <= 4096,
            "fixture config object outgrew a block"
        );
        let blk = a.put(m, &config, ot::PACKED_NVLIST, 0, 100);
        put(
            CONFIG_OBJECT,
            DnodeSpec {
                object_type: ot::PACKED_NVLIST,
                datablksz: 4096,
                blkptrs: vec![blk],
                bonus_type: ot::PACKED_NVLIST_SIZE,
                bonus: (config.len() as u64).to_le_bytes().to_vec(),
                ..DnodeSpec::default()
            }
            .build(),
        );
    }

    let dnode_blk = a.put(m, &dnodes, ot::DNODE, 0, 100);
    let meta = DnodeSpec {
        object_type: ot::DNODE,
        datablksz: 16384,
        blkptrs: vec![dnode_blk],
        ..DnodeSpec::default()
    }
    .build();
    a.put(m, &objset(&meta, 1), ot::OBJSET, 0, 100)
}

/// A mirror whose volume data blocks are addressed on a top-level vdev
/// the pool has since had removed (SPEC F-69).
///
/// The pointers still name the vdev that is gone — removal never
/// rewrites them — the bytes are on the vdev that remains, and the MOS
/// carries the mapping between the two. The labels go on counting the
/// removed vdev in `vdev_children`, because removing a vdev is not the
/// same as forgetting it, and name `device_removal` as active.
pub fn removed_vdev_members(pool: &mut Pool, size: u64) -> Vec<Vec<u8>> {
    let n = pool.members.len();
    let mut members: Vec<Vec<u8>> = (0..n).map(|_| vec![0u8; size as usize]).collect();
    let layout = match pool.nparity {
        Some(p) if pool.kind == "raidz" => Layout::Raidz {
            ashift: pool.ashift,
            nparity: p,
        },
        _ => Layout::Mirror,
    };
    let mut a = Alloc::with_layout(0x20_0000, layout);
    a.removed_vdev = Some(1);
    build_sample_mos(pool, &mut members, &mut a);
    pool.vdev_children = 2;
    pool.features_for_read
        .push("com.delphix:device_removal".into());
    for (i, img) in members.iter_mut().enumerate() {
        pool.write_labels(i, img);
    }
    members
}

/// Where the volume's first data block lives on the *second* top-level
/// vdev of a [`two_top_mirror_members`] pool: its allocator starts here.
pub const TWO_TOP_DATA_OFFSET: u64 = 0x30_0000;

/// A pool of two top-level mirrors — `mirror-0` of `widths[0]` leaves
/// holding the MOS, `mirror-1` of `widths[1]` leaves holding the
/// volume's data — the "RAID10" shape, and the smallest pool a read
/// has to cross top-level vdevs to complete (SPEC §9, "one pool,
/// several geometries").
///
/// Every member's label describes only its own top, as real labels do:
/// take away every member of `mirror-1` and nothing left says what it
/// was. Returns one [`Pool`] per top (the same pool, seen from each) and
/// the member images, `mirror-0`'s first.
pub fn two_top_mirror_members(
    name: &str,
    guid: u64,
    ashift: u32,
    widths: [usize; 2],
    txgs: &[(u64, u64)],
    size: u64,
) -> (Vec<Pool>, Vec<Vec<u8>>) {
    let total = widths[0] + widths[1];
    let mut members: Vec<Vec<u8>> = (0..total).map(|_| vec![0u8; size as usize]).collect();
    let mut a = Alloc::new(0x20_0000);
    a.members = Some(0..widths[0]);
    a.data = Some(Box::new(Alloc::for_top(
        TWO_TOP_DATA_OFFSET,
        1,
        widths[0]..total,
    )));
    let rootbp = build_sample_mos_variant(&mut members, &mut a, true);
    let mut tops = Vec::new();
    for (top_id, range) in [(0u64, 0..widths[0]), (1, widths[0]..total)] {
        let mut p = Pool::mirror_of(name, guid, ashift, range.len()).txgs(txgs);
        p.top_id = top_id;
        p.vdev_children = 2;
        p.members = range
            .clone()
            .map(|i| Member {
                guid: Member::guid_for(guid, i),
                path: format!("/dev/gpt/{name}-d{i}"),
            })
            .collect();
        p.rootbp = Some(rootbp);
        for (k, i) in range.enumerate() {
            p.write_labels(k, &mut members[i]);
        }
        tops.push(p);
    }
    (tops, members)
}

/// A mirror whose newest TXG no longer has `tank/vm/disk0` while the
/// older ones still do — the SPEC UC-1 scenario. Returns the member
/// images and the TXGs `(destroyed_at, last_with_disk0)`.
pub fn destroyed_zvol_members(pool: &mut Pool, size: u64) -> (Vec<Vec<u8>>, u64, u64) {
    destroyed_zvol_members_with(pool, size, false)
}

fn destroyed_zvol_members_with(
    pool: &mut Pool,
    size: u64,
    dedup: bool,
) -> (Vec<Vec<u8>>, u64, u64) {
    let txgs: Vec<u64> = pool.uberblocks.iter().map(|(t, _)| *t).collect();
    assert!(txgs.len() >= 2, "need at least two uberblocks");
    let newest = *txgs.last().expect("non-empty");
    let previous = txgs[txgs.len() - 2];
    let n = pool.members.len();
    let mut members: Vec<Vec<u8>> = (0..n).map(|_| vec![0u8; size as usize]).collect();
    let layout = match pool.nparity {
        Some(p) if pool.kind == "raidz" => Layout::Raidz {
            ashift: pool.ashift,
            nparity: p,
        },
        _ => Layout::Mirror,
    };
    let mut alloc = Alloc::with_layout(0x20_0000, layout);
    alloc.dedup = dedup;
    let with = build_sample_mos_variant(&mut members, &mut alloc, true);
    let without = build_sample_mos_variant(&mut members, &mut alloc, false);
    pool.rootbp = Some(with);
    pool.rootbp_by_txg = vec![(newest, without)];
    for (i, img) in members.iter_mut().enumerate() {
        pool.write_labels(i, img);
    }
    (members, newest, previous)
}

/// [`destroyed_zvol_members`] with `tank/vm/disk0` deduplicated (SPEC
/// F-28): the same bytes under pointers that carry the dedup bit and
/// sha256 checksums, and `dedup=sha256,verify` set on the volume.
pub fn dedup_zvol_members(pool: &mut Pool, size: u64) -> (Vec<Vec<u8>>, u64, u64) {
    destroyed_zvol_members_with(pool, size, true)
}

/// A pool whose `tank/vm/disk0` is dense (SPEC N-03, N-08): `dense.bytes`
/// of data in `dense.blocksize` blocks, every one present under a real
/// indirect tree, compressed as `dense.compression` says. Present at
/// every transaction group; nothing is destroyed. Returns the member
/// images and the SHA-256 the extracted volume must have.
pub fn dense_volume_members(pool: &mut Pool, dense: Dense) -> (Vec<Vec<u8>>, String) {
    assert_eq!(
        dense.bytes % dense.blocksize as u64,
        0,
        "a whole number of blocks"
    );
    let n = pool.members.len();
    let (layout, per_member) = match pool.nparity {
        Some(p) if pool.kind == "raidz" => (
            Layout::Raidz {
                ashift: pool.ashift,
                nparity: p,
            },
            dense.bytes / (n as u64 - p),
        ),
        _ => (Layout::Mirror, dense.bytes),
    };
    // Room for the data, the tree above it, the MOS, and the labels at
    // both ends, in whole MiB.
    let size = (0x20_0000 + per_member + per_member / 32 + (8 << 20)).next_multiple_of(1 << 20);
    let mut members: Vec<Vec<u8>> = (0..n).map(|_| vec![0u8; size as usize]).collect();
    let mut alloc = Alloc::with_layout(0x20_0000, layout);
    alloc.dense = Some(dense.clone());
    let root = build_sample_mos_variant(&mut members, &mut alloc, true);
    pool.rootbp = Some(root);
    for (i, img) in members.iter_mut().enumerate() {
        pool.write_labels(i, img);
    }
    (members, dense.sha256())
}

/// A pool in which `tank/vm/disk0` exists on disk but no uberblock leads
/// to it any more — the COMPANIONS §3.4 scenario for `zvolcarve`.
///
/// The volume's dnode, its indirect blocks and its data blocks are all
/// written; what is missing is any path down to them. Every uberblock
/// carries the MOS *without* the volume, exactly as it would after the
/// ring has rolled past the transaction group that destroyed it, so
/// `zvolrescue list` cannot see it at any transaction group and only a
/// scan of raw space can.
///
/// Returns the member images.
pub fn carved_zvol_members(pool: &mut Pool, size: u64) -> Vec<Vec<u8>> {
    let n = pool.members.len();
    let mut members: Vec<Vec<u8>> = (0..n).map(|_| vec![0u8; size as usize]).collect();
    let layout = match pool.nparity {
        Some(p) if pool.kind == "raidz" => Layout::Raidz {
            ashift: pool.ashift,
            nparity: p,
        },
        _ => Layout::Mirror,
    };
    let mut alloc = Alloc::with_layout(0x20_0000, layout);
    // The volume is written first, so its blocks are really on the
    // member; the root that is published is the one that does not
    // mention it.
    let _with = build_sample_mos_variant(&mut members, &mut alloc, true);
    let without = build_sample_mos_variant(&mut members, &mut alloc, false);
    pool.rootbp = Some(without);
    pool.rootbp_by_txg = Vec::new();
    for (i, img) in members.iter_mut().enumerate() {
        pool.write_labels(i, img);
    }
    members
}

/// Attribute numbers this fixture registers.
///
/// The numbers are the fixture's own and are not claimed to match any
/// particular OpenZFS build. They do not need to: an attribute's number
/// is whatever that dataset's registry ZAP says it is, and the reader
/// resolves every attribute through that registry by name, which is how
/// ZFS itself works. What is under test is the lookup, not the number.
mod zpl_attr {
    pub const ATIME: u16 = 0;
    pub const MTIME: u16 = 1;
    pub const CTIME: u16 = 2;
    pub const CRTIME: u16 = 3;
    pub const MODE: u16 = 5;
    pub const SIZE: u16 = 6;
    pub const PARENT: u16 = 7;
    pub const LINKS: u16 = 8;
    pub const UID: u16 = 12;
    pub const GID: u16 = 13;
    pub const SYMLINK: u16 = 17;
    pub const DXATTR: u16 = 19;
    pub const PROJID: u16 = 20;

    /// `(name, number, fixed length)`; a length of 0 means variable.
    pub const REGISTRY: [(&str, u16, u16); 13] = [
        ("ZPL_ATIME", ATIME, 16),
        ("ZPL_MTIME", MTIME, 16),
        ("ZPL_CTIME", CTIME, 16),
        ("ZPL_CRTIME", CRTIME, 16),
        ("ZPL_MODE", MODE, 8),
        ("ZPL_SIZE", SIZE, 8),
        ("ZPL_PARENT", PARENT, 8),
        ("ZPL_LINKS", LINKS, 8),
        ("ZPL_UID", UID, 8),
        ("ZPL_GID", GID, 8),
        ("ZPL_SYMLINK", SYMLINK, 0),
        ("ZPL_DXATTR", DXATTR, 0),
        ("ZPL_PROJID", PROJID, 8),
    ];

    /// The layout every file and directory in the fixture uses.
    pub const PLAIN: [u16; 10] = [
        ATIME, MTIME, CTIME, CRTIME, MODE, SIZE, PARENT, LINKS, UID, GID,
    ];
    /// The same, plus the target of a symbolic link.
    pub const WITH_SYMLINK: [u16; 11] = [
        ATIME, MTIME, CTIME, CRTIME, MODE, SIZE, PARENT, LINKS, UID, GID, SYMLINK,
    ];
    /// The same, plus system-attribute extended attributes.
    pub const WITH_XATTR: [u16; 11] = [
        ATIME, MTIME, CTIME, CRTIME, MODE, SIZE, PARENT, LINKS, UID, GID, DXATTR,
    ];
    /// The plain set plus a project id, which a dataset has only where
    /// the `project_quota` feature is enabled (Z-10).
    pub const WITH_PROJID: [u16; 11] = [
        ATIME, MTIME, CTIME, CRTIME, MODE, SIZE, PARENT, LINKS, UID, GID, PROJID,
    ];
    /// What a spill block holds when the extended attributes did not fit
    /// beside the rest: the overflowing attribute, and only it. The
    /// bonus keeps [`PLAIN`] and names its own layout, exactly as
    /// OpenZFS splits a layout that will not fit one buffer.
    pub const SPILLED: [u16; 1] = [DXATTR];
}

/// The registry value OpenZFS encodes for one attribute.
fn registry_value(num: u16, length: u16) -> u64 {
    (u64::from(length) << 24) | (u64::from(num) << 8)
}

/// A system-attribute bonus buffer in `layout`.
///
/// The header is the magic, the layout number with the header size in
/// eight-byte units above it, and one 16-bit size per variable-length
/// attribute. Fixed attributes take the length the registry gives.
fn sa_bonus(layout: u16, fields: &[(u16, Vec<u8>)], variable: &[u16]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&zfs_ondisk::zpl::SA_MAGIC.to_le_bytes());
    let info: u16 = layout | (1 << 10); // one eight-byte header chunk
    out.extend_from_slice(&info.to_le_bytes());
    // Sizes of the variable-length attributes, in layout order; the
    // header is padded to eight bytes whether or not any are used.
    let mut sizes = Vec::new();
    for num in variable {
        let len = fields
            .iter()
            .find(|(n, _)| n == num)
            .map_or(0, |(_, v)| v.len()) as u16;
        sizes.extend_from_slice(&len.to_le_bytes());
    }
    sizes.resize(2, 0);
    out.extend_from_slice(&sizes[..2]);
    for (_, v) in fields {
        out.extend_from_slice(v);
    }
    out
}

/// The eight-byte value of a fixed attribute.
fn sa_u64(v: u64) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

/// A timestamp attribute: seconds and nanoseconds.
fn sa_time(secs: u64) -> Vec<u8> {
    let mut v = secs.to_le_bytes().to_vec();
    v.extend_from_slice(&0u64.to_le_bytes());
    v
}

/// A directory entry's value: the object number with the POSIX file
/// type in its top four bits.
fn dirent_value(obj: u64, dt: u64) -> u64 {
    (dt << 60) | obj
}

/// The contents of `hello.txt` in the ZPL fixture.
pub fn zpl_hello() -> Vec<u8> {
    b"hello from a dataset nobody can mount\n".to_vec()
}

/// The contents of `sub/deep.txt`: one block of a repeating pattern, so
/// its hash is worth asserting and its blocks are worth verifying.
pub fn zpl_deep() -> Vec<u8> {
    (0..4096u32).map(|i| (i % 251) as u8).collect()
}

/// The project id of `sub/deep.txt` (Z-10). Every other file in the
/// fixture is in a layout with no project id at all, which is the case
/// a dataset without the `project_quota` feature presents.
pub const ZPL_DEEP_PROJID: u64 = 42;

/// The contents of `spilled.txt`, the file whose extended attribute
/// does not fit in its bonus buffer (Z-10).
pub fn zpl_spilled() -> Vec<u8> {
    b"my attributes did not all fit here\n".to_vec()
}

/// The name of that attribute.
pub const ZPL_SPILLED_XATTR: &str = "user.spilled";

/// Its value: 600 bytes, where the bonus buffer of a one-slot dnode
/// with one block pointer has 192 in total.
pub fn zpl_spilled_value() -> Vec<u8> {
    (0..600u32).map(|i| b'a' + (i % 26) as u8).collect()
}

/// The contents of `bigdnode.txt`, the file stored in a two-slot dnode.
pub fn zpl_big_dnode() -> Vec<u8> {
    b"I am two dnode slots wide\n".to_vec()
}

/// The name of its extended attribute.
pub const ZPL_BIG_DNODE_XATTR: &str = "user.wide";

/// Its value: 400 bytes, which fit beside the other attributes only
/// because the dnode is 1024 bytes rather than 512.
///
/// Sixteen of those bytes are [`ZPL_BIG_DNODE_TRAP`], placed where the
/// dnode's second slot begins.
pub fn zpl_big_dnode_value() -> Vec<u8> {
    (0..400u32).map(|i| b'A' + (i % 26) as u8).collect()
}

/// A dnode header, planted in the second slot of the fixture's large
/// dnode (Z-10).
///
/// The slot a large dnode owns holds the rest of its bonus buffer, and
/// those bytes are whatever the file's attributes happen to be. Usually
/// they do not parse as a dnode and a walk that stepped by one slot
/// would merely fail; these do parse, so such a walk reports an object
/// that was never there. A fixture where the wrong answer is a loud one
/// tests nothing about the guard against it.
pub const ZPL_BIG_DNODE_TRAP: [u8; 16] = [
    ot::PLAIN_FILE_CONTENTS, // dn_type
    17,                      // dn_indblkshift
    1,                       // dn_nlevels
    1,                       // dn_nblkptr
    0,                       // dn_bonustype
    0,                       // dn_checksum
    0,                       // dn_compress
    0,                       // dn_flags
    8,
    0, // dn_datablkszsec: 4 KiB
    0,
    0, // dn_bonuslen
    0, // dn_extra_slots
    0,
    0,
    0,
];

/// The name of the fixture's one file whose name is not UTF-8:
/// `café.txt` as a Latin-1 machine wrote it, which is a name a dataset
/// with `utf8only=off` is allowed to hold (Z-09).
pub const ZPL_LATIN1_NAME: &[u8] = b"caf\xe9.txt";

/// The contents of that file.
pub fn zpl_latin1() -> Vec<u8> {
    b"a name is bytes, not text\n".to_vec()
}

/// Build a filesystem objset with a small POSIX tree, and return its
/// block pointer (COMPANIONS §5.4).
///
/// ```text
/// caf\xe9.txt      a regular file whose name is not UTF-8
/// hello.txt        a regular file
/// link             a symbolic link to sub/deep.txt, target in the
///                  system attributes rather than in a block
/// sub/             a directory
/// sub/deep.txt     one block of pattern
/// ```
/// How a ZPL fixture's dataset matches names (Z-09).
///
/// The two are separate fixtures because a real pool cannot be both:
/// `normalization` requires `utf8only`, and a dataset with `utf8only`
/// on cannot hold `caf\xe9.txt`. A fixture that is impossible on disk
/// tests nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Matching {
    /// `casesensitivity=sensitive`, `normalization=none`, `utf8only=off`
    /// — and a name that is not UTF-8, which such a dataset may hold.
    Exact,
    /// `normalization=formD`, `utf8only=on`, and a file whose name is on
    /// disk in composed form, to be found by its decomposed spelling.
    NormalizedFormD,
}

/// What the ZPL fixture's spill block holds (Z-10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spill {
    /// The attribute that did not fit the bonus, written the way
    /// OpenZFS writes it: a buffer with a header of its own, naming a
    /// layout of its own.
    Attributes,
    /// A block that is not a system-attribute buffer at all — the shape
    /// the damage takes when a spill block is overwritten. The dnode
    /// still says an attribute lives there, so the attribute is not
    /// absent, it is unreadable, and the two are not the same answer.
    Unreadable,
}

/// The file in a [`Matching::NormalizedFormD`] fixture, as stored:
/// `résumé.txt` composed, the way most systems write it.
pub const ZPL_COMPOSED_NAME: &[u8] = "r\u{e9}sum\u{e9}.txt".as_bytes();

/// The same name decomposed, the way a macOS client would ask for it.
pub const ZPL_DECOMPOSED_NAME: &[u8] = "re\u{301}sume\u{301}.txt".as_bytes();

fn build_zpl_objset(
    m: &mut [Vec<u8>],
    a: &mut Alloc,
    matching: Matching,
    spill: Spill,
) -> [u8; blkptr::SIZE] {
    let mut dnodes = vec![0u8; 16384];
    let mut put = |obj: u64, bytes: Vec<u8>| {
        let at = obj as usize * DNODE_SIZE;
        dnodes[at..at + bytes.len()].copy_from_slice(&bytes);
    };
    // A ZAP object of `otype` holding `entries`.
    let zap = |a: &mut Alloc, m: &mut [Vec<u8>], otype: u8, entries: &[(&str, u64)]| {
        let blk = a.put(m, &micro(4096, entries), otype, 0, 100);
        DnodeSpec {
            object_type: otype,
            datablksz: 4096,
            blkptrs: vec![blk],
            ..DnodeSpec::default()
        }
        .build()
    };
    // A file object holding `data` in one block.
    let file = |a: &mut Alloc, m: &mut [Vec<u8>], data: &[u8], bonus: Vec<u8>| {
        let mut block = data.to_vec();
        block.resize(4096, 0);
        let blk = a.put(m, &block, ot::PLAIN_FILE_CONTENTS, 0, 100);
        DnodeSpec {
            object_type: ot::PLAIN_FILE_CONTENTS,
            datablksz: 4096,
            bonus_type: ot::SA,
            bonus,
            blkptrs: vec![blk],
            ..DnodeSpec::default()
        }
        .build()
    };
    let meta = |mode: u64, size: u64, parent: u64, links: u64| -> Vec<(u16, Vec<u8>)> {
        vec![
            (zpl_attr::ATIME, sa_time(1_757_100_000)),
            (zpl_attr::MTIME, sa_time(1_757_100_001)),
            (zpl_attr::CTIME, sa_time(1_757_100_002)),
            (zpl_attr::CRTIME, sa_time(1_757_100_003)),
            (zpl_attr::MODE, sa_u64(mode)),
            (zpl_attr::SIZE, sa_u64(size)),
            (zpl_attr::PARENT, sa_u64(parent)),
            (zpl_attr::LINKS, sa_u64(links)),
            (zpl_attr::UID, sa_u64(0)),
            (zpl_attr::GID, sa_u64(0)),
        ]
    };

    // 1: the master node, which names everything else.
    put(
        1,
        zap(
            a,
            m,
            ot::MASTER_NODE,
            &[
                ("VERSION", 5),
                ("ROOT", 3),
                ("SA_ATTRS", 2),
                ("casesensitivity", 0),
                // 0x10 is U8_CANON_DECOMP — `formD` (u8_textprep.h).
                (
                    "normalization",
                    match matching {
                        Matching::Exact => 0,
                        Matching::NormalizedFormD => 0x10,
                    },
                ),
                (
                    "utf8only",
                    match matching {
                        Matching::Exact => 0,
                        Matching::NormalizedFormD => 1,
                    },
                ),
            ],
        ),
    );
    // 2: where the system-attribute registry and layouts live.
    put(2, zap(a, m, ot::SA, &[("REGISTRY", 4), ("LAYOUTS", 5)]));
    // 4: what each attribute is called, what number it has, how long it is.
    let registry: Vec<(&str, u64)> = zpl_attr::REGISTRY
        .iter()
        .map(|(name, num, len)| (*name, registry_value(*num, *len)))
        .collect();
    put(4, zap(a, m, ot::SA, &registry));
    // 5: which attributes each layout holds, in order. Sixteen-bit
    // arrays, so this one has to be a fatzap.
    let as_bytes =
        |nums: &[u16]| -> Vec<u8> { nums.iter().flat_map(|n| n.to_be_bytes()).collect() };
    let hdr = zfs_ondisk::zap::encode::fat_header(4096, 1, 3);
    let leaf = zfs_ondisk::zap::encode::leaf(
        4096,
        &[
            ("2", 2, as_bytes(&zpl_attr::PLAIN)),
            ("3", 2, as_bytes(&zpl_attr::WITH_SYMLINK)),
            ("4", 2, as_bytes(&zpl_attr::WITH_XATTR)),
            ("6", 2, as_bytes(&zpl_attr::SPILLED)),
            ("7", 2, as_bytes(&zpl_attr::WITH_PROJID)),
        ],
    );
    let b0 = a.put(m, &hdr, ot::SA, 0, 100);
    let b1 = a.put(m, &leaf, ot::SA, 0, 100);
    put(
        5,
        DnodeSpec {
            object_type: ot::SA,
            datablksz: 4096,
            maxblkid: 1,
            blkptrs: vec![b0, b1],
            ..DnodeSpec::default()
        }
        .build(),
    );

    // 3: the root directory. Object 10 is the one name that differs
    // between the two fixtures: a dataset that matches exactly may hold
    // bytes that are not UTF-8, and one that normalizes may not.
    let odd_name: &[u8] = match matching {
        Matching::Exact => ZPL_LATIN1_NAME,
        Matching::NormalizedFormD => ZPL_COMPOSED_NAME,
    };
    let root_entries: [(&[u8], u64); 7] = [
        // A large dnode: its attributes fit, but only because it owns
        // two slots instead of one (Z-10).
        (b"bigdnode.txt", dirent_value(12, 8)),
        // A name no dataset with utf8only=on could hold (Z-09).
        (odd_name, dirent_value(10, 8)),
        // Two names for one object: a hard link (Z-07).
        (b"hardlink.txt", dirent_value(6, 8)),
        (b"hello.txt", dirent_value(6, 8)),
        (b"link", dirent_value(8, 10)),
        // An attribute that did not fit the bonus and went to the spill
        // block (Z-10).
        (b"spilled.txt", dirent_value(11, 8)),
        (b"sub", dirent_value(7, 4)),
    ];
    let root_blk = a.put(
        m,
        &zfs_ondisk::zap::encode::micro_bytes(4096, &root_entries),
        ot::DIRECTORY_CONTENTS,
        0,
        100,
    );
    put(
        3,
        DnodeSpec {
            object_type: ot::DIRECTORY_CONTENTS,
            datablksz: 4096,
            bonus_type: ot::SA,
            bonus: sa_bonus(2, &meta(0o40755, 5, 3, 3), &[]),
            blkptrs: vec![root_blk],
            ..DnodeSpec::default()
        }
        .build(),
    );
    // 6: a regular file with two names and two extended attributes
    // stored in the system attributes (`xattr=sa`).
    let hello = zpl_hello();
    let xattrs = pack(&list(vec![
        (
            "user.note",
            Value::Bytes(b"kept in the attributes".to_vec()),
        ),
        ("user.case", Value::Bytes(b"42".to_vec())),
    ]));
    let mut hello_fields = meta(0o100644, hello.len() as u64, 3, 2);
    hello_fields.push((zpl_attr::DXATTR, xattrs));
    put(
        6,
        file(
            a,
            m,
            &hello,
            sa_bonus(4, &hello_fields, &[zpl_attr::DXATTR]),
        ),
    );
    // 7: a subdirectory.
    let sub_blk = a.put(
        m,
        &micro(4096, &[("deep.txt", dirent_value(9, 8))]),
        ot::DIRECTORY_CONTENTS,
        0,
        100,
    );
    put(
        7,
        DnodeSpec {
            object_type: ot::DIRECTORY_CONTENTS,
            datablksz: 4096,
            bonus_type: ot::SA,
            bonus: sa_bonus(2, &meta(0o40755, 1, 3, 2), &[]),
            blkptrs: vec![sub_blk],
            ..DnodeSpec::default()
        }
        .build(),
    );
    // 8: a symbolic link whose target is in the attributes, not a block.
    let target = b"sub/deep.txt".to_vec();
    let mut symlink_fields = meta(0o120777, target.len() as u64, 3, 1);
    symlink_fields.push((zpl_attr::SYMLINK, target.clone()));
    put(
        8,
        DnodeSpec {
            object_type: ot::PLAIN_FILE_CONTENTS,
            datablksz: 4096,
            bonus_type: ot::SA,
            bonus: sa_bonus(3, &symlink_fields, &[zpl_attr::SYMLINK]),
            blkptrs: vec![[0u8; blkptr::SIZE]],
            ..DnodeSpec::default()
        }
        .build(),
    );
    // 9: a file under the subdirectory.
    let deep = zpl_deep();
    let mut deep_fields = meta(0o100600, deep.len() as u64, 7, 1);
    deep_fields.push((zpl_attr::PROJID, sa_u64(ZPL_DEEP_PROJID)));
    put(9, file(a, m, &deep, sa_bonus(7, &deep_fields, &[])));
    // 10: the file whose name is not text.
    let latin1 = zpl_latin1();
    put(
        10,
        file(
            a,
            m,
            &latin1,
            sa_bonus(2, &meta(0o100644, latin1.len() as u64, 3, 1), &[]),
        ),
    );
    // 11: a file whose extended attribute is too large to sit beside
    // the rest of its attributes. The bonus holds the ten plain ones
    // and names layout 2; the spill block holds a buffer of its own,
    // with its own header, naming layout 6 (Z-10).
    let spilled = zpl_spilled();
    let packed = pack(&list(vec![(
        ZPL_SPILLED_XATTR,
        Value::Bytes(zpl_spilled_value()),
    )]));
    let mut spill_block = match spill {
        Spill::Attributes => sa_bonus(6, &[(zpl_attr::DXATTR, packed)], &[zpl_attr::DXATTR]),
        // Checksummed and read back exactly as written; what is wrong
        // with it is what it says, not whether it arrived.
        Spill::Unreadable => b"this is not a system-attribute buffer".to_vec(),
    };
    spill_block.resize(4096, 0);
    let spill_blk = a.put(m, &spill_block, ot::SA, 0, 100);
    let mut spilled_block = spilled.clone();
    spilled_block.resize(4096, 0);
    let spilled_data = a.put(m, &spilled_block, ot::PLAIN_FILE_CONTENTS, 0, 100);
    put(
        11,
        DnodeSpec {
            object_type: ot::PLAIN_FILE_CONTENTS,
            datablksz: 4096,
            bonus_type: ot::SA,
            bonus: sa_bonus(2, &meta(0o100644, spilled.len() as u64, 3, 1), &[]),
            blkptrs: vec![spilled_data],
            spill: Some(spill_blk),
            ..DnodeSpec::default()
        }
        .build(),
    );
    // 12 (and 13, which it owns): a large dnode. The same attributes as
    // object 6, but the extended attribute is large enough that they
    // only fit because the dnode is two slots rather than one — which
    // is what `large_dnode` is for, and what a reader that assumes 512
    // bytes per object would misread (Z-10).
    let big = zpl_big_dnode();
    let big_packed = pack(&list(vec![(
        ZPL_BIG_DNODE_XATTR,
        Value::Bytes(zpl_big_dnode_value()),
    )]));
    let mut big_fields = meta(0o100644, big.len() as u64, 3, 1);
    big_fields.push((zpl_attr::DXATTR, big_packed));
    let mut big_bonus = sa_bonus(4, &big_fields, &[zpl_attr::DXATTR]);
    // Where the second slot of this dnode starts, counted from the
    // beginning of the bonus buffer: the core, then the one block
    // pointer, then 512 bytes of the first slot.
    let second_slot = DNODE_SIZE - (DNODE_CORE_SIZE + blkptr::SIZE);
    big_bonus[second_slot..second_slot + ZPL_BIG_DNODE_TRAP.len()]
        .copy_from_slice(&ZPL_BIG_DNODE_TRAP);
    let mut big_block = big.clone();
    big_block.resize(4096, 0);
    let big_data = a.put(m, &big_block, ot::PLAIN_FILE_CONTENTS, 0, 100);
    put(
        12,
        DnodeSpec {
            object_type: ot::PLAIN_FILE_CONTENTS,
            datablksz: 4096,
            bonus_type: ot::SA,
            bonus: big_bonus,
            blkptrs: vec![big_data],
            extra_slots: 1,
            ..DnodeSpec::default()
        }
        .build(),
    );

    let dnode_blk = a.put(m, &dnodes, ot::DNODE, 0, 100);
    let meta_dnode = DnodeSpec {
        object_type: ot::DNODE,
        datablksz: 16384,
        blkptrs: vec![dnode_blk],
        ..DnodeSpec::default()
    }
    .build();
    a.put(m, &objset(&meta_dnode, 2), ot::OBJSET, 0, 100)
}

/// Bytes the parent block-pointer object of the ZPL fixture's deadlist
/// holds itself.
pub const ZPL_BPOBJ_PARENT_BYTES: u64 = 1000;
/// Bytes the object it swallowed holds.
pub const ZPL_BPOBJ_CHILD_BYTES: u64 = 500;
/// What the deadlist's own header therefore says.
pub const ZPL_DEADLIST_BYTES: u64 = ZPL_BPOBJ_PARENT_BYTES + ZPL_BPOBJ_CHILD_BYTES;

/// A block-pointer object: everything it says is in its bonus.
fn bpobj_obj(bytes: u64, subobjs: u64, num_subobjs: u64) -> Vec<u8> {
    let mut bonus = vec![0u8; 48];
    let mut put = |o: usize, v: u64| bonus[o..o + 8].copy_from_slice(&v.to_le_bytes());
    put(8, bytes); // bpo_bytes
    put(32, subobjs);
    put(40, num_subobjs);
    DnodeSpec {
        object_type: ot::BPOBJ,
        bonus_type: ot::BPOBJ,
        bonus,
        ..DnodeSpec::default()
    }
    .build()
}

/// An object holding an array of object numbers.
fn u64_array_obj(a: &mut Alloc, m: &mut [Vec<u8>], values: &[u64]) -> Vec<u8> {
    let mut block = vec![0u8; 4096];
    for (i, v) in values.iter().enumerate() {
        block[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    let blk = a.put(m, &block, ot::BPOBJ_SUBOBJ, 0, 100);
    DnodeSpec {
        object_type: ot::BPOBJ_SUBOBJ,
        datablksz: 4096,
        blkptrs: vec![blk],
        ..DnodeSpec::default()
    }
    .build()
}

/// A deadlist: a ZAP of transaction group to block-pointer object, with
/// its running total in the bonus.
fn deadlist_obj(a: &mut Alloc, m: &mut [Vec<u8>], used: u64, entries: &[(&str, u64)]) -> Vec<u8> {
    let blk = a.put(m, &micro(4096, entries), ot::DEADLIST, 0, 100);
    let mut bonus = vec![0u8; 320];
    bonus[0..8].copy_from_slice(&used.to_le_bytes());
    DnodeSpec {
        object_type: ot::DEADLIST,
        datablksz: 4096,
        bonus_type: ot::DEADLIST,
        bonus,
        blkptrs: vec![blk],
        ..DnodeSpec::default()
    }
    .build()
}

/// A pool with one filesystem dataset, `tank/fs`, holding a small POSIX
/// tree — the fixture `zvolfiles` is accepted against (COMPANIONS §5.4).
///
/// Kept apart from the volume fixture on purpose: that one's dataset
/// list is asserted in several places, and a recovery tool's tests are
/// worth more when each fixture says one thing.
pub fn zpl_members(pool: &mut Pool, size: u64) -> Vec<Vec<u8>> {
    zpl_members_matching(pool, size, Matching::Exact)
}

/// The same fixture with the dataset's name-matching properties chosen
/// (Z-09).
pub fn zpl_members_matching(pool: &mut Pool, size: u64, matching: Matching) -> Vec<Vec<u8>> {
    zpl_members_with(pool, size, matching, Spill::Attributes)
}

/// The same fixture with the spill block chosen too (Z-10).
pub fn zpl_members_with(
    pool: &mut Pool,
    size: u64,
    matching: Matching,
    spill: Spill,
) -> Vec<Vec<u8>> {
    let n = pool.members.len();
    let mut members: Vec<Vec<u8>> = (0..n).map(|_| vec![0u8; size as usize]).collect();
    let layout = match pool.nparity {
        Some(p) if pool.kind == "raidz" => Layout::Raidz {
            ashift: pool.ashift,
            nparity: p,
        },
        _ => Layout::Mirror,
    };
    let mut a = Alloc::with_layout(0x20_0000, layout);
    let m = &mut members[..];
    let os_zpl = build_zpl_objset(m, &mut a, matching, spill);
    let empty_meta = DnodeSpec {
        object_type: ot::DNODE,
        ..DnodeSpec::default()
    }
    .build();
    let os_empty = a.put(m, &objset(&empty_meta, 2), ot::OBJSET, 0, 100);

    let mut dnodes = vec![0u8; 16384];
    let mut put = |obj: u64, bytes: Vec<u8>| {
        let at = obj as usize * DNODE_SIZE;
        dnodes[at..at + bytes.len()].copy_from_slice(&bytes);
    };
    let zap_obj = |a: &mut Alloc, m: &mut [Vec<u8>], entries: &[(&str, u64)]| {
        let blk = a.put(m, &micro(4096, entries), ot::DSL_DIR_CHILD_MAP, 0, 100);
        DnodeSpec {
            object_type: ot::DSL_DIR_CHILD_MAP,
            datablksz: 4096,
            blkptrs: vec![blk],
            ..DnodeSpec::default()
        }
        .build()
    };
    let dir_obj = |head: u64, children: u64, parent: u64| {
        DnodeSpec {
            object_type: ot::DSL_DIR,
            bonus_type: ot::DSL_DIR,
            bonus: dsl_dir(&DslDirPhys {
                head_dataset_obj: head,
                child_dir_zapobj: children,
                parent_obj: parent,
                ..Default::default()
            }),
            ..DnodeSpec::default()
        }
        .build()
    };
    let ds_obj = |d: &DslDatasetPhys| {
        DnodeSpec {
            object_type: ot::DSL_DATASET,
            bonus_type: ot::DSL_DATASET,
            bonus: dsl_dataset(d),
            ..DnodeSpec::default()
        }
        .build()
    };
    put(
        1,
        zap_obj(&mut a, m, &[("root_dataset", 2), ("config", 11)]),
    );
    put(2, dir_obj(3, 4, 0));
    put(3, ds_obj(&dataset_phys(2, 0, &os_empty, 4, 0xb1, 0)));
    put(4, zap_obj(&mut a, m, &[("fs", 5)]));
    put(5, dir_obj(6, 7, 2));
    // tank/fs carries a deadlist (object 12) whose entry is a
    // block-pointer object that has swallowed another (COMPANIONS
    // T-07): the parent's header counts only its own pointers, so the
    // deadlist's total only adds up if the child is followed.
    let mut fs_ds = dataset_phys(5, 0, &os_zpl, 20, 0xb2, 0);
    fs_ds.deadlist_obj = 12;
    put(6, ds_obj(&fs_ds));
    put(7, zap_obj(&mut a, m, &[]));
    put(8, bpobj_obj(ZPL_BPOBJ_PARENT_BYTES, 10, 1));
    put(9, bpobj_obj(ZPL_BPOBJ_CHILD_BYTES, 0, 0));
    put(10, u64_array_obj(&mut a, m, &[9]));
    put(12, deadlist_obj(&mut a, m, ZPL_DEADLIST_BYTES, &[("0", 8)]));

    let dnode_blk = a.put(m, &dnodes, ot::DNODE, 0, 100);
    let meta = DnodeSpec {
        object_type: ot::DNODE,
        datablksz: 16384,
        blkptrs: vec![dnode_blk],
        ..DnodeSpec::default()
    }
    .build();
    let root = a.put(m, &objset(&meta, 1), ot::OBJSET, 0, 100);
    pool.rootbp = Some(root);
    pool.rootbp_by_txg = Vec::new();
    for (i, img) in members.iter_mut().enumerate() {
        pool.write_labels(i, img);
    }
    members
}
