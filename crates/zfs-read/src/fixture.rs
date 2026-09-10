//! Synthetic vdev members for tests and smoke runs.
//!
//! Builds images that carry real label structures — XDR nvlists with
//! embedded SHA-256 checksums and sealed uberblock slots — without any
//! data blocks. Enough for `scan` and pool assembly; the tool itself never
//! writes evidence, so nothing here is reachable from the binaries except
//! through explicit fixture generation.

use zfs_ondisk::blkptr::{self, encode::Builder, LABEL_START_SIZE};
use zfs_ondisk::checksum::seal_label;
use zfs_ondisk::dmu::encode::{objset, DnodeSpec};
use zfs_ondisk::dmu::{ot, DNODE_SIZE};
use zfs_ondisk::dsl::encode::{dsl_dataset, dsl_dir};
use zfs_ondisk::dsl::{DslDatasetPhys, DslDirPhys};
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
    /// Root block pointer to record in every uberblock (128 bytes); when
    /// `None` only the logical birth is filled in.
    pub rootbp: Option<[u8; blkptr::SIZE]>,
    /// Per-TXG root block pointers that override `rootbp` for that TXG,
    /// so different TXGs can describe different dataset trees.
    pub rootbp_by_txg: Vec<(u64, [u8; blkptr::SIZE])>,
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
            rootbp: None,
            rootbp_by_txg: Vec::new(),
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
                        .fold(self.guid ^ 0xf0f0, u64::wrapping_add),
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
}

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
        }
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
        match self.layout {
            Layout::Mirror => {
                let size = data.len().div_ceil(512) * 512;
                let mut padded = data.to_vec();
                padded.resize(size, 0);
                let offset = self.next;
                self.next += size as u64;
                for m in members.iter_mut() {
                    write_at_dva(m, offset, &padded);
                }
                self.bp(offset, size as u64, size as u64, &padded, otype, level, txg)
            }
            Layout::Raidz { ashift, nparity } => {
                let unit = 1usize << ashift;
                let size = data.len().div_ceil(unit) * unit;
                let mut padded = data.to_vec();
                padded.resize(size, 0);
                let offset = self.next;
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
                self.bp(offset, m.asize, size as u64, &padded, otype, level, txg)
            }
        }
    }

    /// Store `data` as a gang block on a mirror layout: the pieces become
    /// ordinary blocks, and a sealed 512-byte gang header at the returned
    /// pointer's DVA (gang bit set) lists them. `pieces` gives the byte
    /// length of each of up to three children (they must sum to
    /// `data.len()`).
    pub fn put_gang(
        &mut self,
        members: &mut [Vec<u8>],
        data: &[u8],
        pieces: &[usize],
        otype: u8,
        txg: u64,
    ) -> [u8; blkptr::SIZE] {
        assert_eq!(self.layout, Layout::Mirror, "gang fixtures are mirror-only");
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
        self.next += blkptr::GANG_HEADER_SIZE as u64;
        let mut header = vec![0u8; blkptr::GANG_HEADER_SIZE];
        for (i, c) in children.iter().enumerate() {
            header[i * blkptr::SIZE..(i + 1) * blkptr::SIZE].copy_from_slice(c);
        }
        zfs_ondisk::checksum::seal_embedded(&mut header, [0, offset, txg, 0]);
        for m in members.iter_mut() {
            write_at_dva(m, offset, &header);
        }
        let size = data.len().div_ceil(512) * 512;
        let mut padded = data.to_vec();
        padded.resize(size, 0);
        Builder::new()
            .dva(0, 0, offset, blkptr::GANG_HEADER_SIZE as u64, true)
            .sizes(size as u64, size as u64)
            .props(2, self.checksum.code(), otype, 0)
            .births(0, txg, 1)
            .cksum(self.cksum(&padded))
            .bytes(Endian::Little)
    }

    #[allow(clippy::too_many_arguments)]
    fn bp(
        &self,
        offset: u64,
        asize: u64,
        size: u64,
        padded: &[u8],
        otype: u8,
        level: u8,
        txg: u64,
    ) -> [u8; blkptr::SIZE] {
        Builder::new()
            .dva(0, 0, offset, asize, false)
            .sizes(size, size)
            .props(2, self.checksum.code(), otype, level)
            .births(0, txg, 1)
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
    (0..8192u64)
        .map(|i| ((blkid * 97 + i * 7) % 251) as u8)
        .collect()
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
    if with_disk0 && a.layout == Layout::Mirror {
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
    }
    let blk0 = a.put(m, &zvol_pattern(0), ot::ZVOL, 0, 100);
    let blk2 = a.put(m, &zvol_pattern(2), ot::ZVOL, 0, 100);
    a.checksum = plain;
    let data_obj = DnodeSpec {
        object_type: ot::ZVOL,
        datablksz: 8192,
        maxblkid: 3,
        blkptrs: vec![blk0, [0u8; blkptr::SIZE], blk2],
        ..DnodeSpec::default()
    }
    .build();
    zvol_dnodes[DNODE_SIZE..2 * DNODE_SIZE].copy_from_slice(&data_obj);
    let props_blk = a.put(
        m,
        &micro(4096, &[("size", 32 << 20)]),
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
        put(12, dir_obj(13, 0, 5));
        put(13, ds_obj(&dataset_phys(12, 0, &os_zvol, 30, 0xa3, 8)));
        put(8, zap_obj(a, m, &[("before", 10)]));
        put(10, ds_obj(&dataset_phys(12, 13, &os_zvol, 25, 0xa4, 0)));
    } else {
        put(7, zap_obj(a, m, &[]));
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

/// A mirror whose newest TXG no longer has `tank/vm/disk0` while the
/// older ones still do — the SPEC UC-1 scenario. Returns the member
/// images and the TXGs `(destroyed_at, last_with_disk0)`.
pub fn destroyed_zvol_members(pool: &mut Pool, size: u64) -> (Vec<Vec<u8>>, u64, u64) {
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
    let with = build_sample_mos_variant(&mut members, &mut alloc, true);
    let without = build_sample_mos_variant(&mut members, &mut alloc, false);
    pool.rootbp = Some(with);
    pool.rootbp_by_txg = vec![(newest, without)];
    for (i, img) in members.iter_mut().enumerate() {
        pool.write_labels(i, img);
    }
    (members, newest, previous)
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
