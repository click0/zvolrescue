//! Whether one transaction group was made from another.
//!
//! A pool's history is a line: each transaction group is made from the
//! one before it, and a block written at one stays where it is, as it
//! is, until a later one writes over it. An import with rewind goes on
//! from an older group and leaves the newer ones in the uberblock ring.
//! They are a line of their own, and no label says so.
//!
//! The blocks do. Where a later group holds a block written at or
//! before an earlier one, the earlier holds that same block in that
//! place — or the later was not made from it. That is the one thing
//! taken as proof here: the object array of the MOS and the trees of
//! its objects are compared wherever the later was written after the
//! earlier, down to the first block that says so.
//!
//! Time is not proof. A clock set back dates a group before the one it
//! was made from, and the two are one line all the same.

use zfs_ondisk::blkptr::{self, BlkPtr};
use zfs_ondisk::checksum::Verify;
use zfs_ondisk::dmu::{ot, DnodePhys, DNODE_SIZE};
use zfs_ondisk::dsl::DslDatasetPhys;
use zfs_ondisk::uberblock::Uberblock;
use zfs_ondisk::Endian;

use crate::dsl::open_mos;
use crate::zio::{PoolReader, ReadError};

/// Blocks read for one comparison before it is given up as saying
/// nothing. Two groups next to each other in the ring differ by what
/// one sync wrote; the bound is for two that are far apart.
const MAX_BLOCKS: u64 = 1 << 16;

/// Where a later transaction group shows it was not made from an
/// earlier one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parted {
    /// What the later one holds: "object 54 of the MOS".
    pub what: String,
    /// The TXG that wrote it — at or before the earlier one.
    pub born: u64,
    /// The TXG that wrote what the earlier one holds in its place, when
    /// it holds anything there.
    pub earlier_born: Option<u64>,
}

impl Parted {
    /// The proof in a sentence, for the groups `earlier` and `later`.
    pub fn says(&self, earlier: u64, later: u64) -> String {
        let Parted {
            what,
            born,
            earlier_born,
        } = self;
        match earlier_born {
            Some(e) => format!(
                "txg {later} holds {what} as txg {born} wrote it, and txg {earlier}, after txg {born}, holds it as txg {e} did"
            ),
            None => format!(
                "txg {later} holds {what} as txg {born} wrote it, and txg {earlier}, after txg {born}, does not hold it"
            ),
        }
    }
}

/// Which tree a block is of, for saying where the proof was found.
#[derive(Clone, Copy)]
enum Tree {
    /// The object array of the MOS.
    Array,
    /// One object of the MOS.
    Object(u64),
}

impl Tree {
    fn block(self, level: u32, blkid: u64) -> String {
        match (self, level) {
            (Tree::Array, 0) => format!("block {blkid} of the MOS's object array"),
            (Tree::Array, l) => format!("a level-{l} block of the MOS's object array"),
            (Tree::Object(n), 0) => format!("block {blkid} of object {n} of the MOS"),
            (Tree::Object(n), l) => format!("a level-{l} block of object {n} of the MOS"),
        }
    }
}

/// What the earlier transaction group holds at a place in the later
/// one's tree.
enum Was<'d> {
    /// This pointer; a hole is one.
    Ptr(Box<BlkPtr>),
    /// Nothing: its object ends before the place, or is not there.
    Nothing,
    /// Its whole tree, which is not as tall as the later one's: all of
    /// it lies under the first pointer of each level above its own.
    Under(&'d DnodePhys),
    /// Not known: what would say did not read.
    Unknown,
}

fn was_ptr<'d>(bp: BlkPtr) -> Was<'d> {
    Was::Ptr(Box::new(bp))
}

/// The same block: written at the same TXG with the same contents.
/// Where it lies is not asked — a block on a removed vdev is pointed at
/// anew, at the vdev it was copied to, without being written again.
fn same_block(a: &BlkPtr, b: &BlkPtr) -> bool {
    if a.is_hole() || b.is_hole() {
        return false;
    }
    if a.embedded || b.embedded {
        return a.raw() == b.raw();
    }
    a.birth == b.birth && a.cksum == b.cksum
}

/// What comparing two transaction groups came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compared {
    /// What shows the later was not made from the earlier, when
    /// something read does.
    pub parted: Option<Parted>,
    /// Blocks of the earlier one that did not read: what lies under
    /// them was not compared. Not counted past the proof — the
    /// comparison ends there.
    pub unread: u64,
    /// The same, of the later one.
    pub unread_later: u64,
}

struct Compare<'r, 'a> {
    reader: &'r PoolReader<'a>,
    /// The earlier transaction group.
    txg: u64,
    blocks: u64,
    /// Blocks that did not read: of the earlier group, of the later.
    unread: [u64; 2],
    found: Option<Parted>,
}

/// Which of the two a block is of.
#[derive(Clone, Copy)]
enum Of {
    Earlier = 0,
    Later = 1,
}

impl Compare<'_, '_> {
    fn done(&self) -> bool {
        self.found.is_some() || self.blocks >= MAX_BLOCKS
    }

    /// A block of pointers or of dnodes, when it reads and its checksum
    /// says it is the one pointed at.
    fn read(&mut self, bp: &BlkPtr, of: Of) -> Option<Vec<u8>> {
        self.blocks += 1;
        let data = self
            .reader
            .read_block(bp, false)
            .ok()
            .filter(|block| block.verify == Verify::Ok)
            .map(|block| block.data);
        if data.is_none() {
            self.unread[of as usize] += 1;
        }
        data
    }

    /// One place in a tree: `c` is what the later group holds there.
    fn visit(&mut self, c: &BlkPtr, was: Was<'_>, level: u32, blkid: u64, tree: Tree, epbs: u32) {
        if self.done() || c.is_hole() || matches!(was, Was::Unknown) {
            return;
        }
        if c.birth <= self.txg {
            // Written at or before the earlier group: it was there then.
            if !matches!(&was, Was::Ptr(p) if same_block(p, c)) {
                self.found = Some(Parted {
                    what: tree.block(level, blkid),
                    born: c.birth,
                    earlier_born: match &was {
                        Was::Ptr(p) if !p.is_hole() => Some(p.birth),
                        _ => None,
                    },
                });
            }
            return;
        }
        // Written since: what is under it may still be older.
        if level == 0 {
            if let Tree::Array = tree {
                self.dnode_block(c, was, blkid);
            }
            return;
        }
        let Some(cb) = self.read(c, Of::Later) else {
            return;
        };
        let pb: Option<(Vec<u8>, Endian)> = match &was {
            Was::Ptr(p) if !p.is_hole() => match self.read(p, Of::Earlier) {
                Some(b) => Some((b, p.endian)),
                None => return,
            },
            _ => None,
        };
        for (i, raw) in cb.chunks_exact(blkptr::SIZE).enumerate() {
            if self.done() {
                return;
            }
            let Ok(child) = BlkPtr::parse(raw, c.endian) else {
                continue;
            };
            if child.is_hole() {
                continue;
            }
            let at = i * blkptr::SIZE;
            let child_was = match (&was, &pb) {
                (_, Some((b, e))) => match b.get(at..at + blkptr::SIZE) {
                    Some(raw) => BlkPtr::parse(raw, *e).map_or(Was::Unknown, was_ptr),
                    None => Was::Unknown,
                },
                (Was::Under(d), _) => {
                    // The children of this block are one level down:
                    // the earlier object's own pointers, once that is
                    // its top level.
                    let top = u32::from(d.nlevels).saturating_sub(1);
                    if level - 1 > top {
                        if i == 0 {
                            Was::Under(d)
                        } else {
                            Was::Nothing
                        }
                    } else {
                        d.blkptr.get(i).cloned().map_or(Was::Nothing, was_ptr)
                    }
                }
                _ => Was::Nothing,
            };
            let below = blkid.checked_shl(epbs).unwrap_or(0) | i as u64;
            self.visit(&child, child_was, level - 1, below, tree, epbs);
        }
    }

    /// The earlier object's pointers at `level`, below its own top:
    /// those under the first pointer of each level above. `None` when
    /// what would say did not read.
    fn lowered(&mut self, p: &DnodePhys, level: u32) -> Option<Vec<BlkPtr>> {
        let mut ptrs = p.blkptr.clone();
        let mut at = u32::from(p.nlevels).saturating_sub(1);
        while at > level {
            let first = ptrs.first()?;
            if first.is_hole() {
                return Some(Vec::new());
            }
            let block = self.read(first, Of::Earlier)?;
            let endian = first.endian;
            ptrs = block
                .chunks_exact(blkptr::SIZE)
                .map(|raw| BlkPtr::parse(raw, endian))
                .collect::<Result<_, _>>()
                .ok()?;
            at -= 1;
        }
        Some(ptrs)
    }

    /// The tree of one object as the later group holds it, `c`, against
    /// the earlier one's, `p` — `None` when the earlier has no such
    /// object in that place.
    fn object(&mut self, c: &DnodePhys, p: Option<&DnodePhys>, tree: Tree) {
        if c.nlevels == 0 {
            return;
        }
        let epbs = u32::from(c.indblkshift).saturating_sub(7);
        let top = u32::from(c.nlevels) - 1;
        // Blocks of another size are another object's, whatever is in
        // them: the place is the same in name only.
        let p = p.filter(|p| {
            p.nlevels != 0 && p.indblkshift == c.indblkshift && p.datablkszsec == c.datablkszsec
        });
        let lowered = match p {
            Some(p) if u32::from(p.nlevels) - 1 > top => match self.lowered(p, top) {
                Some(ptrs) => Some(ptrs),
                None => return,
            },
            _ => None,
        };
        for (i, bp) in c.blkptr.iter().enumerate() {
            let was = match (p, &lowered) {
                (None, _) => Was::Nothing,
                (Some(_), Some(ptrs)) => ptrs.get(i).cloned().map_or(Was::Nothing, was_ptr),
                (Some(p), None) if u32::from(p.nlevels) - 1 == top => {
                    p.blkptr.get(i).cloned().map_or(Was::Nothing, was_ptr)
                }
                (Some(p), None) if i == 0 => Was::Under(p),
                (Some(_), None) => Was::Nothing,
            };
            self.visit(bp, was, top, i as u64, tree, epbs);
        }
    }

    /// A block of the object array written after the earlier group: the
    /// objects in it, each against the one the earlier holds there.
    fn dnode_block(&mut self, c: &BlkPtr, was: Was<'_>, blkid: u64) {
        let Some(cb) = self.read(c, Of::Later) else {
            return;
        };
        let pb: Option<(Vec<u8>, Endian)> = match &was {
            Was::Ptr(p) if !p.is_hole() => match self.read(p, Of::Earlier) {
                Some(b) => Some((b, p.endian)),
                None => return,
            },
            _ => None,
        };
        let slots = cb.len() / DNODE_SIZE;
        let mut slot = 0;
        while slot < slots && !self.done() {
            let at = slot * DNODE_SIZE;
            let Ok(d) = DnodePhys::parse(&cb[at..], c.endian) else {
                slot += 1;
                continue;
            };
            let next = slot + 1 + usize::from(d.extra_slots);
            if d.object_type != ot::NONE {
                let object = blkid.saturating_mul(slots as u64) + slot as u64;
                // What the earlier group holds in the slot. A free slot
                // is nothing there: the object was made since. One of
                // another kind says nothing — an object is given a new
                // type where it lies, a dataset made a ZAP of to hold a
                // feature it uses, and is the same object still.
                let p = pb
                    .as_ref()
                    .and_then(|(b, e)| DnodePhys::parse(b.get(at..)?, *e).ok())
                    .filter(|p| p.object_type != ot::NONE);
                self.dataset(&d, p.as_ref(), object);
                let alike = p
                    .as_ref()
                    .is_none_or(|p| p.object_type == d.object_type && p.bonus_type == d.bonus_type);
                if alike && !self.done() {
                    self.object(&d, p.as_ref(), Tree::Object(object));
                }
            }
            slot = next;
        }
    }

    /// A dataset says in its own record when it was made, and keeps its
    /// object for as long as it lives: one made at or before the earlier
    /// group is in that object there too.
    fn dataset(&mut self, c: &DnodePhys, p: Option<&DnodePhys>, object: u64) {
        if c.bonus_type != ot::DSL_DATASET {
            return;
        }
        let Ok(ds) = DslDatasetPhys::parse(&c.bonus, c.endian) else {
            return;
        };
        if ds.creation_txg == 0 || ds.creation_txg > self.txg {
            return;
        }
        let there = p
            .filter(|p| p.bonus_type == ot::DSL_DATASET)
            .and_then(|p| DslDatasetPhys::parse(&p.bonus, p.endian).ok())
            .is_some_and(|was| was.guid == ds.guid && was.creation_txg == ds.creation_txg);
        if !there {
            self.found = Some(Parted {
                what: format!("the dataset of object {object} of the MOS"),
                born: ds.creation_txg,
                earlier_born: None,
            });
        }
    }
}

/// Compare the pool as `earlier` left it with the pool as `later` holds
/// it: what shows that the later was not made from the earlier, if
/// anything read does.
///
/// No proof is not proof that it was: a line left behind whose every
/// change the other line wrote over again shows nothing, and neither
/// does one whose blocks no longer read. An error is a MOS that does
/// not open at one of the two.
pub fn compare(
    reader: &PoolReader<'_>,
    earlier: &Uberblock,
    later: &Uberblock,
) -> Result<Compared, ReadError> {
    let root = |ub: &Uberblock| BlkPtr::parse(&ub.rootbp, ub.endian);
    let (was, now) = (root(earlier)?, root(later)?);
    // The later one opened last: what it knows of vdevs removed since
    // serves the earlier one's blocks too.
    let before = open_mos(reader, earlier)?.meta_object().dnode().clone();
    let after = open_mos(reader, later)?.meta_object().dnode().clone();
    let mut cmp = Compare {
        reader,
        txg: earlier.txg,
        blocks: 0,
        unread: [0; 2],
        found: None,
    };
    if now.birth <= earlier.txg {
        if !same_block(&was, &now) {
            cmp.found = Some(Parted {
                what: "the root of the MOS".to_string(),
                born: now.birth,
                earlier_born: (!was.is_hole()).then_some(was.birth),
            });
        }
    } else {
        cmp.object(&after, Some(&before), Tree::Array);
    }
    Ok(Compared {
        parted: cmp.found,
        unread: cmp.unread[Of::Earlier as usize],
        unread_later: cmp.unread[Of::Later as usize],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{dataset_phys, write_at_dva, Alloc, Pool};
    use crate::pool::{assemble, uberblock_candidates};
    use crate::vdev::scan_device;
    use zfs_ondisk::dmu::encode::{objset, DnodeSpec};
    use zfs_ondisk::dsl::encode::dsl_dataset;
    use zvolrescue_io::{BlockSource, MemSource};

    type Ptr = [u8; blkptr::SIZE];

    /// A pool written a transaction group at a time: a MOS of nothing
    /// but an object array, which is all that is compared.
    struct Maker {
        pool: Pool,
        members: Vec<Vec<u8>>,
        a: Alloc,
    }

    impl Maker {
        fn new() -> Maker {
            Maker {
                pool: Pool::mirror("tank", 0x11ea, 12),
                members: vec![vec![0u8; 64 << 20]; 2],
                a: Alloc::new(0x20_0000),
            }
        }

        /// A data block of `byte`s, written at `txg`.
        fn data(&mut self, byte: u8, txg: u64) -> Ptr {
            self.a.put(
                &mut self.members,
                &[byte; 4096],
                ot::DSL_DIR_CHILD_MAP,
                0,
                txg,
            )
        }

        /// A block of the object array holding `objects` in their
        /// slots, written at `txg`.
        fn array(&mut self, objects: &[(usize, Vec<u8>)], txg: u64) -> Ptr {
            let mut dnodes = vec![0u8; 16384];
            for (slot, d) in objects {
                dnodes[slot * DNODE_SIZE..][..d.len()].copy_from_slice(d);
            }
            self.a.put_dnodes(&mut self.members, &dnodes, txg).0
        }

        /// The pool as `txg` leaves it: `top` are the pointers of the
        /// object array's dnode, of `nlevels` levels.
        fn sync(&mut self, txg: u64, top: &[Ptr], nlevels: u8) {
            let meta = DnodeSpec {
                object_type: ot::DNODE,
                datablksz: 16384,
                nlevels,
                maxblkid: 2,
                blkptrs: top.to_vec(),
                ..DnodeSpec::default()
            }
            .build();
            let root = self
                .a
                .put_objset(&mut self.members, &objset(&meta, 1), 1, txg);
            self.pool.uberblocks.push((txg, 1000 + txg));
            self.pool.rootbp_by_txg.push((txg, root));
        }

        fn compare(&self, earlier: u64, later: u64) -> Compared {
            let sources: Vec<MemSource> = self
                .members
                .iter()
                .enumerate()
                .map(|(i, m)| {
                    let mut m = m.clone();
                    self.pool.write_labels(i, &mut m);
                    MemSource::new(m)
                })
                .collect();
            let scans: Vec<_> = sources.iter().map(|s| scan_device(s).ok()).collect();
            let pool = assemble(&scans).into_iter().next().expect("one pool");
            let candidates = uberblock_candidates(&scans, &pool);
            let ub = |txg: u64| {
                &candidates
                    .iter()
                    .find(|c| c.ub.txg == txg)
                    .expect("an uberblock of that txg")
                    .ub
            };
            let devs: Vec<Option<&dyn BlockSource>> = sources
                .iter()
                .map(|s| Some(s as &dyn BlockSource))
                .collect();
            let reader = PoolReader::new(&pool, devs);
            compare(&reader, ub(earlier), ub(later)).expect("both open")
        }
    }

    /// An object with one data block.
    fn object(block: Ptr) -> Vec<u8> {
        DnodeSpec {
            object_type: ot::DSL_DIR_CHILD_MAP,
            datablksz: 4096,
            blkptrs: vec![block],
            ..DnodeSpec::default()
        }
        .build()
    }

    /// A dataset made at `txg`.
    fn dataset(txg: u64, guid: u64) -> Vec<u8> {
        DnodeSpec {
            object_type: ot::DSL_DATASET,
            bonus_type: ot::DSL_DATASET,
            bonus: dsl_dataset(&dataset_phys(2, 0, &[0; blkptr::SIZE], txg, guid, 0)),
            ..DnodeSpec::default()
        }
        .build()
    }

    /// The pool at txg 10: an object whose block was written at txg 5,
    /// and a dataset made at txg 7. Returns that block.
    fn at_ten(m: &mut Maker) -> Ptr {
        let old = m.data(0x55, 5);
        let array = m.array(&[(1, object(old)), (2, dataset(7, 0xd1))], 10);
        m.sync(10, &[array], 1);
        old
    }

    /// A group made from another holds what the other held, as it was,
    /// wherever it did not write: nothing parts them, however much it
    /// wrote besides — and whatever the clock said.
    #[test]
    fn a_group_made_from_another_shows_nothing() {
        let mut m = Maker::new();
        let old = at_ten(&mut m);
        let new = m.data(0x66, 20);
        let array = m.array(
            &[
                (1, object(old)),
                (2, dataset(7, 0xd1)),
                (3, object(new)),
                (4, dataset(15, 0xd2)),
            ],
            20,
        );
        m.sync(20, &[array], 1);
        assert_eq!(
            m.compare(10, 20),
            Compared {
                parted: None,
                unread: 0,
                unread_later: 0
            }
        );
    }

    /// The later group holds, in an object, a block written before the
    /// earlier one that the earlier does not hold there: it was made
    /// from a group older than that, and the earlier one is of a line
    /// left behind.
    #[test]
    fn an_older_block_the_earlier_does_not_hold_parts_them() {
        let mut m = Maker::new();
        at_ten(&mut m);
        let other = m.data(0x77, 8);
        let array = m.array(&[(1, object(other)), (2, dataset(7, 0xd1))], 20);
        m.sync(20, &[array], 1);
        let parted = m.compare(10, 20).parted.expect("parted");
        assert_eq!(
            (parted.what.as_str(), parted.born, parted.earlier_born),
            ("block 0 of object 1 of the MOS", 8, Some(5))
        );
        assert_eq!(
            parted.says(10, 20),
            "txg 20 holds block 0 of object 1 of the MOS as txg 8 wrote it, and txg 10, after txg 8, holds it as txg 5 did"
        );
    }

    /// A dataset keeps its object for as long as it lives: one made
    /// before the earlier group and not in it parts the two. One given
    /// a new type where it lies — made a ZAP of — is the same dataset.
    #[test]
    fn a_dataset_made_before_and_not_there_parts_them() {
        let mut m = Maker::new();
        let old = at_ten(&mut m);
        let array = m.array(
            &[
                (1, object(old)),
                (2, dataset(7, 0xd1)),
                (3, dataset(9, 0xd3)),
            ],
            20,
        );
        m.sync(20, &[array], 1);
        let parted = m.compare(10, 20).parted.expect("parted");
        assert_eq!(
            (parted.what.as_str(), parted.born, parted.earlier_born),
            ("the dataset of object 3 of the MOS", 9, None)
        );

        let mut m = Maker::new();
        let old = at_ten(&mut m);
        let entries = m.data(0x11, 20);
        let mut zapified = DnodeSpec {
            object_type: zfs_ondisk::dmu::OT_NEWTYPE | zfs_ondisk::dmu::OT_METADATA | 4,
            datablksz: 4096,
            blkptrs: vec![entries],
            bonus_type: ot::DSL_DATASET,
            ..DnodeSpec::default()
        };
        zapified.bonus = dsl_dataset(&dataset_phys(2, 0, &[0; blkptr::SIZE], 7, 0xd1, 0));
        let array = m.array(&[(1, object(old)), (2, zapified.build())], 20);
        m.sync(20, &[array], 1);
        assert_eq!(m.compare(10, 20).parted, None);
    }

    /// The same of the object array itself, and of the root: a block of
    /// it written before the earlier group, which the earlier does not
    /// hold.
    #[test]
    fn an_older_block_of_the_object_array_parts_them() {
        let mut m = Maker::new();
        let old = at_ten(&mut m);
        let rewritten = m.array(&[(1, object(old)), (2, dataset(7, 0xd1))], 20);
        let stray = m.array(&[(5, object(old))], 9);
        m.sync(20, &[rewritten, stray], 1);
        let parted = m.compare(10, 20).parted.expect("parted");
        assert_eq!(
            (parted.what.as_str(), parted.born, parted.earlier_born),
            ("block 1 of the MOS's object array", 9, None)
        );

        // The root: an uberblock that names an older MOS than the
        // earlier one's.
        let mut m = Maker::new();
        let old = at_ten(&mut m);
        let array = m.array(&[(1, object(old))], 9);
        m.a.born = Some(9);
        m.sync(20, &[array], 1);
        let parted = m.compare(10, 20).parted.expect("parted");
        assert_eq!(
            (parted.what.as_str(), parted.born, parted.earlier_born),
            ("the root of the MOS", 9, Some(10))
        );
    }

    /// An object array that grew a level between the two: what the
    /// earlier held is under the first pointer of the new level, and is
    /// found there.
    #[test]
    fn a_taller_tree_is_compared_under_its_first_pointer() {
        let level = |m: &mut Maker, children: &[Ptr], txg: u64| {
            let mut block = vec![0u8; 1 << 17];
            for (i, c) in children.iter().enumerate() {
                block[i * blkptr::SIZE..][..blkptr::SIZE].copy_from_slice(c);
            }
            m.a.put(&mut m.members, &block, ot::DNODE, 1, txg)
        };
        for (third_born, parts) in [(20, false), (9, true)] {
            let mut m = Maker::new();
            let old = m.data(0x55, 5);
            let first = m.array(&[(1, object(old))], 10);
            let second = m.array(&[(2, dataset(7, 0xd1))], 10);
            m.sync(10, &[first, second], 1);
            let made = m.data(0x66, third_born);
            let third = m.array(&[(3, object(made))], third_born);
            let top = level(&mut m, &[first, second, third], 20);
            m.sync(20, &[top], 2);
            let parted = m.compare(10, 20).parted;
            assert_eq!(parted.is_some(), parts, "{parted:?}");
            if let Some(p) = parted {
                assert_eq!(
                    (p.what.as_str(), p.born, p.earlier_born),
                    ("block 2 of the MOS's object array", 9, None)
                );
            }
        }
    }

    /// And the other way about: the earlier group is of a line that grew
    /// the object array a level, the later of one that did not. What the
    /// later holds is held against the pointers under the earlier one's
    /// first.
    #[test]
    fn a_shorter_tree_is_compared_with_what_is_under_the_taller_ones_first_pointer() {
        for (changed, parts) in [(false, false), (true, true)] {
            let mut m = Maker::new();
            let old = m.data(0x55, 5);
            let first = m.array(&[(1, object(old))], 7);
            let second = m.array(&[(2, dataset(7, 0xd1))], 7);
            let mut block = vec![0u8; 1 << 17];
            block[..blkptr::SIZE].copy_from_slice(&first);
            block[blkptr::SIZE..][..blkptr::SIZE].copy_from_slice(&second);
            let top = m.a.put(&mut m.members, &block, ot::DNODE, 1, 10);
            m.sync(10, &[top], 2);
            let other = m.array(&[(2, dataset(6, 0xd4))], 8);
            m.sync(20, &[first, if changed { other } else { second }], 1);
            let parted = m.compare(10, 20).parted;
            assert_eq!(parted.is_some(), parts, "{parted:?}");
            if let Some(p) = parted {
                assert_eq!(
                    (p.what.as_str(), p.born, p.earlier_born),
                    ("block 1 of the MOS's object array", 8, Some(7))
                );
            }
        }
    }

    /// What does not read says nothing, and is counted: a group whose
    /// blocks were written over since is not thereby one left behind.
    #[test]
    fn what_does_not_read_parts_nothing() {
        let mut m = Maker::new();
        let old = m.data(0x55, 5);
        let array = m.array(&[(1, object(old))], 10);
        let at = BlkPtr::parse(&array, Endian::Little)
            .expect("a pointer")
            .dva[0]
            .offset;
        m.sync(10, &[array], 1);
        let other = m.data(0x77, 8);
        let later = m.array(&[(1, object(other))], 20);
        m.sync(20, &[later], 1);
        assert!(m.compare(10, 20).parted.is_some());
        for member in &mut m.members {
            write_at_dva(member, at, &[0xff; 16384]);
        }
        assert_eq!(
            m.compare(10, 20),
            Compared {
                parted: None,
                unread: 1,
                unread_later: 0
            }
        );
    }
}
