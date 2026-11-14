//! Objects: walking a dnode's block tree and the dnode array of an objset.

use zfs_ondisk::blkptr::{self, BlkPtr};
use zfs_ondisk::dmu::{DnodePhys, DNODE_SIZE};
use zfs_ondisk::Endian;

use crate::zio::{PoolReader, ReadError};
use zvolrescue_io::trace;

/// Reads the data of one object through a [`PoolReader`].
pub struct ObjectReader<'r, 'a> {
    reader: &'r PoolReader<'a>,
    dnode: DnodePhys,
    /// Byte order the dnode (and therefore its block pointers) was written in.
    endian: Endian,
}

impl<'r, 'a> ObjectReader<'r, 'a> {
    /// Wrap a dnode parsed with `endian`.
    pub fn new(reader: &'r PoolReader<'a>, dnode: DnodePhys, endian: Endian) -> Self {
        ObjectReader {
            reader,
            dnode,
            endian,
        }
    }

    /// The dnode.
    pub fn dnode(&self) -> &DnodePhys {
        &self.dnode
    }

    /// The pool reader this object reads through.
    pub fn reader(&self) -> &'r PoolReader<'a> {
        self.reader
    }

    /// log2 of block pointers per indirect block.
    fn epbs(&self) -> u32 {
        u32::from(self.dnode.indblkshift).saturating_sub(7)
    }

    /// Find the level-0 block pointer for `blkid`, or `None` when the path
    /// runs through a hole or beyond the pointers the dnode has.
    pub fn locate(&self, blkid: u64) -> Result<Option<BlkPtr>, ReadError> {
        let levels = u32::from(self.dnode.nlevels);
        if levels == 0 {
            return Ok(None);
        }
        let epbs = self.epbs();
        // Index into the dnode's own pointer array at the top level.
        let top_shift = epbs.saturating_mul(levels - 1);
        let top_index = if top_shift >= 64 {
            0
        } else {
            blkid >> top_shift
        };
        if top_index >= self.dnode.blkptr.len() as u64 {
            return Ok(None);
        }
        let mut bp = self.dnode.blkptr[top_index as usize].clone();
        let mut level = levels - 1;
        trace!(
            "dmu",
            "locate blkid {blkid}: nlevels {levels} epbs {epbs} top index {top_index} ({} dnode ptrs)",
            self.dnode.blkptr.len()
        );
        while level > 0 {
            if bp.is_hole() {
                return Ok(None);
            }
            let block = self.reader.read_block(&bp, false)?;
            let shift = epbs * (level - 1);
            let index = ((blkid >> shift) & ((1u64 << epbs) - 1)) as usize;
            let at = index * blkptr::SIZE;
            let child = block.data.get(at..at + blkptr::SIZE).ok_or_else(|| {
                ReadError::Io(format!("indirect block too small for index {index}"))
            })?;
            bp = BlkPtr::parse(child, bp.endian)?;
            trace!(
                "dmu",
                "  level {level} index {index}: child {} birth {}",
                if bp.is_hole() {
                    "HOLE".to_string()
                } else {
                    format!("dva0 vdev {} off {:#x}", bp.dva[0].vdev, bp.dva[0].offset)
                },
                bp.birth
            );
            level -= 1;
        }
        Ok(if bp.is_hole() { None } else { Some(bp) })
    }

    /// Read data block `blkid`: exactly `datablksz` bytes, zeros for a hole.
    ///
    /// A block of any other size is an error, not a block: every data
    /// block of an object is `datablksz` long, and one that is not was
    /// padded with zeros the object never had, or cut short of bytes it
    /// did, and read as whole.
    pub fn read_blkid(&self, blkid: u64) -> Result<Vec<u8>, ReadError> {
        self.read_blkid_ext(blkid).map(|(d, _)| d)
    }

    /// Like [`read_blkid`](Self::read_blkid) but also returns the byte
    /// order the block was written in (the dnode's for holes), which
    /// structured blocks such as ZAPs need for their own fields.
    pub fn read_blkid_ext(&self, blkid: u64) -> Result<(Vec<u8>, Endian), ReadError> {
        let size = self.dnode.datablksz() as usize;
        match self.locate(blkid)? {
            None => Ok((vec![0; size], self.endian)),
            Some(bp) => {
                let data = self.reader.read_block(&bp, false)?.data;
                if data.len() != size {
                    return Err(ReadError::Io(format!(
                        "block {blkid} is {} bytes, and the object's blocks are {size}",
                        data.len()
                    )));
                }
                Ok((data, bp.endian))
            }
        }
    }

    /// Byte order the dnode was parsed with.
    pub fn endian(&self) -> Endian {
        self.endian
    }

    /// Read `len` bytes starting at byte `offset` of the object, crossing
    /// block boundaries as needed.
    ///
    /// Every caller reads an object meant to be small — a packed nvlist,
    /// a space map, a link target, an attribute — whole, at a length the
    /// object's own dnode gave. A length past [`MAX_RANGE`] is refused as
    /// no such object: one dnode claiming 2^40 blocks asked for 4 PiB up
    /// front, and the allocation's failure aborted the process.
    pub fn read_range(&self, offset: u64, len: usize) -> Result<Vec<u8>, ReadError> {
        let bs = self.dnode.datablksz();
        if bs == 0 {
            return Err(ReadError::Io("dnode has zero data block size".into()));
        }
        let end = offset
            .checked_add(len as u64)
            .filter(|_| len as u64 <= MAX_RANGE)
            .ok_or_else(|| {
                ReadError::Io(format!(
                    "{len} bytes at {offset} is past what an object read whole can be ({MAX_RANGE} bytes)"
                ))
            })?;
        let mut out = Vec::with_capacity(len.min(1 << 24));
        let mut pos = offset;
        while pos < end {
            let blkid = pos / bs;
            let within = (pos % bs) as usize;
            let take = ((bs - within as u64).min(end - pos)) as usize;
            let block = self.read_blkid(blkid)?;
            out.extend_from_slice(&block[within..within + take]);
            pos += take as u64;
        }
        Ok(out)
    }

    /// How many level-0 blocks the object has up to and including the
    /// last one that is not a hole, found from its pointers: `None` when
    /// that is not known — an indirect block on the way did not read, or
    /// was not the size its dnode gives, or the search took more than
    /// [`MAX_TAIL_READS`] of them.
    ///
    /// Past it the object is a hole whatever `dn_maxblkid` says, and
    /// [`locate`](Self::locate) finds nothing there. A forged
    /// `dn_maxblkid` of 2^40 over a file of one block had every one of
    /// those blocks located, through no pointer at all, for days and
    /// without a word.
    pub fn data_blocks(&self) -> Option<u64> {
        let levels = u32::from(self.dnode.nlevels);
        if levels == 0 {
            return Some(0);
        }
        let mut reads = 0;
        let last = self.last_in(&self.dnode.blkptr, levels - 1, 0, &mut reads)?;
        Some(last.map_or(0, |b| b.saturating_add(1)))
    }

    /// The last level-0 block id under `ptrs`, the pointers of one
    /// level whose first starts at block `base`: `Some(None)` when all
    /// of it is holes, `None` when that is not known.
    fn last_in(
        &self,
        ptrs: &[BlkPtr],
        level: u32,
        base: u64,
        reads: &mut u32,
    ) -> Option<Option<u64>> {
        let epbs = self.epbs();
        // How many blocks one pointer at this level spans; more than a
        // block id can count at the top of a tall tree.
        let span = epbs
            .checked_mul(level)
            .and_then(|shift| 1u64.checked_shl(shift));
        for (i, bp) in ptrs.iter().enumerate().rev() {
            if bp.is_hole() {
                continue;
            }
            // A pointer whose first block no block id can name holds no
            // block a reader could ask for; it is passed over. That it
            // could not be counted made the answer "not known", and the
            // caller fell back on `dn_maxblkid` — a tree of 8 levels
            // claiming 2^40 blocks read them all, 56 days, without a word.
            let Some(start) = (if i == 0 {
                Some(base)
            } else {
                span.and_then(|s| (i as u64).checked_mul(s))
                    .and_then(|o| base.checked_add(o))
            }) else {
                continue;
            };
            if level == 0 {
                return Some(Some(start));
            }
            *reads += 1;
            if *reads > MAX_TAIL_READS {
                return None;
            }
            let block = self.reader.read_block(bp, false).ok()?;
            // `locate` takes an index into exactly 2^epbs pointers: an
            // indirect block of another size is not one this answers for.
            let count = 1usize.checked_shl(epbs)?;
            if block.data.len() != count.checked_mul(blkptr::SIZE)? {
                return None;
            }
            let children = block
                .data
                .chunks_exact(blkptr::SIZE)
                .map(|c| BlkPtr::parse(c, bp.endian))
                .collect::<Result<Vec<_>, _>>()
                .ok()?;
            if let Some(found) = self.last_in(&children, level - 1, start, reads)? {
                return Some(Some(found));
            }
        }
        Some(None)
    }

    /// Bytes this object logically spans (`(maxblkid + 1) * datablksz`).
    ///
    /// `dn_maxblkid` is whatever the dnode says, and a hostile one makes
    /// a size no object has: the product saturates rather than wraps, so
    /// a caller sees an absurd size — which [`read_range`](Self::read_range)
    /// refuses — instead of a small wrong one.
    pub fn logical_size(&self) -> u64 {
        self.dnode
            .maxblkid
            .saturating_add(1)
            .saturating_mul(self.dnode.datablksz())
    }
}

/// The most indirect blocks [`ObjectReader::data_blocks`] reads: the
/// last path down is one per level, and an indirect block that is all
/// holes underneath, which sends the search back one pointer, is rare.
pub const MAX_TAIL_READS: u32 = 64;

/// The most [`ObjectReader::read_range`] reads in one call: 1 GiB, far
/// above any object read whole and far below what a hostile length asks.
pub const MAX_RANGE: u64 = 1 << 30;

/// The dnode array of an objset, addressed by object number.
pub struct DnodeArray<'r, 'a> {
    meta: ObjectReader<'r, 'a>,
}

impl<'r, 'a> DnodeArray<'r, 'a> {
    /// Wrap the meta-dnode of an objset.
    pub fn new(reader: &'r PoolReader<'a>, meta_dnode: DnodePhys, endian: Endian) -> Self {
        DnodeArray {
            meta: ObjectReader::new(reader, meta_dnode, endian),
        }
    }

    /// Dnode slots per data block of the array.
    pub fn slots_per_block(&self) -> u64 {
        self.meta.dnode.datablksz() / DNODE_SIZE as u64
    }

    /// Highest object number that can exist in this array.
    pub fn max_object(&self) -> u64 {
        self.meta
            .dnode
            .maxblkid
            .saturating_add(1)
            .saturating_mul(self.slots_per_block())
    }

    /// Read and parse dnode `objnum`; a free slot parses as a free dnode.
    pub fn get(&self, objnum: u64) -> Result<DnodePhys, ReadError> {
        let (block, endian) = self.block(objnum)?;
        self.parse_in(&block, endian, objnum)
    }

    /// The block of the array that holds `objnum`, and the byte order it
    /// was written in. For a caller that walks the array and has to tell
    /// a block that does not read — every object in it lost — from one
    /// object that does not parse.
    pub fn block(&self, objnum: u64) -> Result<(Vec<u8>, Endian), ReadError> {
        let per = self.slots_per_block();
        if per == 0 {
            return Err(ReadError::Io("meta-dnode has zero data block size".into()));
        }
        // Each block of the array in the byte order its own pointer gives:
        // a pool written by two hosts has dnode blocks of both orders, and
        // the array's order read a big-endian block's pointers as nonsense
        // ("DVA names unknown top-level vdev").
        self.meta.read_blkid_ext(objnum / per)
    }

    /// Object `objnum` out of its block, as [`block`](Self::block) gave it.
    pub fn parse_in(
        &self,
        block: &[u8],
        endian: Endian,
        objnum: u64,
    ) -> Result<DnodePhys, ReadError> {
        let per = self.slots_per_block().max(1);
        let at = ((objnum % per) * DNODE_SIZE as u64) as usize;
        let d = DnodePhys::parse(block.get(at..).unwrap_or(&[]), endian)?;
        trace!(
            "dnode",
            "object {objnum} (block {} slot {}): type {} ({}) nlevels {} nblkptr {} indblkshift {} datablksz {} maxblkid {} bonustype {} bonuslen {}{}",
            objnum / per,
            objnum % per,
            d.object_type,
            d.type_name(),
            d.nlevels,
            d.nblkptr,
            d.indblkshift,
            d.datablksz(),
            d.maxblkid,
            d.bonus_type,
            d.bonuslen,
            if d.spill.is_some() { " spill" } else { "" }
        );
        Ok(d)
    }

    /// The next object number after `objnum`, skipping the slots a
    /// large dnode owns.
    ///
    /// A dnode with `dn_extra_slots` occupies the slots that follow it,
    /// and those slots hold the rest of its bonus buffer, not dnodes.
    /// Parsing one as a dnode reads attribute bytes as a header:
    /// usually that fails loudly, but nothing guarantees it — the bytes
    /// are whatever the file's attributes happen to be, and a
    /// sufficiently unlucky bonus parses as an object that was never
    /// there. Stepping with this rather than by one is the only safe
    /// way to walk an array that has large dnodes in it.
    ///
    /// A slot that cannot be read at all advances by one, so a walk
    /// gets past it instead of stopping.
    pub fn next_object(&self, objnum: u64) -> u64 {
        objnum + 1 + self.get(objnum).map_or(0, |d| u64::from(d.extra_slots))
    }

    /// An [`ObjectReader`] for object `objnum`.
    pub fn object(&self, objnum: u64) -> Result<ObjectReader<'r, 'a>, ReadError> {
        let dnode = self.get(objnum)?;
        let endian = dnode.endian;
        Ok(ObjectReader::new(self.meta.reader, dnode, endian))
    }

    /// Byte order the array's dnodes were written in.
    pub fn endian(&self) -> Endian {
        self.meta.endian
    }

    /// The meta-dnode as an object (the raw dnode array).
    pub fn meta_object(&self) -> &ObjectReader<'r, 'a> {
        &self.meta
    }

    /// The pool reader behind this array.
    pub(crate) fn meta_reader(&self) -> &'r PoolReader<'a> {
        self.meta.reader
    }
}

impl From<zfs_ondisk::ParseError> for ReadError {
    fn from(e: zfs_ondisk::ParseError) -> Self {
        ReadError::Io(format!("parse: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{Alloc, Pool};
    use crate::pool::assemble;
    use crate::vdev::scan_device;
    use zfs_ondisk::dmu::{encode::DnodeSpec, ot};
    use zfs_ondisk::label::LABEL_SIZE;
    use zvolrescue_io::{BlockSource, MemSource};

    const SIZE: u64 = 64 * LABEL_SIZE;

    fn pattern(blkid: u64, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| ((blkid * 31 + i as u64) % 251) as u8)
            .collect()
    }

    /// Build a 2-member mirror whose member images carry `f`'s allocations.
    fn build(
        f: impl FnOnce(&mut Alloc, &mut [Vec<u8>]) -> DnodePhys,
    ) -> (Vec<MemSource>, crate::pool::PoolAssembly, DnodePhys) {
        let pool = Pool::mirror("tank", 0x99, 12).txgs(&[(100, 1)]);
        let mut members = vec![pool.member_image(0, SIZE), pool.member_image(1, SIZE)];
        let mut alloc = Alloc::new(0x10_0000);
        let dnode = f(&mut alloc, &mut members);
        let sources: Vec<MemSource> = members.into_iter().map(MemSource::new).collect();
        let scans: Vec<_> = sources.iter().map(|s| scan_device(s).ok()).collect();
        let assembly = assemble(&scans).into_iter().next().unwrap();
        (sources, assembly, dnode)
    }

    fn dyn_sources(s: &[MemSource]) -> Vec<Option<&dyn BlockSource>> {
        s.iter().map(|m| Some(m as &dyn BlockSource)).collect()
    }

    /// An object with `nlevels` levels, indblkshift 10 (8 pointers per
    /// indirect block), 4 KiB data blocks, with data at `present` blkids.
    fn object(
        alloc: &mut Alloc,
        members: &mut [Vec<u8>],
        nlevels: u8,
        present: &[u64],
    ) -> DnodePhys {
        let epbs = 3u32;
        let bs = 4096usize;
        // Build bottom-up: level-0 pointers for present blocks.
        let mut level_ptrs: Vec<(u64, [u8; 128])> = present
            .iter()
            .map(|&b| (b, alloc.put(members, &pattern(b, bs), ot::ZVOL, 0, 100)))
            .collect();
        for level in 1..nlevels {
            let mut next: Vec<(u64, [u8; 128])> = Vec::new();
            let mut ids: Vec<u64> = level_ptrs.iter().map(|(b, _)| b >> epbs).collect();
            ids.dedup();
            for id in ids {
                let mut block = vec![0u8; 1024];
                for (b, bp) in &level_ptrs {
                    if b >> epbs == id {
                        let idx = (b & 7) as usize;
                        block[idx * 128..(idx + 1) * 128].copy_from_slice(bp);
                    }
                }
                next.push((id, alloc.put(members, &block, ot::ZVOL, level, 100)));
            }
            level_ptrs = next;
        }
        assert_eq!(level_ptrs.len(), 1, "top level must fit one pointer");
        let raw = DnodeSpec {
            object_type: ot::ZVOL,
            indblkshift: 10,
            nlevels,
            datablksz: bs as u64,
            maxblkid: *present.iter().max().unwrap(),
            blkptrs: vec![level_ptrs[0].1],
            ..DnodeSpec::default()
        }
        .build();
        DnodePhys::parse(&raw, Endian::Little).unwrap()
    }

    #[test]
    fn two_levels_with_holes() {
        let (sources, assembly, dnode) = build(|a, m| object(a, m, 2, &[0, 1, 5]));
        let dyns = dyn_sources(&sources);
        let reader = PoolReader::new(&assembly, dyns);
        let obj = ObjectReader::new(&reader, dnode, Endian::Little);
        assert_eq!(obj.read_blkid(0).unwrap(), pattern(0, 4096));
        assert_eq!(obj.read_blkid(5).unwrap(), pattern(5, 4096));
        assert_eq!(obj.read_blkid(3).unwrap(), vec![0; 4096]);
        assert!(obj.locate(3).unwrap().is_none());
        assert!(obj.locate(9).unwrap().is_none()); // beyond the single top pointer
        assert_eq!(obj.logical_size(), 6 * 4096);
        // A range spanning the end of block 0 and the start of block 1.
        let r = obj.read_range(4000, 200).unwrap();
        assert_eq!(&r[..96], &pattern(0, 4096)[4000..]);
        assert_eq!(&r[96..], &pattern(1, 4096)[..104]);
    }

    /// A dnode that claims more blocks than any object has — `2^40`, or
    /// `u64::MAX` — gives a size that saturates, and reading it whole is
    /// refused: it used to ask for 4 PiB up front and abort.
    #[test]
    fn an_object_too_large_to_be_read_whole_is_refused() {
        let (sources, assembly, mut dnode) = build(|a, m| object(a, m, 2, &[0, 1, 5]));
        let dyns = dyn_sources(&sources);
        let reader = PoolReader::new(&assembly, dyns);
        for maxblkid in [1u64 << 40, u64::MAX] {
            dnode.maxblkid = maxblkid;
            let obj = ObjectReader::new(&reader, dnode.clone(), Endian::Little);
            assert!(obj.logical_size() >= 1 << 52, "{maxblkid}");
            let len = obj.logical_size().min(usize::MAX as u64) as usize;
            assert!(obj.read_range(0, len).is_err(), "{maxblkid}");
            assert!(obj.read_range(u64::MAX - 1, 16).is_err(), "{maxblkid}");
            // A small read of the same object still works.
            assert_eq!(obj.read_range(0, 16).unwrap(), pattern(0, 4096)[..16]);
        }
    }

    /// The last block that holds data is found from the pointers, not
    /// from `dn_maxblkid`: a forged one of 2^40 over six blocks says
    /// six, and so does an honest one. Where the way down does not read,
    /// it is not known, and not taken as "nothing".
    #[test]
    fn the_last_block_with_data_is_found_from_the_pointers() {
        for (levels, present, want) in [
            (2u8, &[0u64, 1, 5][..], 6u64),
            (3, &[0, 63, 17], 64),
            (3, &[2], 3),
        ] {
            let (sources, assembly, mut dnode) = build(|a, m| object(a, m, levels, present));
            let dyns = dyn_sources(&sources);
            let reader = PoolReader::new(&assembly, dyns);
            for maxblkid in [dnode.maxblkid, 1 << 40] {
                dnode.maxblkid = maxblkid;
                let obj = ObjectReader::new(&reader, dnode.clone(), Endian::Little);
                assert_eq!(
                    obj.data_blocks(),
                    Some(want),
                    "{levels} {present:?} {maxblkid}"
                );
                assert!(obj.locate(want).unwrap().is_none());
            }
        }
        let (sources, assembly, dnode) = build(|a, m| {
            let d = object(a, m, 2, &[0, 1]);
            let off = (zfs_ondisk::blkptr::LABEL_START_SIZE + d.blkptr[0].dva[0].offset) as usize;
            for img in m.iter_mut() {
                img[off + 3] ^= 0xff;
            }
            d
        });
        let dyns = dyn_sources(&sources);
        let reader = PoolReader::new(&assembly, dyns);
        let obj = ObjectReader::new(&reader, dnode, Endian::Little);
        assert_eq!(obj.data_blocks(), None);
    }

    /// A tree of 8 levels has more blocks under each top-level pointer
    /// than a block id counts. Its answer was "not known", and the caller
    /// took `dn_maxblkid` for it — 2^40 blocks of a file whose one
    /// pointer is a hole, read for 56 days. What no block id can name is
    /// passed over; what one can is counted as ever.
    #[test]
    fn a_tree_too_tall_to_count_is_counted_where_it_can_be() {
        let (sources, assembly, mut dnode) = build(|a, m| object(a, m, 2, &[0, 1]));
        let dyns = dyn_sources(&sources);
        let reader = PoolReader::new(&assembly, dyns);
        dnode.nlevels = 8;
        dnode.maxblkid = 1 << 40;
        dnode.blkptr[0] = BlkPtr::parse(&[0u8; blkptr::SIZE], Endian::Little).unwrap();
        let obj = ObjectReader::new(&reader, dnode, Endian::Little);
        assert_eq!(obj.data_blocks(), Some(0));
    }

    /// A data block of another size than the object's is no block of it:
    /// padded with zeros or cut to fit, it was read as whole.
    #[test]
    fn a_block_of_another_size_is_an_error() {
        let (sources, assembly, mut dnode) = build(|a, m| object(a, m, 2, &[0, 1]));
        let dyns = dyn_sources(&sources);
        let reader = PoolReader::new(&assembly, dyns);
        for sectors in [16u16, 2] {
            dnode.datablkszsec = sectors;
            let obj = ObjectReader::new(&reader, dnode.clone(), Endian::Little);
            let e = obj.read_blkid(0).unwrap_err().to_string();
            assert!(
                e.contains(&format!(
                    "block 0 is 4096 bytes, and the object's blocks are {}",
                    u64::from(sectors) * 512
                )),
                "{e}"
            );
        }
    }

    #[test]
    fn three_levels() {
        let (sources, assembly, dnode) = build(|a, m| object(a, m, 3, &[0, 63, 17]));
        let dyns = dyn_sources(&sources);
        let reader = PoolReader::new(&assembly, dyns);
        let obj = ObjectReader::new(&reader, dnode, Endian::Little);
        assert_eq!(obj.read_blkid(63).unwrap(), pattern(63, 4096));
        assert_eq!(obj.read_blkid(17).unwrap(), pattern(17, 4096));
        assert_eq!(obj.read_blkid(18).unwrap(), vec![0; 4096]);
        assert_eq!(obj.read_blkid(64).unwrap(), vec![0; 4096]);
    }

    #[test]
    fn damaged_indirect_block_is_reported() {
        let (sources, assembly, dnode) = build(|a, m| {
            let d = object(a, m, 2, &[0, 1]);
            // Damage the indirect block on both members.
            let off = (zfs_ondisk::blkptr::LABEL_START_SIZE + d.blkptr[0].dva[0].offset) as usize;
            for img in m.iter_mut() {
                img[off + 3] ^= 0xff;
            }
            d
        });
        let dyns = dyn_sources(&sources);
        let reader = PoolReader::new(&assembly, dyns);
        let obj = ObjectReader::new(&reader, dnode, Endian::Little);
        assert_eq!(obj.read_blkid(0).unwrap_err(), ReadError::AllCopiesBad);
    }

    #[test]
    fn dnode_array_lookup() {
        let (sources, assembly, meta) = build(|a, m| {
            // 16 KiB dnode blocks: 32 slots each. Object 40 lives in block 1, slot 8.
            let target = DnodeSpec {
                object_type: ot::DSL_DATASET,
                maxblkid: 77,
                bonus: vec![9u8; 64],
                ..DnodeSpec::default()
            }
            .build();
            let mut block1 = vec![0u8; 16384];
            block1[8 * 512..9 * 512].copy_from_slice(&target);
            let block0 = vec![0u8; 16384];
            let bp0 = a.put(m, &block0, ot::DNODE, 0, 100);
            let bp1 = a.put(m, &block1, ot::DNODE, 0, 100);
            let mut ind = vec![0u8; 1024];
            ind[..128].copy_from_slice(&bp0);
            ind[128..256].copy_from_slice(&bp1);
            let top = a.put(m, &ind, ot::DNODE, 1, 100);
            let raw = DnodeSpec {
                object_type: ot::DNODE,
                indblkshift: 10,
                nlevels: 2,
                datablksz: 16384,
                maxblkid: 1,
                blkptrs: vec![top],
                ..DnodeSpec::default()
            }
            .build();
            DnodePhys::parse(&raw, Endian::Little).unwrap()
        });
        let dyns = dyn_sources(&sources);
        let reader = PoolReader::new(&assembly, dyns);
        let array = DnodeArray::new(&reader, meta, Endian::Little);
        assert_eq!(array.slots_per_block(), 32);
        assert_eq!(array.max_object(), 64);
        let d = array.get(40).unwrap();
        assert_eq!(d.object_type, ot::DSL_DATASET);
        assert_eq!(d.maxblkid, 77);
        assert_eq!(d.bonus.len(), 64);
        assert!(array.get(41).unwrap().is_free());
        assert!(array.get(3).unwrap().is_free());
        let obj = array.object(40).unwrap();
        assert_eq!(obj.dnode().maxblkid, 77);
    }
}
