//! Reading whole ZAP objects: microzap, or fatzap header + pointer table +
//! every leaf.

use std::collections::BTreeSet;

use zfs_ondisk::zap::{
    block_type, embedded_ptrtbl, parse_fat_header, parse_leaf, parse_micro, ptrtbl_block,
    BlockType, Entry,
};

use crate::dmu::ObjectReader;
use crate::zio::ReadError;
use zvolrescue_io::trace;
use zvolrescue_io::trace::hexdump;

/// Upper bound on leaf blocks read from one ZAP, against hostile pointer
/// tables (a real MOS ZAP has at most thousands).
pub const MAX_LEAVES: usize = 1 << 20;

/// The most blocks a fat ZAP's pointer table is read from: 2^20 blocks
/// of pointers name far more leaves than [`MAX_LEAVES`].
pub const MAX_PTRTBL_BLOCKS: u64 = 1 << 20;

/// Read every entry of the ZAP object `obj`, in on-disk order.
///
/// All or nothing: a leaf that cannot be read fails the whole object.
/// That is right for the pool's own metadata, where half a directory of
/// datasets is a wrong answer; a file system's directory wants
/// [`read_zap_partial`].
pub fn read_zap(obj: &ObjectReader<'_, '_>) -> Result<Vec<Entry>, ReadError> {
    let read = read_zap_partial(obj)?;
    match read.lost.into_iter().next() {
        Some((_, e)) => Err(e),
        None => Ok(read.entries),
    }
}

/// What a fat ZAP gave, and the leaves it could not.
#[derive(Debug, Clone)]
pub struct ZapRead {
    /// Every entry of every leaf that could be read.
    pub entries: Vec<Entry>,
    /// Leaf blocks that could not be read, or were not leaves when read
    /// whole, by block id: the entries hashed into them are missing.
    pub lost: Vec<(u64, ReadError)>,
}

/// Read what can be read of the ZAP object `obj`.
///
/// One leaf of a fat ZAP that could not be read failed the whole object,
/// and with it every entry in every other leaf: a directory of thousands
/// of files lost to one bad block, and every subtree under it. The
/// leaves that read are read; the ones that did not are named. Block 0
/// and the pointer table are still all or nothing — without them no
/// leaf can be found — and so is a device whose refusal stops the run.
pub fn read_zap_partial(obj: &ObjectReader<'_, '_>) -> Result<ZapRead, ReadError> {
    let (block0, endian) = obj.read_blkid_ext(0)?;
    let kind = block_type(&block0, endian);
    trace!(
        "zap",
        "block 0: {kind:?} ({} bytes, {endian:?})",
        block0.len()
    );
    match kind {
        Some(BlockType::Micro) => {
            let entries = parse_micro(&block0, endian)?;
            trace!(
                "zap",
                "microzap: {} entries: {}",
                entries.len(),
                names(&entries)
            );
            Ok(ZapRead {
                entries,
                lost: Vec::new(),
            })
        }
        Some(BlockType::Header) => {
            let hdr = parse_fat_header(&block0, endian)?;
            trace!(
                "zap",
                "fatzap: ptrtbl blk {} numblks {} shift {}, {} leafs, {} entries, flags {:#x}",
                hdr.ptrtbl_blk,
                hdr.ptrtbl_numblks,
                hdr.ptrtbl_shift,
                hdr.num_leafs,
                hdr.num_entries,
                hdr.flags
            );
            let mut leaves: BTreeSet<u64> = BTreeSet::new();
            // The table is blocks of this object, so it ends where the
            // object does. Taken as the header gave it, a length of 2^40
            // ran past every block the object has into holes, which read
            // as zeros without touching a disk: a loop of 2^40 steps that
            // named no leaf and never tripped the bound on leaves.
            let blocks = obj.dnode().maxblkid.saturating_add(1);
            if hdr.ptrtbl_numblks > MAX_PTRTBL_BLOCKS
                || hdr.ptrtbl_blk.saturating_add(hdr.ptrtbl_numblks) > blocks
            {
                return Err(ReadError::Io(format!(
                    "ZAP pointer table of {} block(s) from block {} does not fit the object's {blocks} block(s)",
                    hdr.ptrtbl_numblks, hdr.ptrtbl_blk
                )));
            }
            if hdr.ptrtbl_numblks == 0 {
                leaves.extend(embedded_ptrtbl(&block0, endian));
            } else {
                for b in hdr.ptrtbl_blk..hdr.ptrtbl_blk.saturating_add(hdr.ptrtbl_numblks) {
                    let (blk, e) = obj.read_blkid_ext(b)?;
                    leaves.extend(ptrtbl_block(&blk, e));
                    if leaves.len() > MAX_LEAVES {
                        return Err(ReadError::Io(
                            "ZAP pointer table names too many leaves".into(),
                        ));
                    }
                }
            }
            leaves.remove(&0);
            trace!("zap", "leaf blocks: {:?}", leaves);
            if leaves.len() > MAX_LEAVES {
                return Err(ReadError::Io(
                    "ZAP pointer table names too many leaves".into(),
                ));
            }
            let mut out = Vec::new();
            let mut lost = Vec::new();
            for blkid in leaves {
                let (leaf, e) = match obj.read_blkid_ext(blkid) {
                    Ok(v) => v,
                    Err(e @ ReadError::Medium { stop: true, .. }) => return Err(e),
                    Err(e) => {
                        trace!("zap", "leaf {blkid}: {e}");
                        lost.push((blkid, e));
                        continue;
                    }
                };
                match block_type(&leaf, e) {
                    Some(BlockType::Leaf) => {
                        let entries = match parse_leaf(&leaf, e) {
                            Ok(v) => v,
                            Err(err) => {
                                lost.push((blkid, ReadError::from(err)));
                                continue;
                            }
                        };
                        trace!(
                            "zap",
                            "leaf {blkid}: {} entries: {}",
                            entries.len(),
                            names(&entries)
                        );
                        out.extend(entries);
                    }
                    // A pointer into a hole or a non-leaf block: skip, the
                    // table can be stale during a split.
                    other => {
                        trace!("zap", "leaf {blkid}: not a leaf ({other:?}), skipped");
                        continue;
                    }
                }
            }
            Ok(ZapRead { entries: out, lost })
        }
        Some(BlockType::Leaf) => Err(ReadError::Io("ZAP object starts with a leaf block".into())),
        None => {
            trace!(
                "zap",
                "not a ZAP; first bytes:\n{}",
                hexdump(&block0, 0, 64)
            );
            Err(ReadError::Io("object is not a ZAP".into()))
        }
    }
}

fn names(entries: &[Entry]) -> String {
    const MAX: usize = 12;
    let mut s: Vec<String> = entries.iter().take(MAX).map(|e| e.name.clone()).collect();
    if entries.len() > MAX {
        s.push(format!("… +{}", entries.len() - MAX));
    }
    s.join(", ")
}

/// Look up one name.
pub fn lookup(obj: &ObjectReader<'_, '_>, name: &str) -> Result<Option<Entry>, ReadError> {
    Ok(read_zap(obj)?.into_iter().find(|e| e.name == name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{Alloc, Pool};
    use crate::pool::assemble;
    use crate::vdev::scan_device;
    use crate::zio::PoolReader;
    use zfs_ondisk::dmu::{encode::DnodeSpec, ot, DnodePhys};
    use zfs_ondisk::label::LABEL_SIZE;
    use zfs_ondisk::zap::encode::{fat_header, leaf, micro};
    use zfs_ondisk::zap::Value;
    use zfs_ondisk::Endian;
    use zvolrescue_io::{BlockSource, MemSource};

    const SIZE: u64 = 64 * LABEL_SIZE;

    fn setup(
        f: impl FnOnce(&mut Alloc, &mut [Vec<u8>]) -> DnodePhys,
    ) -> (Vec<MemSource>, crate::pool::PoolAssembly, DnodePhys) {
        let pool = Pool::mirror("tank", 0x99, 12).txgs(&[(100, 1)]);
        let mut members = vec![pool.member_image(0, SIZE)];
        let mut alloc = Alloc::new(0x10_0000);
        let dnode = f(&mut alloc, &mut members);
        let sources: Vec<MemSource> = members.into_iter().map(MemSource::new).collect();
        let scans: Vec<_> = sources.iter().map(|s| scan_device(s).ok()).collect();
        let assembly = assemble(&scans).into_iter().next().unwrap();
        (sources, assembly, dnode)
    }

    fn dnode_with_blocks(
        alloc: &mut Alloc,
        m: &mut [Vec<u8>],
        blocks: &[Vec<u8>],
        bs: u64,
    ) -> DnodePhys {
        let ptrs: Vec<[u8; 128]> = blocks
            .iter()
            .map(|b| alloc.put(m, b, ot::OBJECT_DIRECTORY, 0, 100))
            .collect();
        // Up to three blocks hang directly off the dnode; more go through
        // one 1 KiB indirect block (8 pointers).
        let (blkptrs, nlevels) = if ptrs.len() <= 3 {
            (ptrs, 1)
        } else {
            assert!(ptrs.len() <= 8);
            let mut ind = vec![0u8; 1024];
            for (i, p) in ptrs.iter().enumerate() {
                ind[i * 128..(i + 1) * 128].copy_from_slice(p);
            }
            (vec![alloc.put(m, &ind, ot::OBJECT_DIRECTORY, 1, 100)], 2)
        };
        let raw = DnodeSpec {
            object_type: ot::OBJECT_DIRECTORY,
            indblkshift: 10,
            nlevels,
            datablksz: bs,
            maxblkid: blocks.len() as u64 - 1,
            blkptrs,
            ..DnodeSpec::default()
        }
        .build();
        DnodePhys::parse(&raw, Endian::Little).unwrap()
    }

    #[test]
    fn microzap_object() {
        let (s, a, d) = setup(|al, m| {
            dnode_with_blocks(
                al,
                m,
                &[micro(4096, &[("root_dataset", 2), ("config", 3)])],
                4096,
            )
        });
        let dyns: Vec<Option<&dyn BlockSource>> =
            s.iter().map(|x| Some(x as &dyn BlockSource)).collect();
        let reader = PoolReader::new(&a, dyns);
        let obj = ObjectReader::new(&reader, d, Endian::Little);
        let e = read_zap(&obj).unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!(
            lookup(&obj, "config").unwrap().unwrap().value,
            Value::U64(3)
        );
        assert!(lookup(&obj, "nope").unwrap().is_none());
    }

    #[test]
    fn fatzap_object_with_embedded_table() {
        let (s, a, d) = setup(|al, m| {
            let hdr = fat_header(4096, 1, 2);
            let lf = leaf(
                4096,
                &[
                    ("vm", 8, 40u64.to_be_bytes().to_vec()),
                    ("home", 8, 41u64.to_be_bytes().to_vec()),
                ],
            );
            dnode_with_blocks(al, m, &[hdr, lf], 4096)
        });
        let dyns: Vec<Option<&dyn BlockSource>> =
            s.iter().map(|x| Some(x as &dyn BlockSource)).collect();
        let reader = PoolReader::new(&a, dyns);
        let obj = ObjectReader::new(&reader, d, Endian::Little);
        let e = read_zap(&obj).unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].name, "vm");
        assert_eq!(e[1].value.as_u64(), Some(41));
    }

    #[test]
    fn fatzap_object_with_external_table_and_two_leaves() {
        let (s, a, d) = setup(|al, m| {
            let mut hdr = fat_header(4096, 0, 3);
            // External table: 1 block starting at blkid 1, entries point at leaves 2 and 3.
            hdr[16..24].copy_from_slice(&1u64.to_le_bytes());
            hdr[24..32].copy_from_slice(&1u64.to_le_bytes());
            let mut table = vec![0u8; 4096];
            for i in 0..512usize {
                let target: u64 = if i < 256 { 2 } else { 3 };
                table[i * 8..i * 8 + 8].copy_from_slice(&target.to_le_bytes());
            }
            let l2 = leaf(4096, &[("a", 8, 1u64.to_be_bytes().to_vec())]);
            let l3 = leaf(
                4096,
                &[
                    ("b", 8, 2u64.to_be_bytes().to_vec()),
                    ("c", 1, b"str\0".to_vec()),
                ],
            );
            dnode_with_blocks(al, m, &[hdr, table, l2, l3], 4096)
        });
        let dyns: Vec<Option<&dyn BlockSource>> =
            s.iter().map(|x| Some(x as &dyn BlockSource)).collect();
        let reader = PoolReader::new(&a, dyns);
        let obj = ObjectReader::new(&reader, d, Endian::Little);
        let e = read_zap(&obj).unwrap();
        let names: Vec<&str> = e.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "c"]);
        assert_eq!(e[2].value.as_str().as_deref(), Some("str"));
    }

    /// A pointer table longer than the object it is in is refused at
    /// once: one of 2^40 blocks read 2^40 holes, which cost no I/O and
    /// named no leaf, and the walk never ended.
    #[test]
    fn a_pointer_table_past_the_object_is_refused() {
        let (s, a, d) = setup(|al, m| {
            let mut hdr = fat_header(4096, 0, 3);
            hdr[16..24].copy_from_slice(&1u64.to_le_bytes());
            hdr[24..32].copy_from_slice(&(1u64 << 40).to_le_bytes());
            let mut table = vec![0u8; 4096];
            for i in 0..512usize {
                table[i * 8..i * 8 + 8].copy_from_slice(&2u64.to_le_bytes());
            }
            let l2 = leaf(4096, &[("a", 8, 1u64.to_be_bytes().to_vec())]);
            dnode_with_blocks(al, m, &[hdr, table, l2], 4096)
        });
        let dyns: Vec<Option<&dyn BlockSource>> =
            s.iter().map(|x| Some(x as &dyn BlockSource)).collect();
        let reader = PoolReader::new(&a, dyns);
        let obj = ObjectReader::new(&reader, d, Endian::Little);
        let t = std::time::Instant::now();
        let e = read_zap(&obj).unwrap_err().to_string();
        assert!(e.contains("does not fit"), "{e}");
        assert!(t.elapsed().as_secs() < 5);
    }

    /// One leaf that does not verify loses the entries in it and no
    /// other: the whole object failed, and with it every entry of every
    /// leaf that read. The strict reader still refuses.
    #[test]
    fn a_bad_leaf_loses_only_its_own_entries() {
        let (s, a, d) = setup(|al, m| {
            let mut hdr = fat_header(4096, 0, 3);
            hdr[16..24].copy_from_slice(&1u64.to_le_bytes());
            hdr[24..32].copy_from_slice(&1u64.to_le_bytes());
            let mut table = vec![0u8; 4096];
            for i in 0..512usize {
                let target: u64 = if i < 256 { 2 } else { 3 };
                table[i * 8..i * 8 + 8].copy_from_slice(&target.to_le_bytes());
            }
            let l2 = leaf(4096, &[("kept", 8, 1u64.to_be_bytes().to_vec())]);
            let l3 = leaf(4096, &[("lost", 8, 2u64.to_be_bytes().to_vec())]);
            let d = dnode_with_blocks(al, m, &[hdr, table, l2, l3.clone()], 4096);
            let at = m[0]
                .windows(l3.len())
                .position(|w| w == l3.as_slice())
                .expect("the leaf is on the member");
            m[0][at + 100] ^= 0xff;
            d
        });
        let dyns: Vec<Option<&dyn BlockSource>> =
            s.iter().map(|x| Some(x as &dyn BlockSource)).collect();
        let reader = PoolReader::new(&a, dyns);
        let obj = ObjectReader::new(&reader, d, Endian::Little);
        let read = read_zap_partial(&obj).unwrap();
        let names: Vec<&str> = read.entries.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, ["kept"]);
        assert_eq!(read.lost.len(), 1);
        assert_eq!(read.lost[0].0, 3);
        assert!(read_zap(&obj).is_err());
    }

    #[test]
    fn not_a_zap() {
        let (s, a, d) = setup(|al, m| dnode_with_blocks(al, m, &[vec![7u8; 4096]], 4096));
        let dyns: Vec<Option<&dyn BlockSource>> =
            s.iter().map(|x| Some(x as &dyn BlockSource)).collect();
        let reader = PoolReader::new(&a, dyns);
        let obj = ObjectReader::new(&reader, d, Endian::Little);
        assert!(read_zap(&obj).is_err());
    }
}
