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

/// Read every entry of the ZAP object `obj`, in on-disk order.
pub fn read_zap(obj: &ObjectReader<'_, '_>) -> Result<Vec<Entry>, ReadError> {
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
            Ok(entries)
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
            for blkid in leaves {
                let (leaf, e) = obj.read_blkid_ext(blkid)?;
                match block_type(&leaf, e) {
                    Some(BlockType::Leaf) => {
                        let entries = parse_leaf(&leaf, e)?;
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
            Ok(out)
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
