//! Extracting a volume's data object into a sparse image.

use std::fmt::Write as _;

use sha2::{Digest, Sha256};
use zfs_ondisk::dmu::{ObjsetPhys, ObjsetType};
use zfs_ondisk::Endian;
use zvolrescue_io::{trace, BlockSink};

use crate::dmu::{DnodeArray, ObjectReader};
use crate::dsl::{Dataset, ZVOL_OBJ};
use crate::zio::{PoolReader, ReadError};

/// What to do with a block that cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnError {
    /// Write zeros, record the range, continue (default).
    Zero,
    /// Stop at the first unreadable block.
    Abort,
}

/// One unreadable range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadRange {
    /// Byte offset in the volume.
    pub offset: u64,
    /// Length in bytes.
    pub len: u64,
    /// Block id.
    pub blkid: u64,
    /// Why.
    pub reason: String,
}

/// Outcome of an extraction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Bytes the image represents (`volsize`).
    pub volsize: u64,
    /// Data block size.
    pub blocksize: u64,
    /// Blocks in `0..=maxblkid`.
    pub blocks_total: u64,
    /// Blocks read and verified.
    pub blocks_read: u64,
    /// Blocks that were holes.
    pub blocks_holes: u64,
    /// Blocks written as zeros because they could not be read.
    pub blocks_zeroed: u64,
    /// Bytes of real data written.
    pub bytes_written: u64,
    /// Unreadable ranges, in order.
    pub bad: Vec<BadRange>,
    /// True when `OnError::Abort` stopped the extraction early.
    pub aborted: bool,
    /// SHA-256 of the full `volsize` image (holes as zeros), lowercase hex.
    pub sha256: String,
}

/// Open the dataset's objset and return its data object plus block size.
pub fn open_volume<'r, 'a>(
    reader: &'r PoolReader<'a>,
    ds: &Dataset,
) -> Result<(ObjectReader<'r, 'a>, Endian), ReadError> {
    if ds.phys.bp.is_hole() {
        return Err(ReadError::Hole);
    }
    let block = reader.read_block(&ds.phys.bp, false)?;
    let os = ObjsetPhys::parse(&block.data, ds.phys.bp.endian)?;
    if os.os_type != ObjsetType::Zvol {
        return Err(ReadError::Io(format!(
            "{} is a {}, not a volume",
            ds.name,
            os.os_type.name()
        )));
    }
    let objs = DnodeArray::new(reader, os.meta_dnode, ds.phys.bp.endian);
    let data = objs.object(ZVOL_OBJ)?;
    if data.dnode().is_free() {
        return Err(ReadError::Io(format!("{}: data object is free", ds.name)));
    }
    Ok((data, ds.phys.bp.endian))
}

/// Extract `obj` (a volume's data object) to `sink`, producing a
/// `volsize`-byte image. Blocks are visited in order; holes are skipped,
/// unreadable blocks handled per `on_error`. `progress` is called after
/// every block with `(blocks done, blocks total)`.
pub fn extract(
    obj: &ObjectReader<'_, '_>,
    volsize: u64,
    sink: &mut dyn BlockSink,
    on_error: OnError,
    mut progress: impl FnMut(u64, u64),
) -> Result<Report, ReadError> {
    let bs = obj.dnode().datablksz();
    if bs == 0 {
        return Err(ReadError::Io(
            "volume data object has zero block size".into(),
        ));
    }
    // Blocks that lie inside volsize; the tree may extend past it.
    let blocks_in_volume = volsize.div_ceil(bs);
    let blocks_total = (obj.dnode().maxblkid + 1).min(blocks_in_volume);
    let mut report = Report {
        volsize,
        blocksize: bs,
        blocks_total,
        blocks_read: 0,
        blocks_holes: 0,
        blocks_zeroed: 0,
        bytes_written: 0,
        bad: Vec::new(),
        aborted: false,
        sha256: String::new(),
    };
    let mut hasher = Sha256::new();
    let zeros = vec![0u8; bs as usize];
    let mut hashed_to = 0u64;
    trace!(
        "zvol",
        "extract: volsize {volsize} blocksize {bs} maxblkid {} -> {blocks_total} blocks",
        obj.dnode().maxblkid
    );
    for blkid in 0..blocks_total {
        let offset = blkid * bs;
        let take = (volsize - offset).min(bs) as usize;
        let result = match obj.locate(blkid) {
            Ok(None) => Ok(None),
            Ok(Some(bp)) => obj.reader().read_block(&bp, false).map(|b| Some(b.data)),
            Err(e) => Err(e),
        };
        match result {
            Ok(None) => {
                report.blocks_holes += 1;
                hasher.update(&zeros[..take]);
            }
            Ok(Some(mut data)) => {
                data.resize(bs as usize, 0);
                sink.write_at(offset, &data[..take])
                    .map_err(|e| ReadError::Io(e.to_string()))?;
                report.blocks_read += 1;
                report.bytes_written += take as u64;
                hasher.update(&data[..take]);
            }
            Err(e) => {
                trace!("zvol", "blkid {blkid} @ {offset}: UNREADABLE: {e}");
                report.bad.push(BadRange {
                    offset,
                    len: take as u64,
                    blkid,
                    reason: e.to_string(),
                });
                if on_error == OnError::Abort {
                    report.aborted = true;
                    break;
                }
                report.blocks_zeroed += 1;
                hasher.update(&zeros[..take]);
            }
        }
        hashed_to = offset + take as u64;
        progress(blkid + 1, blocks_total);
    }
    if !report.aborted {
        // Everything past the last block is implicit zeros.
        let mut rest = volsize - hashed_to;
        while rest > 0 {
            let n = rest.min(bs) as usize;
            hasher.update(&zeros[..n]);
            rest -= n as u64;
        }
        sink.finish(volsize)
            .map_err(|e| ReadError::Io(e.to_string()))?;
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in digest {
        let _ = write!(hex, "{b:02x}");
    }
    report.sha256 = hex;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsl::{open_mos, walk};
    use crate::fixture::{build_sample_mos, zvol_pattern, Alloc, Pool};
    use crate::pool::assemble;
    use crate::vdev::scan_device;
    use zfs_ondisk::blkptr::LABEL_START_SIZE;
    use zfs_ondisk::label::LABEL_SIZE;
    use zvolrescue_io::{BlockSource, MemSink, MemSource};

    const SIZE: u64 = 64 * LABEL_SIZE;

    fn build() -> (
        Vec<MemSource>,
        crate::pool::PoolAssembly,
        zfs_ondisk::uberblock::Uberblock,
        u64,
    ) {
        let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
        let mut members = vec![vec![0u8; SIZE as usize]];
        let mut a = Alloc::new(0x20_0000);
        build_sample_mos(&mut pool, &mut members, &mut a);
        pool.write_labels(0, &mut members[0]);
        let data_off = crate::fixture::SAMPLE_ZVOL_BLOCK0_OFFSET;
        let sources: Vec<MemSource> = members.into_iter().map(MemSource::new).collect();
        let scans: Vec<_> = sources.iter().map(|s| scan_device(s).ok()).collect();
        let ub = scans[0].as_ref().unwrap().labels[0]
            .best()
            .unwrap()
            .ub
            .clone();
        let assembly = assemble(&scans).into_iter().next().unwrap();
        (sources, assembly, ub, data_off)
    }

    fn expected_image() -> Vec<u8> {
        // Blocks 0 and 2 carry the pattern, 1 and 3 are holes, the rest of
        // the 32 MiB volume is zeros.
        let mut img = vec![0u8; 32 << 20];
        img[..8192].copy_from_slice(&zvol_pattern(0));
        img[16384..24576].copy_from_slice(&zvol_pattern(2));
        img
    }

    #[test]
    fn extracts_sparse_volume_with_correct_hash() {
        let (s, a, ub, _) = build();
        let reader = PoolReader::new(&a, vec![Some(&s[0] as &dyn BlockSource)]);
        let mos = open_mos(&reader, &ub).unwrap();
        let tree = walk(&mos, "tank").unwrap();
        let ds = tree.get("tank/vm/disk0").unwrap();
        let (obj, _) = open_volume(&reader, ds).unwrap();
        let mut sink = MemSink::default();
        let mut calls = 0;
        let r = extract(
            &obj,
            ds.volsize.unwrap(),
            &mut sink,
            OnError::Zero,
            |_, _| calls += 1,
        )
        .unwrap();
        assert_eq!(r.blocks_total, 4);
        assert_eq!((r.blocks_read, r.blocks_holes, r.blocks_zeroed), (2, 2, 0));
        assert_eq!(r.bytes_written, 16384);
        assert_eq!(calls, 4);
        assert!(r.bad.is_empty() && !r.aborted);
        let want = expected_image();
        assert_eq!(sink.data, want);
        assert_eq!(sink.writes, vec![(0, 8192), (16384, 8192)]);
        let mut h = Sha256::new();
        h.update(&want);
        assert_eq!(r.sha256, format!("{:x}", h.finalize()));
        // A filesystem is refused.
        assert!(open_volume(&reader, tree.get("tank/vm").unwrap()).is_err());
    }

    #[test]
    fn unreadable_block_zeroed_or_aborted() {
        let (s, a, ub, data_off) = build();
        let mut img = s[0].clone();
        img.bytes_mut()[(LABEL_START_SIZE + data_off) as usize + 5] ^= 0xff; // damage block 0
        let reader = PoolReader::new(&a, vec![Some(&img as &dyn BlockSource)]);
        let mos = open_mos(&reader, &ub).unwrap();
        let tree = walk(&mos, "tank").unwrap();
        let ds = tree.get("tank/vm/disk0").unwrap();
        let (obj, _) = open_volume(&reader, ds).unwrap();

        let mut sink = MemSink::default();
        let r = extract(
            &obj,
            ds.volsize.unwrap(),
            &mut sink,
            OnError::Zero,
            |_, _| {},
        )
        .unwrap();
        assert_eq!(r.blocks_zeroed, 1);
        assert_eq!(r.bad.len(), 1);
        assert_eq!(
            (r.bad[0].blkid, r.bad[0].offset, r.bad[0].len),
            (0, 0, 8192)
        );
        assert!(r.bad[0].reason.contains("checksum"));
        assert_eq!(&sink.data[..8192], &[0u8; 8192][..]);
        assert_eq!(&sink.data[16384..24576], &zvol_pattern(2)[..]);
        assert_eq!(sink.data.len(), 32 << 20);

        let mut sink = MemSink::default();
        let r = extract(
            &obj,
            ds.volsize.unwrap(),
            &mut sink,
            OnError::Abort,
            |_, _| {},
        )
        .unwrap();
        assert!(r.aborted);
        assert_eq!(r.blocks_read, 0);
        assert!(sink.data.is_empty());
    }
}
