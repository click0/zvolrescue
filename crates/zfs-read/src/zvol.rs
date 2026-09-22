//! Extracting a volume's data object into a sparse image.

use std::sync::atomic::{AtomicBool, Ordering};

use zfs_ondisk::blkptr::{BlkPtr, Compression};
use zfs_ondisk::dmu::{ObjsetPhys, ObjsetType};
use zfs_ondisk::Endian;
use zvolrescue_io::{trace, BlockSink};

use crate::dmu::{DnodeArray, ObjectReader};
use crate::dsl::{Dataset, ZVOL_OBJ};
use crate::hash::{Digests, Extra};
use crate::zio::{PoolReader, ReadError, Salvage};
use zfs_ondisk::checksum::Verify;

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
    /// Blocks written with only their unreadable sectors zeroed (SPEC
    /// F-33): a member refused part of the block and gave the rest.
    /// What was kept is unverified — the checksum covers the whole
    /// block — and each zeroed range is in `bad`.
    pub blocks_salvaged: u64,
    /// Bytes of real data written.
    pub bytes_written: u64,
    /// Unreadable ranges, in order.
    pub bad: Vec<BadRange>,
    /// True when `OnError::Abort` stopped the extraction early, or a
    /// device's refusal did (SPEC F-33, N-10).
    pub aborted: bool,
    /// The device refusal that stopped the extraction, when one did
    /// (SPEC F-33, N-10): the incident, as the ledger recorded it.
    pub stopped_by_medium: Option<String>,
    /// The block the extraction was about to read when it was asked to
    /// stop (a SIGINT, through the flag [`extract_from`] takes): every
    /// block before it is in the image, and a resume starts here. `None`
    /// when nothing asked.
    pub interrupted_at: Option<u64>,
    /// SHA-256 of the full `volsize` image (holes as zeros), lowercase hex.
    pub sha256: String,
    /// SHA-1 of the same image, when it was asked for (SPEC F-53).
    pub sha1: Option<String>,
    /// MD5 of the same image, when it was asked for (SPEC F-53).
    pub md5: Option<String>,
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

/// `volsize` (from the volume's properties ZAP) and `volblocksize` (the
/// data object's block size), read now — for example after the dataset
/// keys were installed, when `list` could not read them.
pub fn volume_facts(reader: &PoolReader<'_>, ds: &Dataset) -> Result<(u64, u64), ReadError> {
    let block = reader.read_block(&ds.phys.bp, false)?;
    let os = ObjsetPhys::parse(&block.data, ds.phys.bp.endian)?;
    let objs = DnodeArray::new(reader, os.meta_dnode, ds.phys.bp.endian);
    let data = objs.get(ZVOL_OBJ)?;
    if data.is_free() {
        return Err(ReadError::Io(format!("{}: data object is free", ds.name)));
    }
    let props = crate::zap::read_zap(&objs.object(crate::dsl::ZVOL_ZAP_OBJ)?)?;
    let volsize = props
        .iter()
        .find(|e| e.name == "size")
        .and_then(|e| e.value.as_u64())
        .ok_or_else(|| ReadError::Io(format!("{}: volume properties have no size", ds.name)))?;
    Ok((volsize, data.datablksz()))
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
    progress: impl FnMut(u64, u64),
) -> Result<Report, ReadError> {
    extract_from(
        obj,
        volsize,
        sink,
        on_error,
        0,
        Digests::new(Extra::none()),
        None,
        progress,
    )
}

/// Like [`extract`], also taking the legacy digests `extra` names
/// (SPEC F-53). One pass over the bytes either way.
pub fn extract_hashing(
    obj: &ObjectReader<'_, '_>,
    volsize: u64,
    sink: &mut dyn BlockSink,
    on_error: OnError,
    extra: Extra,
    progress: impl FnMut(u64, u64),
) -> Result<Report, ReadError> {
    extract_from(
        obj,
        volsize,
        sink,
        on_error,
        0,
        Digests::new(extra),
        None,
        progress,
    )
}

/// Like [`extract`], resuming at block `start_block` with `digests`
/// already fed the first `start_block * blocksize` bytes of the image
/// (read back from the partial output). Counters cover only the blocks
/// visited now.
///
/// `stop` is looked at before every block: once it is set the loop ends
/// there, the report says so in `interrupted_at`, and everything before
/// that block is in the sink. It is how a SIGINT ends a run that can be
/// resumed instead of killing one that cannot.
#[allow(clippy::too_many_arguments)]
pub fn extract_from(
    obj: &ObjectReader<'_, '_>,
    volsize: u64,
    sink: &mut dyn BlockSink,
    on_error: OnError,
    start_block: u64,
    mut digests: Digests,
    stop: Option<&AtomicBool>,
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
        blocks_salvaged: 0,
        bytes_written: 0,
        bad: Vec::new(),
        aborted: false,
        stopped_by_medium: None,
        interrupted_at: None,
        sha256: String::new(),
        sha1: None,
        md5: None,
    };
    let zeros = vec![0u8; bs as usize];
    let mut hashed_to = (start_block * bs).min(volsize);
    trace!(
        "zvol",
        "extract: volsize {volsize} blocksize {bs} maxblkid {} -> {blocks_total} blocks, starting at {start_block}",
        obj.dnode().maxblkid
    );
    for blkid in start_block..blocks_total {
        if stop.is_some_and(|s| s.load(Ordering::Relaxed)) {
            trace!("zvol", "blkid {blkid}: interrupted, stopping here");
            report.interrupted_at = Some(blkid);
            break;
        }
        let offset = blkid * bs;
        let take = (volsize - offset).min(bs) as usize;
        let located = obj.locate(blkid);
        let result = match &located {
            Ok(None) => Ok(None),
            Ok(Some(bp)) => obj.reader().read_block(bp, false).map(|b| Some(b.data)),
            Err(e) => Err(e.clone()),
        };
        match result {
            Ok(None) => {
                report.blocks_holes += 1;
                digests.update(&zeros[..take]);
            }
            Ok(Some(mut data)) => {
                data.resize(bs as usize, 0);
                sink.write_at(offset, &data[..take])
                    .map_err(|e| ReadError::Io(e.to_string()))?;
                report.blocks_read += 1;
                report.bytes_written += take as u64;
                digests.update(&data[..take]);
            }
            Err(e) => {
                trace!("zvol", "blkid {blkid} @ {offset}: UNREADABLE: {e}");
                // A device refused a read and the medium policy stops
                // the run here: the range is logged, nothing is read
                // again — not in pieces, not by sector, not from another
                // copy — and the operator decides (SPEC F-33, N-10).
                if let ReadError::Medium { stop: true, .. } = &e {
                    report.bad.push(BadRange {
                        offset,
                        len: take as u64,
                        blkid,
                        reason: e.to_string(),
                    });
                    report.aborted = true;
                    report.stopped_by_medium = Some(e.to_string());
                    break;
                }
                if on_error == OnError::Abort {
                    report.bad.push(BadRange {
                        offset,
                        len: take as u64,
                        blkid,
                        reason: e.to_string(),
                    });
                    report.aborted = true;
                    break;
                }
                // A member that refused part of the block may still give
                // the rest (SPEC F-33): keep every sector it will, zero
                // only what it will not, and say which is which.
                let bp = located.as_ref().ok().and_then(|b| b.as_ref());
                match bp.and_then(|bp| salvage(obj.reader(), bp, &e)) {
                    Some(Salvaged::Whole(mut data)) => {
                        // The retry read every sector and the checksum
                        // agrees: a transient failure, and a whole block.
                        trace!("zvol", "blkid {blkid}: read whole on retry, verified");
                        data.resize(bs as usize, 0);
                        sink.write_at(offset, &data[..take])
                            .map_err(|e| ReadError::Io(e.to_string()))?;
                        report.blocks_read += 1;
                        report.bytes_written += take as u64;
                        digests.update(&data[..take]);
                    }
                    Some(Salvaged::Partial(mut data, ranges)) => {
                        data.resize(bs as usize, 0);
                        sink.write_at(offset, &data[..take])
                            .map_err(|e| ReadError::Io(e.to_string()))?;
                        let mut lost = 0;
                        for (start, len) in ranges {
                            if start >= take as u64 {
                                break;
                            }
                            let len = len.min(take as u64 - start);
                            lost += len;
                            report.bad.push(BadRange {
                                offset: offset + start,
                                len,
                                blkid,
                                reason: format!(
                                    "sector(s) unreadable: {e}; the rest of the block was read and kept unverified (the checksum covers the whole block)"
                                ),
                            });
                        }
                        trace!(
                            "zvol",
                            "blkid {blkid}: salvaged, {lost} of {take} bytes zeroed"
                        );
                        report.blocks_salvaged += 1;
                        report.bytes_written += take as u64 - lost;
                        digests.update(&data[..take]);
                    }
                    None => {
                        report.bad.push(BadRange {
                            offset,
                            len: take as u64,
                            blkid,
                            reason: match bp {
                                Some(bp) if matches!(e, ReadError::Io(_)) => {
                                    format!("{e}; {}", why_not_salvaged(obj.reader(), bp))
                                }
                                _ => e.to_string(),
                            },
                        });
                        report.blocks_zeroed += 1;
                        digests.update(&zeros[..take]);
                    }
                }
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
            digests.update(&zeros[..n]);
            rest -= n as u64;
        }
        sink.finish(volsize)
            .map_err(|e| ReadError::Io(e.to_string()))?;
    }
    let done = digests.finish();
    report.sha256 = done.sha256;
    report.sha1 = done.sha1;
    report.md5 = done.md5;
    Ok(report)
}

/// What a salvage of a block that could not be read whole came to.
enum Salvaged {
    /// Every sector read on retry and the block verifies.
    Whole(Vec<u8>),
    /// Some sectors are gone; the rest is here, unverified.
    Partial(Vec<u8>, Vec<(u64, u64)>),
}

/// Try to keep what a member will still give of a block it refused
/// (SPEC F-33). Only an I/O failure on an uncompressed, unencrypted
/// block on a disk or mirror is salvaged: a checksum mismatch says
/// nothing about *which* bytes are wrong, a compressed block cannot be
/// decompressed in part, ciphertext cannot be decrypted in part, and
/// under parity a partial column is reconstructed rather than kept.
fn salvage(reader: &PoolReader<'_>, bp: &BlkPtr, e: &ReadError) -> Option<Salvaged> {
    // A device's refusal is never read around (N-10): with
    // `--device-may-fail` the block is zeroed whole, once.
    if !matches!(e, ReadError::Io(_))
        || bp.compression != Compression::Off
        || bp.is_encrypted()
        || bp.embedded_payload().is_some()
    {
        return None;
    }
    let mut best: Option<Salvage> = None;
    for dva in bp.dvas() {
        if let Ok((data, bad)) = reader.salvage_dva(dva, bp.psize as usize) {
            let lost: u64 = bad.iter().map(|&(_, l)| l).sum();
            if best
                .as_ref()
                .is_none_or(|(_, b)| lost < b.iter().map(|&(_, l)| l).sum::<u64>())
            {
                best = Some((data, bad));
            }
            if lost == 0 {
                break;
            }
        }
    }
    let (data, bad) = best?;
    if bad.is_empty() {
        // Nothing was refused the second time. Only a checksum makes
        // that a block; without one it is a read that happened to work.
        return (reader.verify(bp, &data) == Verify::Ok).then_some(Salvaged::Whole(data));
    }
    Some(Salvaged::Partial(data, bad))
}

/// Why an I/O failure on this block was not salvaged, for the record.
fn why_not_salvaged(reader: &PoolReader<'_>, bp: &BlkPtr) -> String {
    if bp.is_encrypted() {
        return "ciphertext cannot be decrypted in part, so the whole block is zeros".into();
    }
    if bp.compression != Compression::Off {
        return format!(
            "compressed ({}): a partial block cannot be decompressed, so the whole block is zeros",
            bp.compression.name()
        );
    }
    match bp
        .dvas()
        .next()
        .map(|d| reader.salvage_dva(d, bp.psize as usize))
    {
        Some(Err(err)) => format!("not salvaged: {err}"),
        _ => "not salvaged".into(),
    }
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
    use zvolrescue_io::{BlockSource, FlakySource, MemSink, MemSource};

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
        let mut h = Digests::new(Extra::none());
        h.update(&want);
        assert_eq!(r.sha256, h.finish().sha256);
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

    /// `extract_hashing` is `extract` with the legacy digests taken in
    /// the same pass: the image is the same, and each digest is what
    /// the written bytes hash to.
    #[test]
    fn hashing_as_it_goes_gives_the_digests_of_the_image_written() {
        let (s, a, ub, _) = build();
        let reader = PoolReader::new(&a, vec![Some(&s[0] as &dyn BlockSource)]);
        let mos = open_mos(&reader, &ub).unwrap();
        let tree = walk(&mos, "tank").unwrap();
        let ds = tree.get("tank/vm/disk0").unwrap();
        let (obj, _) = open_volume(&reader, ds).unwrap();
        let extra = Extra {
            md5: true,
            sha1: true,
        };
        let mut sink = MemSink::default();
        let r = extract_hashing(
            &obj,
            ds.volsize.unwrap(),
            &mut sink,
            OnError::Zero,
            extra,
            |_, _| {},
        )
        .unwrap();
        assert_eq!(sink.data, expected_image());
        let mut direct = Digests::new(extra);
        direct.update(&sink.data);
        let direct = direct.finish();
        assert_eq!(r.sha256, direct.sha256);
        assert!(r.sha1.is_some() && r.md5.is_some());
        assert_eq!((r.sha1, r.md5), (direct.sha1, direct.md5));

        // Not asked for: not there.
        let mut sink = MemSink::default();
        let r = extract_hashing(
            &obj,
            ds.volsize.unwrap(),
            &mut sink,
            OnError::Zero,
            Extra::none(),
            |_, _| {},
        )
        .unwrap();
        assert_eq!((r.sha1, r.md5), (None, None));
        assert_eq!(r.sha256, direct.sha256);
    }

    /// A member with a bad sector refuses the whole 8 KiB read that
    /// touches it. With no other copy, the block used to become 8 KiB
    /// of zeros; now it is the 7.5 KiB the disk will still give, the
    /// one sector zeroed and named (SPEC F-33).
    #[test]
    fn a_bad_sector_costs_its_sector_and_not_its_block() {
        let (s, a, ub, data_off) = build();
        let bad_at = LABEL_START_SIZE + data_off + 1024 + 7;
        let flaky = FlakySource::new(s[0].clone(), vec![(bad_at, 100)]);
        let reader = PoolReader::new(&a, vec![Some(&flaky as &dyn BlockSource)]);
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
        assert_eq!(
            (r.blocks_read, r.blocks_salvaged, r.blocks_zeroed),
            (1, 1, 0)
        );
        assert_eq!(r.bytes_written, 16384 - 512);
        assert_eq!(r.bad.len(), 1);
        assert_eq!(
            (r.bad[0].blkid, r.bad[0].offset, r.bad[0].len),
            (0, 1024, 512)
        );
        assert!(
            r.bad[0].reason.contains("sector(s) unreadable")
                && r.bad[0].reason.contains("kept unverified"),
            "{}",
            r.bad[0].reason
        );
        let mut want = expected_image();
        want[1024..1536].fill(0);
        assert_eq!(sink.data, want);
        let mut h = Digests::new(Extra::none());
        h.update(&want);
        assert_eq!(r.sha256, h.finish().sha256);

        // --strict does not salvage: the block is refused whole.
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
        assert_eq!((r.bad[0].offset, r.bad[0].len), (0, 8192));
    }

    /// A deduplicated volume (SPEC F-28): its pointers carry the dedup
    /// bit and a dedup-capable checksum, and they are read as the
    /// pointers they are — no table is consulted, and the image is the
    /// one the plain volume gives.
    #[test]
    fn a_deduplicated_volume_is_read_through_its_pointers() {
        let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
        let mut members = vec![vec![0u8; SIZE as usize]];
        let mut a = Alloc::new(0x20_0000);
        a.dedup = true;
        build_sample_mos(&mut pool, &mut members, &mut a);
        pool.write_labels(0, &mut members[0]);
        let sources: Vec<MemSource> = members.into_iter().map(MemSource::new).collect();
        let scans: Vec<_> = sources.iter().map(|s| scan_device(s).ok()).collect();
        let ub = scans[0].as_ref().unwrap().labels[0]
            .best()
            .unwrap()
            .ub
            .clone();
        let assembly = assemble(&scans).into_iter().next().unwrap();
        let reader = PoolReader::new(&assembly, vec![Some(&sources[0] as &dyn BlockSource)]);
        let mos = open_mos(&reader, &ub).unwrap();
        let tree = walk(&mos, "tank").unwrap();
        let ds = tree.get("tank/vm/disk0").unwrap();
        let (obj, _) = open_volume(&reader, ds).unwrap();
        let bps: Vec<_> = obj
            .dnode()
            .blkptr
            .iter()
            .filter(|bp| !bp.is_hole())
            .collect();
        assert_eq!(bps.len(), 2);
        for bp in &bps {
            assert!(bp.dedup, "{bp:?}");
            assert_eq!(bp.checksum, zfs_ondisk::blkptr::Checksum::Sha256);
            assert!(bp.checksum.dedup_capable());
        }
        let mut sink = MemSink::default();
        let r = extract(
            &obj,
            ds.volsize.unwrap(),
            &mut sink,
            OnError::Zero,
            |_, _| {},
        )
        .unwrap();
        assert_eq!(
            (r.blocks_read, r.blocks_salvaged, r.blocks_zeroed),
            (2, 0, 0)
        );
        assert!(r.bad.is_empty());
        assert_eq!(sink.data, expected_image());
    }

    /// A mirror heals a bad sector from its other side, and nothing is
    /// salvaged: what could be read whole and verified is.
    #[test]
    fn a_mirror_heals_a_bad_sector_before_anything_is_salvaged() {
        let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
        let mut members = vec![vec![0u8; SIZE as usize], vec![0u8; SIZE as usize]];
        let mut a = Alloc::new(0x20_0000);
        build_sample_mos(&mut pool, &mut members, &mut a);
        for (i, m) in members.iter_mut().enumerate() {
            pool.write_labels(i, m);
        }
        let data_off = crate::fixture::SAMPLE_ZVOL_BLOCK0_OFFSET;
        let bad_at = LABEL_START_SIZE + data_off + 4096;
        let sources: Vec<MemSource> = members.into_iter().map(MemSource::new).collect();
        let scans: Vec<_> = sources.iter().map(|s| scan_device(s).ok()).collect();
        let ub = scans[0].as_ref().unwrap().labels[0]
            .best()
            .unwrap()
            .ub
            .clone();
        let assembly = assemble(&scans).into_iter().next().unwrap();
        let flaky = FlakySource::new(sources[0].clone(), vec![(bad_at, 512)]);
        let reader = PoolReader::new(
            &assembly,
            vec![
                Some(&flaky as &dyn BlockSource),
                Some(&sources[1] as &dyn BlockSource),
            ],
        );
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
        assert_eq!(
            (r.blocks_read, r.blocks_salvaged, r.blocks_zeroed),
            (2, 0, 0)
        );
        assert!(r.bad.is_empty());
        assert_eq!(sink.data, expected_image());
    }

    /// The mirror of [`a_mirror_heals_a_bad_sector_before_anything_is_salvaged`]
    /// with the flaky side a *device*: a pool with one side reading
    /// from a mirror member, the other from a disk that refuses a
    /// read (SPEC F-33, N-10).
    fn mirror_with_a_device(
        ledger: std::sync::Arc<zvolrescue_io::medium::Ledger>,
        bad: Vec<(u64, u64)>,
    ) -> (
        FlakySource<MemSource>,
        MemSource,
        crate::pool::PoolAssembly,
        zfs_ondisk::uberblock::Uberblock,
    ) {
        let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
        let mut members = vec![vec![0u8; SIZE as usize], vec![0u8; SIZE as usize]];
        let mut a = Alloc::new(0x20_0000);
        build_sample_mos(&mut pool, &mut members, &mut a);
        for (i, m) in members.iter_mut().enumerate() {
            pool.write_labels(i, m);
        }
        let sources: Vec<MemSource> = members.into_iter().map(MemSource::new).collect();
        let scans: Vec<_> = sources.iter().map(|s| scan_device(s).ok()).collect();
        let ub = scans[0].as_ref().unwrap().labels[0]
            .best()
            .unwrap()
            .ub
            .clone();
        let assembly = assemble(&scans).into_iter().next().unwrap();
        let device = FlakySource::new(sources[0].clone(), bad).as_device("/dev/da0", ledger);
        (device, sources[1].clone(), assembly, ub)
    }

    fn extract_all(
        reader: &PoolReader<'_>,
        ub: &zfs_ondisk::uberblock::Uberblock,
    ) -> (Report, MemSink) {
        let mos = open_mos(reader, ub).unwrap();
        let tree = walk(&mos, "tank").unwrap();
        let ds = tree.get("tank/vm/disk0").unwrap();
        let (obj, _) = open_volume(reader, ds).unwrap();
        let mut sink = MemSink::default();
        let r = extract(
            &obj,
            ds.volsize.unwrap(),
            &mut sink,
            OnError::Zero,
            |_, _| {},
        )
        .unwrap();
        (r, sink)
    }

    /// A device that refuses a read stops the extraction there, even
    /// though the other side of the mirror holds the block: the
    /// operator is told first and decides (SPEC F-33, N-10). The device
    /// was asked once — no pieces, no sectors, no retry.
    #[test]
    fn a_device_that_refuses_a_read_stops_the_extraction_even_under_a_mirror() {
        use zvolrescue_io::medium::Ledger;
        let ledger = std::sync::Arc::new(Ledger::stop_at_first());
        let data_off = crate::fixture::SAMPLE_ZVOL_BLOCK0_OFFSET;
        let bad_at = LABEL_START_SIZE + data_off + 4096;
        let (device, other, assembly, ub) =
            mirror_with_a_device(ledger.clone(), vec![(bad_at, 512)]);
        let reader = PoolReader::new(
            &assembly,
            vec![
                Some(&device as &dyn BlockSource),
                Some(&other as &dyn BlockSource),
            ],
        );
        let (r, _sink) = extract_all(&reader, &ub);
        assert!(r.aborted, "the run stops at the first refused read");
        let why = r
            .stopped_by_medium
            .as_deref()
            .expect("the incident is named");
        assert!(
            why.starts_with("medium refused a read, stopping: /dev/da0"),
            "{why}"
        );
        assert!(
            why.contains(&format!("at byte {}", LABEL_START_SIZE + data_off)),
            "{why}"
        );
        assert_eq!(
            (r.blocks_read, r.blocks_salvaged, r.blocks_zeroed),
            (0, 0, 0)
        );
        assert_eq!(r.bad.len(), 1);
        assert_eq!(
            (r.bad[0].blkid, r.bad[0].offset, r.bad[0].len),
            (0, 0, 8192)
        );
        assert_eq!(r.bad[0].reason, why);
        assert_eq!(
            device.reads_touching(bad_at),
            1,
            "the refused address was asked for once: {:?}",
            device.reads()
        );
        assert_eq!(ledger.incidents().len(), 1);
        assert!(ledger.stopped().is_some());
        assert!(matches!(
            reader.medium_stop(),
            Some(ReadError::Medium { stop: true, .. })
        ));
    }

    /// With `--device-may-fail` the refusal is skipped: the mirror heals
    /// the block from its other side, the image is whole, the incident
    /// is on record — and the device was still asked once.
    #[test]
    fn with_device_may_fail_the_mirror_heals_and_nothing_is_read_twice() {
        use zvolrescue_io::medium::Ledger;
        let ledger = std::sync::Arc::new(Ledger::may_fail());
        let data_off = crate::fixture::SAMPLE_ZVOL_BLOCK0_OFFSET;
        let bad_at = LABEL_START_SIZE + data_off + 4096;
        let (device, other, assembly, ub) =
            mirror_with_a_device(ledger.clone(), vec![(bad_at, 512)]);
        let reader = PoolReader::new(
            &assembly,
            vec![
                Some(&device as &dyn BlockSource),
                Some(&other as &dyn BlockSource),
            ],
        );
        let (r, sink) = extract_all(&reader, &ub);
        assert!(!r.aborted);
        assert!(r.stopped_by_medium.is_none());
        assert_eq!(
            (r.blocks_read, r.blocks_salvaged, r.blocks_zeroed),
            (2, 0, 0)
        );
        assert!(r.bad.is_empty());
        assert_eq!(sink.data, expected_image());
        assert_eq!(device.reads_touching(bad_at), 1, "{:?}", device.reads());
        let incidents = ledger.incidents();
        assert_eq!(incidents.len(), 1);
        assert!(!incidents[0].stopped);
        assert!(reader.medium_stop().is_none());
    }

    /// With `--device-may-fail` and no other copy, the block is zeroed
    /// whole, once, with the incident as its reason: nothing is salvaged
    /// from a device, in pieces or by sector.
    #[test]
    fn with_device_may_fail_and_no_other_copy_the_block_is_zeroed_once() {
        use zvolrescue_io::medium::Ledger;
        let ledger = std::sync::Arc::new(Ledger::may_fail());
        let (s, a, ub, data_off) = build();
        let bad_at = LABEL_START_SIZE + data_off + 1024 + 7;
        let device = FlakySource::new(s[0].clone(), vec![(bad_at, 100)])
            .as_device("/dev/da0", ledger.clone());
        let reader = PoolReader::new(&a, vec![Some(&device as &dyn BlockSource)]);
        let (r, sink) = extract_all(&reader, &ub);
        assert!(!r.aborted);
        assert_eq!(
            (r.blocks_read, r.blocks_salvaged, r.blocks_zeroed),
            (1, 0, 1)
        );
        assert_eq!(r.bad.len(), 1);
        assert_eq!((r.bad[0].offset, r.bad[0].len), (0, 8192));
        assert!(
            r.bad[0]
                .reason
                .starts_with("medium refused a read, skipped: /dev/da0"),
            "{}",
            r.bad[0].reason
        );
        assert_eq!(device.reads_touching(bad_at), 1, "{:?}", device.reads());
        let mut want = expected_image();
        want[..8192].fill(0);
        assert_eq!(sink.data, want);
    }

    /// The allowance of `--device-may-fail` is spent per incident: the
    /// one that reaches the limit stops the run like the first would
    /// have without the flag.
    #[test]
    fn the_last_allowed_incident_stops_a_device_that_may_fail() {
        use zvolrescue_io::medium::Ledger;
        let ledger = std::sync::Arc::new(Ledger::may_fail());
        for n in 1..Ledger::MAY_FAIL_LIMIT {
            ledger.record(
                std::path::Path::new("/dev/da0"),
                (n as u64) << 20,
                4096,
                &std::io::Error::from_raw_os_error(5),
            );
        }
        let (s, a, ub, data_off) = build();
        let bad_at = LABEL_START_SIZE + data_off + 8192 + 4096;
        let device = FlakySource::new(s[0].clone(), vec![(bad_at, 512)])
            .as_device("/dev/da0", ledger.clone());
        let reader = PoolReader::new(&a, vec![Some(&device as &dyn BlockSource)]);
        let (r, _sink) = extract_all(&reader, &ub);
        assert!(r.aborted);
        assert!(r.stopped_by_medium.is_some());
        // Block 0 came out; block 2 is where the disk was asked and refused.
        assert_eq!((r.blocks_read, r.bad.len()), (1, 1));
        assert_eq!(r.bad[0].blkid, 2);
        assert_eq!(ledger.incidents().len(), Ledger::MAY_FAIL_LIMIT);
        assert_eq!(device.reads_touching(bad_at), 1);
    }

    /// A read that fails once and then gives every sector is a block
    /// only because its checksum says so: it is counted as read, not
    /// as salvaged.
    #[test]
    fn a_failure_that_clears_on_retry_is_a_verified_block() {
        struct Once {
            inner: MemSource,
            at: (u64, u64),
            tripped: std::cell::Cell<bool>,
        }
        impl BlockSource for Once {
            fn size(&self) -> u64 {
                self.inner.size()
            }
            fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
                let end = offset + buf.len() as u64;
                if !self.tripped.get() && self.at.0 < end && offset < self.at.0 + self.at.1 {
                    self.tripped.set(true);
                    return Err(std::io::Error::from_raw_os_error(5));
                }
                self.inner.read_at(offset, buf)
            }
            fn read_at_salvaging(
                &self,
                offset: u64,
                buf: &mut [u8],
            ) -> std::io::Result<Vec<(u64, u64)>> {
                zvolrescue_io::salvage(&mut |o, b| self.read_at(o, b), offset, buf)
            }
        }
        let (s, a, ub, data_off) = build();
        let once = Once {
            inner: s[0].clone(),
            at: (LABEL_START_SIZE + data_off + 100, 1),
            tripped: std::cell::Cell::new(false),
        };
        let reader = PoolReader::new(&a, vec![Some(&once as &dyn BlockSource)]);
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
        assert!(once.tripped.get(), "the first read did fail");
        assert_eq!(
            (r.blocks_read, r.blocks_salvaged, r.blocks_zeroed),
            (2, 0, 0)
        );
        assert!(r.bad.is_empty());
        assert_eq!(sink.data, expected_image());
    }

    /// A pool of two mirrors: the MOS on `mirror-0`, the volume's data on
    /// `mirror-1`. The image is the same as from a one-top pool, and it
    /// still is with one side of each mirror gone. With every member of
    /// `mirror-1` gone nothing describes that top, and its blocks are
    /// refused by name rather than read from anywhere else.
    #[test]
    fn a_volume_whose_data_is_on_another_top_reads_across_both() {
        use crate::fixture::two_top_mirror_members;
        let (tops, members) = two_top_mirror_members("tank", 0x7070, 12, [2, 3], &[(100, 1)], SIZE);
        assert_eq!((tops.len(), members.len()), (2, 5));
        let sources: Vec<MemSource> = members.into_iter().map(MemSource::new).collect();
        let run = |present: &[bool]| {
            let scans: Vec<_> = sources
                .iter()
                .zip(present)
                .map(|(s, &p)| if p { scan_device(s).ok() } else { None })
                .collect();
            let ub = scans.iter().flatten().next().expect("a scan").labels[0]
                .best()
                .unwrap()
                .ub
                .clone();
            let assembly = assemble(&scans).into_iter().next().expect("one pool");
            let devices: Vec<Option<&dyn BlockSource>> = sources
                .iter()
                .zip(present)
                .map(|(s, &p)| p.then_some(s as &dyn BlockSource))
                .collect();
            let reader = PoolReader::new(&assembly, devices);
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
            (assembly.missing_tops(), r, sink.data)
        };
        let (missing, r, data) = run(&[true; 5]);
        assert!(missing.is_empty());
        assert_eq!((r.blocks_read, r.blocks_zeroed), (2, 0));
        assert_eq!(data, expected_image());

        // One side of each mirror gone: the other sides answer.
        let (missing, r, data) = run(&[true, false, false, true, false]);
        assert!(missing.is_empty());
        assert_eq!((r.blocks_read, r.blocks_zeroed), (2, 0));
        assert_eq!(data, expected_image());

        // mirror-1 gone entirely: the MOS still lists the volume, and its
        // data blocks name a top nothing describes.
        let (missing, r, _) = run(&[true, true, false, false, false]);
        assert_eq!(missing, vec![1]);
        assert_eq!((r.blocks_read, r.blocks_zeroed), (0, 2));
        assert!(
            r.bad[0].reason.contains("unknown top-level vdev 1"),
            "{}",
            r.bad[0].reason
        );
    }

    #[test]
    fn resuming_mid_way_yields_the_same_image_and_hash() {
        let (s, a, ub, _) = build();
        let reader = PoolReader::new(&a, vec![Some(&s[0] as &dyn BlockSource)]);
        let mos = open_mos(&reader, &ub).unwrap();
        let tree = walk(&mos, "tank").unwrap();
        let ds = tree.get("tank/vm/disk0").unwrap();
        let (obj, _) = open_volume(&reader, ds).unwrap();
        let volsize = ds.volsize.unwrap();
        let mut full = MemSink::default();
        let whole = extract(&obj, volsize, &mut full, OnError::Zero, |_, _| {}).unwrap();
        // Simulate a run that stopped after 2 blocks: keep its prefix,
        // hash it back, continue from block 2.
        let mut partial = MemSink {
            data: full.data[..2 * 8192].to_vec(),
            ..Default::default()
        };
        // Resuming takes the legacy digests too: the prefix goes into
        // each of them before the rest of the image does.
        let extra = Extra {
            md5: true,
            sha1: true,
        };
        let mut h = Digests::new(extra);
        h.update(&partial.data);
        let rest = extract_from(
            &obj,
            volsize,
            &mut partial,
            OnError::Zero,
            2,
            h,
            None,
            |_, _| {},
        )
        .unwrap();
        assert_eq!(partial.data, full.data);
        assert_eq!(rest.sha256, whole.sha256);
        let mut direct = Digests::new(extra);
        direct.update(&full.data);
        let direct = direct.finish();
        assert_eq!((rest.sha1, rest.md5), (direct.sha1, direct.md5));
        assert_eq!((rest.blocks_read, rest.blocks_holes), (1, 1)); // blocks 2 and 3 only
    }

    /// A SIGINT reaches the loop as a flag, and the loop ends at the
    /// block it was about to read: the report names that block, the
    /// sink holds every block before it, and an extraction resumed
    /// there completes the image with the hash of a straight run — the
    /// state a killed run could only have written five seconds ago.
    #[test]
    fn an_interrupt_ends_the_run_where_a_resume_can_take_it_up() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let (s, a, ub, _) = build();
        let reader = PoolReader::new(&a, vec![Some(&s[0] as &dyn BlockSource)]);
        let mos = open_mos(&reader, &ub).unwrap();
        let tree = walk(&mos, "tank").unwrap();
        let ds = tree.get("tank/vm/disk0").unwrap();
        let (obj, _) = open_volume(&reader, ds).unwrap();
        let volsize = ds.volsize.unwrap();
        let mut full = MemSink::default();
        let whole = extract(&obj, volsize, &mut full, OnError::Zero, |_, _| {}).unwrap();

        // The flag goes up once block 0 is done — as a signal would
        // between two blocks — and block 1 is never looked at.
        let flag = AtomicBool::new(false);
        let mut sink = MemSink::default();
        let stopped = extract_from(
            &obj,
            volsize,
            &mut sink,
            OnError::Zero,
            0,
            Digests::new(Extra::none()),
            Some(&flag),
            |done, _| {
                if done == 1 {
                    flag.store(true, Ordering::Relaxed);
                }
            },
        )
        .unwrap();
        assert_eq!(stopped.interrupted_at, Some(1));
        assert_eq!((stopped.blocks_read, stopped.blocks_holes), (1, 0));
        assert!(!stopped.aborted && stopped.bad.is_empty());
        assert_eq!(sink.writes, vec![(0, 8192)]);

        // A flag already up before the first block stops before it.
        let mut none = MemSink::default();
        let at_once = extract_from(
            &obj,
            volsize,
            &mut none,
            OnError::Zero,
            0,
            Digests::new(Extra::none()),
            Some(&flag),
            |_, _| {},
        )
        .unwrap();
        assert_eq!(at_once.interrupted_at, Some(0));
        assert!(none.writes.is_empty());

        // Resumed at the block the report names, with the prefix hashed
        // back: the image and its hash are those of the straight run.
        let mut h = Digests::new(Extra::none());
        h.update(&sink.data[..8192]);
        let rest = extract_from(
            &obj,
            volsize,
            &mut sink,
            OnError::Zero,
            stopped.interrupted_at.unwrap(),
            h,
            None,
            |_, _| {},
        )
        .unwrap();
        assert_eq!(rest.interrupted_at, None);
        assert_eq!(sink.data, full.data);
        assert_eq!(rest.sha256, whole.sha256);
        assert_eq!((rest.blocks_read, rest.blocks_holes), (1, 2));
    }
}
