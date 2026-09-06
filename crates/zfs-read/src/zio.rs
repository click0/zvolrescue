//! Reading blocks through an assembled pool: DVA → top-level vdev → leaf
//! device, then checksum verification and decompression.
//!
//! Redundancy handled here: any number of DVA copies, and mirror children.
//! RAIDZ and dRAID reconstruction (SPEC F-24/F-25) and gang blocks (F-26)
//! arrive in phase 2 and are reported as unsupported until then.

use std::collections::BTreeMap;
use std::fmt;

use zfs_ondisk::blkptr::{BlkPtr, Dva, LABEL_START_SIZE};
use zfs_ondisk::checksum::{verify, Verify};
use zfs_ondisk::compress::{decompress, DecompressError};
use zvolrescue_io::BlockSource;

use crate::pool::PoolAssembly;

/// One top-level vdev as the reader sees it.
#[derive(Debug, Clone)]
struct Top {
    kind: String,
    nparity: u64,
    /// For each leaf in configuration order, the index of its scanned
    /// device, or `None` if that member is missing.
    leaves: Vec<Option<usize>>,
}

/// Reads blocks from the members of one pool.
pub struct PoolReader<'a> {
    devices: Vec<Option<&'a dyn BlockSource>>,
    tops: BTreeMap<u32, Top>,
}

/// Why a block could not be produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    /// The DVA names a top-level vdev the labels do not describe.
    UnknownVdev(u32),
    /// Every leaf that could hold the copy is missing.
    NoMember,
    /// The top-level vdev type is not readable in this build.
    Unsupported(String),
    /// Gang blocks are not readable in this build.
    Gang,
    /// I/O error on a member.
    Io(String),
    /// All copies were read but none passed its checksum.
    AllCopiesBad,
    /// The block pointer is a hole (callers usually treat this as zeros).
    Hole,
    /// The payload could not be decompressed.
    Decompress(DecompressError),
    /// Checksum algorithm not implemented; data returned unverified only
    /// when the caller asked for that.
    ChecksumUnsupported,
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::UnknownVdev(v) => write!(f, "DVA names unknown top-level vdev {v}"),
            ReadError::NoMember => write!(f, "no present member holds this copy"),
            ReadError::Unsupported(k) => write!(f, "top-level vdev type {k} not supported yet"),
            ReadError::Gang => write!(f, "gang blocks not supported yet"),
            ReadError::Io(e) => write!(f, "I/O error: {e}"),
            ReadError::AllCopiesBad => write!(f, "every copy failed its checksum"),
            ReadError::Hole => write!(f, "block pointer is a hole"),
            ReadError::Decompress(e) => write!(f, "{e}"),
            ReadError::ChecksumUnsupported => write!(f, "checksum algorithm not supported yet"),
        }
    }
}

impl std::error::Error for ReadError {}

/// What happened when one copy was tried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    /// DVA index in the block pointer.
    pub dva: usize,
    /// Top-level vdev id.
    pub vdev: u32,
    /// Scanned device index the bytes came from, if a read happened.
    pub device: Option<usize>,
    /// Outcome.
    pub result: Result<Verify, ReadError>,
}

/// A block that has been read, verified and decompressed.
#[derive(Debug, Clone)]
pub struct Block {
    /// Exactly `lsize` bytes.
    pub data: Vec<u8>,
    /// Verification result of the copy that was used.
    pub verify: Verify,
    /// Every copy tried, in order, including the successful one.
    pub attempts: Vec<Attempt>,
}

impl<'a> PoolReader<'a> {
    /// Build a reader for `pool` over `devices`, indexed exactly like the
    /// scans that produced the assembly (`None` for unreadable devices).
    pub fn new(pool: &PoolAssembly, devices: Vec<Option<&'a dyn BlockSource>>) -> Self {
        let tops = pool
            .tops
            .iter()
            .map(|t| {
                (
                    t.id as u32,
                    Top {
                        kind: t.kind.clone(),
                        nparity: t.nparity.unwrap_or(0),
                        leaves: t.members.iter().map(|m| m.present).collect(),
                    },
                )
            })
            .collect();
        PoolReader { devices, tops }
    }

    /// Read the raw `psize` bytes behind one DVA, trying each present
    /// leaf of a mirror until one read succeeds. No verification.
    pub fn read_dva(&self, dva: &Dva, psize: usize) -> Result<(Vec<u8>, usize), ReadError> {
        if dva.gang {
            return Err(ReadError::Gang);
        }
        let top = self
            .tops
            .get(&dva.vdev)
            .ok_or(ReadError::UnknownVdev(dva.vdev))?;
        match top.kind.as_str() {
            "mirror" | "disk" | "file" => {
                let mut last = ReadError::NoMember;
                for leaf in top.leaves.iter().flatten() {
                    let Some(dev) = self.devices.get(*leaf).copied().flatten() else {
                        continue;
                    };
                    let mut buf = vec![0u8; psize];
                    match dev.read_at(LABEL_START_SIZE + dva.offset, &mut buf) {
                        Ok(()) => return Ok((buf, *leaf)),
                        Err(e) => last = ReadError::Io(e.to_string()),
                    }
                }
                Err(last)
            }
            "raidz" | "draid" => Err(ReadError::Unsupported(format!(
                "{}{}",
                top.kind, top.nparity
            ))),
            other => Err(ReadError::Unsupported(other.to_string())),
        }
    }

    /// Read, verify and decompress the block behind `bp`.
    ///
    /// Copies are tried in DVA order and, within a mirror, in child order.
    /// The first copy whose checksum verifies (or that cannot be checked
    /// because the algorithm is `off`) is decompressed. A copy whose
    /// checksum algorithm is unsupported is used only if `allow_unverified`.
    pub fn read_block(&self, bp: &BlkPtr, allow_unverified: bool) -> Result<Block, ReadError> {
        if bp.is_hole() {
            return Err(ReadError::Hole);
        }
        let lsize = bp.lsize as usize;
        if let Some(payload) = bp.embedded_payload() {
            let data =
                decompress(bp.compression, &payload, lsize).map_err(ReadError::Decompress)?;
            return Ok(Block {
                data,
                verify: Verify::NotChecked,
                attempts: Vec::new(),
            });
        }
        let psize = bp.psize as usize;
        let mut attempts = Vec::new();
        let mut unverified: Option<(Vec<u8>, Verify)> = None;
        for (i, dva) in bp.dva.iter().enumerate() {
            if dva.is_empty() {
                continue;
            }
            let top = match self.tops.get(&dva.vdev) {
                Some(t) => t,
                None => {
                    attempts.push(Attempt {
                        dva: i,
                        vdev: dva.vdev,
                        device: None,
                        result: Err(ReadError::UnknownVdev(dva.vdev)),
                    });
                    continue;
                }
            };
            // Mirror children are distinct copies: try each one. A missing
            // child is recorded as such, never silently substituted.
            let candidates: Vec<Option<Option<usize>>> = match top.kind.as_str() {
                "mirror" | "disk" | "file" => top.leaves.iter().map(|l| Some(*l)).collect(),
                _ => vec![None],
            };
            for candidate in candidates {
                let read = match candidate {
                    Some(None) => Err(ReadError::NoMember),
                    Some(Some(l)) => self
                        .devices
                        .get(l)
                        .copied()
                        .flatten()
                        .ok_or(ReadError::NoMember)
                        .and_then(|dev| {
                            let mut buf = vec![0u8; psize];
                            dev.read_at(LABEL_START_SIZE + dva.offset, &mut buf)
                                .map(|()| (buf, l))
                                .map_err(|e| ReadError::Io(e.to_string()))
                        }),
                    None => self.read_dva(dva, psize),
                };
                match read {
                    Err(e) => attempts.push(Attempt {
                        dva: i,
                        vdev: dva.vdev,
                        device: candidate.flatten(),
                        result: Err(e),
                    }),
                    Ok((raw, device)) => {
                        let v = verify(bp.checksum, &raw, bp.endian, &bp.cksum);
                        attempts.push(Attempt {
                            dva: i,
                            vdev: dva.vdev,
                            device: Some(device),
                            result: Ok(v),
                        });
                        match v {
                            Verify::Ok | Verify::NotChecked => {
                                let data = decompress(bp.compression, &raw, lsize)
                                    .map_err(ReadError::Decompress)?;
                                return Ok(Block {
                                    data,
                                    verify: v,
                                    attempts,
                                });
                            }
                            Verify::Unsupported => {
                                if unverified.is_none() {
                                    unverified = Some((raw, v));
                                }
                            }
                            Verify::Mismatch => {}
                        }
                    }
                }
            }
        }
        if let (true, Some((raw, v))) = (allow_unverified, unverified) {
            let data = decompress(bp.compression, &raw, lsize).map_err(ReadError::Decompress)?;
            return Ok(Block {
                data,
                verify: v,
                attempts,
            });
        }
        if attempts
            .iter()
            .any(|a| matches!(a.result, Ok(Verify::Unsupported)))
        {
            return Err(ReadError::ChecksumUnsupported);
        }
        if attempts
            .iter()
            .any(|a| matches!(a.result, Ok(Verify::Mismatch)))
        {
            return Err(ReadError::AllCopiesBad);
        }
        Err(attempts
            .into_iter()
            .filter_map(|a| a.result.err())
            .next_back()
            .unwrap_or(ReadError::NoMember))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{write_at_dva, Pool};
    use crate::pool::assemble;
    use crate::vdev::scan_device;
    use zfs_ondisk::blkptr::encode::Builder;
    use zfs_ondisk::checksum::fletcher4;
    use zfs_ondisk::label::LABEL_SIZE;
    use zfs_ondisk::Endian;
    use zvolrescue_io::MemSource;

    const SIZE: u64 = 32 * LABEL_SIZE;

    fn payload() -> Vec<u8> {
        (0..8192u32).flat_map(|i| (i % 251).to_le_bytes()).collect()
    }

    /// A 32 KiB block compressed with lz4, stored at DVA 0x10000 on vdev 0.
    fn compressed() -> (Vec<u8>, BlkPtr) {
        let data = payload();
        let block = lz4_flex::block::compress(&data);
        let mut raw = (block.len() as u32).to_be_bytes().to_vec();
        raw.extend(block);
        let psize = raw.len().div_ceil(512) * 512;
        raw.resize(psize, 0);
        let bp = Builder::new()
            .dva(0, 0, 0x10000, psize as u64, false)
            .sizes(data.len() as u64, psize as u64)
            .props(15, 7, 19, 0)
            .births(0, 100, 1)
            .cksum(fletcher4(&raw, Endian::Little))
            .bytes(Endian::Little);
        (raw, BlkPtr::parse(&bp, Endian::Little).unwrap())
    }

    fn reader_over(images: Vec<Option<Vec<u8>>>) -> (Vec<Option<MemSource>>, PoolAssembly) {
        let sources: Vec<Option<MemSource>> =
            images.into_iter().map(|i| i.map(MemSource::new)).collect();
        let scans: Vec<_> = sources
            .iter()
            .map(|s| s.as_ref().and_then(|s| scan_device(s).ok()))
            .collect();
        let pools = assemble(&scans);
        assert_eq!(pools.len(), 1);
        (sources, pools.into_iter().next().unwrap())
    }

    fn as_dyn(sources: &[Option<MemSource>]) -> Vec<Option<&dyn BlockSource>> {
        sources
            .iter()
            .map(|s| s.as_ref().map(|s| s as &dyn BlockSource))
            .collect()
    }

    #[test]
    fn mirror_reads_good_copy_after_bad_one() {
        let pool = Pool::mirror("tank", 0x77, 12).txgs(&[(100, 1)]);
        let (raw, bp) = compressed();
        let mut m0 = pool.member_image(0, SIZE);
        let mut m1 = pool.member_image(1, SIZE);
        write_at_dva(&mut m0, 0x10000, &raw);
        write_at_dva(&mut m1, 0x10000, &raw);
        m0[(LABEL_START_SIZE + 0x10000) as usize + 7] ^= 0xff; // damage copy on member 0
        let (sources, assembly) = reader_over(vec![Some(m0), Some(m1)]);
        let reader = PoolReader::new(&assembly, as_dyn(&sources));
        let block = reader.read_block(&bp, false).unwrap();
        assert_eq!(block.data, payload());
        assert_eq!(block.verify, Verify::Ok);
        assert_eq!(block.attempts.len(), 2);
        assert_eq!(block.attempts[0].result, Ok(Verify::Mismatch));
        assert_eq!(block.attempts[0].device, Some(0));
        assert_eq!(block.attempts[1].device, Some(1));
    }

    #[test]
    fn mirror_with_missing_member_still_reads() {
        let pool = Pool::mirror("tank", 0x77, 12).txgs(&[(100, 1)]);
        let (raw, bp) = compressed();
        let mut m1 = pool.member_image(1, SIZE);
        write_at_dva(&mut m1, 0x10000, &raw);
        let (sources, assembly) = reader_over(vec![None, Some(m1)]);
        let reader = PoolReader::new(&assembly, as_dyn(&sources));
        let block = reader.read_block(&bp, false).unwrap();
        assert_eq!(block.data, payload());
        assert_eq!(block.attempts.len(), 2);
        assert_eq!(block.attempts[0].result, Err(ReadError::NoMember));
    }

    #[test]
    fn all_copies_bad_and_unknown_vdev() {
        let pool = Pool::mirror("tank", 0x77, 12).txgs(&[(100, 1)]);
        let (raw, bp) = compressed();
        let mut m0 = pool.member_image(0, SIZE);
        write_at_dva(&mut m0, 0x10000, &raw);
        m0[(LABEL_START_SIZE + 0x10000) as usize + 7] ^= 0xff;
        let (sources, assembly) = reader_over(vec![Some(m0)]);
        let reader = PoolReader::new(&assembly, as_dyn(&sources));
        assert_eq!(
            reader.read_block(&bp, false).unwrap_err(),
            ReadError::AllCopiesBad
        );

        let far = Builder::new()
            .dva(0, 9, 0x10000, 512, false)
            .sizes(512, 512)
            .props(2, 7, 19, 0)
            .births(0, 1, 1)
            .bytes(Endian::Little);
        let far = BlkPtr::parse(&far, Endian::Little).unwrap();
        assert_eq!(
            reader.read_block(&far, false).unwrap_err(),
            ReadError::UnknownVdev(9)
        );
        assert_eq!(
            reader.read_dva(&far.dva[0], 512).unwrap_err(),
            ReadError::UnknownVdev(9)
        );
    }

    #[test]
    fn embedded_hole_and_raidz() {
        let pool = Pool::raidz("tank", 0x78, 12, 4, 2).txgs(&[(100, 1)]);
        let m0 = pool.member_image(0, SIZE);
        let (sources, assembly) = reader_over(vec![Some(m0)]);
        let reader = PoolReader::new(&assembly, as_dyn(&sources));

        let data: Vec<u8> = (0..90u8).collect();
        let bp = Builder::new()
            .births(0, 5, 0)
            .embedded(&data, 90, 2, 19)
            .bytes(Endian::Little);
        let bp = BlkPtr::parse(&bp, Endian::Little).unwrap();
        assert_eq!(reader.read_block(&bp, false).unwrap().data, data);

        let hole = BlkPtr::parse(&[0u8; 128], Endian::Little).unwrap();
        assert_eq!(
            reader.read_block(&hole, false).unwrap_err(),
            ReadError::Hole
        );

        let (_, on_raidz) = compressed();
        assert!(matches!(
            reader.read_block(&on_raidz, false).unwrap_err(),
            ReadError::Unsupported(k) if k == "raidz2"
        ));
    }
}
