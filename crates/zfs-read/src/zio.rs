//! Reading blocks through an assembled pool: DVA → top-level vdev → leaf
//! device, then checksum verification and decompression.
//!
//! Redundancy handled here: any number of DVA copies, and mirror children.
//! RAIDZ and dRAID reconstruction (SPEC F-24/F-25) and gang blocks (F-26)
//! arrive in phase 2 and are reported as unsupported until then.

use std::collections::BTreeMap;
use std::fmt;

use zfs_ondisk::blkptr::{self, BlkPtr, Dva, LABEL_START_SIZE};
use zfs_ondisk::checksum::{verify, Verify};
use zfs_ondisk::compress::{decompress, DecompressError};
use zfs_ondisk::raidz;
use zvolrescue_io::trace::hexdump;
use zvolrescue_io::{trace, BlockSource};

use crate::pool::PoolAssembly;

/// One way to obtain a block's raw bytes: the device it came from (if a
/// single device) and the bytes or the error.
type RawCandidate = (Option<usize>, Result<Vec<u8>, ReadError>);

/// One top-level vdev as the reader sees it.
#[derive(Debug, Clone)]
struct Top {
    kind: String,
    nparity: u64,
    ashift: u32,
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
    /// A gang block header failed its checksum or could not be parsed.
    Gang(String),
    /// Redundancy exhausted: the pool cannot supply this block.
    Unrecoverable(String),
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
            ReadError::Gang(e) => write!(f, "gang block: {e}"),
            ReadError::Unrecoverable(e) => write!(f, "not recoverable: {e}"),
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
                        ashift: t.ashift.and_then(|a| u32::try_from(a).ok()).unwrap_or(9),
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
            "raidz" => Err(ReadError::Unsupported(
                "raidz raw DVA reads go through read_block".into(),
            )),
            "draid" => Err(ReadError::Unsupported(format!("draid{}", top.nparity))),
            other => Err(ReadError::Unsupported(other.to_string())),
        }
    }

    /// Every independent way to obtain the raw `psize` bytes behind a
    /// non-gang DVA: one entry per present mirror child, or a single
    /// parity-reconstructed entry for raidz. Errors are kept so callers
    /// can report them.
    fn raw_candidates(&self, top: &Top, dva: &Dva, psize: usize) -> Vec<RawCandidate> {
        match top.kind.as_str() {
            "raidz" => {
                let unit = 1u64 << top.ashift;
                let padded = (psize as u64).div_ceil(unit) * unit;
                let m = raidz::map(
                    dva.offset,
                    padded,
                    top.ashift,
                    top.leaves.len() as u64,
                    top.nparity,
                );
                let mut parity = Vec::new();
                for c in m.parity() {
                    parity.push(self.read_column(top, c).ok());
                }
                let mut data = Vec::new();
                let mut lost = Vec::new();
                for (i, c) in m.data().iter().enumerate() {
                    match self.read_column(top, c) {
                        Ok(b) => data.push(b),
                        Err(_) => {
                            lost.push(i);
                            data.push(vec![0u8; c.size as usize]);
                        }
                    }
                }
                let result = if lost.is_empty() {
                    Ok(())
                } else {
                    raidz::reconstruct(&mut data, &parity, &lost)
                        .map_err(|e| ReadError::Unrecoverable(format!("raidz reconstruct: {e:?}")))
                };
                vec![(
                    None,
                    result.map(|()| {
                        let mut out: Vec<u8> = data.iter().flatten().copied().collect();
                        out.truncate(psize);
                        out
                    }),
                )]
            }
            "draid" => vec![(
                None,
                Err(ReadError::Unsupported(format!("draid{}", top.nparity))),
            )],
            _ => top
                .leaves
                .iter()
                .map(|leaf| {
                    let read = leaf
                        .and_then(|l| self.devices.get(l).copied().flatten().map(|d| (l, d)))
                        .ok_or(ReadError::NoMember)
                        .and_then(|(_, dev)| {
                            let mut buf = vec![0u8; psize];
                            dev.read_at(LABEL_START_SIZE + dva.offset, &mut buf)
                                .map(|()| buf)
                                .map_err(|e| ReadError::Io(e.to_string()))
                        });
                    (*leaf, read)
                })
                .collect(),
        }
    }

    /// Read the raw bytes behind a gang pointer: the 512-byte header at
    /// the DVA (verified against the pointer's identity and birth, trying
    /// every copy), then each child pointer in order, concatenated;
    /// children may be gang blocks themselves.
    fn read_gang(
        &self,
        top: &Top,
        dva: &Dva,
        bp: &BlkPtr,
        depth: usize,
    ) -> Result<Vec<u8>, ReadError> {
        if depth > 8 {
            return Err(ReadError::Gang("nesting deeper than 8".into()));
        }
        let plain = Dva {
            gang: false,
            ..*dva
        };
        let mut header = None;
        let mut last = ReadError::NoMember;
        for (device, candidate) in self.raw_candidates(top, &plain, blkptr::GANG_HEADER_SIZE) {
            match candidate {
                Ok(buf) => {
                    let status = zfs_ondisk::checksum::verify_gang_header(
                        &buf,
                        u64::from(bp.dva[0].vdev),
                        bp.dva[0].offset,
                        bp.birth,
                    );
                    trace!(
                        "gang",
                        "header @ vdev {} off {:#x} device {device:?} (depth {depth}): checksum {}",
                        dva.vdev,
                        dva.offset,
                        status.as_str()
                    );
                    if status == zfs_ondisk::checksum::ChecksumStatus::Ok {
                        header = Some(buf);
                        break;
                    }
                    last = ReadError::Gang(format!("header checksum {}", status.as_str()));
                }
                Err(e) => last = e,
            }
        }
        let Some(header) = header else {
            return Err(last);
        };
        let children = blkptr::parse_gang_header(&header, bp.endian)?;
        let mut out = Vec::with_capacity(bp.psize as usize);
        for (i, child) in children.iter().enumerate() {
            if child.is_hole() {
                continue;
            }
            trace!(
                "gang",
                "  child {i}: psize {} {} birth {} dvas [{}]",
                child.psize,
                child.checksum.name(),
                child.birth,
                child
                    .dvas()
                    .map(|d| format!(
                        "vdev {} off {:#x}{}",
                        d.vdev,
                        d.offset,
                        if d.gang { " GANG" } else { "" }
                    ))
                    .collect::<Vec<_>>()
                    .join("; ")
            );
            out.extend_from_slice(&self.read_raw_verified(child, depth + 1)?);
        }
        out.truncate(bp.psize as usize);
        Ok(out)
    }

    /// Read the psize bytes of `bp` from any copy that verifies, resolving
    /// gang pointers; no decompression.
    fn read_raw_verified(&self, bp: &BlkPtr, depth: usize) -> Result<Vec<u8>, ReadError> {
        let mut last = ReadError::NoMember;
        for dva in bp.dvas() {
            let Some(top) = self.tops.get(&dva.vdev) else {
                last = ReadError::UnknownVdev(dva.vdev);
                continue;
            };
            let candidates = if dva.gang {
                vec![(None, self.read_gang(top, dva, bp, depth))]
            } else {
                self.raw_candidates(top, dva, bp.psize as usize)
            };
            for (_, raw) in candidates {
                match raw {
                    Ok(raw) => match verify(bp.checksum, &raw, bp.endian, &bp.cksum) {
                        Verify::Ok | Verify::NotChecked => return Ok(raw),
                        Verify::Mismatch => last = ReadError::AllCopiesBad,
                        Verify::Unsupported => last = ReadError::ChecksumUnsupported,
                    },
                    Err(e) => last = e,
                }
            }
        }
        Err(last)
    }

    /// Read one column of a RAIDZ stripe from its leaf.
    fn read_column(&self, top: &Top, col: &raidz::Column) -> Result<Vec<u8>, ReadError> {
        let leaf = top
            .leaves
            .get(col.devidx as usize)
            .copied()
            .flatten()
            .ok_or(ReadError::NoMember)?;
        let dev = self
            .devices
            .get(leaf)
            .copied()
            .flatten()
            .ok_or(ReadError::NoMember)?;
        let mut buf = vec![0u8; col.size as usize];
        dev.read_at(LABEL_START_SIZE + col.offset, &mut buf)
            .map_err(|e| ReadError::Io(e.to_string()))?;
        Ok(buf)
    }

    /// Read the `psize` bytes behind a DVA on a RAIDZ top-level vdev,
    /// reconstructing from parity when columns are missing or, if the
    /// checksum still fails, trying every combination of up to `nparity`
    /// data columns as silently corrupted (`vdev_raidz_combrec`).
    fn read_raidz(
        &self,
        top: &Top,
        dva: &Dva,
        bp: &BlkPtr,
        attempts: &mut Vec<Attempt>,
        dva_index: usize,
    ) -> Result<(Vec<u8>, Verify), ReadError> {
        let unit = 1u64 << top.ashift;
        let psize = bp.psize as usize;
        let padded = bp.psize.div_ceil(unit) * unit;
        let m = raidz::map(
            dva.offset,
            padded,
            top.ashift,
            top.leaves.len() as u64,
            top.nparity,
        );
        trace!(
            "raidz",
            "  dva {dva_index}: {}{} ashift {} -> {} cols ({} parity, {} big, nskip {}): {}",
            top.kind,
            top.nparity,
            top.ashift,
            m.acols,
            m.nparity,
            m.bigcols,
            m.nskip,
            m.cols[..m.acols]
                .iter()
                .map(|c| format!("dev{}@{:#x}+{}", c.devidx, c.offset, c.size))
                .collect::<Vec<_>>()
                .join(" ")
        );
        let mut parity: Vec<Option<Vec<u8>>> = Vec::with_capacity(m.nparity);
        for c in m.parity() {
            parity.push(match self.read_column(top, c) {
                Ok(b) => Some(b),
                Err(e) => {
                    trace!("raidz", "    parity column dev{}: {e}", c.devidx);
                    None
                }
            });
        }
        let mut data: Vec<Vec<u8>> = Vec::with_capacity(m.acols - m.nparity);
        let mut lost: Vec<usize> = Vec::new();
        for (i, c) in m.data().iter().enumerate() {
            match self.read_column(top, c) {
                Ok(b) => data.push(b),
                Err(e) => {
                    trace!("raidz", "    data column {i} dev{}: {e}", c.devidx);
                    lost.push(i);
                    data.push(vec![0u8; c.size as usize]);
                }
            }
        }
        let available = parity.iter().filter(|p| p.is_some()).count();
        let assemble = |data: &[Vec<u8>]| -> Vec<u8> {
            let mut out: Vec<u8> = data.iter().flatten().copied().collect();
            out.truncate(psize);
            out
        };
        let record = |attempts: &mut Vec<Attempt>, result: Result<Verify, ReadError>| {
            attempts.push(Attempt {
                dva: dva_index,
                vdev: dva.vdev,
                device: None,
                result,
            });
        };
        // 1. Known losses first.
        if lost.len() > available {
            let e = ReadError::Unrecoverable(format!(
                "{} data column(s) missing, only {} parity column(s) readable",
                lost.len(),
                available
            ));
            record(attempts, Err(e.clone()));
            return Err(e);
        }
        if !lost.is_empty() {
            raidz::reconstruct(&mut data, &parity, &lost)
                .map_err(|e| ReadError::Io(format!("raidz reconstruct: {e:?}")))?;
            trace!(
                "raidz",
                "    reconstructed missing data column(s) {lost:?} from parity"
            );
        }
        let raw = assemble(&data);
        let v = verify(bp.checksum, &raw, bp.endian, &bp.cksum);
        trace!(
            "raidz",
            "    checksum after direct read{}: {v:?}",
            if lost.is_empty() {
                ""
            } else {
                " + reconstruction"
            }
        );
        record(attempts, Ok(v));
        if v != Verify::Mismatch {
            return Ok((raw, v));
        }
        // 2. Silent corruption: assume every combination of up to `budget`
        //    readable columns — parity or data — is bad, rebuild the data
        //    among them from the parity that is not suspected, and keep
        //    the first result that verifies (vdev_raidz_combrec).
        let budget = available - lost.len();
        let readable_parity: Vec<usize> =
            (0..parity.len()).filter(|&r| parity[r].is_some()).collect();
        let readable_data: Vec<usize> = (0..data.len()).filter(|i| !lost.contains(i)).collect();
        let columns: Vec<(bool, usize)> = readable_parity
            .iter()
            .map(|&r| (true, r))
            .chain(readable_data.iter().map(|&i| (false, i)))
            .collect();
        for k in 1..=budget.min(columns.len()) {
            for combo in combinations(columns.len(), k) {
                let mut bad_parity: Vec<usize> = Vec::new();
                let mut missing = lost.clone();
                for &j in &combo {
                    match columns[j] {
                        (true, r) => bad_parity.push(r),
                        (false, i) => missing.push(i),
                    }
                }
                missing.sort_unstable();
                let usable: Vec<Option<Vec<u8>>> = parity
                    .iter()
                    .enumerate()
                    .map(|(r, p)| {
                        if bad_parity.contains(&r) {
                            None
                        } else {
                            p.clone()
                        }
                    })
                    .collect();
                let usable_count = usable.iter().filter(|p| p.is_some()).count();
                if missing.is_empty() || missing.len() > usable_count {
                    continue;
                }
                let mut work = data.clone();
                if raidz::reconstruct(&mut work, &usable, &missing).is_err() {
                    continue;
                }
                let raw = assemble(&work);
                let v = verify(bp.checksum, &raw, bp.endian, &bp.cksum);
                if v != Verify::Mismatch {
                    trace!(
                        "raidz",
                        "    combinatorial reconstruction succeeded: data columns {missing:?} rebuilt, parity rows {bad_parity:?} distrusted"
                    );
                    record(attempts, Ok(v));
                    return Ok((raw, v));
                }
            }
        }
        trace!(
            "raidz",
            "    no reconstruction produced a block matching its checksum"
        );
        Err(ReadError::AllCopiesBad)
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
        trace!(
            "zio",
            "read bp: level {} type {} lsize {} psize {} {} {} birth {} dvas [{}]",
            bp.level,
            bp.object_type,
            bp.lsize,
            bp.psize,
            bp.compression.name(),
            bp.checksum.name(),
            bp.birth,
            bp.dvas()
                .map(|d| format!(
                    "vdev {} off {:#x} asize {}{}",
                    d.vdev,
                    d.offset,
                    d.asize,
                    if d.gang { " GANG" } else { "" }
                ))
                .collect::<Vec<_>>()
                .join("; ")
        );
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
            if dva.gang {
                let result = self.read_gang(top, dva, bp, 0).and_then(|raw| {
                    let v = verify(bp.checksum, &raw, bp.endian, &bp.cksum);
                    match v {
                        Verify::Ok | Verify::NotChecked => Ok((raw, v)),
                        Verify::Mismatch => Err(ReadError::AllCopiesBad),
                        Verify::Unsupported => Err(ReadError::ChecksumUnsupported),
                    }
                });
                match result {
                    Ok((raw, v)) => {
                        attempts.push(Attempt {
                            dva: i,
                            vdev: dva.vdev,
                            device: None,
                            result: Ok(v),
                        });
                        let data = decompress(bp.compression, &raw, lsize)
                            .map_err(ReadError::Decompress)?;
                        return Ok(Block {
                            data,
                            verify: v,
                            attempts,
                        });
                    }
                    Err(e) => {
                        trace!("gang", "  dva {i}: {e}");
                        attempts.push(Attempt {
                            dva: i,
                            vdev: dva.vdev,
                            device: None,
                            result: Err(e),
                        });
                        continue;
                    }
                }
            }
            if top.kind == "raidz" {
                match self.read_raidz(top, dva, bp, &mut attempts, i) {
                    Ok((raw, v)) => {
                        let data = decompress(bp.compression, &raw, lsize)
                            .map_err(ReadError::Decompress)?;
                        return Ok(Block {
                            data,
                            verify: v,
                            attempts,
                        });
                    }
                    Err(_) => continue,
                }
            }
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
                    Err(e) => {
                        trace!("zio", "  dva {i} candidate {candidate:?}: {e}");
                        attempts.push(Attempt {
                            dva: i,
                            vdev: dva.vdev,
                            device: candidate.flatten(),
                            result: Err(e),
                        });
                    }
                    Ok((raw, device)) => {
                        let v = verify(bp.checksum, &raw, bp.endian, &bp.cksum);
                        trace!(
                            "zio",
                            "  dva {i} device #{device} @ {:#x}: checksum {v:?}",
                            LABEL_START_SIZE + dva.offset
                        );
                        if v == Verify::Mismatch {
                            trace!(
                                "zio",
                                "    expected {:x?} computed {:x?}; first bytes:\n{}",
                                bp.cksum,
                                zfs_ondisk::checksum::compute(bp.checksum, &raw, bp.endian)
                                    .unwrap_or([0; 4]),
                                hexdump(&raw, LABEL_START_SIZE + dva.offset, 64)
                            );
                        }
                        attempts.push(Attempt {
                            dva: i,
                            vdev: dva.vdev,
                            device: Some(device),
                            result: Ok(v),
                        });
                        match v {
                            Verify::Ok | Verify::NotChecked => {
                                let data = match decompress(bp.compression, &raw, lsize) {
                                    Ok(d) => d,
                                    Err(e) => {
                                        trace!(
                                            "zio",
                                            "    decompress {} failed: {e}; first bytes:\n{}",
                                            bp.compression.name(),
                                            hexdump(&raw, LABEL_START_SIZE + dva.offset, 64)
                                        );
                                        return Err(ReadError::Decompress(e));
                                    }
                                };
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

/// All `k`-element index subsets of `0..n`, in lexicographic order.
fn combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
    let mut out = Vec::new();
    let mut cur: Vec<usize> = Vec::with_capacity(k);
    fn go(start: usize, n: usize, k: usize, cur: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
        if cur.len() == k {
            out.push(cur.clone());
            return;
        }
        for i in start..n {
            cur.push(i);
            go(i + 1, n, k, cur, out);
            cur.pop();
        }
    }
    go(0, n, k, &mut cur, &mut out);
    out
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

        // A pointer into unwritten space on the raidz: every column reads
        // as zeros, no combination verifies, and the error says so.
        let (_, on_raidz) = compressed();
        assert_eq!(
            reader.read_block(&on_raidz, false).unwrap_err(),
            ReadError::AllCopiesBad
        );
    }

    mod raidz_tests {
        use super::*;
        use crate::dsl::{open_mos, walk};
        use crate::fixture::{destroyed_zvol_members, Pool};
        use crate::zvol::{extract, open_volume, OnError};
        use zvolrescue_io::MemSink;

        /// 4-wide raidz2 at ashift 12 with the sample MOS; returns images
        /// and the assembly built from `present` members only.
        fn raidz2(
            present: &[bool],
        ) -> (
            Vec<MemSource>,
            PoolAssembly,
            zfs_ondisk::uberblock::Uberblock,
        ) {
            let mut pool = Pool::raidz("tank", 0x7a1d, 12, 4, 2).txgs(&[(100, 1), (101, 2)]);
            let (members, _, _) = destroyed_zvol_members(&mut pool, 64 * LABEL_SIZE);
            let sources: Vec<MemSource> = members.into_iter().map(MemSource::new).collect();
            let scans: Vec<_> = sources
                .iter()
                .zip(present)
                .map(|(s, &p)| if p { scan_device(s).ok() } else { None })
                .collect();
            // txg 100 still has the volume; 101 has it destroyed.
            let ub = scans.iter().flatten().next().unwrap().labels[0]
                .uberblocks
                .iter()
                .find(|s| s.ub.txg == 100)
                .unwrap()
                .ub
                .clone();
            let assembly = assemble(&scans).into_iter().next().unwrap();
            (sources, assembly, ub)
        }

        fn devices<'a>(s: &'a [MemSource], present: &[bool]) -> Vec<Option<&'a dyn BlockSource>> {
            s.iter()
                .zip(present)
                .map(|(m, &p)| if p { Some(m as &dyn BlockSource) } else { None })
                .collect()
        }

        fn dump_disk0(
            reader: &PoolReader<'_>,
            ub: &zfs_ondisk::uberblock::Uberblock,
        ) -> Result<(Vec<u8>, String), ReadError> {
            let mos = open_mos(reader, ub)?;
            let tree = walk(&mos, "tank")?;
            let ds = tree.get("tank/vm/disk0").ok_or(ReadError::Hole)?;
            let (obj, _) = open_volume(reader, ds)?;
            let mut sink = MemSink::default();
            let r = extract(
                &obj,
                ds.volsize.unwrap(),
                &mut sink,
                OnError::Abort,
                |_, _| {},
            )?;
            assert!(!r.aborted);
            Ok((sink.data, r.sha256))
        }

        #[test]
        fn all_members_present() {
            let present = [true; 4];
            let (s, a, ub) = raidz2(&present);
            let reader = PoolReader::new(&a, devices(&s, &present));
            let (img, sha) = dump_disk0(&reader, &ub).unwrap();
            assert_eq!(&img[..8192], &crate::fixture::zvol_pattern(0)[..]);
            assert_eq!(&img[16384..24576], &crate::fixture::zvol_pattern(2)[..]);
            // Same image as the mirror fixture produces.
            assert_eq!(
                sha,
                "d6d58af862ec2761bf43158f7ee2b2b0f4628fa6ca8095544493f9d698d7b80d"
            );
        }

        #[test]
        fn two_members_missing_reconstructs() {
            for present in [
                [false, false, true, true],
                [true, false, true, false],
                [false, true, false, true],
            ] {
                let (s, a, ub) = raidz2(&present);
                assert!(a.tops[0].readable());
                let reader = PoolReader::new(&a, devices(&s, &present));
                let (_, sha) = dump_disk0(&reader, &ub).unwrap();
                assert_eq!(
                    sha, "d6d58af862ec2761bf43158f7ee2b2b0f4628fa6ca8095544493f9d698d7b80d",
                    "{present:?}"
                );
            }
        }

        #[test]
        fn three_members_missing_fails_cleanly() {
            let present = [true, false, false, false];
            let (s, a, ub) = raidz2(&present);
            assert!(!a.tops[0].readable());
            let reader = PoolReader::new(&a, devices(&s, &present));
            let err = dump_disk0(&reader, &ub).unwrap_err();
            assert!(matches!(err, ReadError::Unrecoverable(_)), "{err}");
        }

        #[test]
        fn silently_corrupted_column_is_found_by_checksum() {
            let present = [true; 4];
            let (mut s, a, ub) = raidz2(&present);
            // Flip bytes where the stripes land on each child: DVA offsets
            // from 0x20_0000 map to child offsets from 0x20_0000 / 4, so a
            // 1 MiB window there covers every column of every block.
            let bytes = s[2].bytes_mut();
            let start = LABEL_START_SIZE as usize + 0x20_0000 / 4;
            for b in bytes[start..start + (1 << 20)].iter_mut() {
                *b ^= 0xa5;
            }
            let reader = PoolReader::new(&a, devices(&s, &present));
            let (_, sha) = dump_disk0(&reader, &ub).unwrap();
            assert_eq!(
                sha,
                "d6d58af862ec2761bf43158f7ee2b2b0f4628fa6ca8095544493f9d698d7b80d"
            );
            // Two corrupted members: still within raidz2's budget.
            let bytes = s[0].bytes_mut();
            for b in bytes[start..start + (1 << 20)].iter_mut() {
                *b ^= 0x5a;
            }
            let reader = PoolReader::new(&a, devices(&s, &present));
            let (_, sha) = dump_disk0(&reader, &ub).unwrap();
            assert_eq!(
                sha,
                "d6d58af862ec2761bf43158f7ee2b2b0f4628fa6ca8095544493f9d698d7b80d"
            );
            // Three: beyond the budget, and the failure is a clean error.
            let bytes = s[1].bytes_mut();
            for b in bytes[start..start + (1 << 20)].iter_mut() {
                *b ^= 0x33;
            }
            let reader = PoolReader::new(&a, devices(&s, &present));
            assert!(dump_disk0(&reader, &ub).is_err());
        }
    }

    mod gang_tests {
        use super::*;
        use crate::fixture::{Alloc, Pool};
        use zfs_ondisk::dmu::ot;

        fn payload() -> Vec<u8> {
            (0..12288u32).map(|i| (i % 253) as u8).collect()
        }

        fn build() -> (Vec<MemSource>, PoolAssembly, BlkPtr, u64) {
            let pool = Pool::mirror("tank", 0x9a9a, 12).txgs(&[(100, 1)]);
            let mut members = vec![pool.member_image(0, SIZE), pool.member_image(1, SIZE)];
            let mut a = Alloc::new(0x30_0000);
            let bp = a.put_gang(&mut members, &payload(), &[4096, 4096, 4096], ot::ZVOL, 100);
            let bp = BlkPtr::parse(&bp, Endian::Little).unwrap();
            let header_off = bp.dva[0].offset;
            let sources: Vec<MemSource> = members.into_iter().map(MemSource::new).collect();
            let scans: Vec<_> = sources.iter().map(|s| scan_device(s).ok()).collect();
            let assembly = assemble(&scans).into_iter().next().unwrap();
            (sources, assembly, bp, header_off)
        }

        fn reader<'a>(s: &'a [MemSource], a: &PoolAssembly) -> PoolReader<'a> {
            PoolReader::new(a, s.iter().map(|m| Some(m as &dyn BlockSource)).collect())
        }

        #[test]
        fn reads_gang_block_through_its_header() {
            let (s, a, bp, _) = build();
            assert!(bp.dva[0].gang);
            let block = reader(&s, &a).read_block(&bp, false).unwrap();
            assert_eq!(block.data, payload());
            assert_eq!(block.verify, Verify::Ok);
        }

        #[test]
        fn damaged_header_falls_back_to_other_copy_then_fails() {
            let (mut s, a, bp, header_off) = build();
            let at = (LABEL_START_SIZE + header_off) as usize + 3;
            s[0].bytes_mut()[at] ^= 0xff;
            // Mirror child 0 has a bad header; child 1 still serves it.
            assert_eq!(
                reader(&s, &a).read_block(&bp, false).unwrap().data,
                payload()
            );
            // Both headers damaged: a clean gang error.
            s[1].bytes_mut()[at] ^= 0xff;
            assert!(matches!(
                reader(&s, &a).read_block(&bp, false).unwrap_err(),
                ReadError::Gang(_)
            ));
        }

        #[test]
        fn damaged_child_on_one_mirror_side_is_healed() {
            let (mut s, a, bp, _) = build();
            // Child blocks precede the header: damage the second piece on member 0.
            let at = (LABEL_START_SIZE + 0x30_0000 + 4096) as usize + 10;
            s[0].bytes_mut()[at] ^= 0xff;
            assert_eq!(
                reader(&s, &a).read_block(&bp, false).unwrap().data,
                payload()
            );
            s[1].bytes_mut()[at] ^= 0xff;
            assert_eq!(
                reader(&s, &a).read_block(&bp, false).unwrap_err(),
                ReadError::AllCopiesBad
            );
        }
    }
}
