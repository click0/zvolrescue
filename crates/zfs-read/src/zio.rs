//! Reading blocks through an assembled pool: DVA → top-level vdev → leaf
//! device, then checksum verification and decompression.
//!
//! Redundancy handled here: any number of DVA copies, and mirror children.
//! RAIDZ and dRAID reconstruction (SPEC F-24/F-25) and gang blocks (F-26)
//! arrive in phase 2 and are reported as unsupported until then.

use std::collections::BTreeMap;
use std::fmt;

use std::cell::{Cell, RefCell};

use crate::crypt::{decrypt_block, CryptError, DatasetKeys};
use zfs_ondisk::blkptr::{self, BlkPtr, Dva, LABEL_START_SIZE};

use std::rc::Rc;
use zfs_ondisk::checksum::{verify_block, Salt, Verify};
use zfs_ondisk::compress::{decompress, DecompressError};
use zfs_ondisk::dmu::ot;
use zfs_ondisk::draid;
use zfs_ondisk::raidz;
use zvolrescue_io::trace::hexdump;
use zvolrescue_io::{trace, BlockSource};

use crate::pool::{Member, PoolAssembly};
use zfs_ondisk::label::VdevNode;

/// One way to obtain a block's raw bytes: the device it came from (if a
/// single device) and the bytes or the error.
type RawCandidate = (Option<usize>, Result<Vec<u8>, ReadError>);

/// The columns of one parity row (a raidz stripe or a dRAID row): parity
/// (`None` when unreadable), data (zero-filled where lost), lost data
/// column indices, and the row map.
type Columns = (Vec<Option<Vec<u8>>>, Vec<Vec<u8>>, Vec<usize>, raidz::Map);

/// A vdev as the reader sees it: the tree under one top-level vdev.
#[derive(Debug, Clone)]
enum Node {
    /// A disk or file; `None` when the member was not scanned.
    Leaf { device: Option<usize>, guid: u64 },
    /// Any child holds a full copy.
    Mirror { children: Vec<Node> },
    /// Data striped with parity over the children.
    Raidz {
        nparity: u64,
        ashift: u32,
        children: Vec<Node>,
    },
    /// dRAID: parity rows placed by a permutation map; children may be
    /// distributed spares standing in for a failed child.
    Draid {
        cfg: Rc<draid::Config>,
        ashift: u32,
        children: Vec<Node>,
    },
    /// A distributed spare (`draid<p>-<vdev>-<n>`): resolves to another
    /// child of its dRAID per permutation row. Only read through `Draid`.
    Dspare { spare_id: u64 },
    /// A vdev type this build cannot read.
    Unsupported { kind: String },
}

impl Node {
    fn from_tree(tree: &VdevNode, members: &[Member], ashift: u32) -> Node {
        if tree.kind == "dspare" {
            return match tree.path.as_deref().and_then(draid::spare_id_from_name) {
                Some(spare_id) => Node::Dspare { spare_id },
                None => Node::Unsupported {
                    kind: format!("dspare {:?}", tree.path),
                },
            };
        }
        if tree.children.is_empty() {
            return Node::Leaf {
                device: members
                    .iter()
                    .find(|m| m.guid == tree.guid)
                    .and_then(|m| m.present),
                guid: tree.guid,
            };
        }
        let children = tree
            .children
            .iter()
            .map(|c| Node::from_tree(c, members, ashift))
            .collect();
        let ashift = tree
            .ashift
            .and_then(|a| u32::try_from(a).ok())
            .unwrap_or(ashift);
        match tree.kind.as_str() {
            // spare and replacing vdevs are mirrors of the old and new child.
            "mirror" | "spare" | "replacing" => Node::Mirror { children },
            "draid" => match draid::Config::new(
                tree.draid_ndata.unwrap_or(0),
                tree.nparity.unwrap_or(0),
                tree.draid_nspares.unwrap_or(0),
                tree.children.len() as u64,
                tree.draid_ngroups.unwrap_or(0),
            ) {
                Ok(cfg) => Node::Draid {
                    cfg: Rc::new(cfg),
                    ashift,
                    children,
                },
                Err(e) => Node::Unsupported {
                    kind: format!("draid ({e})"),
                },
            },
            "raidz" => Node::Raidz {
                nparity: tree.nparity.unwrap_or(1),
                ashift,
                children,
            },
            other => Node::Unsupported {
                kind: other.to_string(),
            },
        }
    }

    fn describe(&self) -> String {
        match self {
            Node::Leaf { device, guid } => match device {
                Some(d) => format!("dev{d}"),
                None => format!("MISSING({guid:#x})"),
            },
            Node::Mirror { children } => format!(
                "mirror({})",
                children
                    .iter()
                    .map(Node::describe)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Node::Raidz {
                nparity, children, ..
            } => {
                format!(
                    "raidz{nparity}({})",
                    children
                        .iter()
                        .map(Node::describe)
                        .collect::<Vec<_>>()
                        .join(",")
                )
            }
            Node::Draid {
                cfg,
                ashift,
                children,
            } => format!(
                "draid{}:{}d:{}c:{}s ashift {ashift} ({})",
                cfg.nparity,
                cfg.ndata,
                cfg.children,
                cfg.nspares,
                children
                    .iter()
                    .map(Node::describe)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Node::Dspare { spare_id } => format!("dspare#{spare_id}"),
            Node::Unsupported { kind } => format!("{kind}?"),
        }
    }
}

/// Reads blocks from the members of one pool.
pub struct PoolReader<'a> {
    devices: Vec<Option<&'a dyn BlockSource>>,
    /// Byte offset at which each device's vdev begins. Zero unless a
    /// member was found somewhere other than the start of what was
    /// opened — a partition whose table was rewritten, an image cut with
    /// a different start — in which case the zero point recovered from
    /// its uberblocks (SPEC F-61) goes here.
    bases: Vec<u64>,
    tops: BTreeMap<u32, Node>,
    /// How many leaf reads each device has served. Used when deciding
    /// whether a member really contributed to what was read (F-62).
    reads: RefCell<Vec<u64>>,
    /// Pool checksum salt once the MOS object directory has been read.
    salt: Cell<Option<Salt>>,
    /// Keys of the encrypted dataset currently being read, if any.
    keys: RefCell<Option<DatasetKeys>>,
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
    /// The copy verified but is ciphertext of an encrypted dataset and no
    /// key is installed.
    Encrypted,
    /// Decryption failed: wrong key for this block, or a MAC mismatch.
    Crypt(CryptError),
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
            ReadError::Encrypted => write!(f, "encrypted block: no key"),
            ReadError::Crypt(e) => write!(f, "decrypt: {e}"),
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
    /// Scanned device index the bytes came from, if a single device.
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
                let ashift = t.ashift.and_then(|a| u32::try_from(a).ok()).unwrap_or(9);
                let node = Node::from_tree(&t.tree, &t.members, ashift);
                trace!("zio", "top-level vdev {}: {}", t.id, node.describe());
                (t.id as u32, node)
            })
            .collect();
        let bases = vec![0u64; devices.len()];
        let reads = RefCell::new(vec![0u64; devices.len()]);
        PoolReader {
            devices,
            bases,
            reads,
            tops,
            salt: Cell::new(None),
            keys: RefCell::new(None),
        }
    }

    /// Set where each device's vdev begins, indexed like the devices.
    ///
    /// A DVA is read at `base + 4 MiB + offset`, so a member whose labels
    /// put it elsewhere than offset 0 is read correctly once its base is
    /// known. Shorter lists leave the remaining devices at 0.
    pub fn with_base_offsets(mut self, bases: &[u64]) -> Self {
        for (i, &b) in bases.iter().enumerate() {
            if let Some(slot) = self.bases.get_mut(i) {
                *slot = b;
                if b != 0 {
                    trace!("zio", "device {i}: vdev starts at byte {b}");
                }
            }
        }
        self
    }

    /// How many leaf reads device `index` has served.
    pub fn reads_of(&self, index: usize) -> u64 {
        self.reads.borrow().get(index).copied().unwrap_or(0)
    }

    /// Record the pool checksum salt (from `org.illumos:checksum_salt` in
    /// the MOS object directory); needed by blake3/skein/edonr blocks.
    pub fn set_salt(&self, salt: Option<Salt>) {
        self.salt.set(salt);
    }

    /// The pool checksum salt, if known.
    pub fn salt(&self) -> Option<Salt> {
        self.salt.get()
    }

    /// Install (or clear) the dataset keys used to decrypt ciphertext
    /// blocks from now on. Blocks of other datasets must not be read
    /// with a foreign key: their MACs fail and read as `WrongKey`.
    pub fn set_keys(&self, keys: Option<DatasetKeys>) {
        *self.keys.borrow_mut() = keys;
    }

    /// Whether dataset keys are installed.
    pub fn has_keys(&self) -> bool {
        self.keys.borrow().is_some()
    }

    /// Verify `raw` against `bp` with the pool salt when one is known.
    fn verify(&self, bp: &BlkPtr, raw: &[u8]) -> Verify {
        let salt = self.salt.get();
        let crypt = bp.uses_crypt() && bp.object_type != ot::OBJSET;
        verify_block(bp.checksum, raw, bp.endian, &bp.cksum, salt.as_ref(), crypt)
    }

    /// Read `size` bytes at vdev-relative `offset` from a leaf device.
    fn read_leaf(
        &self,
        device: Option<usize>,
        offset: u64,
        size: usize,
    ) -> Result<Vec<u8>, ReadError> {
        let index = device.ok_or(ReadError::NoMember)?;
        let dev = self
            .devices
            .get(index)
            .copied()
            .flatten()
            .ok_or(ReadError::NoMember)?;
        let base = self.bases.get(index).copied().unwrap_or(0);
        if let Some(n) = self.reads.borrow_mut().get_mut(index) {
            *n += 1;
        }
        let mut buf = vec![0u8; size];
        dev.read_at(base + LABEL_START_SIZE + offset, &mut buf)
            .map(|()| buf)
            .map_err(|e| ReadError::Io(e.to_string()))
    }

    /// Every independent, *unverified* way to obtain `size` bytes at
    /// `offset` under `node`: one per leaf of a mirror (recursively), a
    /// single parity-reconstructed entry for raidz.
    fn read_candidates(&self, node: &Node, offset: u64, size: usize) -> Vec<RawCandidate> {
        match node {
            Node::Leaf { device, .. } => vec![(*device, self.read_leaf(*device, offset, size))],
            Node::Mirror { children } => children
                .iter()
                .flat_map(|c| self.read_candidates(c, offset, size))
                .collect(),
            Node::Raidz { .. } | Node::Draid { .. } => {
                let rows = self.read_rows(node, offset, size);
                let mut out = Vec::with_capacity(size);
                for (parity, mut data, lost, _) in rows {
                    if !lost.is_empty() {
                        if let Err(e) = raidz::reconstruct(&mut data, &parity, &lost) {
                            return vec![(
                                None,
                                Err(ReadError::Unrecoverable(format!("reconstruct: {e:?}"))),
                            )];
                        }
                    }
                    out.extend(data.iter().flatten());
                }
                out.truncate(size);
                vec![(None, Ok(out))]
            }
            Node::Dspare { .. } => vec![(
                None,
                Err(ReadError::Unsupported(
                    "distributed spare read outside its dRAID".into(),
                )),
            )],
            Node::Unsupported { kind } => vec![(None, Err(ReadError::Unsupported(kind.clone())))],
        }
    }

    /// First successful unverified read under `node`.
    fn read_first(&self, node: &Node, offset: u64, size: usize) -> Result<Vec<u8>, ReadError> {
        let mut last = ReadError::NoMember;
        for (_, c) in self.read_candidates(node, offset, size) {
            match c {
                Ok(b) => return Ok(b),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Read the raw `psize` bytes behind one DVA without verification
    /// (first copy that reads). Gang pointers are followed.
    pub fn read_dva(&self, dva: &Dva, psize: usize) -> Result<(Vec<u8>, usize), ReadError> {
        let top = self
            .tops
            .get(&dva.vdev)
            .ok_or(ReadError::UnknownVdev(dva.vdev))?;
        if dva.gang {
            return Err(ReadError::Gang("use read_block for gang pointers".into()));
        }
        for (device, c) in self.read_candidates(top, dva.offset, psize) {
            if let Ok(b) = c {
                return Ok((b, device.unwrap_or(usize::MAX)));
            }
        }
        Err(ReadError::NoMember)
    }

    /// Read the columns of one raidz stripe: parity (None when unreadable),
    /// data (zero-filled where lost), lost data column indices, and the map.
    /// The parity rows holding `size` bytes at `offset` under a raidz or
    /// dRAID node, each read column by column.
    fn read_rows(&self, node: &Node, offset: u64, size: usize) -> Vec<Columns> {
        match node {
            Node::Raidz {
                nparity,
                ashift,
                children,
            } => {
                let unit = 1u64 << ashift;
                let padded = (size as u64).div_ceil(unit) * unit;
                let m = raidz::map(offset, padded, *ashift, children.len() as u64, *nparity);
                vec![self.read_row(m, children, None)]
            }
            Node::Draid {
                cfg,
                ashift,
                children,
            } => {
                let unit = 1u64 << ashift;
                let padded = (size as u64).div_ceil(unit) * unit;
                cfg.map(offset, padded, *ashift)
                    .into_iter()
                    .map(|m| self.read_row(m, children, Some(cfg)))
                    .collect()
            }
            _ => Vec::new(),
        }
    }

    /// Read every column of one row. A distributed spare column is read
    /// from the child the dRAID permutation assigns to it at that offset.
    fn read_row(&self, m: raidz::Map, children: &[Node], cfg: Option<&draid::Config>) -> Columns {
        let column = |c: &raidz::Column| -> Result<Vec<u8>, ReadError> {
            if c.size == 0 {
                // An empty column (dRAID short row): nothing on disk, but
                // it keeps its place in the parity equations.
                return Ok(Vec::new());
            }
            let mut devidx = c.devidx;
            for _ in 0..children.len() {
                let child = children
                    .get(devidx as usize)
                    .ok_or(ReadError::UnknownVdev(devidx as u32))?;
                match (child, cfg) {
                    (Node::Dspare { spare_id }, Some(cfg)) => {
                        let target = cfg.spare_child(*spare_id, c.offset);
                        trace!(
                            "draid",
                            "    dspare#{spare_id} at {:#x} -> child {target}",
                            c.offset
                        );
                        devidx = target;
                    }
                    (Node::Dspare { .. }, None) => {
                        return Err(ReadError::Unsupported("dspare outside dRAID".into()))
                    }
                    _ => return self.read_first(child, c.offset, c.size as usize),
                }
            }
            Err(ReadError::Unsupported(
                "distributed spare chain loops".into(),
            ))
        };
        let mut parity = Vec::with_capacity(m.nparity);
        for c in m.parity() {
            parity.push(match column(c) {
                Ok(b) => Some(b),
                Err(e) => {
                    trace!("raidz", "    parity column dev{}: {e}", c.devidx);
                    None
                }
            });
        }
        let mut data = Vec::with_capacity(m.acols.saturating_sub(m.nparity));
        let mut lost = Vec::new();
        for (i, c) in m.data().iter().enumerate() {
            match column(c) {
                Ok(b) => data.push(b),
                Err(e) => {
                    trace!("raidz", "    data column {i} dev{}: {e}", c.devidx);
                    lost.push(i);
                    data.push(vec![0u8; c.size as usize]);
                }
            }
        }
        (parity, data, lost, m)
    }

    /// Read and verify the `psize` bytes behind a DVA on a raidz or dRAID
    /// node, reconstructing missing columns from parity and, if the
    /// checksum still fails, distrusting every combination of up to
    /// `nparity` readable columns of one row — parity rows and data
    /// columns alike — as `vdev_raidz_combrec` does.
    fn read_striped(
        &self,
        node: &Node,
        dva: &Dva,
        bp: &BlkPtr,
        attempts: &mut Vec<Attempt>,
        dva_index: usize,
    ) -> Result<(Vec<u8>, Verify), ReadError> {
        let psize = bp.psize as usize;
        let mut rows = self.read_rows(node, dva.offset, psize);
        let label = match node {
            Node::Draid { cfg, .. } => format!("draid{}", cfg.nparity),
            Node::Raidz { nparity, .. } => format!("raidz{nparity}"),
            _ => "?".into(),
        };
        for (r, (parity, _, _, m)) in rows.iter().enumerate() {
            trace!(
                "raidz",
                "  dva {dva_index}: {label} row {r} -> {} cols ({} parity, {} big, nskip {}, {} parity readable): {}",
                m.acols,
                m.nparity,
                m.bigcols,
                m.nskip,
                parity.iter().filter(|p| p.is_some()).count(),
                m.cols[..m.acols]
                    .iter()
                    .map(|c| format!("dev{}@{:#x}+{}", c.devidx, c.offset, c.size))
                    .collect::<Vec<_>>()
                    .join(" ")
            );
        }
        let assemble = |rows: &[Columns]| -> Vec<u8> {
            let mut out: Vec<u8> = rows
                .iter()
                .flat_map(|(_, data, _, _)| data.iter().flatten().copied())
                .collect();
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
        for (parity, data, lost, _) in rows.iter_mut() {
            let available = parity.iter().filter(|p| p.is_some()).count();
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
                raidz::reconstruct(data, parity, lost)
                    .map_err(|e| ReadError::Unrecoverable(format!("reconstruct: {e:?}")))?;
                trace!(
                    "raidz",
                    "    reconstructed missing data column(s) {lost:?} from parity"
                );
            }
        }
        let raw = assemble(&rows);
        let v = self.verify(bp, &raw);
        let any_lost = rows.iter().any(|(_, _, lost, _)| !lost.is_empty());
        trace!(
            "raidz",
            "    checksum after direct read{}: {v:?}",
            if any_lost { " + reconstruction" } else { "" }
        );
        record(attempts, Ok(v));
        if v != Verify::Mismatch {
            return Ok((raw, v));
        }
        // Combinatorial reconstruction, one row at a time (the other rows
        // are kept as read).
        for r in 0..rows.len() {
            let (parity, data, lost, _) = &rows[r];
            let available = parity.iter().filter(|p| p.is_some()).count();
            let budget = available - lost.len();
            let readable_parity: Vec<usize> =
                (0..parity.len()).filter(|&i| parity[i].is_some()).collect();
            let readable_data: Vec<usize> = (0..data.len()).filter(|i| !lost.contains(i)).collect();
            let columns: Vec<(bool, usize)> = readable_parity
                .iter()
                .map(|&i| (true, i))
                .chain(readable_data.iter().map(|&i| (false, i)))
                .collect();
            for k in 1..=budget.min(columns.len()) {
                for combo in combinations(columns.len(), k) {
                    let mut bad_parity: Vec<usize> = Vec::new();
                    let mut missing = lost.clone();
                    for &j in &combo {
                        match columns[j] {
                            (true, i) => bad_parity.push(i),
                            (false, i) => missing.push(i),
                        }
                    }
                    missing.sort_unstable();
                    let usable: Vec<Option<Vec<u8>>> = parity
                        .iter()
                        .enumerate()
                        .map(|(i, p)| {
                            if bad_parity.contains(&i) {
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
                    let mut work = rows.clone();
                    if raidz::reconstruct(&mut work[r].1, &usable, &missing).is_err() {
                        continue;
                    }
                    let raw = assemble(&work);
                    let v = self.verify(bp, &raw);
                    if v != Verify::Mismatch {
                        trace!(
                            "raidz",
                            "    combinatorial reconstruction succeeded (row {r}): data columns {missing:?} rebuilt, parity rows {bad_parity:?} distrusted"
                        );
                        record(attempts, Ok(v));
                        return Ok((raw, v));
                    }
                }
            }
        }
        trace!(
            "raidz",
            "    no reconstruction produced a block matching its checksum"
        );
        Err(ReadError::AllCopiesBad)
    }

    /// Read and verify the psize bytes of `bp` behind a non-gang `dva`
    /// under `node`: leaves verify their copy, mirrors try each child,
    /// raidz reconstructs.
    fn read_verified(
        &self,
        node: &Node,
        dva: &Dva,
        bp: &BlkPtr,
        attempts: &mut Vec<Attempt>,
        i: usize,
    ) -> Result<(Vec<u8>, Verify), ReadError> {
        match node {
            Node::Leaf { device, .. } => {
                let read = self.read_leaf(*device, dva.offset, bp.psize as usize);
                match read {
                    Err(e) => {
                        trace!("zio", "  dva {i} leaf {device:?}: {e}");
                        attempts.push(Attempt {
                            dva: i,
                            vdev: dva.vdev,
                            device: *device,
                            result: Err(e.clone()),
                        });
                        Err(e)
                    }
                    Ok(raw) => {
                        let v = self.verify(bp, &raw);
                        trace!(
                            "zio",
                            "  dva {i} device {device:?} @ {:#x}: checksum {v:?}",
                            LABEL_START_SIZE + dva.offset
                        );
                        if v == Verify::Mismatch {
                            trace!(
                                "zio",
                                "    expected {:x?} computed {:x?}; first bytes:\n{}",
                                bp.cksum,
                                zfs_ondisk::checksum::compute_salted(
                                    bp.checksum,
                                    &raw,
                                    bp.endian,
                                    self.salt.get().as_ref()
                                )
                                .unwrap_or([0; 4]),
                                hexdump(&raw, LABEL_START_SIZE + dva.offset, 64)
                            );
                        }
                        attempts.push(Attempt {
                            dva: i,
                            vdev: dva.vdev,
                            device: *device,
                            result: Ok(v),
                        });
                        match v {
                            Verify::Ok | Verify::NotChecked => Ok((raw, v)),
                            Verify::Unsupported => Err(ReadError::ChecksumUnsupported),
                            Verify::Mismatch => Err(ReadError::AllCopiesBad),
                        }
                    }
                }
            }
            Node::Mirror { children } => {
                let mut last = ReadError::NoMember;
                for child in children {
                    match self.read_verified(child, dva, bp, attempts, i) {
                        Ok(x) => return Ok(x),
                        Err(e) => last = e,
                    }
                }
                Err(last)
            }
            Node::Raidz { .. } | Node::Draid { .. } => {
                self.read_striped(node, dva, bp, attempts, i)
            }
            Node::Dspare { .. } => Err(ReadError::Unsupported(
                "distributed spare read outside its dRAID".into(),
            )),
            Node::Unsupported { kind } => {
                let e = ReadError::Unsupported(kind.clone());
                attempts.push(Attempt {
                    dva: i,
                    vdev: dva.vdev,
                    device: None,
                    result: Err(e.clone()),
                });
                Err(e)
            }
        }
    }

    /// Read the raw bytes behind a gang pointer: the 512-byte header at
    /// the DVA (verified against the pointer's identity and birth, trying
    /// every copy), then each child pointer in order, concatenated;
    /// children may be gang blocks themselves.
    fn read_gang(
        &self,
        node: &Node,
        dva: &Dva,
        bp: &BlkPtr,
        depth: usize,
    ) -> Result<Vec<u8>, ReadError> {
        if depth > 8 {
            return Err(ReadError::Gang("nesting deeper than 8".into()));
        }
        let mut header = None;
        let mut last = ReadError::NoMember;
        for (device, candidate) in self.read_candidates(node, dva.offset, blkptr::GANG_HEADER_SIZE)
        {
            match candidate {
                Ok(buf) => {
                    // Verifier: DVA[0] and the physical birth. A gang
                    // header of an encrypted dataset carries the folded
                    // checksum.
                    let status = if bp.uses_crypt() && bp.object_type != ot::OBJSET {
                        zfs_ondisk::checksum::verify_gang_header_crypt(
                            &buf,
                            u64::from(bp.dva[0].vdev),
                            bp.dva[0].offset,
                            bp.physical_birth_or_logical(),
                        )
                    } else {
                        zfs_ondisk::checksum::verify_gang_header(
                            &buf,
                            u64::from(bp.dva[0].vdev),
                            bp.dva[0].offset,
                            bp.physical_birth_or_logical(),
                        )
                    };
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
            let mut attempts = Vec::new();
            out.extend_from_slice(&self.read_raw_verified(child, depth + 1, &mut attempts)?);
        }
        out.truncate(bp.psize as usize);
        Ok(out)
    }

    /// Read the psize bytes of `bp` from any copy that verifies, resolving
    /// gang pointers; no decompression.
    fn read_raw_verified(
        &self,
        bp: &BlkPtr,
        depth: usize,
        attempts: &mut Vec<Attempt>,
    ) -> Result<Vec<u8>, ReadError> {
        let mut last = ReadError::NoMember;
        for (i, dva) in bp.dva.iter().enumerate() {
            if dva.is_empty() {
                continue;
            }
            let Some(top) = self.tops.get(&dva.vdev) else {
                last = ReadError::UnknownVdev(dva.vdev);
                attempts.push(Attempt {
                    dva: i,
                    vdev: dva.vdev,
                    device: None,
                    result: Err(last.clone()),
                });
                continue;
            };
            if dva.gang {
                match self.read_gang(top, dva, bp, depth) {
                    Ok(raw) => {
                        let v = self.verify(bp, &raw);
                        attempts.push(Attempt {
                            dva: i,
                            vdev: dva.vdev,
                            device: None,
                            result: Ok(v),
                        });
                        match v {
                            Verify::Ok | Verify::NotChecked => return Ok(raw),
                            Verify::Mismatch => last = ReadError::AllCopiesBad,
                            Verify::Unsupported => last = ReadError::ChecksumUnsupported,
                        }
                    }
                    Err(e) => {
                        trace!("gang", "  dva {i}: {e}");
                        attempts.push(Attempt {
                            dva: i,
                            vdev: dva.vdev,
                            device: None,
                            result: Err(e.clone()),
                        });
                        last = e;
                    }
                }
                continue;
            }
            match self.read_verified(top, dva, bp, attempts, i) {
                Ok((raw, _)) => return Ok(raw),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Read, verify and decompress the block behind `bp`.
    ///
    /// Copies are tried in DVA order and, within a mirror, in child order.
    /// The first copy whose checksum verifies (or that cannot be checked
    /// because the algorithm is `off`) is decompressed. `allow_unverified`
    /// is reserved for algorithms this build cannot verify.
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
        let raw = self.read_raw_verified(bp, 0, &mut attempts);
        let _ = allow_unverified;
        match raw {
            Ok(_) if bp.is_encrypted() && !self.has_keys() => Err(ReadError::Encrypted),
            Ok(raw) => {
                let raw = if bp.is_encrypted() {
                    let keys = self.keys.borrow();
                    let keys = keys.as_ref().expect("checked");
                    match decrypt_block(keys, bp, &raw) {
                        Ok(p) => {
                            trace!("zio", "    decrypted {} bytes ({})", p.len(), keys.suite);
                            p
                        }
                        Err(e) => {
                            trace!("zio", "    decrypt failed: {e}");
                            return Err(ReadError::Crypt(e));
                        }
                    }
                } else {
                    raw
                };
                let verify = attempts
                    .iter()
                    .rev()
                    .find_map(|a| a.result.as_ref().ok().copied())
                    .unwrap_or(Verify::NotChecked);
                let data = match decompress(bp.compression, &raw, lsize) {
                    Ok(d) => d,
                    Err(e) => {
                        trace!(
                            "zio",
                            "    decompress {} failed: {e}; first bytes:\n{}",
                            bp.compression.name(),
                            hexdump(&raw, 0, 64)
                        );
                        return Err(ReadError::Decompress(e));
                    }
                };
                Ok(Block {
                    data,
                    verify,
                    attempts,
                })
            }
            Err(e) => {
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
                Err(e)
            }
        }
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
    fn a_member_that_starts_later_is_read_from_its_base() {
        // Member 0 was found 1 MiB into what was opened — a partition
        // whose table was rewritten. Its copy is intact, member 1's is
        // damaged, so the read succeeds only if the base is honoured.
        let pool = Pool::mirror("tank", 0x77, 12).txgs(&[(100, 1)]);
        let (raw, bp) = compressed();
        let mut m0 = pool.member_image(0, SIZE);
        let mut m1 = pool.member_image(1, SIZE);
        write_at_dva(&mut m0, 0x10000, &raw);
        write_at_dva(&mut m1, 0x10000, &raw);
        m1[(LABEL_START_SIZE + 0x10000) as usize + 7] ^= 0xff;
        let (_, assembly) = reader_over(vec![Some(m0.clone()), Some(m1.clone())]);

        let base = 1024 * 1024u64;
        let mut shifted = vec![0x5au8; base as usize];
        shifted.extend_from_slice(&m0);
        let sources = vec![Some(MemSource::new(shifted)), Some(MemSource::new(m1))];

        // Without the base, member 0 reads garbage and only the damaged
        // copy is left: the block does not verify.
        let blind = PoolReader::new(&assembly, as_dyn(&sources));
        assert!(matches!(
            blind.read_block(&bp, false),
            Err(ReadError::AllCopiesBad)
        ));

        let reader = PoolReader::new(&assembly, as_dyn(&sources)).with_base_offsets(&[base, 0]);
        let block = reader.read_block(&bp, false).unwrap();
        assert_eq!(block.data, payload());
        assert_eq!(block.verify, Verify::Ok);
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
