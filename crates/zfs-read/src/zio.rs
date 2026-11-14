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
use zfs_ondisk::indirect::{Mapping, Unmapped};
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
        // The geometry comes from a label or a hand-written layout, and
        // either can say anything; what the layout code is handed must be
        // a layout ZFS could have made. `raidz2` over two children leaves
        // no data column, and an ashift of 63 shifts a sector out of the
        // word: both reached a division or a shift that does not exist.
        let width = tree.children.len() as u64;
        // Wider than any raidz or dRAID can be made: the label says how
        // many children, and combinatorial reconstruction would try every
        // subset of them.
        if matches!(tree.kind.as_str(), "raidz" | "draid") && width > MAX_PARITY_WIDTH {
            return Node::Unsupported {
                kind: format!(
                    "{} of {width} children (at most {MAX_PARITY_WIDTH})",
                    tree.kind
                ),
            };
        }
        if matches!(tree.kind.as_str(), "raidz" | "draid")
            && !(ASHIFT_MIN..=ASHIFT_MAX).contains(&ashift)
        {
            return Node::Unsupported {
                kind: format!(
                    "{} with ashift {ashift} (ZFS uses {ASHIFT_MIN}..={ASHIFT_MAX})",
                    tree.kind
                ),
            };
        }
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
            "raidz" => match tree.nparity.unwrap_or(1) {
                nparity @ 1..=3 if nparity < width => Node::Raidz {
                    nparity,
                    ashift,
                    children,
                },
                nparity => Node::Unsupported {
                    kind: format!("raidz{nparity} of {width} children (parity 1 to 3, and fewer than the children)"),
                },
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

/// The sector sizes a vdev can have: `ASHIFT_MIN` and `ASHIFT_MAX` of
/// OpenZFS's `vdev_impl.h`.
/// The most children a raidz or dRAID vdev has: dRAID's permutation maps
/// stop at 255, and so does what `zpool create` makes of a raidz.
const MAX_PARITY_WIDTH: u64 = 255;

/// Reconstructions combinatorial repair tries for one block before it
/// gives up: every subset of up to three columns of a 40-wide raidz, and
/// a bound on what a forged block can cost — for the block, however many
/// rows of a dRAID it spans.
const MAX_COMBREC_TRIES: usize = 10_000;

/// Bytes of block combinatorial repair checks against the checksum, for
/// one block: what bounds the tries of a large block, each of which is
/// the whole block assembled and checksummed again. 16 GiB is every
/// subset of up to three columns of a 12-wide raidz3 at 16 MiB.
const MAX_COMBREC_BYTES: u64 = 16 << 30;

/// How far a row's combinatorial tries may go, `spent` of `max` gone and
/// `rows_left` rows to try, this one among them: its part of what is
/// left, and what the rows before it did not use.
fn row_share(spent: usize, max: usize, rows_left: usize) -> usize {
    spent + max.saturating_sub(spent) / rows_left.max(1)
}

const ASHIFT_MIN: u32 = 9;
const ASHIFT_MAX: u32 = 16;

/// What a DVA's top-level vdev id resolves to.
enum Where<'n> {
    /// A vdev the labels describe.
    Top(&'n Node),
    /// A vdev that was removed, and the mapping it left behind.
    Removed(Rc<Mapping>),
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
    /// `ashift` of each top-level vdev, by id: what a gang header's size
    /// follows once the pool has `dynamic_gang_header` active.
    top_ashift: BTreeMap<u32, u32>,
    /// `com.klarasystems:dynamic_gang_header` is active (OpenZFS 2.4):
    /// a gang header fills the smallest allocation its top-level vdev
    /// makes instead of one 512-byte sector, and holds as many child
    /// pointers as fit. Without it, every header is 512 bytes.
    dynamic_gang: bool,
    /// How many leaf reads each device has served. Used when deciding
    /// whether a member really contributed to what was read (F-62).
    reads: RefCell<Vec<u64>>,
    /// The device refusal that stopped the run, once one has (SPEC
    /// F-33, N-10): every block read after it answers with this.
    medium_stop: RefCell<Option<ReadError>>,
    /// Metadata blocks already read, by device, offset and size, so
    /// that no address on a device is asked for twice (SPEC N-10): the
    /// MOS is walked through the same few blocks many times over.
    /// Bounded — small blocks only, and dropped whole past a budget —
    /// so that memory stays bounded on any pool (N-03).
    cache: RefCell<ReadCache>,
    /// How many block checksums have failed on the data as first read.
    /// Zero on a healthy pool read through the right topology; a wrong
    /// member order shows up here before anything else does (F-66).
    mismatches: Cell<u64>,
    /// Pool checksum salt once the MOS object directory has been read.
    salt: Cell<Option<Salt>>,
    /// Keys of the encrypted dataset currently being read, if any.
    keys: RefCell<Option<DatasetKeys>>,
    /// Mappings of top-level vdevs that were removed, by vdev id (F-69).
    /// Filled from the MOS configuration once it has been read; empty
    /// on a pool that never had a vdev removed, which is most of them.
    removed: RefCell<BTreeMap<u32, Rc<Mapping>>>,
}

/// Why a block could not be produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    /// The DVA names a top-level vdev the labels do not describe.
    UnknownVdev(u32),
    /// The DVA names a vdev that was removed, and the mapping it left
    /// behind does not account for this range (SPEC F-69).
    Unmapped(u32, Unmapped),
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
    /// A device refused a read (SPEC F-33, N-10). `stop` says whether
    /// the run's medium policy stops here; the text is the incident.
    Medium {
        /// Whether this refusal stops the run.
        stop: bool,
        /// The incident, as the ledger recorded it.
        what: String,
    },
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
            ReadError::Unmapped(v, gap) => {
                write!(f, "removed top-level vdev {v}: {gap}")
            }
            ReadError::NoMember => write!(f, "no present member holds this copy"),
            ReadError::Unsupported(k) => write!(f, "top-level vdev type {k} not supported yet"),
            ReadError::Gang(e) => write!(f, "gang block: {e}"),
            ReadError::Unrecoverable(e) => write!(f, "not recoverable: {e}"),
            ReadError::Io(e) => write!(f, "I/O error: {e}"),
            ReadError::Medium { what, .. } => write!(f, "{what}"),
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

/// What a salvage comes to: the bytes, with each refused sector zeroed,
/// and those sectors as `(start, len)` ranges relative to the first byte.
pub type Salvage = (Vec<u8>, Vec<(u64, u64)>);

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

/// Of two reasons a copy could not be had, the one worth reporting: a
/// member that is not there says nothing about the copy, so a failure
/// on a member that *is* there — an I/O error, a checksum that did not
/// match — is kept over it. Otherwise the later one wins, as before.
/// Blocks read from the members, kept so that the same address is not
/// asked for again (SPEC N-10). Only blocks up to [`ReadCache::MAX_ENTRY`]
/// are kept — the metadata the walk keeps coming back to, not a
/// volume's data, which is read once anyway — and the whole cache is
/// dropped when it passes [`ReadCache::BUDGET`], so the memory it holds
/// is bounded on any pool (N-03).
#[derive(Default)]
struct ReadCache {
    map: std::collections::HashMap<(usize, u64, usize), Rc<Vec<u8>>>,
    bytes: usize,
}

impl ReadCache {
    /// The largest block kept: a MOS block is 16 KiB by default and an
    /// indirect block 128 KiB.
    const MAX_ENTRY: usize = 128 << 10;
    /// Kept bytes past which the cache starts over.
    const BUDGET: usize = 64 << 20;

    fn get(&self, device: usize, at: u64, size: usize) -> Option<Vec<u8>> {
        self.map.get(&(device, at, size)).map(|b| b.to_vec())
    }

    fn put(&mut self, device: usize, at: u64, bytes: &[u8]) {
        if bytes.len() > Self::MAX_ENTRY {
            return;
        }
        if self.bytes + bytes.len() > Self::BUDGET {
            self.map.clear();
            self.bytes = 0;
        }
        self.bytes += bytes.len();
        self.map
            .insert((device, at, bytes.len()), Rc::new(bytes.to_vec()));
    }
}

fn more_telling(so_far: ReadError, next: ReadError) -> ReadError {
    match (&so_far, &next) {
        // A medium's refusal is what the operator must hear about,
        // whatever else went wrong beside it.
        (ReadError::Medium { .. }, _) => so_far,
        (_, ReadError::Medium { .. }) => next,
        (ReadError::NoMember, _) => next,
        (_, ReadError::NoMember) => so_far,
        _ => next,
    }
}

/// `ranges` with `[from, to)` taken out of them.
fn cut(ranges: &[(u64, u64)], from: u64, to: u64) -> Vec<(u64, u64)> {
    let mut out = Vec::with_capacity(ranges.len());
    for &(s, l) in ranges {
        let e = s.saturating_add(l);
        if e <= from || s >= to {
            out.push((s, l));
            continue;
        }
        if s < from {
            out.push((s, from - s));
        }
        if e > to {
            out.push((to, e - to));
        }
    }
    out
}

/// Sorted ranges with the adjacent and overlapping ones joined.
fn merge_ranges(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (s, l) in ranges {
        match out.last_mut() {
            Some((ps, pl)) if *ps + *pl >= s => *pl = (*pl).max(s + l - *ps),
            _ => out.push((s, l)),
        }
    }
    out
}

/// Lay `from` under `into`: every byte `into` lost and `from` has is
/// taken from `from`, and what is still lost is what both lost.
fn fill_from(into: &mut Salvage, from: &Salvage) {
    let (data, bad) = into;
    let (other, other_bad) = from;
    let mut left = Vec::new();
    for &(s, l) in bad.iter() {
        let end = (s + l).min(data.len() as u64).min(other.len() as u64);
        let mut pos = s;
        for &(os, ol) in other_bad.iter() {
            let oe = os + ol;
            if oe <= pos {
                continue;
            }
            if os >= end {
                break;
            }
            if os > pos {
                data[pos as usize..os as usize].copy_from_slice(&other[pos as usize..os as usize]);
            }
            let held = oe.min(end);
            left.push((os.max(pos), held - os.max(pos)));
            pos = held;
        }
        if pos < end {
            data[pos as usize..end as usize].copy_from_slice(&other[pos as usize..end as usize]);
        }
        if end < s + l {
            left.push((end.max(s), s + l - end.max(s)));
        }
    }
    *bad = merge_ranges(left);
}

impl<'a> PoolReader<'a> {
    /// Build a reader for `pool` over `devices`, indexed exactly like the
    /// scans that produced the assembly (`None` for unreadable devices).
    pub fn new(pool: &PoolAssembly, devices: Vec<Option<&'a dyn BlockSource>>) -> Self {
        let mut top_ashift = BTreeMap::new();
        let tops = pool
            .tops
            .iter()
            .map(|t| {
                let ashift = t.ashift.and_then(|a| u32::try_from(a).ok()).unwrap_or(9);
                // Every top-level vdev, not only raidz and dRAID: a mirror
                // or a single disk with an ashift of 50 made the size of a
                // dynamic gang header a petabyte, allocated at once.
                if !(ASHIFT_MIN..=ASHIFT_MAX).contains(&ashift) {
                    top_ashift.insert(t.id as u32, ASHIFT_MIN);
                    let node = Node::Unsupported {
                        kind: format!(
                            "{} with ashift {ashift} (ZFS uses {ASHIFT_MIN}..={ASHIFT_MAX})",
                            t.kind
                        ),
                    };
                    trace!("zio", "top-level vdev {}: {}", t.id, node.describe());
                    return (t.id as u32, node);
                }
                top_ashift.insert(t.id as u32, ashift);
                let node = Node::from_tree(&t.tree, &t.members, ashift);
                trace!("zio", "top-level vdev {}: {}", t.id, node.describe());
                (t.id as u32, node)
            })
            .collect();
        let dynamic_gang = pool
            .features_for_read
            .iter()
            .any(|f| f == "com.klarasystems:dynamic_gang_header");
        if dynamic_gang {
            trace!(
                "zio",
                "dynamic_gang_header is active: gang headers are sized by their vdev"
            );
        }
        let bases = vec![0u64; devices.len()];
        let reads = RefCell::new(vec![0u64; devices.len()]);
        PoolReader {
            devices,
            bases,
            reads,
            medium_stop: RefCell::new(None),
            cache: RefCell::new(ReadCache::default()),
            mismatches: Cell::new(0),
            tops,
            top_ashift,
            dynamic_gang,
            salt: Cell::new(None),
            keys: RefCell::new(None),
            removed: RefCell::new(BTreeMap::new()),
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

    /// How many checksums have failed on data as first read.
    pub fn mismatches(&self) -> u64 {
        self.mismatches.get()
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

    /// Record the mapping a removed top-level vdev left behind, so that
    /// pointers still naming it can be translated (SPEC F-69).
    pub fn set_removed_mapping(&self, vdev: u32, mapping: Mapping) {
        trace!(
            "indirect",
            "top-level vdev {vdev} was removed: {} mapping entry(ies), {} byte(s) mapped",
            mapping.len(),
            mapping.mapped_bytes()
        );
        self.removed.borrow_mut().insert(vdev, Rc::new(mapping));
    }

    /// Removed top-level vdevs and how many mapping entries each has.
    pub fn removed_vdevs(&self) -> Vec<(u32, usize)> {
        self.removed
            .borrow()
            .iter()
            .map(|(v, m)| (*v, m.len()))
            .collect()
    }

    /// Where a DVA's vdev id leads.
    ///
    /// A removed vdev wins over a top-level vdev of the same id built
    /// from the labels. The mapping comes from the configuration object
    /// of the MOS being read, written at the transaction group this
    /// read is working from; a label that still describes that vdev was
    /// last written before it was removed and is the older account.
    fn locate_vdev(&self, vdev: u32) -> Option<Where<'_>> {
        if let Some(m) = self.removed.borrow().get(&vdev) {
            return Some(Where::Removed(Rc::clone(m)));
        }
        self.tops.get(&vdev).map(Where::Top)
    }

    /// Every independent, unverified way to read `size` bytes at
    /// `offset` of top-level vdev `vdev`, following the mapping of a
    /// removed one.
    fn candidates_on(
        &self,
        vdev: u32,
        offset: u64,
        size: usize,
        depth: usize,
    ) -> Vec<RawCandidate> {
        match self.locate_vdev(vdev) {
            Some(Where::Top(node)) => self.read_candidates(node, offset, size),
            Some(Where::Removed(m)) => self.remapped_candidates(vdev, &m, offset, size, depth),
            None => vec![(None, Err(ReadError::UnknownVdev(vdev)))],
        }
    }

    /// The same, for a range that lives on a vdev that was removed: the
    /// mapping says which pieces of it went where, and the pieces are
    /// read in order and joined.
    ///
    /// A piece may land on a vdev that was itself removed later, so this
    /// recurses; `depth` bounds a mapping that points at itself.
    fn remapped_candidates(
        &self,
        vdev: u32,
        mapping: &Mapping,
        offset: u64,
        size: usize,
        depth: usize,
    ) -> Vec<RawCandidate> {
        if depth > 8 {
            return vec![(
                None,
                Err(ReadError::Unrecoverable(
                    "indirect mappings nested deeper than 8".into(),
                )),
            )];
        }
        let segments = match mapping.remap(offset, size as u64) {
            Ok(s) => s,
            Err(gap) => return vec![(None, Err(ReadError::Unmapped(vdev, gap)))],
        };
        trace!(
            "indirect",
            "vdev {vdev} {offset:#x}+{size} -> {}",
            segments
                .iter()
                .map(|s| format!("vdev {} {:#x}+{}", s.vdev, s.offset, s.size))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let per: Vec<Vec<RawCandidate>> = segments
            .iter()
            .map(|s| self.candidates_on(s.vdev, s.offset, s.size as usize, depth + 1))
            .collect();
        // One way per copy the destinations offer: way k takes each
        // segment's k-th candidate, so a piece that landed on a mirror
        // still offers each of its sides rather than only the first.
        //
        // A piece that landed on a raidz or dRAID offers one way, which
        // is that vdev's ordinary read with parity reconstruction where
        // columns are lost. What it does not get is the combinatorial
        // search that a block read directly from such a vdev falls back
        // on when the checksum still fails afterwards: that works a
        // whole block at a time, and here a block may be several pieces
        // from several places. So a remapped block is recovered from a
        // clean parity failure but not from a silently bad column.
        let ways = per.iter().map(Vec::len).max().unwrap_or(0);
        (0..ways)
            .map(|k| {
                let mut out = Vec::with_capacity(size);
                for c in &per {
                    match c.get(k.min(c.len().saturating_sub(1))) {
                        Some((_, Ok(b))) => out.extend_from_slice(b),
                        Some((_, Err(e))) => return (None, Err(e.clone())),
                        None => return (None, Err(ReadError::NoMember)),
                    }
                }
                (None, Ok(out))
            })
            .collect()
    }

    /// Verify `raw` against `bp` with the pool salt when one is known.
    pub fn verify(&self, bp: &BlkPtr, raw: &[u8]) -> Verify {
        let salt = self.salt.get();
        let crypt = bp.uses_crypt() && bp.object_type != ot::OBJSET;
        let v = verify_block(bp.checksum, raw, bp.endian, &bp.cksum, salt.as_ref(), crypt);
        if v == Verify::Mismatch {
            self.mismatches.set(self.mismatches.get() + 1);
        }
        v
    }

    /// The error a leaf read failed with, as the reader carries it. A
    /// device's refusal (SPEC N-10) becomes [`ReadError::Medium`], and
    /// one that stops the run is remembered: from then on every block
    /// read answers with it, before any device is asked anything more.
    fn io_error(&self, e: std::io::Error) -> ReadError {
        match zvolrescue_io::medium::incident_of(&e) {
            Some(i) => {
                let err = ReadError::Medium {
                    stop: i.stopped,
                    what: e.to_string(),
                };
                if i.stopped {
                    let mut stop = self.medium_stop.borrow_mut();
                    if stop.is_none() {
                        *stop = Some(err.clone());
                    }
                }
                err
            }
            None => ReadError::Io(e.to_string()),
        }
    }

    /// The refusal that stopped the run, once one has (SPEC F-33).
    pub fn medium_stop(&self) -> Option<ReadError> {
        self.medium_stop.borrow().clone()
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
        if let Some(stop) = self.medium_stop() {
            return Err(stop);
        }
        let at = base + LABEL_START_SIZE + offset;
        if let Some(hit) = self.cache.borrow().get(index, at, size) {
            return Ok(hit);
        }
        let mut buf = vec![0u8; size];
        dev.read_at(at, &mut buf).map_err(|e| self.io_error(e))?;
        self.cache.borrow_mut().put(index, at, &buf);
        Ok(buf)
    }

    /// [`read_leaf`](Self::read_leaf), reading around the sectors the
    /// member refuses (SPEC F-33): the bytes, with each refused sector
    /// zeroed, and those sectors as ranges relative to `offset`.
    fn salvage_leaf(
        &self,
        device: Option<usize>,
        offset: u64,
        size: usize,
    ) -> Result<Salvage, ReadError> {
        let index = device.ok_or(ReadError::NoMember)?;
        let dev = self
            .devices
            .get(index)
            .copied()
            .flatten()
            .ok_or(ReadError::NoMember)?;
        let base = self.bases.get(index).copied().unwrap_or(0);
        let at = base + LABEL_START_SIZE + offset;
        let cached = self.cache.borrow().get(index, at, size);
        if cached.is_none() && dev.kind() == zvolrescue_io::medium::Kind::Device {
            // A device was asked for this block once already, by the read
            // that failed; it is not asked again (N-10).
            return Err(ReadError::Unsupported(
                "a device is not asked for a block twice".into(),
            ));
        }
        if let Some(n) = self.reads.borrow_mut().get_mut(index) {
            *n += 1;
        }
        if let Some(stop) = self.medium_stop() {
            return Err(stop);
        }
        if let Some(hit) = cached {
            return Ok((hit, Vec::new()));
        }
        let mut buf = vec![0u8; size];
        let bad = dev
            .read_at_salvaging(at, &mut buf)
            .map_err(|e| self.io_error(e))?;
        if bad.is_empty() {
            self.cache.borrow_mut().put(index, at, &buf);
        }
        Ok((buf, bad))
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
                let (children, cfg) = match node {
                    Node::Raidz { children, .. } => (children.as_slice(), None),
                    Node::Draid { children, cfg, .. } => (children.as_slice(), Some(cfg.as_ref())),
                    _ => unreachable!("the arm matched raidz or draid"),
                };
                let mut rows = self.read_rows(node, offset, size);
                let mut out = Vec::with_capacity(size);
                for row in rows.iter_mut() {
                    // A row that lost a column needs its parity; a row
                    // that read whole does not, and never fetches it.
                    if !row.2.is_empty() {
                        self.read_parity(row, children, cfg);
                    }
                    let (parity, data, lost, _) = row;
                    if !lost.is_empty() {
                        if let Err(e) = raidz::reconstruct(data, parity, lost) {
                            return vec![(
                                None,
                                Err(ReadError::Unrecoverable(format!("reconstruct: {e:?}"))),
                            )];
                        }
                    }
                    for column in data.iter() {
                        out.extend_from_slice(column);
                    }
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
        if dva.gang {
            return Err(ReadError::Gang("use read_block for gang pointers".into()));
        }
        let mut last = ReadError::NoMember;
        for (device, c) in self.candidates_on(dva.vdev, dva.offset, psize, 0) {
            match c {
                Ok(b) => return Ok((b, device.unwrap_or(usize::MAX))),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// What is left of one DVA on members with bad sectors (SPEC F-33):
    /// the `psize` bytes behind it read around every sector a member
    /// refuses, with the sectors no member gives zeroed and named as
    /// ranges relative to the block's start.
    ///
    /// The sides of a mirror fill each other: a sector one side refused
    /// is taken from a side that read it. Under raidz or dRAID a refused
    /// sector of a column is rebuilt from the same sector of the other
    /// columns and the parity, wherever they hold it. Before, the mirror
    /// side that lost least was kept with its holes, though the other
    /// side had them, and a raidz block was not salvaged at all: a
    /// column with one refused sector was lost whole, two such columns
    /// on a raidz1 lost the block, and every sector was zeros. What
    /// comes back is unverified — the caller checks the checksum when
    /// nothing is missing, and says so when something is.
    pub fn salvage_dva(&self, dva: &Dva, psize: usize) -> Result<Salvage, ReadError> {
        if dva.gang {
            return Err(ReadError::Gang("a gang block is not salvaged".into()));
        }
        let node = match self.locate_vdev(dva.vdev) {
            Some(Where::Top(n)) => n,
            Some(Where::Removed(_)) => {
                return Err(ReadError::Unsupported(
                    "salvage through a removed vdev's mapping".into(),
                ))
            }
            None => return Err(ReadError::UnknownVdev(dva.vdev)),
        };
        match node {
            Node::Raidz { .. } | Node::Draid { .. } => {
                self.salvage_striped(node, dva.offset, psize)
            }
            _ => self.salvage_node(node, dva.offset, psize, None, &[], 0),
        }
    }

    /// Every copy of `bp` salvaged and laid over each other
    /// ([`salvage_dva`](Self::salvage_dva)): a sector one copy lost is
    /// taken from a copy that has it. The error is the first copy's.
    pub fn salvage_copies(&self, bp: &BlkPtr) -> Result<Salvage, ReadError> {
        let psize = bp.psize as usize;
        let mut got: Option<Salvage> = None;
        let mut first: Option<ReadError> = None;
        for dva in bp.dvas() {
            if got.as_ref().is_some_and(|(_, bad)| bad.is_empty()) {
                break;
            }
            match self.salvage_dva(dva, psize) {
                Ok(s) => match got.as_mut() {
                    Some(g) => fill_from(g, &s),
                    None => got = Some(s),
                },
                Err(e) => {
                    first.get_or_insert(e);
                }
            }
        }
        got.ok_or_else(|| first.unwrap_or(ReadError::NoMember))
    }

    /// `size` bytes at `offset` under a disk, a mirror, or a child of a
    /// raidz or dRAID (`cfg` and `children` for its distributed spares),
    /// read around refused sectors, each side of a mirror filling what
    /// the sides before it refused.
    fn salvage_node(
        &self,
        node: &Node,
        offset: u64,
        size: usize,
        cfg: Option<&draid::Config>,
        children: &[Node],
        hops: usize,
    ) -> Result<Salvage, ReadError> {
        if hops > children.len() {
            return Err(ReadError::Unsupported(
                "distributed spare chain loops".into(),
            ));
        }
        match node {
            Node::Leaf { device, .. } => self.salvage_leaf(*device, offset, size),
            Node::Mirror { children: sides } => {
                let mut got: Option<Salvage> = None;
                let mut last = ReadError::NoMember;
                for side in sides {
                    if got.as_ref().is_some_and(|(_, bad)| bad.is_empty()) {
                        break;
                    }
                    match self.salvage_node(side, offset, size, cfg, children, hops) {
                        Ok(s) => match got.as_mut() {
                            Some(g) => fill_from(g, &s),
                            None => got = Some(s),
                        },
                        Err(e) => last = more_telling(last, e),
                    }
                }
                got.ok_or(last)
            }
            Node::Dspare { spare_id } => {
                let cfg = cfg.ok_or_else(|| {
                    ReadError::Unsupported("distributed spare read outside its dRAID".into())
                })?;
                let target = cfg.spare_child(*spare_id, offset).ok_or_else(|| {
                    ReadError::Unsupported(format!(
                        "distributed spare {spare_id} of a dRAID with {} spare(s)",
                        cfg.nspares
                    ))
                })?;
                let next = children
                    .get(target as usize)
                    .ok_or(ReadError::UnknownVdev(target as u32))?;
                self.salvage_node(next, offset, size, Some(cfg), children, hops + 1)
            }
            other => Err(ReadError::Unsupported(format!(
                "salvage under {}",
                other.describe()
            ))),
        }
    }

    /// [`salvage_dva`](Self::salvage_dva) under a raidz or dRAID: every
    /// column of every row read around what its member refuses, then
    /// each [`SALVAGE_SECTOR`](zvolrescue_io::SALVAGE_SECTOR) of a row
    /// whose data columns lost no more of it than the parity columns
    /// kept rebuilt from them. Only a block some member refused in
    /// sectors is salvaged: one that lost whole columns, and nothing
    /// else, is what the read already said it was.
    fn salvage_striped(&self, node: &Node, offset: u64, size: usize) -> Result<Salvage, ReadError> {
        let (children, cfg, maps) = match node {
            Node::Raidz {
                nparity,
                ashift,
                children,
            } => {
                let unit = 1u64 << ashift;
                let padded = (size as u64).div_ceil(unit) * unit;
                let m = raidz::map(offset, padded, *ashift, children.len() as u64, *nparity);
                (children.as_slice(), None, vec![m])
            }
            Node::Draid {
                cfg,
                ashift,
                children,
            } => {
                let unit = 1u64 << ashift;
                let padded = (size as u64).div_ceil(unit) * unit;
                (
                    children.as_slice(),
                    Some(cfg.as_ref()),
                    cfg.map(offset, padded, *ashift),
                )
            }
            _ => return Err(ReadError::Unsupported("not a raidz or dRAID".into())),
        };
        let sector = zvolrescue_io::SALVAGE_SECTOR as usize;
        let mut refused = false;
        let mut column = |c: &raidz::Column| -> Salvage {
            let n = c.size as usize;
            if n == 0 {
                return (Vec::new(), Vec::new());
            }
            let got = children
                .get(c.devidx as usize)
                .ok_or(ReadError::UnknownVdev(c.devidx as u32))
                .and_then(|child| self.salvage_node(child, c.offset, n, cfg, children, 0));
            match got {
                Ok(s) => {
                    refused |= !s.1.is_empty();
                    s
                }
                Err(e) => {
                    trace!("raidz", "    salvage: column dev{}: {e}", c.devidx);
                    (vec![0u8; n], vec![(0, n as u64)])
                }
            }
        };
        let mut out: Vec<u8> = Vec::with_capacity(size);
        let mut bad: Vec<(u64, u64)> = Vec::new();
        for m in &maps {
            let parity: Vec<Salvage> = m.parity().iter().map(&mut column).collect();
            let mut data: Vec<Salvage> = m.data().iter().map(&mut column).collect();
            let len = data.iter().map(|d| d.0.len()).max().unwrap_or(0);
            let touches = |s: &Salvage, from: usize, to: usize| {
                s.1.iter()
                    .any(|&(b, l)| (b as usize) < to && (b + l) as usize > from)
            };
            for from in (0..len).step_by(sector) {
                let to = (from + sector).min(len);
                let lost: Vec<usize> = (0..data.len())
                    .filter(|&i| from < data[i].0.len() && touches(&data[i], from, to))
                    .collect();
                if lost.is_empty() {
                    continue;
                }
                let usable: Vec<Option<Vec<u8>>> = parity
                    .iter()
                    .map(|p| {
                        (!touches(p, from, to) && p.0.len() >= to).then(|| p.0[from..to].to_vec())
                    })
                    .collect();
                if lost.len() > usable.iter().filter(|p| p.is_some()).count() {
                    continue;
                }
                let mut piece: Vec<Vec<u8>> = data
                    .iter()
                    .map(|d| d.0[from.min(d.0.len())..to.min(d.0.len())].to_vec())
                    .collect();
                if raidz::reconstruct(&mut piece, &usable, &lost).is_err() {
                    continue;
                }
                for &i in &lost {
                    let end = from + piece[i].len();
                    data[i].0[from..end].copy_from_slice(&piece[i]);
                    data[i].1 = cut(&data[i].1, from as u64, end as u64);
                }
                trace!(
                    "raidz",
                    "    salvage: bytes {from}..{to} of data column(s) {lost:?} rebuilt from parity"
                );
            }
            for (bytes, holes) in data {
                let base = out.len() as u64;
                out.extend_from_slice(&bytes);
                bad.extend(holes.iter().map(|&(s, l)| (base + s, l)));
            }
        }
        if !refused {
            return Err(ReadError::Unrecoverable(
                "no member refused a sector of it: the columns it lost are lost whole".into(),
            ));
        }
        out.truncate(size);
        let bad = cut(&bad, size as u64, u64::MAX);
        Ok((out, merge_ranges(bad)))
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

    /// Read one column of a row. A distributed spare column is read
    /// from the child the dRAID permutation assigns to it at that offset.
    fn read_column(
        &self,
        c: &raidz::Column,
        children: &[Node],
        cfg: Option<&draid::Config>,
    ) -> Result<Vec<u8>, ReadError> {
        if c.size == 0 {
            // An empty column (dRAID short row): nothing on disk, but
            // it keeps its place in the parity equations.
            return Ok(Vec::new());
        }
        let child = children
            .get(c.devidx as usize)
            .ok_or(ReadError::UnknownVdev(c.devidx as u32))?;
        self.read_raid_child(child, c, children, cfg, 0)
    }

    /// One child of a raidz or dRAID at a column. A distributed spare is
    /// read from the child the dRAID's permutation gives it at that
    /// offset; a `spare` or `replacing` vdev over one — the shape OpenZFS
    /// leaves when it puts a distributed spare in for a failed disk —
    /// through whichever side answers. That shape was read as a mirror
    /// of an ordinary disk and of "a distributed spare outside its
    /// dRAID": with the failed disk gone, its column was lost on every
    /// row, and a pool `zdb` reads whole was called unreadable.
    fn read_raid_child(
        &self,
        child: &Node,
        c: &raidz::Column,
        children: &[Node],
        cfg: Option<&draid::Config>,
        hops: usize,
    ) -> Result<Vec<u8>, ReadError> {
        if hops > children.len() {
            return Err(ReadError::Unsupported(
                "distributed spare chain loops".into(),
            ));
        }
        match (child, cfg) {
            (Node::Dspare { spare_id }, Some(cfg)) => {
                let Some(target) = cfg.spare_child(*spare_id, c.offset) else {
                    return Err(ReadError::Unsupported(format!(
                        "distributed spare {spare_id} of a dRAID with {} spare(s)",
                        cfg.nspares
                    )));
                };
                trace!(
                    "draid",
                    "    dspare#{spare_id} at {:#x} -> child {target}",
                    c.offset
                );
                let next = children
                    .get(target as usize)
                    .ok_or(ReadError::UnknownVdev(target as u32))?;
                self.read_raid_child(next, c, children, Some(cfg), hops + 1)
            }
            (Node::Dspare { .. }, None) => {
                Err(ReadError::Unsupported("dspare outside dRAID".into()))
            }
            (Node::Mirror { children: sides }, Some(_)) => {
                let mut last = ReadError::NoMember;
                for side in sides {
                    match self.read_raid_child(side, c, children, cfg, hops + 1) {
                        Ok(b) => return Ok(b),
                        Err(e) => last = more_telling(last, e),
                    }
                }
                Err(last)
            }
            _ => self.read_first(child, c.offset, c.size as usize),
        }
    }

    /// Read the data columns of one row. The parity columns are left
    /// unread (`None`) until [`PoolReader::read_parity`] is asked for
    /// them: a row whose data columns all read and verify has no use
    /// for its parity, and on a device every read counts (SPEC N-10) —
    /// OpenZFS itself reads only the data columns of a healthy stripe.
    fn read_row(&self, m: raidz::Map, children: &[Node], cfg: Option<&draid::Config>) -> Columns {
        let parity = vec![None; m.nparity];
        let mut data = Vec::with_capacity(m.acols.saturating_sub(m.nparity));
        let mut lost = Vec::new();
        for (i, c) in m.data().iter().enumerate() {
            match self.read_column(c, children, cfg) {
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

    /// Read the parity columns of a row that needs them — a data column
    /// was lost, or the row read whole did not verify. Once.
    fn read_parity(&self, row: &mut Columns, children: &[Node], cfg: Option<&draid::Config>) {
        let (parity, _, _, m) = row;
        for (i, c) in m.parity().iter().enumerate() {
            if parity[i].is_some() {
                continue;
            }
            parity[i] = match self.read_column(c, children, cfg) {
                Ok(b) => Some(b),
                Err(e) => {
                    trace!("raidz", "    parity column dev{}: {e}", c.devidx);
                    None
                }
            };
        }
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
        for (r, (_, _, _, m)) in rows.iter().enumerate() {
            trace!(
                "raidz",
                "  dva {dva_index}: {label} row {r} -> {} cols ({} parity, {} big, nskip {}): {}",
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
        }
        let assemble = |rows: &[Columns]| -> Vec<u8> {
            let mut out: Vec<u8> = Vec::with_capacity(psize);
            for (_, data, _, _) in rows {
                for column in data {
                    out.extend_from_slice(column);
                }
            }
            out.truncate(psize);
            out
        };
        let (children, cfg) = match node {
            Node::Raidz { children, .. } => (children.as_slice(), None),
            Node::Draid { children, cfg, .. } => (children.as_slice(), Some(cfg.as_ref())),
            _ => (&[][..], None),
        };
        let record = |attempts: &mut Vec<Attempt>, result: Result<Verify, ReadError>| {
            attempts.push(Attempt {
                dva: dva_index,
                vdev: dva.vdev,
                device: None,
                result,
            });
        };
        for row in rows.iter_mut() {
            if !row.2.is_empty() {
                self.read_parity(row, children, cfg);
            }
            let (parity, data, lost, _) = row;
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
        match v {
            Verify::Ok | Verify::NotChecked => return Ok((raw, v)),
            // Nothing tells a good column from a bad one: refused, as a
            // disk or a mirror refuses it. Taken as read it was written
            // and counted as verified, and no parity was tried.
            Verify::Unsupported => return Err(ReadError::ChecksumUnsupported),
            Verify::Mismatch => {}
        }
        // Combinatorial reconstruction, one row at a time (the other rows
        // are kept as read). Now the parity is needed.
        for row in rows.iter_mut() {
            self.read_parity(row, children, cfg);
        }
        // One budget for the block. Counted per row it started again for
        // each row of a dRAID: sixteen rows, sixteen times the tries. And
        // shared among the rows, each taking its part of what is left:
        // taken whole by the first, a wide row 0 used it all and the row
        // that was damaged was never tried.
        let max_tries =
            MAX_COMBREC_TRIES.min((MAX_COMBREC_BYTES / (psize.max(1) as u64)).max(1) as usize);
        let mut tries = 0usize;
        let mut cut_short = false;
        for r in 0..rows.len() {
            let row_limit = row_share(tries, max_tries, rows.len() - r);
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
            'row: for k in 1..=budget.min(columns.len()) {
                for combo in Combinations::new(columns.len(), k) {
                    if tries >= row_limit {
                        cut_short = true;
                        break 'row;
                    }
                    tries += 1;
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
                    // Only this row's data is rebuilt; the rest of the
                    // block is as read, and is not copied for each try.
                    let mut work = rows[r].1.clone();
                    if raidz::reconstruct(&mut work, &usable, &missing).is_err() {
                        continue;
                    }
                    let mut raw: Vec<u8> = Vec::with_capacity(psize);
                    for (i, (_, data, _, _)) in rows.iter().enumerate() {
                        for column in if i == r { &work } else { data } {
                            raw.extend_from_slice(column);
                        }
                    }
                    raw.truncate(psize);
                    let v = self.verify(bp, &raw);
                    if matches!(v, Verify::Ok | Verify::NotChecked) {
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
        if cut_short {
            trace!(
                "raidz",
                "    combinatorial reconstruction gave up after {tries} of {max_tries} tries, shared among {} row(s)",
                rows.len()
            );
        } else {
            trace!(
                "raidz",
                "    no reconstruction produced a block matching its checksum"
            );
        }
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
                        Err(e) => last = more_telling(last, e),
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

    /// Read and verify the psize bytes of `bp` behind a `dva` that names
    /// a vdev that was removed (SPEC F-69).
    ///
    /// The bytes are assembled from wherever the mapping sends each
    /// piece, so a copy here is a whole assembled block rather than one
    /// leaf's read, and the checksum is what says the assembly was
    /// right. No device is named in the attempt: several may have
    /// contributed to one copy.
    fn read_verified_remapped(
        &self,
        dva: &Dva,
        mapping: &Mapping,
        bp: &BlkPtr,
        attempts: &mut Vec<Attempt>,
        i: usize,
    ) -> Result<(Vec<u8>, Verify), ReadError> {
        let mut last = ReadError::NoMember;
        for (_, candidate) in
            self.remapped_candidates(dva.vdev, mapping, dva.offset, bp.psize as usize, 0)
        {
            let result = match candidate {
                Err(e) => {
                    trace!(
                        "indirect",
                        "  dva {i} through removed vdev {}: {e}",
                        dva.vdev
                    );
                    last = e.clone();
                    Err(e)
                }
                Ok(raw) => {
                    let v = self.verify(bp, &raw);
                    trace!(
                        "indirect",
                        "  dva {i} through removed vdev {}: checksum {v:?}",
                        dva.vdev
                    );
                    match v {
                        Verify::Ok | Verify::NotChecked => {
                            attempts.push(Attempt {
                                dva: i,
                                vdev: dva.vdev,
                                device: None,
                                result: Ok(v),
                            });
                            return Ok((raw, v));
                        }
                        Verify::Unsupported => last = ReadError::ChecksumUnsupported,
                        Verify::Mismatch => last = ReadError::AllCopiesBad,
                    }
                    Ok(v)
                }
            };
            attempts.push(Attempt {
                dva: i,
                vdev: dva.vdev,
                device: None,
                result,
            });
        }
        Err(last)
    }

    /// The smallest allocation top-level vdev `vdev` makes
    /// (`vdev_get_min_alloc`): one sector of its `ashift`, or a full data
    /// row of a dRAID — the size of a dynamic gang header there.
    fn min_alloc(&self, vdev: u32) -> u64 {
        let ashift = self.top_ashift.get(&vdev).copied().unwrap_or(9);
        match self.tops.get(&vdev) {
            Some(Node::Draid { cfg, .. }) => cfg.ndata << ashift,
            _ => 1u64 << ashift,
        }
    }

    /// How many bytes the gang header behind `bp` may be: 512 on every
    /// pool before `dynamic_gang_header`, and with that feature active
    /// the smallest of its copies' allocations (`zio_gang_tree_assemble`:
    /// the header was written once, at the size every DVA could hold).
    /// "May be": a pool keeps the 512-byte headers it wrote before the
    /// feature went active — it goes active on the first gang write that
    /// needed more than three children — so the reader tries the old
    /// size when the full one does not verify, as `zio_checksum_error`
    /// does.
    fn gang_header_size(&self, bp: &BlkPtr) -> usize {
        if !self.dynamic_gang {
            return blkptr::GANG_HEADER_SIZE;
        }
        bp.dvas()
            .map(|d| self.min_alloc(d.vdev))
            .min()
            .map(|n| usize::try_from(n).unwrap_or(blkptr::GANG_HEADER_SIZE))
            .unwrap_or(blkptr::GANG_HEADER_SIZE)
            .max(blkptr::GANG_HEADER_SIZE)
    }

    /// Read the raw bytes behind a gang pointer: the header at the DVA
    /// (verified against the pointer's identity and birth, trying every
    /// copy), then each child pointer in order, concatenated; children
    /// may be gang blocks themselves.
    fn read_gang(&self, dva: &Dva, bp: &BlkPtr, depth: usize) -> Result<Vec<u8>, ReadError> {
        if depth > 8 {
            return Err(ReadError::Gang("nesting deeper than 8".into()));
        }
        let header_size = self.gang_header_size(bp);
        // Verifier: DVA[0] and the physical birth. A gang header of an
        // encrypted dataset carries the folded checksum.
        let verify = |buf: &[u8]| {
            if bp.uses_crypt() && bp.object_type != ot::OBJSET {
                zfs_ondisk::checksum::verify_gang_header_crypt(
                    buf,
                    u64::from(bp.dva[0].vdev),
                    bp.dva[0].offset,
                    bp.physical_birth_or_logical(),
                )
            } else {
                zfs_ondisk::checksum::verify_gang_header(
                    buf,
                    u64::from(bp.dva[0].vdev),
                    bp.dva[0].offset,
                    bp.physical_birth_or_logical(),
                )
            }
        };
        let mut header = None;
        let mut last = ReadError::NoMember;
        for (device, candidate) in self.candidates_on(dva.vdev, dva.offset, header_size, 0) {
            match candidate {
                Ok(mut buf) => {
                    let mut status = verify(&buf);
                    let mut size = header_size;
                    if status != zfs_ondisk::checksum::ChecksumStatus::Ok
                        && header_size > blkptr::GANG_HEADER_SIZE
                    {
                        // Written before the feature went active: a
                        // 512-byte header at the start of the allocation.
                        let old = verify(&buf[..blkptr::GANG_HEADER_SIZE]);
                        if old == zfs_ondisk::checksum::ChecksumStatus::Ok {
                            buf.truncate(blkptr::GANG_HEADER_SIZE);
                            status = old;
                            size = blkptr::GANG_HEADER_SIZE;
                        }
                    }
                    trace!(
                        "gang",
                        "header @ vdev {} off {:#x} device {device:?} (depth {depth}): {size} bytes, checksum {}",
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
            // The children together are the block, no more: once its
            // psize is in hand the rest would be cut off anyway. Read on
            // regardless, a header of 31 children, each a gang of 31
            // more, eight deep, was 31^8 reads of one block.
            if out.len() >= bp.psize as usize {
                trace!(
                    "gang",
                    "  {} more child(ren) past the block's {} bytes, not read",
                    children.len() - i,
                    bp.psize
                );
                break;
            }
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
        // The children are the block: OpenZFS splits a gang block's data
        // among them to the byte. Fewer bytes than that is not the block
        // — and taken as it was, a gang whose children were holes was
        // "read" as nothing, padded with zeros and passed its checksum
        // over the short buffer, and a tree of such gangs read every
        // header it had: 31 to the eighth power of them.
        if out.len() < bp.psize as usize {
            return Err(ReadError::Gang(format!(
                "the children give {} of the block's {} bytes",
                out.len(),
                bp.psize
            )));
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
            let Some(location) = self.locate_vdev(dva.vdev) else {
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
                match self.read_gang(dva, bp, depth) {
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
            let read = match &location {
                Where::Top(top) => self.read_verified(top, dva, bp, attempts, i),
                Where::Removed(m) => self.read_verified_remapped(dva, m, bp, attempts, i),
            };
            match read {
                Ok((raw, _)) => return Ok(raw),
                Err(e) => last = more_telling(last, e),
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
        // A device that refused a read and stopped the run stops it here
        // too, whatever the other copies made of the block: the operator
        // is told first, and decides (SPEC F-33, N-10).
        if let Some(stop) = self.medium_stop() {
            return Err(stop);
        }
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

/// The `k`-element index subsets of `0..n`, in lexicographic order, one
/// at a time. Collected up front they were C(n, k) vectors before the
/// first was tried — billions for a forged width.
struct Combinations {
    n: usize,
    cur: Vec<usize>,
    done: bool,
}

impl Combinations {
    fn new(n: usize, k: usize) -> Combinations {
        Combinations {
            n,
            cur: (0..k).collect(),
            done: k > n,
        }
    }
}

impl Iterator for Combinations {
    type Item = Vec<usize>;

    fn next(&mut self) -> Option<Vec<usize>> {
        if self.done {
            return None;
        }
        let out = self.cur.clone();
        let k = self.cur.len();
        // The rightmost index that can still move right, moved, and the
        // ones after it set just past it.
        match (0..k).rev().find(|&i| self.cur[i] < self.n - k + i) {
            Some(i) => {
                self.cur[i] += 1;
                for j in i + 1..k {
                    self.cur[j] = self.cur[j - 1] + 1;
                }
            }
            None => self.done = true,
        }
        Some(out)
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

    /// A geometry no pool could have — from a label whose checksum a
    /// forger got right, or from a layout typed by hand — is a vdev that
    /// cannot be read, never a division by zero or a shift out of the
    /// word in the layout code.
    #[test]
    fn a_geometry_no_pool_has_is_not_read() {
        use zfs_ondisk::label::VdevNode;
        let top = |kind: &str, nparity: u64, ashift: u64, width: usize| VdevNode {
            kind: kind.into(),
            nparity: Some(nparity),
            ashift: Some(ashift),
            draid_ndata: Some(u64::MAX),
            draid_nspares: Some(0),
            draid_ngroups: Some(1),
            children: (0..width)
                .map(|i| VdevNode {
                    kind: "file".into(),
                    guid: i as u64 + 1,
                    ..VdevNode::default()
                })
                .collect(),
            ..VdevNode::default()
        };
        let bad = [
            top("raidz", 4, 12, 4),
            top("raidz", 5, 12, 4),
            top("raidz", u64::MAX, 12, 4),
            top("raidz", 0, 12, 4),
            top("raidz", 2, 63, 4),
            top("raidz", 2, 8, 4),
            top("draid", 1, 12, 6),
        ];
        for t in &bad {
            assert!(
                matches!(Node::from_tree(t, &[], 12), Node::Unsupported { .. }),
                "{t:?}"
            );
        }
        assert!(matches!(
            Node::from_tree(&top("raidz", 2, 12, 4), &[], 12),
            Node::Raidz { nparity: 2, .. }
        ));
        // Wider than any raidz is made: combinatorial repair would try
        // every subset of the columns.
        assert!(matches!(
            Node::from_tree(&top("raidz", 3, 12, 256), &[], 12),
            Node::Unsupported { .. }
        ));
    }

    /// A pool assembled by hand: one raidz or dRAID top-level vdev of
    /// `width` members, with no labels behind it.
    fn striped_by_hand(kind: &str, width: usize, nparity: u64, ndata: Option<u64>) -> PoolAssembly {
        use zfs_ondisk::label::VdevNode;
        let children: Vec<VdevNode> = (0..width)
            .map(|i| VdevNode {
                kind: "file".into(),
                id: i as u64,
                guid: i as u64 + 1,
                ..VdevNode::default()
            })
            .collect();
        let tree = VdevNode {
            kind: kind.into(),
            guid: 999,
            nparity: Some(nparity),
            ashift: Some(9),
            draid_ndata: ndata,
            draid_nspares: Some(0),
            draid_ngroups: Some(1),
            children,
            ..VdevNode::default()
        };
        PoolAssembly {
            name: "tank".into(),
            guid: 1,
            state: None,
            txg: None,
            vdev_children: Some(1),
            features_for_read: vec![],
            tops: vec![crate::pool::TopVdev {
                id: 0,
                guid: 999,
                name: format!("{kind}-0"),
                kind: kind.into(),
                nparity: Some(nparity),
                ashift: Some(9),
                members: (0..width)
                    .map(|i| crate::pool::Member {
                        guid: i as u64 + 1,
                        path: None,
                        present: Some(i),
                    })
                    .collect(),
                tree,
            }],
            removed_tops: vec![],
            hosts: vec![],
            host_txgs: Vec::new(),
            devices: (0..width).collect(),
            stale: vec![],
        }
    }

    /// A raidz block whose checksum cannot be computed (BLAKE3 with no
    /// salt known) is refused, as a disk or a mirror refuses it, damaged
    /// column or not. It was taken as read: the damaged column written,
    /// counted as verified, and no parity tried.
    #[test]
    fn a_raidz_block_nothing_can_verify_is_refused() {
        let a = striped_by_hand("raidz", 3, 1, None);
        let data: Vec<u8> = (0..1024u32).map(|i| (i * 13 % 251) as u8).collect();
        let offset = 0x2_0000u64;
        let m = raidz::map(offset, data.len() as u64, 9, 3, 1);
        let mut at = 0usize;
        let cols: Vec<Vec<u8>> = m
            .data()
            .iter()
            .map(|c| {
                let col = data[at..at + c.size as usize].to_vec();
                at += c.size as usize;
                col
            })
            .collect();
        let parity = raidz::generate_parity(&cols, 1);
        let placed: Vec<(raidz::Column, Vec<u8>)> = m
            .parity()
            .iter()
            .cloned()
            .zip(parity)
            .chain(m.data().iter().cloned().zip(cols))
            .collect();
        let raw = Builder::new()
            .dva(0, 0, offset, data.len() as u64 * 2, false)
            .sizes(data.len() as u64, data.len() as u64)
            .props(2, 14, ot::ZVOL, 0)
            .births(0, 100, 1)
            .cksum([1, 2, 3, 4])
            .bytes(Endian::Little);
        let bp = BlkPtr::parse(&raw, Endian::Little).unwrap();
        for damaged in [None, Some(m.data()[0].devidx)] {
            let mut images = vec![vec![0u8; 5 << 20]; 3];
            for (c, bytes) in &placed {
                let mut bytes = bytes.clone();
                if Some(c.devidx) == damaged {
                    bytes.iter_mut().for_each(|b| *b ^= 0xff);
                }
                crate::fixture::write_at_dva(&mut images[c.devidx as usize], c.offset, &bytes);
            }
            let sources: Vec<MemSource> = images.into_iter().map(MemSource::new).collect();
            let devs: Vec<Option<&dyn BlockSource>> = sources
                .iter()
                .map(|s| Some(s as &dyn BlockSource))
                .collect();
            let reader = PoolReader::new(&a, devs);
            assert!(
                matches!(
                    reader.read_block(&bp, false),
                    Err(ReadError::ChecksumUnsupported)
                ),
                "damaged column {damaged:?}"
            );
        }
    }

    /// Two data columns of a raidz1 block, each with one sector the
    /// imager's map refuses: lost whole, the block was past its parity
    /// and every byte zeros. Sector by sector each refused piece is the
    /// only one lost in its stripe, and parity rebuilds the block whole.
    /// Where both columns lost the same sector, only that sector is lost.
    #[test]
    fn refused_sectors_of_raidz_columns_are_rebuilt_sector_by_sector() {
        use zvolrescue_io::FlakySource;
        let a = striped_by_hand("raidz", 3, 1, None);
        let data: Vec<u8> = (0..4096u32).map(|i| (i * 31 % 253) as u8).collect();
        let offset = 0x2_0000u64;
        let m = raidz::map(offset, data.len() as u64, 9, 3, 1);
        let mut at = 0usize;
        let cols: Vec<Vec<u8>> = m
            .data()
            .iter()
            .map(|c| {
                let col = data[at..at + c.size as usize].to_vec();
                at += c.size as usize;
                col
            })
            .collect();
        let parity = raidz::generate_parity(&cols, 1);
        let mut images = vec![vec![0u8; 5 << 20]; 3];
        for (c, bytes) in m
            .parity()
            .iter()
            .zip(parity.iter())
            .chain(m.data().iter().zip(cols.iter()))
        {
            crate::fixture::write_at_dva(&mut images[c.devidx as usize], c.offset, bytes);
        }
        let raw = Builder::new()
            .dva(0, 0, offset, data.len() as u64 * 3 / 2, false)
            .sizes(data.len() as u64, data.len() as u64)
            .props(2, 7, ot::ZVOL, 0)
            .births(0, 100, 1)
            .cksum(zfs_ondisk::checksum::fletcher4(&data, Endian::Little))
            .bytes(Endian::Little);
        let bp = BlkPtr::parse(&raw, Endian::Little).unwrap();
        let (d0, d1) = (&m.data()[0], &m.data()[1]);
        let sector_of = |c: &raidz::Column, k: u64| (LABEL_START_SIZE + c.offset + k * 512, 512);
        let run = |bad0: u64, bad1: u64| {
            let mut refused = vec![Vec::new(); 3];
            refused[d0.devidx as usize].push(sector_of(d0, bad0));
            refused[d1.devidx as usize].push(sector_of(d1, bad1));
            let sources: Vec<FlakySource<MemSource>> = images
                .iter()
                .zip(refused)
                .map(|(img, bad)| FlakySource::new(MemSource::new(img.clone()), bad))
                .collect();
            let devs: Vec<Option<&dyn BlockSource>> = sources
                .iter()
                .map(|s| Some(s as &dyn BlockSource))
                .collect();
            let reader = PoolReader::new(&a, devs);
            assert!(reader.read_block(&bp, false).is_err(), "two columns lost");
            reader.salvage_copies(&bp).unwrap()
        };
        let (whole, bad) = run(0, 1);
        assert!(bad.is_empty(), "{bad:?}");
        assert_eq!(whole, data);
        let (part, bad) = run(1, 1);
        assert_eq!(bad, vec![(512, 512), (d0.size + 512, 512)]);
        let mut expected = data.clone();
        expected[512..1024].fill(0);
        let second = d0.size as usize + 512;
        expected[second..second + 512].fill(0);
        assert_eq!(part, expected);
    }

    /// The pieces of ranges: what one copy lost and another has is
    /// filled from it, and only what both lost stays lost.
    #[test]
    fn copies_fill_each_others_refused_ranges() {
        let mut a: Salvage = (vec![1u8; 4096], vec![(0, 1024), (2048, 1024)]);
        let b: Salvage = (vec![2u8; 4096], vec![(512, 1024), (3584, 512)]);
        fill_from(&mut a, &b);
        assert_eq!(a.1, vec![(512, 512)]);
        assert!(a.0[..512].iter().all(|&x| x == 2));
        assert!(a.0[1024..2048].iter().all(|&x| x == 1));
        assert!(a.0[2048..3072].iter().all(|&x| x == 2));
        assert!(a.0[3072..].iter().all(|&x| x == 1));
        assert_eq!(cut(&[(0, 100)], 10, 20), vec![(0, 10), (20, 80)]);
        assert_eq!(
            merge_ranges(vec![(10, 5), (0, 10), (30, 1)]),
            vec![(0, 15), (30, 1)]
        );
    }

    /// A dRAID child OpenZFS replaced with a distributed spare — the
    /// child becomes `spare{failed disk, draid1-0-0}` — is read from where
    /// the spare put its columns, with the failed disk gone. It was read
    /// as a mirror of a missing disk and of "a distributed spare outside
    /// its dRAID", and the pool was called unreadable.
    #[test]
    fn a_distributed_spare_under_a_spare_vdev_is_read() {
        use zfs_ondisk::label::VdevNode;
        let leaf = |i: u64| VdevNode {
            kind: "file".into(),
            id: i,
            guid: i + 1,
            ..VdevNode::default()
        };
        let mut children: Vec<VdevNode> = (0..5).map(leaf).collect();
        children.push(VdevNode {
            kind: "spare".into(),
            id: 5,
            guid: 50,
            children: vec![
                leaf(5),
                VdevNode {
                    kind: "dspare".into(),
                    id: 1,
                    guid: 70,
                    path: Some("draid1-0-0".into()),
                    ..VdevNode::default()
                },
            ],
            ..VdevNode::default()
        });
        let tree = VdevNode {
            kind: "draid".into(),
            guid: 999,
            nparity: Some(1),
            ashift: Some(9),
            draid_ndata: Some(4),
            draid_nspares: Some(1),
            draid_ngroups: Some(1),
            children,
            ..VdevNode::default()
        };
        let mut a = striped_by_hand("draid", 6, 1, Some(4));
        a.tops[0].tree = tree;
        a.tops[0].members[5].present = None;
        a.devices = (0..5).collect();
        assert!(a.readable(), "the spare stands in for the failed disk");

        // The block's columns where OpenZFS writes them: a column of the
        // replaced child on the child the spare's permutation names.
        let cfg = draid::Config::new(4, 1, 1, 6, 1).unwrap();
        let data: Vec<u8> = (0..8192u32).map(|i| (i * 7 % 251) as u8).collect();
        let offset = 0x10_0000u64;
        let mut images = vec![vec![0u8; 8 << 20]; 5];
        let mut at = 0usize;
        let mut spared = 0;
        for m in cfg.map(offset, data.len() as u64, 9) {
            let cols: Vec<Vec<u8>> = m
                .data()
                .iter()
                .map(|c| {
                    let n = c.size as usize;
                    let col = data[at..at + n].to_vec();
                    at += n;
                    col
                })
                .collect();
            let parity = raidz::generate_parity(&cols, 1);
            let placed = m
                .parity()
                .iter()
                .zip(parity.iter())
                .chain(m.data().iter().zip(cols.iter()));
            for (c, bytes) in placed {
                let mut dev = c.devidx;
                if dev == 5 {
                    dev = cfg.spare_child(0, c.offset).expect("a spare slice");
                    spared += 1;
                }
                crate::fixture::write_at_dva(&mut images[dev as usize], c.offset, bytes);
            }
        }
        assert_eq!(at, data.len());
        assert!(spared > 0, "the block has a column on the replaced child");
        let sources: Vec<MemSource> = images.into_iter().map(MemSource::new).collect();
        let devs: Vec<Option<&dyn BlockSource>> = sources
            .iter()
            .map(|s| Some(s as &dyn BlockSource))
            .collect();
        let reader = PoolReader::new(&a, devs);
        let raw = Builder::new()
            .dva(0, 0, offset, data.len() as u64 * 2, false)
            .sizes(data.len() as u64, data.len() as u64)
            .props(2, 7, ot::ZVOL, 0)
            .births(0, 100, 1)
            .cksum(zfs_ondisk::checksum::fletcher4(&data, Endian::Little))
            .bytes(Endian::Little);
        let bp = BlkPtr::parse(&raw, Endian::Little).unwrap();
        assert_eq!(reader.read_block(&bp, false).unwrap().data, data);
    }

    /// A block no combination of columns repairs gives up in bounded
    /// time, on a raidz as wide as a label may say and on a dRAID whose
    /// block spans many rows: the budget is for the block, and a try is
    /// a column, not a byte at a time. A hopeless 128 KiB block on a
    /// 255-wide raidz3 took three minutes.
    #[test]
    fn a_hopeless_block_gives_up_in_bounded_time() {
        let zero = MemSource::new(vec![0u8; 16 << 20]);
        let read = |a: &PoolAssembly, width: usize, psize: u64| {
            let devs: Vec<Option<&dyn BlockSource>> = (0..width)
                .map(|_| Some(&zero as &dyn BlockSource))
                .collect();
            let reader = PoolReader::new(a, devs);
            let raw = Builder::new()
                .dva(0, 0, 0x10_0000, psize * 2, false)
                .sizes(psize, psize)
                .props(2, 7, ot::ZVOL, 0)
                .births(0, 100, 1)
                .cksum([1, 2, 3, 4])
                .bytes(Endian::Little);
            let bp = BlkPtr::parse(&raw, Endian::Little).unwrap();
            let t = std::time::Instant::now();
            let r = reader.read_block(&bp, false).map(|b| b.data.len());
            (r, t.elapsed())
        };
        // Release builds are held to a time; a debug build only to the
        // answer, on the narrower geometries.
        let cases: &[(&str, usize, u64, Option<u64>, u64)] = if cfg!(debug_assertions) || cfg!(miri)
        {
            &[("raidz", 12, 3, None, 16 << 10)]
        } else {
            &[
                ("raidz", 40, 3, None, 128 << 10),
                ("raidz", 255, 3, None, 128 << 10),
                ("draid", 20, 3, Some(17), 128 << 10),
            ]
        };
        for &(kind, width, nparity, ndata, psize) in cases {
            let a = striped_by_hand(kind, width, nparity, ndata);
            let (r, took) = read(&a, width, psize);
            assert!(
                matches!(r, Err(ReadError::AllCopiesBad)),
                "{kind} {width}: {r:?}"
            );
            if !cfg!(debug_assertions) {
                assert!(took.as_secs() < 20, "{kind} {width}: {took:?}");
            }
            eprintln!("{kind}-{width} p{nparity}: {took:?}");
        }
    }

    /// The subsets are what they were when collected up front — the same
    /// ones, in the same order — but made one at a time.
    #[test]
    fn combinations_come_one_at_a_time_in_order() {
        let all: Vec<Vec<usize>> = Combinations::new(5, 2).collect();
        assert_eq!(all.len(), 10);
        assert_eq!(all[0], [0, 1]);
        assert_eq!(all[4], [1, 2]);
        assert_eq!(all[9], [3, 4]);
        assert_eq!(
            Combinations::new(4, 4).collect::<Vec<_>>(),
            [vec![0, 1, 2, 3]]
        );
        assert_eq!(Combinations::new(3, 4).count(), 0);
        // Taking the first few of a vast number costs the first few.
        assert_eq!(Combinations::new(2000, 3).take(5).count(), 5);
    }

    /// A top-level vdev of any kind with an ashift ZFS does not use is a
    /// vdev that cannot be read: a mirror's of 50 made a dynamic gang
    /// header a petabyte.
    #[test]
    fn a_top_level_ashift_no_pool_has_is_not_read() {
        let mut a = crate::pool::PoolAssembly {
            name: "tank".into(),
            guid: 1,
            state: None,
            txg: None,
            vdev_children: Some(1),
            features_for_read: vec!["com.klarasystems:dynamic_gang_header".into()],
            tops: vec![crate::pool::TopVdev {
                id: 0,
                guid: 2,
                name: "mirror-0".into(),
                kind: "mirror".into(),
                nparity: None,
                ashift: Some(50),
                members: Vec::new(),
                tree: Default::default(),
            }],
            removed_tops: Vec::new(),
            hosts: Vec::new(),
            host_txgs: Vec::new(),
            devices: Vec::new(),
            stale: Vec::new(),
        };
        let reader = PoolReader::new(&a, Vec::new());
        assert!(matches!(
            reader.tops.get(&0),
            Some(Node::Unsupported { .. })
        ));
        assert_eq!(reader.min_alloc(0), 1 << ASHIFT_MIN);
        a.tops[0].ashift = Some(12);
        let reader = PoolReader::new(&a, Vec::new());
        assert!(!matches!(
            reader.tops.get(&0),
            Some(Node::Unsupported { .. })
        ));
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
                "febfe0108392728dbde89ee63f9f25419a0192ac04420db3ad88b0032a088585"
            );
        }

        /// A healthy stripe is read from its data columns alone: the
        /// parity is not fetched until a column is lost or the checksum
        /// fails, as OpenZFS reads it, and as a device asks (SPEC N-10).
        #[test]
        fn a_healthy_stripe_leaves_its_parity_unread() {
            let present = [true; 4];
            let (s, a, ub) = raidz2(&present);
            let counted: Vec<zvolrescue_io::FlakySource<MemSource>> = s
                .iter()
                .map(|m| zvolrescue_io::FlakySource::new(m.clone(), Vec::new()))
                .collect();
            let devices: Vec<Option<&dyn BlockSource>> = counted
                .iter()
                .map(|c| Some(c as &dyn BlockSource))
                .collect();
            let reader = PoolReader::new(&a, devices);
            let mos = open_mos(&reader, &ub).unwrap();
            let tree = walk(&mos, "tank").unwrap();
            let ds = tree.get("tank/vm/disk0").unwrap();
            let (obj, _) = open_volume(&reader, ds).unwrap();
            let before: usize = counted.iter().map(|c| c.reads().len()).sum();
            let mut sink = MemSink::default();
            let r = extract(
                &obj,
                ds.volsize.unwrap(),
                &mut sink,
                OnError::Abort,
                |_, _| {},
            )
            .unwrap();
            assert_eq!(r.blocks_read, 2);
            let during: usize = counted.iter().map(|c| c.reads().len()).sum::<usize>() - before;
            // Two 8 KiB blocks, each two 4 KiB data columns on a 4-wide
            // raidz2: four reads, and none of the four parity columns.
            assert_eq!(during, 4, "reads during the extract");
            assert_eq!(
                r.sha256,
                "febfe0108392728dbde89ee63f9f25419a0192ac04420db3ad88b0032a088585"
            );
        }

        /// The unverified read path reconstructs too. `read_dva` and
        /// the gang and remapped reads go through `read_candidates`,
        /// not `read_striped`, and that arm has to fetch the parity of
        /// a row that lost a column just the same — a degraded raidz is
        /// the case this tool exists for.
        #[test]
        fn a_degraded_stripe_reconstructs_on_the_unverified_path() {
            for present in [
                [false, true, true, true],
                [true, false, true, true],
                [true, true, false, true],
                [true, true, true, false],
            ] {
                let (s, a, ub) = raidz2(&present);
                let reader = PoolReader::new(&a, devices(&s, &present));
                let rootbp =
                    zfs_ondisk::blkptr::BlkPtr::parse(&ub.rootbp, ub.endian).expect("rootbp");
                let dva = &rootbp.dva[0];
                let psize = rootbp.psize as usize;
                // Unverified: the bytes come back reconstructed.
                let (raw, _) = reader
                    .read_dva(dva, psize)
                    .unwrap_or_else(|e| panic!("read_dva with {present:?}: {e}"));
                assert_eq!(raw.len(), psize, "{present:?}");
                // The bytes are right, not merely present: unverified
                // as they are, they match the pointer's checksum.
                assert_eq!(
                    reader.verify(&rootbp, &raw),
                    Verify::Ok,
                    "unverified read of a degraded stripe does not match its checksum: {present:?}"
                );
            }
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
                    sha, "febfe0108392728dbde89ee63f9f25419a0192ac04420db3ad88b0032a088585",
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
                "febfe0108392728dbde89ee63f9f25419a0192ac04420db3ad88b0032a088585"
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
                "febfe0108392728dbde89ee63f9f25419a0192ac04420db3ad88b0032a088585"
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
        use crate::fixture::{Alloc, Layout, Pool};
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
            // A gang header on a mirror takes one sector; nothing in the
            // read path looks at the pointer's asize, so it is checked
            // here, where a wrong one would otherwise go unseen until
            // the zdb cross-check.
            assert_eq!(bp.dva[0].asize, 512);
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

        const DGH: &str = "com.klarasystems:dynamic_gang_header";

        /// Five pieces behind one header: more than the three a 512-byte
        /// header holds, so only a dynamic header can carry them.
        fn wide_payload() -> Vec<u8> {
            (0..20480u32).map(|i| (i % 251) as u8).collect()
        }

        /// A mirror whose labels say `dynamic_gang_header` is active, or
        /// not, over the same bytes: a 4 KiB gang header with five
        /// children, as OpenZFS 2.4 writes it on an `ashift=12` mirror.
        fn build_dynamic(active: bool) -> (Vec<MemSource>, PoolAssembly, BlkPtr) {
            let mut pool = Pool::mirror("tank", 0x9c9c, 12).txgs(&[(100, 1)]);
            if active {
                pool = pool.with_feature(DGH);
            }
            let mut members = vec![pool.member_image(0, SIZE), pool.member_image(1, SIZE)];
            let mut a = Alloc::new(0x30_0000);
            let bp = a.put_gang_sized(
                &mut members,
                &wide_payload(),
                &[4096; 5],
                ot::ZVOL,
                100,
                4096,
            );
            let bp = BlkPtr::parse(&bp, Endian::Little).unwrap();
            let sources: Vec<MemSource> = members.into_iter().map(MemSource::new).collect();
            let scans: Vec<_> = sources.iter().map(|s| scan_device(s).ok()).collect();
            let assembly = assemble(&scans).into_iter().next().unwrap();
            (sources, assembly, bp)
        }

        /// A tree of gang headers, every one of whose 31 pointers leads to
        /// the next level's header, and the last level all holes: the
        /// children give no bytes at all. Read as a block it was 31^8
        /// header reads, two months of them, and at a shallower depth a
        /// block of zeros that passed its checksum. It is a gang error at
        /// once.
        #[test]
        fn a_gang_whose_children_give_short_is_an_error_at_once() {
            use crate::fixture::write_at_dva;
            use zfs_ondisk::blkptr::encode::Builder;
            let pool = Pool::mirror("tank", 0x6a6e, 12)
                .txgs(&[(100, 1)])
                .with_feature(DGH);
            let mut members = vec![pool.member_image(0, SIZE), pool.member_image(1, SIZE)];
            let (levels, fanout, hsize) = (8usize, 31usize, 4096usize);
            let off = |l: usize| 0x10_0000u64 + (l * hsize) as u64;
            let gang_ptr = |at: u64| {
                Builder::new()
                    .dva(0, 0, at, hsize as u64, true)
                    .sizes(128 * 1024, 128 * 1024)
                    .props(2, 7, ot::ZVOL, 0)
                    .births(0, 100, 1)
                    .cksum([0, 0, 0, 0])
                    .bytes(Endian::Little)
            };
            for l in (0..=levels).rev() {
                let mut header = vec![0u8; hsize];
                if l < levels {
                    let child = gang_ptr(off(l + 1));
                    for i in 0..fanout {
                        header[i * 128..(i + 1) * 128].copy_from_slice(&child);
                    }
                }
                zfs_ondisk::checksum::seal_embedded(&mut header, [0, off(l), 100, 0]);
                for m in members.iter_mut() {
                    write_at_dva(m, off(l), &header);
                }
            }
            let s: Vec<MemSource> = members.into_iter().map(MemSource::new).collect();
            let scans: Vec<_> = s.iter().map(|m| scan_device(m).ok()).collect();
            let a = assemble(&scans).into_iter().next().unwrap();
            let top = BlkPtr::parse(&gang_ptr(off(0)), Endian::Little).unwrap();
            let t = std::time::Instant::now();
            let r = reader(&s, &a).read_block(&top, false);
            assert!(matches!(r, Err(ReadError::Gang(_))), "{r:?}");
            assert!(t.elapsed().as_secs() < 5, "{:?}", t.elapsed());
        }

        /// With `dynamic_gang_header` active the header is read at the
        /// vdev's smallest allocation — 4 KiB here — and every pointer
        /// in it is followed (SPEC F-26, F-70).
        #[test]
        fn dynamic_gang_header_on_a_mirror_reads_every_pointer_it_holds() {
            let (s, a, bp) = build_dynamic(true);
            assert!(bp.dva[0].gang);
            assert_eq!(bp.dva[0].asize, 4096);
            assert!(a.features_for_read.iter().any(|f| f == DGH));
            let block = reader(&s, &a).read_block(&bp, false).unwrap();
            assert_eq!(block.data, wide_payload());
            assert_eq!(block.verify, Verify::Ok);
        }

        /// A pool keeps the 512-byte headers it wrote before the feature
        /// went active (the first golden image had hundreds of them, and
        /// not one 4 KiB header): with the feature claimed, a header that
        /// does not verify at the vdev's allocation is tried at the old
        /// size, as OpenZFS tries it.
        #[test]
        fn an_old_header_on_a_pool_with_the_feature_active_still_reads() {
            let pool = Pool::mirror("tank", 0x9e9e, 12)
                .txgs(&[(100, 1)])
                .with_feature(DGH);
            let mut members = vec![pool.member_image(0, SIZE), pool.member_image(1, SIZE)];
            let mut a = Alloc::new(0x30_0000);
            let bp = a.put_gang(&mut members, &payload(), &[4096, 4096, 4096], ot::ZVOL, 100);
            let bp = BlkPtr::parse(&bp, Endian::Little).unwrap();
            let s: Vec<MemSource> = members.into_iter().map(MemSource::new).collect();
            let scans: Vec<_> = s.iter().map(|m| scan_device(m).ok()).collect();
            let a = assemble(&scans).into_iter().next().unwrap();
            assert!(a.features_for_read.iter().any(|f| f == DGH));
            let block = reader(&s, &a).read_block(&bp, false).unwrap();
            assert_eq!(block.data, payload());
            assert_eq!(block.verify, Verify::Ok);
        }

        /// The same bytes under a pool that does not claim the feature
        /// are read as a 512-byte header, whose checksum tail is not
        /// where the old format puts it: a clean gang error, never
        /// three children passed off as the block.
        #[test]
        fn the_same_header_without_the_feature_is_a_clean_gang_error() {
            let (s, a, bp) = build_dynamic(false);
            assert!(!a.features_for_read.iter().any(|f| f == DGH));
            assert!(matches!(
                reader(&s, &a).read_block(&bp, false).unwrap_err(),
                ReadError::Gang(_)
            ));
        }

        /// On a 4-wide raidz2 at `ashift=12` the smallest allocation is
        /// one 4 KiB sector too, and the header reads through parity with
        /// a member absent like any other block.
        #[test]
        fn dynamic_gang_header_on_a_raidz2_reads_whole_and_degraded() {
            let pool = Pool::raidz("tank", 0x9d9d, 12, 4, 2)
                .txgs(&[(100, 1)])
                .with_feature(DGH);
            let mut members: Vec<Vec<u8>> = (0..4).map(|i| pool.member_image(i, SIZE)).collect();
            let mut a = Alloc::with_layout(
                0x30_0000,
                Layout::Raidz {
                    ashift: 12,
                    nparity: 2,
                },
            );
            let bp = a.put_gang_sized(
                &mut members,
                &wide_payload(),
                &[4096; 5],
                ot::ZVOL,
                100,
                4096,
            );
            let bp = BlkPtr::parse(&bp, Endian::Little).unwrap();
            let s: Vec<MemSource> = members.into_iter().map(MemSource::new).collect();
            for present in [
                [true; 4],
                [false, true, true, true],
                [true, true, false, true],
            ] {
                let (a, devs) = degraded(&s, &present);
                let block = PoolReader::new(&a, devs)
                    .read_block(&bp, false)
                    .unwrap_or_else(|e| panic!("dynamic gang read with {present:?}: {e}"));
                assert_eq!(block.data, wide_payload(), "{present:?}");
            }
        }

        /// The same gang block on a 4-wide raidz2: header and children
        /// striped with parity, as ZFS lays them out there.
        fn build_raidz2() -> (Vec<MemSource>, BlkPtr) {
            let pool = Pool::raidz("tank", 0x9b9b, 12, 4, 2).txgs(&[(100, 1)]);
            let mut members: Vec<Vec<u8>> = (0..4).map(|i| pool.member_image(i, SIZE)).collect();
            let mut a = Alloc::with_layout(
                0x30_0000,
                Layout::Raidz {
                    ashift: 12,
                    nparity: 2,
                },
            );
            let bp = a.put_gang(&mut members, &payload(), &[4096, 4096, 4096], ot::ZVOL, 100);
            let bp = BlkPtr::parse(&bp, Endian::Little).unwrap();
            (members.into_iter().map(MemSource::new).collect(), bp)
        }

        /// The pool as assembled from the `present` members only, and
        /// the device list with the others absent.
        fn degraded<'a>(
            s: &'a [MemSource],
            present: &[bool],
        ) -> (PoolAssembly, Vec<Option<&'a dyn BlockSource>>) {
            let scans: Vec<_> = s
                .iter()
                .zip(present)
                .map(|(m, &p)| if p { scan_device(m).ok() } else { None })
                .collect();
            let a = assemble(&scans).into_iter().next().unwrap();
            let devs = s
                .iter()
                .zip(present)
                .map(|(m, &p)| if p { Some(m as &dyn BlockSource) } else { None })
                .collect();
            (a, devs)
        }

        /// A gang block on a degraded raidz reads through parity: the
        /// header goes through the unverified path (`read_candidates`),
        /// which is the path the lazy-parity change once left without
        /// its parity, and the children through the verified one. Each
        /// member missing in turn, then two at once — raidz2's budget.
        #[test]
        fn gang_block_on_a_degraded_raidz_reads_through_parity() {
            let (s, bp) = build_raidz2();
            assert!(bp.dva[0].gang);
            // On a 4-wide raidz2 at ashift 12 the 512-byte header is one
            // data column plus two parity columns: three units, which
            // is what vdev_raidz_asize gives for that psize.
            assert_eq!(bp.dva[0].asize, 3 * 4096);
            for present in [
                [true; 4],
                [false, true, true, true],
                [true, false, true, true],
                [true, true, false, true],
                [true, true, true, false],
                [false, true, false, true],
                [true, false, true, false],
            ] {
                let (a, devs) = degraded(&s, &present);
                let block = PoolReader::new(&a, devs)
                    .read_block(&bp, false)
                    .unwrap_or_else(|e| panic!("gang read with {present:?}: {e}"));
                assert_eq!(block.data, payload(), "{present:?}");
                assert_eq!(block.verify, Verify::Ok, "{present:?}");
            }
        }

        /// Three members gone is past raidz2's budget: a clean error
        /// from the header read, not a panic and not zeros.
        /// The tries a block gets are shared by its rows: the first of a
        /// dRAID's sixteen gets a sixteenth, not all of them, and what a row
        /// does not use passes on to the rows after it.
        #[test]
        fn the_rows_of_a_block_share_its_tries() {
            assert_eq!(super::row_share(0, 10_000, 16), 625);
            // Row 0 found nothing in 10 tries: row 1 gets its part of the rest.
            assert_eq!(super::row_share(10, 10_000, 15), 10 + 9_990 / 15);
            // The last row gets whatever is left.
            assert_eq!(super::row_share(9_000, 10_000, 1), 10_000);
            assert_eq!(super::row_share(10_000, 10_000, 3), 10_000);
        }

        #[test]
        fn gang_block_past_the_parity_budget_fails_cleanly() {
            let (s, bp) = build_raidz2();
            let present = [true, false, false, false];
            let (a, devs) = degraded(&s, &present);
            let err = PoolReader::new(&a, devs)
                .read_block(&bp, false)
                .unwrap_err();
            assert!(
                matches!(err, ReadError::Unrecoverable(_) | ReadError::Gang(_)),
                "{err}"
            );
        }

        /// A silently corrupted *data* column under the header is not
        /// healed: the unverified path reconstructs lost columns but does
        /// not search for a bad one, and the header's own checksum is
        /// what catches it. The result is a clean gang error. This pins
        /// that limitation, so that changing it is a decision and not a
        /// slip — and it pins the other half of the lazy-parity rule:
        /// the same damage on a *parity* column of a healthy row is
        /// never even read.
        #[test]
        fn gang_header_with_a_silently_bad_column_is_a_clean_error() {
            let (s, bp) = build_raidz2();
            let m = zfs_ondisk::raidz::map(bp.dva[0].offset, 4096, 12, 4, 2);
            let corrupt = |s: &mut [MemSource], c: &zfs_ondisk::raidz::Column| {
                let at = (LABEL_START_SIZE + c.offset) as usize;
                for b in s[c.devidx as usize].bytes_mut()[at..at + c.size as usize].iter_mut() {
                    *b ^= 0xa5;
                }
            };
            // Parity column bad, row healthy: not read, so not noticed.
            let mut sp = s.clone();
            corrupt(&mut sp, &m.parity()[0]);
            let present = [true; 4];
            let (a, devs) = degraded(&sp, &present);
            let block = PoolReader::new(&a, devs).read_block(&bp, false).unwrap();
            assert_eq!(block.data, payload());
            // Data column bad: the header checksum fails and nothing
            // goes looking for which column to distrust.
            let mut sd = s.clone();
            corrupt(&mut sd, &m.data()[0]);
            let (a, devs) = degraded(&sd, &present);
            let err = PoolReader::new(&a, devs)
                .read_block(&bp, false)
                .unwrap_err();
            assert!(matches!(err, ReadError::Gang(_)), "{err}");
        }
    }
}

/// The dense fixture's indirect tree says what ZFS would say about it
/// (SPEC N-03, N-08). This tool never reads `fill`, but `zdb` does, and
/// a fixture that lies to the cross-check is worse than none.
#[cfg(test)]
mod dense_tree_tests {
    use super::*;
    use crate::dsl::{open_mos, walk};
    use crate::fixture::{Dense, Pool};
    use crate::pool::assemble;
    use crate::vdev::scan_device;
    use crate::zvol::open_volume;
    use zfs_ondisk::blkptr::Compression;
    use zvolrescue_io::{BlockSource, MemSource};

    /// 2048 blocks of 4 KiB under 128 KiB indirect blocks of 1024
    /// pointers each: two L1 blocks under one L2 pointer. Every level's
    /// pointers carry the number of level-0 blocks beneath them.
    #[test]
    fn every_indirect_pointer_counts_the_blocks_beneath_it() {
        let mut pool = Pool::mirror("tank", 0xf111, 12).txgs(&[(100, 1)]);
        let dense = Dense {
            bytes: 2048 * 4096,
            blocksize: 4096,
            compression: Compression::Off,
        };
        let (members, _) = crate::fixture::dense_volume_members(&mut pool, dense);
        let sources: Vec<MemSource> = members.into_iter().map(MemSource::new).collect();
        let scans: Vec<_> = sources.iter().map(|s| scan_device(s).ok()).collect();
        let ub = scans[0].as_ref().unwrap().labels[0]
            .best()
            .unwrap()
            .ub
            .clone();
        let a = assemble(&scans).into_iter().next().unwrap();
        let reader = PoolReader::new(
            &a,
            sources
                .iter()
                .map(|m| Some(m as &dyn BlockSource))
                .collect(),
        );
        let mos = open_mos(&reader, &ub).unwrap();
        let tree = walk(&mos, "tank").unwrap();
        let ds = tree.get("tank/vm/disk0").unwrap();
        let (obj, _) = open_volume(&reader, ds).unwrap();
        let dn = obj.dnode();
        assert_eq!(dn.nlevels, 3, "2048 leaves need two indirect levels");
        let top = &dn.blkptr[0];
        assert_eq!((top.level, top.fill), (2, 2048), "the L2 pointer");
        let l2 = reader.read_block(top, false).unwrap().data;
        let l1: Vec<BlkPtr> = l2
            .chunks(zfs_ondisk::blkptr::SIZE)
            .map(|b| BlkPtr::parse(b, top.endian).unwrap())
            .filter(|b| !b.is_hole())
            .collect();
        assert_eq!(l1.len(), 2);
        for (i, bp) in l1.iter().enumerate() {
            assert_eq!((bp.level, bp.fill), (1, 1024), "L1 pointer {i}");
            let blk = reader.read_block(bp, false).unwrap().data;
            let l0: Vec<BlkPtr> = blk
                .chunks(zfs_ondisk::blkptr::SIZE)
                .map(|b| BlkPtr::parse(b, bp.endian).unwrap())
                .filter(|b| !b.is_hole())
                .collect();
            assert_eq!(l0.len(), 1024, "L1 block {i}");
            assert!(
                l0.iter().all(|b| b.level == 0 && b.fill == 1),
                "every L0 pointer under L1 block {i} is one block"
            );
        }
    }
}

/// The fixtures' dnode and objset pointers carry the object counts ZFS
/// keeps in `fill`, which `zdb -d` prints and this tool never reads: a
/// fixture that lies to the cross-check is worse than none.
#[cfg(test)]
mod objset_fill_tests {
    use super::*;
    use crate::dsl::{open_mos, walk};
    use crate::fixture::{destroyed_zvol_members, dnodes_allocated, Pool};
    use crate::pool::assemble;
    use crate::vdev::scan_device;
    use zfs_ondisk::dmu::ObjsetPhys;
    use zfs_ondisk::label::LABEL_SIZE;
    use zvolrescue_io::{BlockSource, MemSource};

    /// An objset pointer's fill is the number of allocated dnodes under
    /// its meta dnode; the meta dnode's own pointer says the same; and
    /// both equal what a count of the dnode block's slots finds.
    fn check(reader: &PoolReader<'_>, bp: &BlkPtr, what: &str) -> u64 {
        let os = ObjsetPhys::parse(&reader.read_block(bp, false).unwrap().data, bp.endian).unwrap();
        let mut counted = 0u64;
        let mut summed = 0u64;
        for child in os.meta_dnode.blkptr.iter().filter(|b| !b.is_hole()) {
            let block = reader.read_block(child, false).unwrap().data;
            let n = dnodes_allocated(&block);
            assert_eq!(
                child.fill, n,
                "{what}: a dnode block's fill is its allocated dnodes"
            );
            assert!(n > 0, "{what}: the sample dnode blocks are not empty");
            counted += n;
            summed += child.fill;
        }
        assert_eq!(
            bp.fill, summed,
            "{what}: the objset's fill is the sum under its meta dnode"
        );
        assert_eq!(bp.fill, counted, "{what}");
        counted
    }

    #[test]
    fn dnode_and_objset_pointers_count_their_objects() {
        let mut pool = Pool::mirror("tank", 0xf1e1, 12).txgs(&[(100, 1), (101, 2)]);
        let (members, _, _) = destroyed_zvol_members(&mut pool, 64 * LABEL_SIZE);
        let sources: Vec<MemSource> = members.into_iter().map(MemSource::new).collect();
        let scans: Vec<_> = sources.iter().map(|s| scan_device(s).ok()).collect();
        let ub = scans[0].as_ref().unwrap().labels[0]
            .uberblocks
            .iter()
            .find(|s| s.ub.txg == 100)
            .unwrap()
            .ub
            .clone();
        let a = assemble(&scans).into_iter().next().unwrap();
        let reader = PoolReader::new(
            &a,
            sources
                .iter()
                .map(|m| Some(m as &dyn BlockSource))
                .collect(),
        );
        // The MOS: its root pointer counts every object in it.
        let rootbp = BlkPtr::parse(&ub.rootbp, ub.endian).unwrap();
        let mos_objects = check(&reader, &rootbp, "MOS");
        assert!(
            mos_objects >= 8,
            "the sample MOS has more than a handful of objects: {mos_objects}"
        );
        // The volume's objset: the data object and its properties ZAP.
        let mos = open_mos(&reader, &ub).unwrap();
        let tree = walk(&mos, "tank").unwrap();
        let ds = tree.get("tank/vm/disk0").unwrap();
        assert_eq!(check(&reader, &ds.phys.bp, "tank/vm/disk0"), 2);
        // A filesystem with nothing in it: an empty meta dnode, fill 0.
        let fs = tree.get("tank/vm").or_else(|| tree.get("tank")).unwrap();
        if !fs.phys.bp.is_hole() {
            let os = ObjsetPhys::parse(
                &reader.read_block(&fs.phys.bp, false).unwrap().data,
                fs.phys.bp.endian,
            )
            .unwrap();
            if os.meta_dnode.blkptr.iter().all(|b| b.is_hole()) {
                assert_eq!(fs.phys.bp.fill, 0, "an empty objset counts nothing");
            }
        }
    }
}

/// Reading a pool a top-level vdev was removed from (SPEC F-69).
#[cfg(test)]
mod removed_vdev_tests {
    use super::*;
    use crate::dmu::DnodeArray;
    use crate::dsl::{open_mos, walk};
    use crate::fixture::{removed_vdev_members, zvol_pattern, Pool};
    use crate::pool::assemble;
    use crate::vdev::scan_device;
    use crate::zvol::{extract, open_volume, OnError};
    use zfs_ondisk::dmu::ObjsetPhys;
    use zfs_ondisk::label::LABEL_SIZE;
    use zfs_ondisk::uberblock::Uberblock;
    use zvolrescue_io::{BlockSource, MemSink, MemSource};

    const SIZE: u64 = 64 * LABEL_SIZE;

    fn build() -> (Vec<MemSource>, crate::pool::PoolAssembly, Uberblock) {
        let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
        let members = removed_vdev_members(&mut pool, SIZE);
        let sources: Vec<MemSource> = members.into_iter().map(MemSource::new).collect();
        let scans: Vec<_> = sources.iter().map(|s| scan_device(s).ok()).collect();
        let ub = scans[0].as_ref().expect("member scans").labels[0]
            .best()
            .expect("a verified uberblock")
            .ub
            .clone();
        let assembly = assemble(&scans).into_iter().next().expect("one pool");
        (sources, assembly, ub)
    }

    /// The volume's bytes come out whole, through a vdev that is gone.
    #[test]
    fn a_volume_addressed_on_a_removed_vdev_reads() {
        let (s, a, ub) = build();
        // The labels still count the removed vdev, and nothing describes
        // it: that is the state a pool is really in after a removal.
        assert_eq!(a.missing_tops(), vec![1]);
        let reader = PoolReader::new(&a, vec![Some(&s[0] as &dyn BlockSource)]);
        let mos = open_mos(&reader, &ub).expect("MOS opens: it is on the vdev that remains");
        assert_eq!(
            reader.removed_vdevs(),
            vec![(1, 4)],
            "the mapping of vdev 1 should have come from the MOS configuration"
        );
        let tree = walk(&mos, "tank").expect("dataset tree");
        let ds = tree.get("tank/vm/disk0").expect("the volume");
        let (obj, _) = open_volume(&reader, ds).expect("volume opens");
        let mut sink = MemSink::default();
        let r = extract(
            &obj,
            ds.volsize.expect("volsize"),
            &mut sink,
            OnError::Zero,
            |_, _| {},
        )
        .expect("extraction");
        assert!(r.bad.is_empty() && !r.aborted);
        assert_eq!(&sink.data[..8192], &zvol_pattern(0)[..]);
        assert_eq!(&sink.data[16384..24576], &zvol_pattern(2)[..]);
        assert_eq!(
            reader.mismatches(),
            0,
            "a mistranslation would have shown up here: the checksum is of \
             the bytes, and the bytes are somewhere else entirely"
        );
    }

    /// And without the mapping they do not, which is what makes the test
    /// above a test of the translation and not of the fixture.
    #[test]
    fn without_the_mapping_the_same_blocks_are_refused_by_name() {
        let (s, a, ub) = build();
        let reader = PoolReader::new(&a, vec![Some(&s[0] as &dyn BlockSource)]);
        // Reach the MOS without going through `open_mos`, which is what
        // loads the mapping. This is what the tool did before F-69, and
        // what it still does when the configuration object is unreadable.
        let rootbp =
            zfs_ondisk::blkptr::BlkPtr::parse(&ub.rootbp, ub.endian).expect("root pointer");
        let block = reader.read_block(&rootbp, false).expect("MOS objset");
        let os = ObjsetPhys::parse(&block.data, rootbp.endian).expect("objset");
        let mos = DnodeArray::new(&reader, os.meta_dnode, rootbp.endian);
        assert!(reader.removed_vdevs().is_empty());
        let tree = walk(&mos, "tank").expect("the dataset tree is not on the removed vdev");
        let ds = tree.get("tank/vm/disk0").expect("the volume");
        let (obj, _) = open_volume(&reader, ds).expect("its dnode is not on it either");
        let mut sink = MemSink::default();
        let r = extract(
            &obj,
            ds.volsize.expect("volsize"),
            &mut sink,
            OnError::Zero,
            |_, _| {},
        )
        .expect("a refused block is reported, not fatal");
        assert_eq!(r.bad.len(), 2, "both data blocks are out of reach");
        assert!(
            r.bad
                .iter()
                .all(|b| b.reason.contains("unknown top-level vdev 1")),
            "expected refusals naming the removed vdev, got {:?}",
            r.bad.iter().map(|b| b.reason.clone()).collect::<Vec<_>>()
        );
    }

    /// The same removal, with the copied blocks landing on a 4-wide
    /// raidz2 — the shape `zpool remove` of a mirror leaves when the
    /// pool's other top is raidz. Read with each member missing in
    /// turn: the remapped read goes through `read_candidates`, the
    /// unverified path, and a lost column there is rebuilt from parity.
    #[test]
    fn a_volume_remapped_onto_a_degraded_raidz_reads() {
        let mut pool = Pool::raidz("tank", 0x4343, 12, 4, 2).txgs(&[(100, 1)]);
        let members = removed_vdev_members(&mut pool, SIZE);
        let sources: Vec<MemSource> = members.into_iter().map(MemSource::new).collect();
        for present in [
            [true; 4],
            [false, true, true, true],
            [true, false, true, true],
            [true, true, false, true],
            [true, true, true, false],
            [true, false, false, true],
        ] {
            let scans: Vec<_> = sources
                .iter()
                .zip(&present)
                .map(|(m, &p)| if p { scan_device(m).ok() } else { None })
                .collect();
            let ub = scans
                .iter()
                .flatten()
                .next()
                .expect("a present member")
                .labels[0]
                .best()
                .expect("a verified uberblock")
                .ub
                .clone();
            let a = assemble(&scans).into_iter().next().expect("one pool");
            assert_eq!(a.missing_tops(), vec![1], "{present:?}");
            let devs: Vec<Option<&dyn BlockSource>> = sources
                .iter()
                .zip(&present)
                .map(|(m, &p)| if p { Some(m as &dyn BlockSource) } else { None })
                .collect();
            let reader = PoolReader::new(&a, devs);
            let mos =
                open_mos(&reader, &ub).unwrap_or_else(|e| panic!("MOS with {present:?}: {e}"));
            assert_eq!(reader.removed_vdevs(), vec![(1, 2)], "{present:?}");
            let tree = walk(&mos, "tank").expect("dataset tree");
            let ds = tree.get("tank/vm/disk0").expect("the volume");
            let (obj, _) = open_volume(&reader, ds).expect("volume opens");
            let mut sink = MemSink::default();
            let r = extract(
                &obj,
                ds.volsize.expect("volsize"),
                &mut sink,
                OnError::Zero,
                |_, _| {},
            )
            .expect("extraction");
            assert!(r.bad.is_empty() && !r.aborted, "{present:?}: {:?}", r.bad);
            assert_eq!(&sink.data[..8192], &zvol_pattern(0)[..], "{present:?}");
            assert_eq!(
                &sink.data[16384..24576],
                &zvol_pattern(2)[..],
                "{present:?}"
            );
            assert_eq!(reader.mismatches(), 0, "{present:?}");
        }
    }
}

/// Reading through the mapping a removed vdev leaves behind, with the
/// mapping installed by hand so that each shape can be tried on its
/// own (SPEC F-69).
#[cfg(test)]
mod mapping_reader_tests {
    use super::*;
    use crate::dsl::{open_mos, walk};
    use crate::fixture::{build_sample_mos, zvol_pattern, Alloc, Pool, SAMPLE_ZVOL_BLOCK0_OFFSET};
    use crate::pool::assemble;
    use crate::vdev::scan_device;
    use crate::zvol::open_volume;
    use zfs_ondisk::indirect::{Entry, Mapping};
    use zfs_ondisk::label::LABEL_SIZE;
    use zfs_ondisk::uberblock::Uberblock;
    use zvolrescue_io::MemSource;

    const SIZE: u64 = 64 * LABEL_SIZE;
    /// An address in a removed vdev's own space, nowhere near where the
    /// bytes are: a reader that ignored the mapping could not land on
    /// them by luck.
    const AWAY: u64 = 0x100_0000;
    const BLOCK: u64 = 8192;

    /// A two-way mirror with the sample MOS, every pointer on vdev 0.
    /// `damage` flips one byte of one member at an absolute offset.
    fn build(
        damage: Option<(usize, u64)>,
    ) -> (Vec<MemSource>, crate::pool::PoolAssembly, Uberblock) {
        let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
        let mut members = vec![vec![0u8; SIZE as usize], vec![0u8; SIZE as usize]];
        let mut a = Alloc::new(0x20_0000);
        build_sample_mos(&mut pool, &mut members, &mut a);
        for (i, m) in members.iter_mut().enumerate() {
            pool.write_labels(i, m);
        }
        if let Some((member, at)) = damage {
            members[member][at as usize] ^= 0xff;
        }
        let sources: Vec<MemSource> = members.into_iter().map(MemSource::new).collect();
        let scans: Vec<_> = sources.iter().map(|s| scan_device(s).ok()).collect();
        let ub = scans[0].as_ref().expect("scan").labels[0]
            .best()
            .expect("ub")
            .ub
            .clone();
        let assembly = assemble(&scans).into_iter().next().expect("one pool");
        (sources, assembly, ub)
    }

    fn reader<'a>(s: &'a [MemSource], a: &crate::pool::PoolAssembly) -> PoolReader<'a> {
        PoolReader::new(a, s.iter().map(|x| Some(x as &dyn BlockSource)).collect())
    }

    /// The volume's first data block pointer, renamed onto `vdev` at
    /// `offset`. The checksum is untouched: it is of the bytes, and the
    /// bytes have not moved.
    fn block0_on(reader: &PoolReader<'_>, ub: &Uberblock, vdev: u32, offset: u64) -> BlkPtr {
        let mos = open_mos(reader, ub).expect("MOS");
        let tree = walk(&mos, "tank").expect("tree");
        let ds = tree.get("tank/vm/disk0").expect("the volume");
        let (obj, _) = open_volume(reader, ds).expect("volume");
        let mut bp = obj.locate(0).expect("locate").expect("block 0 is data");
        assert_eq!(
            (bp.dva[0].vdev, bp.dva[0].offset),
            (0, SAMPLE_ZVOL_BLOCK0_OFFSET)
        );
        assert_eq!(bp.dva[0].asize, BLOCK);
        bp.dva[0].vdev = vdev;
        bp.dva[0].offset = offset;
        bp
    }

    fn entry(src: u64, dst_vdev: u32, dst_offset: u64) -> Entry {
        Entry {
            src,
            size: BLOCK,
            dst_vdev,
            dst_offset,
        }
    }

    #[test]
    fn a_pointer_onto_a_removed_vdev_reads_through_its_mapping() {
        let (s, a, ub) = build(None);
        let r = reader(&s, &a);
        let bp = block0_on(&r, &ub, 7, AWAY);
        // Before the mapping is known, the vdev is unknown.
        assert_eq!(
            r.read_block(&bp, false).unwrap_err(),
            ReadError::UnknownVdev(7)
        );
        r.set_removed_mapping(
            7,
            Mapping::from_entries(vec![entry(AWAY, 0, SAMPLE_ZVOL_BLOCK0_OFFSET)]),
        );
        let block = r.read_block(&bp, false).expect("reads through the mapping");
        assert_eq!(block.verify, Verify::Ok);
        assert_eq!(block.data, zvol_pattern(0));
        assert_eq!(r.removed_vdevs(), vec![(7, 1)]);
    }

    /// The raw read `zvolcarve` uses goes through the same translation:
    /// a DVA on a removed vdev yields the bytes, and says which member
    /// they came from.
    #[test]
    fn a_raw_read_of_a_dva_on_a_removed_vdev_is_translated_too() {
        let (s, a, ub) = build(None);
        let r = reader(&s, &a);
        let bp = block0_on(&r, &ub, 7, AWAY);
        assert_eq!(
            r.read_dva(&bp.dva[0], BLOCK as usize).unwrap_err(),
            ReadError::UnknownVdev(7)
        );
        r.set_removed_mapping(
            7,
            Mapping::from_entries(vec![entry(AWAY, 0, SAMPLE_ZVOL_BLOCK0_OFFSET)]),
        );
        let (bytes, device) = r.read_dva(&bp.dva[0], BLOCK as usize).expect("translated");
        assert_eq!(bytes, zvol_pattern(0));
        // A translated read is joined from pieces and has no one member
        // to name; the caller gets the sentinel, not a made-up index.
        assert_eq!(device, usize::MAX);
    }

    /// A vdev removed onto another that was itself removed later: the
    /// mapping is followed twice.
    #[test]
    fn a_mapping_that_lands_on_another_removed_vdev_is_followed_through() {
        let (s, a, ub) = build(None);
        let r = reader(&s, &a);
        let bp = block0_on(&r, &ub, 8, AWAY);
        r.set_removed_mapping(
            7,
            Mapping::from_entries(vec![entry(AWAY, 0, SAMPLE_ZVOL_BLOCK0_OFFSET)]),
        );
        r.set_removed_mapping(8, Mapping::from_entries(vec![entry(AWAY, 7, AWAY)]));
        let block = r.read_block(&bp, false).expect("two hops");
        assert_eq!(block.verify, Verify::Ok);
        assert_eq!(block.data, zvol_pattern(0));
    }

    /// A range the mapping does not cover is refused by name, not read
    /// from somewhere near.
    #[test]
    fn a_gap_in_the_mapping_is_refused_and_says_where() {
        let (s, a, ub) = build(None);
        let r = reader(&s, &a);
        r.set_removed_mapping(
            7,
            Mapping::from_entries(vec![entry(AWAY, 0, SAMPLE_ZVOL_BLOCK0_OFFSET)]),
        );
        let bp = block0_on(&r, &ub, 7, AWAY + 0x10000);
        let err = r.read_block(&bp, false).unwrap_err();
        assert!(matches!(err, ReadError::Unmapped(7, _)), "{err}");
        assert!(
            err.to_string()
                .contains("not in the removed vdev's mapping"),
            "{err}"
        );
    }

    /// A mapping that points at itself is a malformed pool, not an
    /// infinite read.
    #[test]
    fn a_mapping_that_loops_is_cut_off() {
        let (s, a, ub) = build(None);
        let r = reader(&s, &a);
        r.set_removed_mapping(9, Mapping::from_entries(vec![entry(AWAY, 9, AWAY)]));
        let bp = block0_on(&r, &ub, 9, AWAY);
        let err = r.read_block(&bp, false).unwrap_err();
        assert!(err.to_string().contains("nested deeper than 8"), "{err}");
    }

    /// The claim in the changelog: a piece that landed on a mirror still
    /// offers each side. One side is damaged at the destination; the
    /// read comes back through the other, and the attempts say so.
    #[test]
    fn a_mirror_destination_still_offers_its_other_side() {
        let damaged_at = LABEL_START_SIZE + SAMPLE_ZVOL_BLOCK0_OFFSET + 100;
        let (s, a, ub) = build(Some((0, damaged_at)));
        let r = reader(&s, &a);
        let bp = block0_on(&r, &ub, 7, AWAY);
        r.set_removed_mapping(
            7,
            Mapping::from_entries(vec![entry(AWAY, 0, SAMPLE_ZVOL_BLOCK0_OFFSET)]),
        );
        let block = r.read_block(&bp, false).expect("the other side");
        assert_eq!(block.verify, Verify::Ok);
        assert_eq!(block.data, zvol_pattern(0));
        let outcomes: Vec<_> = block.attempts.iter().map(|t| t.result.clone()).collect();
        assert_eq!(outcomes, vec![Ok(Verify::Mismatch), Ok(Verify::Ok)]);
        assert_eq!(r.mismatches(), 1);
    }
}
