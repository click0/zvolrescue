//! Scanning raw vdev space for metadata nothing points at any more
//! (COMPANIONS C-01, C-03, C-04, C-08, C-10).
//!
//! When the uberblock ring has rolled past the last transaction group
//! that referenced a dataset, no walk can reach it: there is no path
//! from any uberblock down to its dnode. The blocks are usually still
//! there, though, and a dnode is recognisable on its own. This module
//! streams a member from end to end and hands every slot that could be
//! a dnode to the recogniser in `zfs-ondisk`.
//!
//! Two passes over the same bytes, because metadata is usually
//! compressed:
//!
//! * **plaintext** — every 512-byte slot, which is where a dnode sits
//!   inside a dnode block that was written uncompressed;
//! * **lz4** — every block-sized offset tried as the start of a
//!   compressed block, since OpenZFS compresses metadata with lz4 by
//!   default and a compressed dnode block matches nothing in plaintext.
//!
//! Read-only, streaming and bounded: one buffer, whatever the member's
//! size, and nothing is written anywhere.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use zfs_ondisk::blkptr;
use zfs_ondisk::carve::{plausible_dnode, plausible_head, Profile, Reject};
use zfs_ondisk::compress;
use zfs_ondisk::dmu::{ot, DnodePhys, ObjsetPhys, ObjsetType, DNODE_SIZE};
use zfs_ondisk::Endian;
use zvolrescue_io::{trace, BlockSource};

/// How the bytes of a hit were found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Found {
    /// The dnode was on disk as it is in memory.
    Plaintext,
    /// It came out of a compressed block at this offset.
    Compressed(Codec),
}

impl Found {
    /// Stable name for the report.
    pub fn as_str(self) -> &'static str {
        match self {
            Found::Plaintext => "plaintext",
            Found::Compressed(c) => c.as_str(),
        }
    }
}

/// A compression a metadata block may have been written with.
///
/// lz4 is what OpenZFS has used for metadata since the `lz4_compress`
/// feature; a pool made before it used lzjb, and a pool whose datasets
/// were given `compression=gzip` or `zstd` can carry those too. Which
/// ones are worth trying is the operator's call, because each one costs
/// a pass over every allocation-aligned offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Codec {
    /// `lz4`, the default for metadata on any modern pool.
    Lz4,
    /// `lzjb`, the default before lz4.
    Lzjb,
    /// `gzip-N`, a zlib stream.
    Gzip,
    /// `zstd`, as OpenZFS frames it.
    Zstd,
}

impl Codec {
    /// Stable name, as written on the command line and in the report.
    pub fn as_str(self) -> &'static str {
        match self {
            Codec::Lz4 => "lz4",
            Codec::Lzjb => "lzjb",
            Codec::Gzip => "gzip",
            Codec::Zstd => "zstd",
        }
    }

    /// From the name, for the command line.
    pub fn named(name: &str) -> Option<Codec> {
        match name {
            "lz4" => Some(Codec::Lz4),
            "lzjb" => Some(Codec::Lzjb),
            "gzip" => Some(Codec::Gzip),
            "zstd" => Some(Codec::Zstd),
            _ => None,
        }
    }

    /// Every one this build knows, in the order they are tried.
    pub const ALL: [Codec; 4] = [Codec::Lz4, Codec::Lzjb, Codec::Gzip, Codec::Zstd];

    /// Whether a block starting here could be this compression, judged
    /// on its first bytes alone.
    ///
    /// This is what keeps the pass affordable: three of the four frame
    /// themselves in a way that settles nearly every offset without
    /// decompressing anything. lzjb does not, which is why it costs what
    /// it costs and is not tried unless asked for.
    fn could_start(self, buf: &[u8], lsize: u64) -> bool {
        match self {
            Codec::Lz4 => {
                let Some(head) = buf.get(0..4) else {
                    return false;
                };
                let clen = u64::from(u32::from_be_bytes(head.try_into().expect("4 bytes")));
                // A compressed block is never as long as what it
                // decompresses to, and never longer than the buffer.
                clen > 0 && clen < lsize && (clen as usize) + 4 <= buf.len()
            }
            // A zlib stream: the low nibble of the first byte is the
            // method (8 = deflate) and the two bytes are a multiple of 31.
            Codec::Gzip => match buf.get(0..2) {
                Some([a, b]) => a & 0x0f == 8 && (u16::from(*a) * 256 + u16::from(*b)) % 31 == 0,
                _ => false,
            },
            // OpenZFS puts the decompressed size and the level in front
            // of a magicless zstd frame.
            Codec::Zstd => compress::zstd_header(buf)
                .is_some_and(|(_, size)| u64::from(size) > 0 && u64::from(size) <= lsize),
            // lzjb has no header at all: every offset has to be tried.
            Codec::Lzjb => true,
        }
    }

    /// Decompress `buf` to exactly `lsize` bytes.
    fn decompress(self, buf: &[u8], lsize: usize) -> Option<Vec<u8>> {
        match self {
            Codec::Lz4 => compress::lz4(buf, lsize).ok(),
            Codec::Lzjb => compress::lzjb(buf, lsize).ok(),
            Codec::Gzip => compress::gzip(buf, lsize).ok(),
            Codec::Zstd => compress::zstd(buf, lsize).ok(),
        }
    }
}

/// One dnode the scan found.
#[derive(Debug, Clone)]
pub struct Hit {
    /// Index of the member it was found on.
    pub device: usize,
    /// Offset in that member where the dnode's first slot starts. For a
    /// compressed hit this is the start of the compressed block, plus
    /// the slot's offset inside it in `slot`.
    pub offset: u64,
    /// Slot index inside the block, for a compressed hit.
    pub slot: u64,
    /// How it was found.
    pub found: Found,
    /// The dnode itself.
    pub dnode: DnodePhys,
    /// Profile fields it failed, empty when it matched everything asked
    /// for. A soft profile keeps these; a strict one never records them.
    pub misses: Vec<Reject>,
}

/// How many hits each reason accounted for (C-14, C-15).
#[derive(Debug, Clone, Default)]
pub struct Counts(pub BTreeMap<Reject, u64>);

impl Counts {
    fn bump(&mut self, r: Reject) {
        *self.0.entry(r).or_insert(0) += 1;
    }

    /// Reasons that rejected at least one candidate, most first, then by
    /// name so two runs of the same evidence read the same.
    pub fn ranked(&self) -> Vec<(Reject, u64)> {
        let mut v: Vec<(Reject, u64)> = self.0.iter().map(|(r, n)| (*r, *n)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v
    }

    /// Rejections that came from the profile rather than from the bytes.
    /// This is the number that tells "the filter is too tight" from
    /// "there is nothing here" (C-14).
    pub fn by_profile(&self) -> u64 {
        self.0
            .iter()
            .filter(|(r, _)| r.is_profile())
            .map(|(_, n)| n)
            .sum()
    }
}

/// What to scan and what to look for.
#[derive(Debug, Clone)]
pub struct Options {
    /// The search profile (C-13).
    pub profile: Profile,
    /// Profile fields are hard filters rather than hints (C-18).
    pub strict_profile: bool,
    /// Byte range of the member to read; the whole member when absent.
    pub range: Option<(u64, u64)>,
    /// Compressions to try at each allocation-aligned offset (C-10).
    /// Empty means the plaintext pass only.
    pub codecs: Vec<Codec>,
    /// Block sizes to try when decompressing, largest first.
    pub block_sizes: Vec<u64>,
    /// Stop after the chunk in which this many hits have been found, so
    /// a wide search can be bounded. The chunk is finished first: a scan
    /// stopped in the middle of one had looked at part of it, and the
    /// resume that went on from the chunk's start met the same hits,
    /// reached the same bound, and never got further. A caller that
    /// wants exactly this many takes the first of them by offset and
    /// goes on from the one after (see [`Scan::capped`]).
    pub max_hits: usize,
    /// Collect dnode candidates at all.
    ///
    /// The header search (SPEC F-64) wants none of them, and setting
    /// `max_hits` to zero to say so would stop the whole scan at the
    /// first dnode it met — the cap bounds the *scan*, not just the
    /// list. Saying it here instead leaves the scan running to the end
    /// of the member, which is what a search for one header needs.
    pub collect_hits: bool,
    /// Read this many bytes at a time.
    pub chunk: usize,
    /// Where the vdev starts on the member (SPEC F-60). Blocks are
    /// allocated at multiples of the ashift from there, not from the
    /// member's first byte: on a partition that starts at sector 63 a
    /// pass that stepped from byte 0 tried no offset a block was at.
    pub vdev_start: u64,
    /// Count nothing before this offset: slots, rejections, bytes. A
    /// resume reads again what an interrupted run had read and counted,
    /// and counted it twice — more slots than both members have.
    pub count_from: u64,
    /// Looked at before every chunk: once it is set the scan stops
    /// where that chunk begins, says so in `stopped_early`, and
    /// `resume_at` names the offset — how a SIGINT ends a scan that
    /// `--resume` continues (C-08) instead of killing one.
    pub stop: Option<Arc<AtomicBool>>,
}

impl Options {
    /// Whether what is at `offset` is counted (see `count_from`).
    fn counts(&self, offset: u64) -> bool {
        offset >= self.count_from
    }
}

impl Default for Options {
    fn default() -> Self {
        Options {
            profile: Profile::default(),
            strict_profile: false,
            range: None,
            // All of them by default. lz4 is what metadata is written
            // with on any modern pool, but a pool made before the
            // `lz4_compress` feature used lzjb, and for such a pool an
            // lz4-only scan finds nothing at all — a silent, total
            // failure for exactly the operators most likely to need
            // this. On a ztest pool the other three cost about a
            // quarter again on top of lz4, which is the cheaper
            // mistake.
            codecs: Codec::ALL.to_vec(),
            // The sizes a dnode block is written at: `dnodesize` blocks
            // are 16 KiB by default, 32 KiB and 128 KiB for large dnodes
            // and busy objsets.
            block_sizes: vec![16384, 32768, 131072],
            max_hits: 100_000,
            collect_hits: true,
            chunk: 4 << 20,
            vdev_start: 0,
            count_from: 0,
            stop: None,
        }
    }
}

/// What one pass over one member found.
#[derive(Debug, Clone, Default)]
pub struct Scan {
    /// Candidates that survived both tests, in the order they were met.
    pub hits: Vec<Hit>,
    /// How many candidates each reason accounted for.
    pub counts: Counts,
    /// Bytes read from the member.
    pub bytes_read: u64,
    /// 512-byte slots the cheap test looked at.
    pub slots_examined: u64,
    /// Offset the scan reached, so it can be resumed from there (C-08).
    pub resume_at: u64,
    /// The scan stopped before the end of the range.
    pub stopped_early: bool,
    /// It stopped because it held `max_hits` hits, not because it was
    /// asked to: every slot of the chunks it read was looked at and every
    /// hit is in `hits` — possibly more than `max_hits` — and
    /// `resume_at` is past the last of those chunks.
    pub capped: bool,
    /// Bytes of the range that could not be read, and so were not
    /// searched: sectors an imager's map refuses, chunks a device did.
    pub unreadable_bytes: u64,
    /// Dataset dnodes met along the way, whatever the profile asked for
    /// (C-11). A candidate whose DSL metadata survived somewhere on the
    /// disk can be named from these, and a search for volumes would
    /// otherwise throw them away.
    pub datasets: Vec<Hit>,
    /// Object-set headers of the MOS met along the way (SPEC F-64), for
    /// a pool whose uberblock rings are gone and which therefore has no
    /// root pointer to follow.
    pub roots: Vec<RootHit>,
    /// More headers were found than [`MAX_ROOTS`] and the rest were
    /// dropped. Said rather than left to be inferred from a round number.
    pub roots_truncated: bool,
}

/// An object-set header found in raw space (SPEC F-64).
#[derive(Debug, Clone)]
pub struct RootHit {
    /// Index of the member it was found on.
    pub device: usize,
    /// Offset in that member where the header starts. For a compressed
    /// hit this is the start of the compressed block.
    pub offset: u64,
    /// How it was found.
    pub found: Found,
    /// The header itself.
    pub objset: ObjsetPhys,
}

/// How many object-set headers are kept before the list is truncated.
///
/// The test below is specific enough that a real member yields a
/// handful; a cap only matters for a disk whose bytes happen to be
/// adversarial, and a truncated list that says it was truncated beats
/// one that grows until the machine gives out.
const MAX_ROOTS: usize = 4096;

/// Try `buf` as the start of the MOS's `objset_phys_t` (SPEC F-64).
///
/// An objset header begins with its meta-dnode, so the first 512 bytes
/// have to parse as a dnode of type `DMU_OT_DNODE` before anything
/// after them is worth reading — which settles almost every offset for
/// the price of the check the dnode scan already makes.
///
/// Only `DMU_OST_META` is collected. A filesystem's or a volume's
/// objset is reached *through* the MOS, so one found loose says nothing
/// about where the pool's root is; and a meta-dnode with no block
/// pointer has no dnode array under it, which is the one thing this is
/// being found for.
fn as_meta_objset(buf: &[u8]) -> Option<ObjsetPhys> {
    if buf.len() < 1024 {
        return None;
    }
    plausible_head(buf).ok()?;
    let os = ObjsetPhys::parse(buf, Endian::Little).ok()?;
    if os.meta_dnode.object_type != ot::DNODE || os.os_type != ObjsetType::Meta {
        return None;
    }
    os.meta_dnode
        .blkptr
        .iter()
        .any(|b| !b.is_hole())
        .then_some(os)
}

/// Record an object-set header, unless the list is already full.
fn consider_root(scan: &mut Scan, device: usize, offset: u64, found: Found, objset: ObjsetPhys) {
    if scan.roots.len() >= MAX_ROOTS {
        scan.roots_truncated = true;
        return;
    }
    scan.roots.push(RootHit {
        device,
        offset,
        found,
        objset,
    });
}

/// Judge one candidate dnode and, if it survives, record it.
///
/// The structural test comes first and is absolute; the profile comes
/// second and, unless it was made strict, only annotates.
fn consider(
    scan: &mut Scan,
    opts: &Options,
    device: usize,
    offset: u64,
    slot: u64,
    found: Found,
    dnode: DnodePhys,
) {
    if !opts.collect_hits {
        return;
    }
    let counting = opts.counts(offset);
    if let Err(r) = plausible_dnode(&dnode) {
        if counting {
            scan.counts.bump(r);
        }
        return;
    }
    // A dataset dnode is kept whatever was asked for: it is not a
    // candidate, it is what lets one be named (C-11).
    if dnode.object_type == zfs_ondisk::dmu::ot::DSL_DATASET && scan.datasets.len() < opts.max_hits
    {
        scan.datasets.push(Hit {
            device,
            offset,
            slot,
            found,
            dnode: dnode.clone(),
            misses: Vec::new(),
        });
    }
    let misses = opts.profile.misses(&dnode);
    if counting {
        for m in &misses {
            scan.counts.bump(*m);
        }
    }
    if opts.strict_profile && !misses.is_empty() {
        return;
    }
    trace!(
        "carve",
        "hit: device {device} offset {offset:#x} slot {slot} {} type {} datablksz {} nlevels {} maxblkid {}",
        found.as_str(),
        dnode.type_name(),
        dnode.datablksz(),
        dnode.nlevels,
        dnode.maxblkid
    );
    scan.hits.push(Hit {
        device,
        offset,
        slot,
        found,
        dnode,
        misses,
    });
}

/// Every 512-byte slot of `buf` that could be a dnode.
///
/// Every slot that starts in the first `own` bytes is examined, and read
/// from the whole of `buf`: a dnode or an object-set header in the last
/// slot of a chunk runs past it, and cut at the chunk's end it was not
/// one — the MOS header that held the newest pool was lost that way to
/// where a `--range` happened to start, and a dnode starting in a range
/// that ended inside its slot.
fn plaintext_pass(
    scan: &mut Scan,
    opts: &Options,
    device: usize,
    base: u64,
    buf: &[u8],
    own: usize,
) {
    let mut at = 0usize;
    while at < own && at + DNODE_SIZE <= buf.len() {
        let counting = opts.counts(base + at as u64);
        if counting {
            scan.slots_examined += 1;
        }
        match plausible_head(&buf[at..]) {
            Err(r) => {
                if counting {
                    scan.counts.bump(r);
                }
            }
            Ok(()) => match DnodePhys::parse(&buf[at..], Endian::Little) {
                Ok(d) => consider(scan, opts, device, base + at as u64, 0, Found::Plaintext, d),
                Err(_) => {
                    if counting {
                        scan.counts.bump(Reject::BonusLen);
                    }
                }
            },
        }
        if let Some(os) = as_meta_objset(&buf[at..]) {
            consider_root(scan, device, base + at as u64, Found::Plaintext, os);
        }
        at += DNODE_SIZE;
    }
}

/// Try `buf` at `at` as the start of an lz4-compressed block.
///
/// OpenZFS frames lz4 with a big-endian four-byte compressed length, so
/// a length that does not fit the block is settled without decompressing
/// anything — which is what keeps this pass affordable.
fn compressed_pass(
    scan: &mut Scan,
    opts: &Options,
    device: usize,
    base: u64,
    buf: &[u8],
    at: usize,
) {
    let Some(here) = buf.get(at..) else {
        return;
    };
    for codec in &opts.codecs {
        for lsize in &opts.block_sizes {
            if !codec.could_start(here, *lsize) {
                continue;
            }
            let Some(out) = codec.decompress(here, *lsize as usize) else {
                continue;
            };
            if let Some(os) = as_meta_objset(&out) {
                consider_root(
                    scan,
                    device,
                    base + at as u64,
                    Found::Compressed(*codec),
                    os,
                );
            }
            let mut slot = 0u64;
            let mut off = 0usize;
            let counting = opts.counts(base + at as u64);
            while off + DNODE_SIZE <= out.len() {
                if counting {
                    scan.slots_examined += 1;
                }
                // Counted the same way as a slot read in plaintext: a
                // rejection reason for every slot looked at is what
                // makes an empty result readable (C-15).
                match plausible_head(&out[off..]) {
                    Err(r) => {
                        if counting {
                            scan.counts.bump(r);
                        }
                    }
                    Ok(()) => match DnodePhys::parse(&out[off..], Endian::Little) {
                        Ok(d) => consider(
                            scan,
                            opts,
                            device,
                            base + at as u64,
                            slot,
                            Found::Compressed(*codec),
                            d,
                        ),
                        Err(_) => {
                            if counting {
                                scan.counts.bump(Reject::BonusLen);
                            }
                        }
                    },
                }
                off += DNODE_SIZE;
                slot += 1;
            }
            // One size that decompressed cleanly is enough; trying the
            // rest would report the same block again under another name.
            break;
        }
    }
}

/// Scan one member.
///
/// `ashift` sets the granularity of the compressed pass: a block starts
/// at an allocation boundary, so nothing in between needs trying.
pub fn scan_member(
    src: &dyn BlockSource,
    device: usize,
    ashift: u32,
    opts: &Options,
) -> std::io::Result<Scan> {
    let size = src.size();
    let (start, end) = opts.range.unwrap_or((0, size));
    // Dnodes sit on 512-byte slots, and a range is the slots that start
    // in it: it is read from the slot its start is in to the first slot
    // boundary at or past its end. Ended where it was asked, a scan done
    // in parts went on from a byte that is no boundary, and read every
    // slot after it off by the difference — the dnodes there were never
    // seen, and the scan said it was complete.
    let start = start / 512 * 512;
    let end = end.next_multiple_of(512).min(size);
    let step = 1u64 << ashift.clamp(9, 17);
    let mut scan = Scan {
        resume_at: start,
        ..Scan::default()
    };
    // A block that starts near the end of a chunk has to be readable
    // whole, so each read carries a tail past its own chunk. The tail is
    // the largest thing that is actually looked at — the biggest
    // compressed block tried, or one dnode's worth of slots — not the
    // largest block ZFS can write: an overlap of 16 MiB on a 4 MiB chunk
    // would read every byte of the member five times.
    let overlap = opts
        .block_sizes
        .iter()
        .copied()
        .max()
        .unwrap_or(0)
        .max(DNODE_SIZE as u64 * 256) as usize
        + 4;
    let mut at = start;
    let mut buf = vec![0u8; opts.chunk + overlap];
    while at < end {
        if opts
            .stop
            .as_ref()
            .is_some_and(|s| s.load(Ordering::Relaxed))
        {
            trace!(
                "carve",
                "device {device} offset {at:#x}: interrupted, stopping here"
            );
            scan.stopped_early = true;
            scan.resume_at = at;
            break;
        }
        let want = ((end - at) as usize + overlap).min(buf.len());
        let readable = (size - at).min(want as u64) as usize;
        if readable < DNODE_SIZE {
            break;
        }
        let window = &mut buf[..readable];
        // Only offsets that start inside this chunk are examined; the
        // overlap belongs to the next one.
        let own = (opts.chunk).min((end - at) as usize);
        // A sector the imager could not read is not a reason to lose
        // the 4 MiB around it: the chunk is read again around it, the
        // sector left as zeros, and counted (SPEC F-72). A device is
        // asked once (N-10); its refusal skips the chunk, counted too.
        // What of this chunk is counted: none of it a resume read and
        // counted before.
        let own_from = opts.count_from.saturating_sub(at).min(own as u64);
        match src.read_at_salvaging(at, window) {
            Ok(bad) => {
                scan.unreadable_bytes += bad
                    .iter()
                    .map(|&(s, l)| (s + l).min(own as u64).saturating_sub(s.max(own_from)))
                    .sum::<u64>();
                if !bad.is_empty() {
                    trace!(
                        "carve",
                        "device {device} offset {at:#x}: {} unreadable range(s), read around",
                        bad.len()
                    );
                }
            }
            Err(e) => {
                trace!(
                    "carve",
                    "device {device} offset {at:#x}: {e}; skipping chunk"
                );
                scan.unreadable_bytes += own as u64 - own_from;
                at += opts.chunk as u64;
                scan.resume_at = at;
                continue;
            }
        }
        // The chunk's own bytes: the tail read past it is the next
        // chunk's, and counted there.
        scan.bytes_read += (own.min(readable) as u64).saturating_sub(own_from);
        plaintext_pass(&mut scan, opts, device, at, window, own.min(readable));
        if !opts.codecs.is_empty() {
            // The first allocation boundary in this chunk, counted from
            // where the vdev starts.
            let mut off = (opts.vdev_start as i128 - at as i128).rem_euclid(step as i128) as usize;
            while off < own && off < readable {
                compressed_pass(&mut scan, opts, device, at, window, off);
                off += step as usize;
            }
        }
        at += opts.chunk as u64;
        scan.resume_at = at.min(end);
        if opts.collect_hits && scan.hits.len() >= opts.max_hits {
            scan.capped = true;
            scan.stopped_early = at < end;
            break;
        }
    }
    Ok(scan)
}

/// A candidate's final rank, once its tree has been walked (C-05).
///
/// The profile decides the half of the range a candidate lands in, and
/// the evidence decides where in that half. A candidate that matched
/// everything asked for scores 0.5 or above and one that did not scores
/// below 0.5 — always, whatever else it has going for it. That is what
/// C-18 asks for: a hint that was wrong costs ranking rather than the
/// recovery, and a hint that was right is not outvoted by a well-formed
/// dnode of something else. The two bands are disjoint, so 0.5 reads as
/// a line between them and not as a score anything can have.
///
/// Within a half: the structure says whether the slot could be a dnode,
/// the walk says whether what it points at is really there, and the
/// second is much the stronger evidence — a slot can look perfect and
/// address nothing — so the two weigh equally once a walk has happened.
pub fn rank(hit: &Hit, assessed: Option<&Assessment>) -> f64 {
    let base = match assessed {
        None => score(hit),
        Some(a) => 0.5 * score(hit) + 0.5 * a.agreement(),
    };
    // The two bands do not touch, so 0.5 reads as a dividing line
    // rather than as a value a candidate can land on from either side.
    let base = base.clamp(0.0, 1.0);
    if hit.misses.is_empty() {
        0.55 + 0.45 * base
    } else {
        0.45 * base
    }
}

/// How good a candidate looks, in 0.0..=1.0 (C-05).
///
/// Not a probability: a ranking. What it weighs, and why:
///
/// * how much of the tree the dnode claims is actually addressable —
///   pointers that address nothing are the commonest sign of a slot that
///   only resembles a dnode;
/// * whether the births are consistent — a real tree's children are no
///   younger than their parents;
/// * whether the shape is possible at all — a single-level tree cannot
///   hold more blocks than the dnode has pointers.
///
/// Whether the profile matched is not weighed here; [`rank`] does that,
/// and decisively. The extraction itself trusts none of it: every block
/// `dump` reads is verified by its own checksum.
pub fn score(hit: &Hit) -> f64 {
    let d = &hit.dnode;
    let live: Vec<&blkptr::BlkPtr> = d.blkptr.iter().filter(|b| !b.is_hole()).collect();
    if live.is_empty() {
        return 0.0;
    }
    let addressable = live
        .iter()
        .filter(|b| b.dva[0].asize != 0 && b.lsize > 0)
        .count() as f64
        / live.len() as f64;
    let births: Vec<u64> = live.iter().map(|b| b.birth).collect();
    let consistent = if births.iter().all(|b| *b > 0) {
        let (lo, hi) = (
            births.iter().copied().min().unwrap_or(0),
            births.iter().copied().max().unwrap_or(0),
        );
        // Pointers of one object are written over a window of
        // transaction groups, not all at once; a spread of more than a
        // few thousand is a sign of pointers that never belonged
        // together.
        if hi.saturating_sub(lo) <= 4096 {
            1.0
        } else {
            0.5
        }
    } else {
        0.0
    };
    // A tree that says it has more levels than one indirect block could
    // hold is describing something real; a single-level dnode with a
    // huge maxblkid is not.
    let shape = {
        let per = d.ptrs_per_indirect().max(1);
        let capacity = (d.nblkptr as u64)
            .saturating_mul(per.saturating_pow(u32::from(d.nlevels.saturating_sub(1)).min(6)));
        if capacity > d.maxblkid {
            1.0
        } else {
            0.0
        }
    };
    (0.5 * addressable + 0.25 * consistent + 0.25 * shape).clamp(0.0, 1.0)
}

/// What walking a candidate's tree found (C-04).
///
/// This is the part that separates a dnode-shaped slot from a volume
/// that is really there: the tree is walked, every block that is not a
/// hole is read, and the checksum decides. Nothing is kept — only the
/// counts — so assessing a 300 GB candidate costs the reads and no
/// memory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Assessment {
    /// Blocks the dnode claims (`maxblkid + 1`, capped by the walk).
    pub blocks_total: u64,
    /// Blocks that read and whose checksum verified.
    pub blocks_verified: u64,
    /// Blocks the tree says are holes: never written, not lost.
    pub blocks_holes: u64,
    /// Blocks that could not be read or did not verify.
    pub blocks_failed: u64,
    /// Oldest and newest birth transaction group met in the tree.
    pub birth: Option<(u64, u64)>,
    /// Blocks whose space the allocator still has given out (C-06): the
    /// candidate is either live somewhere or its space went to something
    /// else.
    pub blocks_allocated: u64,
    /// Blocks whose space has been released. The likeliest state for
    /// something destroyed, and the one a recovery is racing.
    pub blocks_free: u64,
    /// Blocks the space maps say nothing about.
    pub blocks_unknown: u64,
    /// The walk stopped before the end of the tree.
    pub sampled: bool,
}

impl Assessment {
    /// Share of the blocks that are either present and verified or
    /// honestly absent, in 0.0..=1.0.
    pub fn agreement(&self) -> f64 {
        let looked = self.blocks_verified + self.blocks_holes + self.blocks_failed;
        if looked == 0 {
            return 0.0;
        }
        (self.blocks_verified + self.blocks_holes) as f64 / looked as f64
    }
}

/// Walk a candidate's tree and see how much of it is really there.
///
/// `sample` bounds the walk: a candidate is ranked, not extracted, so
/// there is no reason to read a terabyte to decide whether to offer it.
/// Blocks are taken evenly across the whole tree rather than from the
/// front, because the front of an overwritten volume is the part most
/// likely to still look intact.
pub fn assess(obj: &crate::dmu::ObjectReader<'_, '_>, sample: u64) -> Assessment {
    assess_against(obj, sample, None, None)
}

/// Like [`assess`], and also asking the space maps about each block it
/// finds (C-06).
///
/// The space maps say whether the allocator still has that space given
/// out. They are not a verdict on the data — the checksum is — but they
/// tell "released, and still there until something overwrites it" from
/// "handed to something else", which is the difference between a
/// recovery worth starting now and one that is already too late.
///
/// The walk visits a counted number of block ids, so a `maxblkid` of
/// `u64::MAX` — one planted dnode is enough — ends like any other: the
/// next id used to saturate at `u64::MAX`, which is never past it, and
/// the scan spun for ever. `stop` ends it early, marked as sampled.
pub fn assess_against(
    obj: &crate::dmu::ObjectReader<'_, '_>,
    sample: u64,
    space: Option<&crate::spacemap::Space>,
    stop: Option<&std::sync::atomic::AtomicBool>,
) -> Assessment {
    let d = obj.dnode();
    let total = d.maxblkid.saturating_add(1);
    let step = if sample == 0 || total <= sample {
        1
    } else {
        total.div_ceil(sample)
    };
    let mut a = Assessment {
        blocks_total: total,
        sampled: step > 1,
        ..Assessment::default()
    };
    // `i * step` stays below `total` for every `i` below `visits`.
    let visits = total.div_ceil(step);
    for i in 0..visits {
        if stop.is_some_and(|s| s.load(Ordering::Relaxed)) {
            a.sampled = true;
            break;
        }
        let blkid = i * step;
        match obj.locate(blkid) {
            Err(_) => a.blocks_failed += 1,
            Ok(None) => a.blocks_holes += 1,
            Ok(Some(bp)) => {
                if let Some(space) = space {
                    let dva = &bp.dva[0];
                    match space.allocated(dva.vdev.into(), dva.offset, dva.asize) {
                        Some(true) => a.blocks_allocated += 1,
                        Some(false) => a.blocks_free += 1,
                        None => a.blocks_unknown += 1,
                    }
                }
                a.birth = Some(match a.birth {
                    None => (bp.birth, bp.birth),
                    Some((lo, hi)) => (lo.min(bp.birth), hi.max(bp.birth)),
                });
                // read_blkid verifies the checksum; a block that comes
                // back is a block that was really written here.
                match obj.read_blkid(blkid) {
                    Ok(_) => a.blocks_verified += 1,
                    Err(_) => a.blocks_failed += 1,
                }
            }
        }
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{carved_zvol_members, Pool};
    use crate::pool::assemble;
    use crate::vdev::scan_device;
    use crate::zio::PoolReader;
    use zfs_ondisk::dmu::ot;
    use zvolrescue_io::MemSource;

    const SIZE: u64 = 64 * 1024 * 1024;

    /// SPEC F-64: the MOS's own header is recognised in raw bytes, and
    /// the three things that are not it are not.
    #[test]
    fn a_meta_objset_header_is_told_from_everything_that_is_not_one() {
        use zfs_ondisk::blkptr::encode::Builder;
        use zfs_ondisk::dmu::encode::{objset, DnodeSpec};

        // `os_type` as it is on disk: DMU_OST_META is 1, DMU_OST_ZFS 2.
        const META: u64 = 1;
        const ZFS: u64 = 2;

        let pointing = |kind: u8| {
            DnodeSpec {
                object_type: kind,
                datablksz: 16384,
                blkptrs: vec![Builder::new()
                    .dva(0, 0, 0x20_0000, 0x1000, false)
                    .sizes(16384, 16384)
                    .bytes(Endian::Little)],
                ..DnodeSpec::default()
            }
            .build()
        };
        // DMU_OST_META with a meta-dnode that points somewhere: the one
        // shape worth stopping on.
        let mos = objset(&pointing(ot::DNODE), META);
        let found = as_meta_objset(&mos).expect("the MOS header");
        assert_eq!(found.os_type, ObjsetType::Meta);
        assert_eq!(found.meta_dnode.object_type, ot::DNODE);

        // A filesystem's objset is reached through the MOS, so finding
        // one loose says nothing about where the root is.
        assert!(as_meta_objset(&objset(&pointing(ot::DNODE), ZFS)).is_none());
        // A meta-dnode that is not a dnode array.
        assert!(as_meta_objset(&objset(&pointing(ot::PLAIN_FILE_CONTENTS), META)).is_none());
        // A meta-dnode with no pointer has no array under it to walk.
        let empty = DnodeSpec {
            object_type: ot::DNODE,
            datablksz: 16384,
            ..DnodeSpec::default()
        }
        .build();
        assert!(as_meta_objset(&objset(&empty, META)).is_none());
        // And a buffer too short to hold a header is not guessed at.
        assert!(as_meta_objset(&mos[..1023]).is_none());
    }

    fn carved() -> Vec<Vec<u8>> {
        let mut pool = Pool::mirror("tank", 0x5eed_0000_0000_0001, 12).txgs(&[
            (4816228, 1757100000),
            (4816229, 1757100005),
            (4816230, 1757100010),
        ]);
        carved_zvol_members(&mut pool, SIZE)
    }

    /// SPEC F-64, end to end: the MOS is found in raw space and the
    /// dataset tree is walked from it, with no uberblock involved at any
    /// point.
    ///
    /// The header on its own proves nothing — the thing worth asserting
    /// is that a pool comes out of it, which is also what ranks one
    /// candidate above another.
    #[test]
    fn the_dataset_tree_comes_out_of_a_header_found_in_raw_space() {
        let members = carved();
        let sources: Vec<MemSource> = members.into_iter().map(MemSource::new).collect();
        let opts = Options {
            collect_hits: false,
            ..Options::default()
        };
        let mut roots = Vec::new();
        for (i, src) in sources.iter().enumerate() {
            roots.extend(scan_member(src, i, 12, &opts).expect("scan").roots);
        }
        assert!(!roots.is_empty(), "the MOS header is somewhere on a member");

        let scans: Vec<_> = sources
            .iter()
            .map(|s| Some(scan_device(s).expect("scan")))
            .collect();
        let pool = assemble(&scans).into_iter().next().expect("a pool");
        let devices: Vec<Option<&dyn BlockSource>> = sources
            .iter()
            .map(|s| Some(s as &dyn BlockSource))
            .collect();
        let reader = PoolReader::new(&pool, devices);
        // The best header is the one the most of the pool comes out of,
        // which is the same rule `zvolcarve roots` ranks by.
        let best = roots
            .iter()
            .filter_map(|r| {
                let mos =
                    crate::dsl::open_mos_objset(&reader, r.objset.clone(), Endian::Little).ok()?;
                crate::dsl::walk(&mos, "tank").ok()
            })
            .max_by_key(|t| t.datasets.len())
            .expect("a header the DSL walks out of");
        let names: Vec<&str> = best.datasets.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"tank"), "{names:?}");
        assert!(names.contains(&"tank/vm"), "{names:?}");
    }

    /// The volume nothing points at is found by scanning for it, and its
    /// dnode says what it was: 8 KiB blocks, four of them.
    #[test]
    fn a_volume_no_uberblock_leads_to_is_found_by_scanning() {
        let members = carved();
        let src = MemSource::new(members[0].clone());
        let opts = Options {
            profile: Profile {
                dnode_type: Some(ot::ZVOL),
                ..Profile::default()
            },
            strict_profile: true,
            ..Options::default()
        };
        let scan = scan_member(&src, 0, 12, &opts).expect("scan");
        assert!(
            !scan.hits.is_empty(),
            "no zvol dnode found; counts {:?}",
            scan.counts.ranked()
        );
        assert!(scan.hits.iter().all(|h| h.dnode.object_type == ot::ZVOL));
        let best = scan
            .hits
            .iter()
            .max_by(|a, b| score(a).partial_cmp(&score(b)).expect("finite"))
            .expect("a hit");
        assert_eq!(best.dnode.datablksz(), 8192);
        assert_eq!(best.dnode.maxblkid, 3);
    }

    /// A header or a dnode in the last slot of a chunk is read whole,
    /// from the bytes past the chunk: it was cut at the chunk's end and
    /// was not one, so where a `--range` began decided which of the
    /// pool's roots were found. And a range that ends inside a slot
    /// still has the dnode that starts there.
    #[test]
    fn what_starts_in_a_chunk_is_read_past_its_end() {
        let members = carved();
        let src = MemSource::new(members[0].clone());
        let whole = scan_member(
            &src,
            0,
            12,
            &Options {
                collect_hits: false,
                ..Options::default()
            },
        )
        .expect("scan");
        let header = whole.roots.first().expect("a header").offset;
        let chunk = 4096usize;
        // The header in the last slot of the first chunk.
        let edge = scan_member(
            &src,
            0,
            12,
            &Options {
                collect_hits: false,
                chunk,
                range: Some((header - (chunk as u64 - 512), SIZE)),
                ..Options::default()
            },
        )
        .expect("scan");
        assert!(
            edge.roots.iter().any(|r| r.offset == header),
            "the header at the chunk's edge was lost"
        );
        // A volume's dnode, in a range that ends 100 bytes into its slot.
        let zvol = Options {
            profile: Profile {
                dnode_type: Some(ot::ZVOL),
                ..Profile::default()
            },
            strict_profile: true,
            ..Options::default()
        };
        let at = scan_member(&src, 0, 12, &zvol).expect("scan").hits[0].offset;
        let short = scan_member(
            &src,
            0,
            12,
            &Options {
                range: Some((at, at + 100)),
                ..zvol.clone()
            },
        )
        .expect("scan");
        assert_eq!(
            short.hits.iter().map(|h| h.offset).collect::<Vec<_>>(),
            [at]
        );
    }

    /// A scan done in parts is the scan done in one: each part ends at
    /// an offset that is no slot boundary, and the next goes on from
    /// where the last stopped. The resume used to start at the end
    /// itself and read every slot after it off by the difference.
    #[test]
    fn a_scan_in_parts_is_the_scan_in_one() {
        let members = carved();
        let src = MemSource::new(members[0].clone());
        let key = |s: &Scan| {
            s.hits
                .iter()
                .map(|h| (h.offset, h.slot))
                .collect::<Vec<_>>()
        };
        let whole = scan_member(&src, 0, 12, &Options::default()).expect("scan");
        let mut hits = Vec::new();
        let (mut slots, mut bytes, mut at) = (0, 0, 0u64);
        for end in [1_000_003u64, 5_000_001, 9_999_999, SIZE] {
            let part = scan_member(
                &src,
                0,
                12,
                &Options {
                    range: Some((at, end)),
                    ..Options::default()
                },
            )
            .expect("scan");
            assert_eq!(part.resume_at % 512, 0, "a resume starts on a slot");
            hits.extend(key(&part));
            slots += part.slots_examined;
            bytes += part.bytes_read;
            at = part.resume_at;
        }
        assert_eq!(hits, key(&whole));
        assert_eq!((slots, bytes), (whole.slots_examined, whole.bytes_read));
    }

    /// The hit limit ends the scan after the chunk it was reached in, with
    /// every hit of that chunk kept and the resume point past it: one that
    /// stopped inside the chunk went on from the chunk's start, met the
    /// same hits, and never got further.
    #[test]
    fn the_hit_limit_stops_after_a_whole_chunk() {
        let members = carved();
        let src = MemSource::new(members[0].clone());
        let whole = scan_member(&src, 0, 12, &Options::default()).expect("scan");
        let chunk = 1 << 20;
        let capped = scan_member(
            &src,
            0,
            12,
            &Options {
                max_hits: 1,
                chunk,
                ..Options::default()
            },
        )
        .expect("scan");
        assert!(capped.capped && capped.stopped_early);
        let first = whole.hits.iter().map(|h| h.offset).min().expect("a hit");
        let chunk_end = (first / chunk as u64 + 1) * chunk as u64;
        assert_eq!(capped.resume_at, chunk_end);
        let in_chunk = whole.hits.iter().filter(|h| h.offset < chunk_end).count();
        assert_eq!(capped.hits.len(), in_chunk, "every hit of that chunk");
    }

    /// The compressed pass steps from where the vdev starts. On a
    /// member whose vdev starts at sector 7 — or 63, as an old
    /// partition table puts it — a pass that stepped from byte 0 tried
    /// no offset a block was at and found nothing compressed at all.
    #[test]
    fn the_compressed_pass_steps_from_the_vdev_start() {
        let members = carved();
        let zvol = Options {
            profile: Profile {
                dnode_type: Some(ot::ZVOL),
                ..Profile::default()
            },
            strict_profile: true,
            ..Options::default()
        };
        let src = MemSource::new(members[0].clone());
        let at = scan_member(&src, 0, 12, &zvol).expect("scan").hits[0].offset as usize;
        // That dnode alone in a block of 16 KiB, compressed with lz4 in
        // ZFS's framing, at an allocation boundary of a vdev that starts
        // 3584 bytes into the member.
        let mut block = vec![0u8; 16384];
        block[..DNODE_SIZE].copy_from_slice(&members[0][at..at + DNODE_SIZE]);
        let packed = lz4_flex::block::compress(&block);
        let mut framed = (packed.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(&packed);
        let vdev_start = 3584usize;
        let mut member = vec![0u8; 1 << 20];
        let put = vdev_start + 8 * 4096;
        member[put..put + framed.len()].copy_from_slice(&framed);
        let src = MemSource::new(member);
        let lz4 = |vdev_start: u64| Options {
            codecs: vec![Codec::Lz4],
            vdev_start,
            ..zvol.clone()
        };
        let blind = scan_member(&src, 0, 12, &lz4(0)).expect("scan");
        assert!(blind.hits.is_empty());
        let found = scan_member(&src, 0, 12, &lz4(vdev_start as u64)).expect("scan");
        assert_eq!(
            found
                .hits
                .iter()
                .map(|h| (h.offset, h.found))
                .collect::<Vec<_>>(),
            [(put as u64, Found::Compressed(Codec::Lz4))]
        );
    }

    /// A stop flag already up ends the scan before its first chunk,
    /// with the offset to go on from and nothing read; one that is not
    /// up changes nothing about the scan.
    #[test]
    fn a_stop_flag_ends_the_scan_where_a_resume_takes_it_up() {
        let members = carved();
        let src = MemSource::new(members[0].clone());
        let flag = Arc::new(AtomicBool::new(true));
        let opts = Options {
            range: Some((1 << 20, SIZE)),
            stop: Some(Arc::clone(&flag)),
            ..Options::default()
        };
        let scan = scan_member(&src, 0, 12, &opts).expect("scan");
        assert!(scan.stopped_early);
        assert_eq!(scan.resume_at, 1 << 20);
        assert_eq!((scan.bytes_read, scan.hits.len()), (0, 0));

        flag.store(false, Ordering::Relaxed);
        let scan = scan_member(&src, 0, 12, &opts).expect("scan");
        assert!(!scan.stopped_early);
        assert_eq!(scan.resume_at, SIZE);
        assert!(scan.bytes_read > 0);
    }

    /// C-14: a profile that matches nothing must be visibly a rejection.
    /// "0 candidates, all of them rejected by volblocksize" is a
    /// different fact from "there is nothing on this disk", and the
    /// operator has to be able to tell which one they are looking at.
    #[test]
    fn a_profile_that_matches_nothing_says_which_field_rejected_what() {
        let members = carved();
        let src = MemSource::new(members[0].clone());
        let opts = Options {
            profile: Profile {
                dnode_type: Some(ot::ZVOL),
                volblocksize: Some(1 << 20),
                ..Profile::default()
            },
            strict_profile: true,
            ..Options::default()
        };
        let scan = scan_member(&src, 0, 12, &opts).expect("scan");
        assert!(scan.hits.is_empty());
        assert!(scan.counts.by_profile() > 0, "{:?}", scan.counts.ranked());
        let named: Vec<&str> = scan
            .counts
            .ranked()
            .iter()
            .map(|(r, _)| r.as_str())
            .collect();
        assert!(named.contains(&"profile_volblocksize"), "{named:?}");
    }

    /// A soft profile costs ranking, not the recovery: the hit is still
    /// recorded, with the field it failed named (C-18).
    #[test]
    fn a_soft_profile_records_what_it_would_have_dropped() {
        let members = carved();
        let src = MemSource::new(members[0].clone());
        let wrong = Profile {
            dnode_type: Some(ot::ZVOL),
            volblocksize: Some(1 << 20),
            ..Profile::default()
        };
        let soft = scan_member(
            &src,
            0,
            12,
            &Options {
                profile: wrong.clone(),
                strict_profile: false,
                ..Options::default()
            },
        )
        .expect("scan");
        let kept: Vec<&Hit> = soft
            .hits
            .iter()
            .filter(|h| h.dnode.object_type == ot::ZVOL)
            .collect();
        assert!(!kept.is_empty(), "a soft profile dropped the volume");
        assert!(kept
            .iter()
            .all(|h| h.misses.contains(&Reject::ProfileVolBlockSize)));
        // And it ranks below what a right profile would have matched —
        // decisively: no amount of structural quality lifts a candidate
        // that failed the profile above one that passed it.
        let hit = kept[0];
        let mut matched = hit.clone();
        matched.misses.clear();
        assert!(rank(&matched, None) > 0.5);
        assert!(rank(hit, None) < 0.5);
        assert!(rank(&matched, None) > rank(hit, None));
    }

    /// C-04: the tree of the carved volume is really there — every block
    /// the dnode claims either reads and verifies, or is a hole.
    #[test]
    fn the_carved_volume_walks_and_verifies() {
        let members = carved();
        let sources: Vec<MemSource> = members.iter().map(|m| MemSource::new(m.clone())).collect();
        let scans: Vec<_> = sources
            .iter()
            .map(|s| Some(scan_device(s).expect("scan")))
            .collect();
        let pools = assemble(&scans);
        let devices: Vec<Option<&dyn BlockSource>> = sources
            .iter()
            .map(|s| Some(s as &dyn BlockSource))
            .collect();
        let reader = PoolReader::new(&pools[0], devices);

        let opts = Options {
            profile: Profile {
                dnode_type: Some(ot::ZVOL),
                ..Profile::default()
            },
            strict_profile: true,
            ..Options::default()
        };
        let scan = scan_member(&sources[0], 0, 12, &opts).expect("scan");
        let best = scan
            .hits
            .iter()
            .max_by(|a, b| score(a).partial_cmp(&score(b)).expect("finite"))
            .expect("a hit");
        let obj = crate::dmu::ObjectReader::new(&reader, best.dnode.clone(), Endian::Little);
        let a = assess(&obj, 0);
        assert_eq!(a.blocks_total, 4);
        assert_eq!(a.blocks_failed, 0, "{a:?}");
        assert_eq!(a.blocks_verified + a.blocks_holes, 4, "{a:?}");
        assert_eq!(a.agreement(), 1.0);

        // The same dnode claiming every block id there is: a sampled walk
        // ends after its samples — the next id used to saturate at
        // u64::MAX and the walk never ended — and a full one ends when
        // asked to stop.
        let mut huge = best.dnode.clone();
        huge.maxblkid = u64::MAX;
        let obj = crate::dmu::ObjectReader::new(&reader, huge, Endian::Little);
        let a = assess(&obj, 256);
        assert!(a.sampled);
        assert_eq!(
            a.blocks_verified + a.blocks_holes + a.blocks_failed,
            256,
            "{a:?}"
        );
        let stop = AtomicBool::new(true);
        let a = assess_against(&obj, 0, None, Some(&stop));
        assert!(a.sampled);
        assert_eq!(a.blocks_verified + a.blocks_holes + a.blocks_failed, 0);
    }

    /// The counters are what makes an empty result readable, so every
    /// slot the scan looked at has to be accounted for by exactly one.
    #[test]
    fn a_blank_member_rejects_everything_as_free() {
        let src = MemSource::new(vec![0u8; 4 << 20]);
        let scan = scan_member(&src, 0, 12, &Options::default()).expect("scan");
        assert!(scan.hits.is_empty());
        assert_eq!(scan.counts.by_profile(), 0);
        assert_eq!(
            scan.counts.0.get(&Reject::Free).copied().unwrap_or(0),
            scan.slots_examined
        );
    }
}
