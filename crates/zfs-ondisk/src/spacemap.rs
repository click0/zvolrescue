//! Space maps: what the allocator has given out and taken back
//! (COMPANIONS C-06).
//!
//! Every top-level vdev is cut into metaslabs, and each metaslab keeps a
//! log of allocations and frees rather than a bitmap. Replayed in order
//! the log says which ranges of the vdev are in use, which is the
//! difference between a carved candidate whose space is merely free —
//! its blocks still there, readable, at risk — and one whose space has
//! been handed to something else, where the data is gone whatever the
//! dnode still says.
//!
//! The encoding is `include/sys/space_map.h`: a stream of 64-bit words,
//! each either a debug marker, a one-word entry, or a two-word entry.
//! Nothing here does I/O.

use crate::error::ParseError;
use crate::Endian;

/// Entries in the histogram of a `space_map_phys_t`.
pub const HISTOGRAM_SIZE: usize = 32;

/// Bytes of a `space_map_phys_t` up to and including `smp_alloc`.
const PHYS_MIN_LEN: usize = 24;

/// Whether an entry gives space out or takes it back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapType {
    /// `SM_ALLOC`: the run became used.
    Alloc,
    /// `SM_FREE`: the run became free again.
    Free,
}

/// One entry of a space map, in bytes rather than in `sm_shift` units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// Allocation or free.
    pub kind: MapType,
    /// Byte offset within the vdev (a metaslab's start already added by
    /// the caller for a metaslab's own map, or carried by the entry for
    /// a log space map).
    pub offset: u64,
    /// Length in bytes.
    pub run: u64,
    /// Vdev the entry is about, when the entry names one. A metaslab's
    /// own space map does not: it is about its own vdev.
    pub vdev: Option<u32>,
}

/// The header of a space map, from the object's bonus buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SpaceMapPhys {
    /// The object's own number, kept for compatibility.
    pub object: u64,
    /// Bytes of the object that hold entries. The object may be longer;
    /// everything past this is not part of the log.
    pub length: u64,
    /// Space this map accounts for as allocated. Signed on disk, and a
    /// map can be rewritten to a negative intermediate, so it is kept
    /// signed here too.
    pub alloc: i64,
}

impl SpaceMapPhys {
    /// Parse from a bonus buffer.
    pub fn parse(bonus: &[u8], endian: Endian) -> Result<SpaceMapPhys, ParseError> {
        if bonus.len() < PHYS_MIN_LEN {
            return Err(ParseError::Truncated {
                needed: PHYS_MIN_LEN,
                got: bonus.len(),
            });
        }
        let at = |o: usize| endian.u64_at(bonus, o).expect("length checked");
        Ok(SpaceMapPhys {
            object: at(0),
            length: at(8),
            alloc: at(16) as i64,
        })
    }
}

/// A debug marker: which transaction group and sync pass the entries
/// after it belong to. It changes no space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Debug {
    /// Transaction group.
    pub txg: u64,
    /// Sync pass within it.
    pub sync_pass: u64,
}

/// What one step of the decoder produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// An allocation or a free.
    Entry(Entry),
    /// A marker, or the padding one that fills the end of a block.
    Debug(Debug),
}

const SM_DEBUG_PREFIX: u64 = 2;
const SM2_PREFIX: u64 = 3;

/// Decode the word at `at`, in `shift`-byte units.
///
/// Returns the step and how many words it consumed, or `None` when a
/// two-word entry is cut short by the end of the buffer. A two-word
/// entry never straddles a block boundary — the last word of a block is
/// padded with a debug entry instead — so a truncated one means the
/// stream ended, not that the next block continues it.
pub fn decode(words: &[u64], at: usize, shift: u32) -> Option<(Step, usize)> {
    let w = *words.get(at)?;
    let unit = 1u64 << shift;
    match w >> 62 {
        SM_DEBUG_PREFIX => Some((
            Step::Debug(Debug {
                txg: w & ((1 << 50) - 1),
                sync_pass: (w >> 50) & ((1 << 10) - 1),
            }),
            1,
        )),
        SM2_PREFIX => {
            let second = *words.get(at + 1)?;
            let run = ((w >> 24) & ((1u64 << 36) - 1)) + 1;
            let vdev = (w & ((1 << 24) - 1)) as u32;
            let kind = if second >> 63 == 0 {
                MapType::Alloc
            } else {
                MapType::Free
            };
            let offset = second & ((1u64 << 63) - 1);
            Some((
                Step::Entry(Entry {
                    kind,
                    offset: offset.wrapping_mul(unit),
                    run: run.wrapping_mul(unit),
                    vdev: Some(vdev),
                }),
                2,
            ))
        }
        // Prefix 0 and 1 are both one-word entries: the top bit of the
        // offset is bit 62, which is what makes the prefix 1.
        _ => {
            let offset = (w >> 16) & ((1u64 << 47) - 1);
            let kind = if (w >> 15) & 1 == 0 {
                MapType::Alloc
            } else {
                MapType::Free
            };
            let run = (w & ((1 << 15) - 1)) + 1;
            Some((
                Step::Entry(Entry {
                    kind,
                    offset: offset.wrapping_mul(unit),
                    run: run.wrapping_mul(unit),
                    vdev: None,
                }),
                1,
            ))
        }
    }
}

/// Decode a whole space map into its entries, in order.
///
/// `bytes` is the object's data truncated to `smp_length`; `shift` is
/// the vdev's `ashift`. Debug markers are dropped: they say when, and
/// what is being asked here is what.
pub fn entries(bytes: &[u8], shift: u32, endian: Endian) -> Vec<Entry> {
    let words: Vec<u64> = bytes
        .chunks_exact(8)
        .map(|c| {
            let b: [u8; 8] = c.try_into().expect("8 bytes");
            match endian {
                Endian::Little => u64::from_le_bytes(b),
                Endian::Big => u64::from_be_bytes(b),
            }
        })
        .collect();
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < words.len() {
        match decode(&words, at, shift) {
            None => break,
            Some((Step::Entry(e), n)) => {
                out.push(e);
                at += n;
            }
            Some((Step::Debug(_), n)) => at += n,
        }
    }
    out
}

/// A set of byte ranges, kept sorted and merged.
///
/// Space maps are replayed into one of these: an allocation adds a
/// range, a free takes one away. A metaslab's log can be long, so the
/// set is built once and asked many times — and each step touches only
/// the ranges it meets. Kept as one sorted vector rebuilt on every
/// step, the replay was quadratic: 80 000 entries took 18 s, and a
/// space map of a million was an afternoon.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ranges(std::collections::BTreeMap<u64, u64>);

impl Ranges {
    /// An empty set.
    pub fn new() -> Ranges {
        Ranges(std::collections::BTreeMap::new())
    }

    /// The ranges `[start, end)`, sorted by start.
    pub fn to_vec(&self) -> Vec<(u64, u64)> {
        self.0.iter().map(|(&a, &b)| (a, b)).collect()
    }

    /// Total bytes covered.
    pub fn bytes(&self) -> u64 {
        self.0.iter().map(|(a, b)| b - a).sum()
    }

    /// How many ranges there are.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Add `[start, start + len)`; ranges it overlaps or touches become
    /// one with it.
    pub fn add(&mut self, start: u64, len: u64) {
        if len == 0 {
            return;
        }
        let (mut lo, mut hi) = (start, start.saturating_add(len));
        // One that begins at or before `lo` and reaches it.
        if let Some((&a, &b)) = self.0.range(..=lo).next_back() {
            if b >= lo {
                lo = a;
                hi = hi.max(b);
                self.0.remove(&a);
            }
        }
        // Every one that begins inside, or right at the end.
        while let Some((&a, &b)) = self.0.range(lo..=hi).next() {
            hi = hi.max(b);
            self.0.remove(&a);
        }
        self.0.insert(lo, hi);
    }

    /// Take `[start, start + len)` out.
    pub fn remove(&mut self, start: u64, len: u64) {
        if len == 0 {
            return;
        }
        let (from, to) = (start, start.saturating_add(len));
        // One that begins before the hole and runs into it: keep its
        // head, and its tail when it runs past.
        if let Some((&a, &b)) = self.0.range(..from).next_back() {
            if b > from {
                self.0.insert(a, from);
                if b > to {
                    self.0.insert(to, b);
                }
            }
        }
        // Every one that begins inside the hole.
        while let Some((&a, &b)) = self.0.range(from..to).next() {
            self.0.remove(&a);
            if b > to {
                self.0.insert(to, b);
            }
        }
    }

    /// Whether any part of `[start, start + len)` is in the set.
    pub fn intersects(&self, start: u64, len: u64) -> bool {
        if len == 0 {
            return false;
        }
        let end = start.saturating_add(len);
        self.0
            .range(..end)
            .next_back()
            .is_some_and(|(_, &b)| b > start)
    }

    /// Replay a space map's entries into the set.
    pub fn replay(&mut self, entries: &[Entry], base: u64) {
        for e in entries {
            let at = base.saturating_add(e.offset);
            match e.kind {
                MapType::Alloc => self.add(at, e.run),
                MapType::Free => self.remove(at, e.run),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a one-word entry the way OpenZFS encodes one.
    fn one_word(kind: MapType, offset: u64, run: u64) -> u64 {
        assert!((1..=1 << 15).contains(&run));
        (offset << 16) | (u64::from(kind == MapType::Free) << 15) | (run - 1)
    }

    /// Build a two-word entry.
    fn two_word(kind: MapType, vdev: u32, offset: u64, run: u64) -> [u64; 2] {
        let first = (SM2_PREFIX << 62) | ((run - 1) << 24) | u64::from(vdev);
        let second = (u64::from(kind == MapType::Free) << 63) | offset;
        [first, second]
    }

    fn debug_word(txg: u64, pass: u64) -> u64 {
        (SM_DEBUG_PREFIX << 62) | (pass << 50) | txg
    }

    fn bytes(words: &[u64]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    #[test]
    fn a_one_word_entry_decodes_to_bytes() {
        let w = one_word(MapType::Alloc, 3, 2);
        let e = entries(&bytes(&[w]), 12, Endian::Little);
        assert_eq!(
            e,
            [Entry {
                kind: MapType::Alloc,
                offset: 3 * 4096,
                run: 2 * 4096,
                vdev: None
            }]
        );
    }

    /// Bit 62 is the top of the offset, which makes the prefix read as 1
    /// — still a one-word entry, and a decoder that treated the prefix
    /// as a tag would lose every allocation in the upper half of a vdev.
    #[test]
    fn an_offset_that_reaches_bit_62_is_still_one_word() {
        let high = (1u64 << 46) + 5;
        let w = one_word(MapType::Free, high, 1);
        assert_eq!(w >> 62, 1);
        let e = entries(&bytes(&[w]), 9, Endian::Little);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].kind, MapType::Free);
        assert_eq!(e[0].offset, high * 512);
    }

    #[test]
    fn a_two_word_entry_carries_its_vdev() {
        let w = two_word(MapType::Alloc, 7, 1 << 40, 1 << 20);
        let e = entries(&bytes(&w), 12, Endian::Little);
        assert_eq!(
            e,
            [Entry {
                kind: MapType::Alloc,
                offset: (1u64 << 40) * 4096,
                run: (1u64 << 20) * 4096,
                vdev: Some(7)
            }]
        );
    }

    #[test]
    fn debug_markers_change_no_space() {
        let words = [
            debug_word(4816229, 1),
            one_word(MapType::Alloc, 0, 1),
            debug_word(0, 0), // the padding at the end of a block
        ];
        let e = entries(&bytes(&words), 12, Endian::Little);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].offset, 0);
    }

    /// A two-word entry cut short by the end of the stream is dropped,
    /// not half-read: guessing the missing word would invent space.
    #[test]
    fn a_truncated_two_word_entry_is_dropped() {
        let w = two_word(MapType::Alloc, 0, 9, 1);
        assert!(entries(&bytes(&w[..1]), 12, Endian::Little).is_empty());
    }

    #[test]
    fn a_header_says_how_long_the_log_is() {
        let mut bonus = vec![0u8; 24];
        bonus[0..8].copy_from_slice(&76u64.to_le_bytes());
        bonus[8..16].copy_from_slice(&0x6c50u64.to_le_bytes());
        bonus[16..24].copy_from_slice(&0x1a5000u64.to_le_bytes());
        let p = SpaceMapPhys::parse(&bonus, Endian::Little).expect("parses");
        assert_eq!((p.object, p.length, p.alloc), (76, 0x6c50, 0x1a5000));
    }

    #[test]
    fn allocations_and_frees_replay_into_ranges() {
        let mut r = Ranges::new();
        r.replay(
            &entries(
                &bytes(&[
                    one_word(MapType::Alloc, 0, 4),
                    one_word(MapType::Alloc, 4, 4),
                    one_word(MapType::Free, 2, 2),
                ]),
                12,
                Endian::Little,
            ),
            0,
        );
        assert_eq!(r.to_vec(), [(0, 2 * 4096), (4 * 4096, 8 * 4096)]);
        assert_eq!(r.bytes(), 6 * 4096);
        assert!(r.intersects(0, 4096));
        assert!(!r.intersects(2 * 4096, 2 * 4096));
        assert!(r.intersects(3 * 4096, 2 * 4096));
    }

    /// Adjacent allocations are one range: a set that kept them apart
    /// would grow with every transaction group.
    #[test]
    fn touching_ranges_merge() {
        let mut r = Ranges::new();
        r.add(0, 100);
        r.add(100, 100);
        r.add(300, 100);
        assert_eq!(r.to_vec(), [(0, 200), (300, 400)]);
        r.add(200, 100);
        assert_eq!(r.to_vec(), [(0, 400)]);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn a_free_can_split_a_range_and_empty_the_set() {
        let mut r = Ranges::new();
        r.add(0, 1000);
        r.remove(400, 200);
        assert_eq!(r.to_vec(), [(0, 400), (600, 1000)]);
        r.remove(0, 1000);
        assert!(r.is_empty());
        assert_eq!(r.bytes(), 0);
        // Freeing what was never allocated changes nothing.
        r.remove(0, 1000);
        assert!(r.is_empty());
    }

    /// The property that matters when replaying a real log: whatever the
    /// order, the bytes covered equal the bytes allocated minus freed.
    #[test]
    fn replaying_in_order_gives_the_space_the_log_describes() {
        let mut r = Ranges::new();
        let mut expected: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        let mut state = 0x1234_5678_9abc_def0u64;
        // A tenth of the operations under Miri: the set arithmetic is
        // what is checked there, not the statistics of the mix.
        for _ in 0..(if cfg!(miri) { 200 } else { 2000 }) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let start = (state % 512) * 8;
            let len = (state / 512 % 8 + 1) * 8;
            if state & 1 == 0 {
                r.add(start, len);
                expected.extend(start..start + len);
            } else {
                r.remove(start, len);
                for b in start..start + len {
                    expected.remove(&b);
                }
            }
        }
        assert_eq!(r.bytes(), expected.len() as u64);
        for b in 0..4096u64 {
            assert_eq!(r.intersects(b, 1), expected.contains(&b), "byte {b}");
        }
    }

    /// Against a plain model — one bit per byte — over random steps: the
    /// set holds exactly the bytes the steps leave, merged into as few
    /// ranges as there are runs, and answers `intersects` the same.
    #[test]
    fn ranges_agree_with_a_byte_by_byte_model() {
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let mut next = |n: u64| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x % n
        };
        // A fiftieth of the rounds under Miri, which interprets every step.
        for _ in 0..(if cfg!(miri) { 4 } else { 200 }) {
            let mut r = Ranges::new();
            let mut bits = [false; 272];
            for _ in 0..40 {
                let (start, len) = (next(240), next(24));
                let add = next(3) != 0;
                if add {
                    r.add(start, len);
                } else {
                    r.remove(start, len);
                }
                for b in &mut bits[start as usize..(start + len) as usize] {
                    *b = add;
                }
                let runs: Vec<(u64, u64)> = {
                    let mut v = Vec::new();
                    let mut i = 0;
                    while i < bits.len() {
                        if bits[i] {
                            let a = i;
                            while i < bits.len() && bits[i] {
                                i += 1;
                            }
                            v.push((a as u64, i as u64));
                        }
                        i += 1;
                    }
                    v
                };
                assert_eq!(r.to_vec(), runs);
                let (qs, ql) = (next(250), next(10));
                let want = bits[qs as usize..(qs + ql) as usize].contains(&true);
                assert_eq!(r.intersects(qs, ql), want, "{qs}+{ql} in {runs:?}");
            }
        }
    }

    /// A long log replays in time proportional to it: 80 000 disjoint
    /// allocations took 18 s when every step rebuilt the set. A time is
    /// what this checks, so not under Miri, where every step is
    /// interpreted and 200 000 of them would take the job's hour.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn a_long_space_map_replays_quickly() {
        let es: Vec<Entry> = (0..200_000u64)
            .map(|i| Entry {
                kind: if i % 7 == 6 {
                    MapType::Free
                } else {
                    MapType::Alloc
                },
                offset: (i * 7919 % 200_000) * 8192,
                run: 4096,
                vdev: None,
            })
            .collect();
        let t = std::time::Instant::now();
        let mut r = Ranges::new();
        r.replay(&es, 0);
        assert!(t.elapsed().as_secs() < 5, "{:?}", t.elapsed());
        assert!(r.len() > 100_000);
        assert!(r.intersects(0, 1));
    }
}
