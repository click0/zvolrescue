//! The mapping a removed top-level vdev leaves behind (SPEC F-69).
//!
//! `zpool remove` of a top-level vdev does not free what was on it: it
//! copies those blocks onto the vdevs that remain, and leaves in the
//! removed vdev's place an `indirect` vdev that holds no data at all —
//! only a record of where each range of its old address space went.
//!
//! The block pointers are not rewritten. Rewriting them would mean
//! walking every pointer in the pool, so instead the old addresses stay
//! exactly as they were and are translated on the way to the disk. A
//! reader that does not translate them is holding addresses on a vdev
//! that no longer exists, which is why those blocks are refused by name
//! until this mapping is read.
//!
//! `vdev_indirect_mapping.h`: the mapping is a DMU object whose bonus is
//! a `vdev_indirect_mapping_phys_t` and whose data is an array of
//! `vdev_indirect_mapping_entry_phys_t`, sorted by source offset and
//! non-overlapping. Each entry is a source offset and one destination
//! DVA, and the length of the mapped range is that DVA's `asize` — the
//! mapping is always to a single DVA, so a range that had to be split
//! when it was copied is several entries rather than one.
//!
//! Nothing here does I/O.

use crate::blkptr::{Dva, MINBLOCKSHIFT};
use crate::error::ParseError;
use crate::Endian;

/// Bytes of one `vdev_indirect_mapping_entry_phys_t`: the source word
/// and a `dva_t`.
pub const ENTRY_SIZE: usize = 24;

/// Bytes of a `vdev_indirect_mapping_phys_t`.
const PHYS_LEN: usize = 32;

/// The bonus buffer of a mapping object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MappingPhys {
    /// One past the highest source offset the mapping covers.
    pub max_offset: u64,
    /// Bytes of live data the mapping accounts for.
    pub bytes_mapped: u64,
    /// Entries in the object's data.
    pub num_entries: u64,
    /// Object holding, per entry, how much of it was already obsolete
    /// when the mapping was last condensed. Reading does not need it:
    /// a pointer that still names the removed vdev is by definition
    /// live, so its entry is valid whatever the counts say. Kept
    /// because it is what `com.delphix:obsolete_counts` maintains, and
    /// saying it is there is not the same as using it.
    pub counts_object: u64,
}

impl MappingPhys {
    /// Parse from a mapping object's bonus buffer.
    pub fn parse(bonus: &[u8], endian: Endian) -> Result<MappingPhys, ParseError> {
        if bonus.len() < PHYS_LEN {
            return Err(ParseError::Truncated {
                needed: PHYS_LEN,
                got: bonus.len(),
            });
        }
        let at = |o: usize| endian.u64_at(bonus, o).expect("length checked");
        Ok(MappingPhys {
            max_offset: at(0),
            bytes_mapped: at(8),
            num_entries: at(16),
            counts_object: at(24),
        })
    }
}

/// One entry: a range of the removed vdev, and where it went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// Start of the range, in the removed vdev's address space.
    pub src: u64,
    /// Length of the range. On disk this is the destination DVA's
    /// `asize`; the source and destination ranges are the same length.
    pub size: u64,
    /// Top-level vdev the bytes were copied to.
    pub dst_vdev: u32,
    /// Offset within that vdev's allocatable space.
    pub dst_offset: u64,
}

impl Entry {
    /// One past the last byte of the source range.
    pub fn end(&self) -> u64 {
        self.src.saturating_add(self.size)
    }

    /// Parse one entry from 24 bytes.
    pub fn parse(buf: &[u8], endian: Endian) -> Result<Entry, ParseError> {
        if buf.len() < ENTRY_SIZE {
            return Err(ParseError::Truncated {
                needed: ENTRY_SIZE,
                got: buf.len(),
            });
        }
        let at = |o: usize| endian.u64_at(buf, o).expect("length checked");
        // The top bit of the source word is the mark `zdb` sets when it
        // walks the mapping for garbage collection; it is not part of
        // the offset. The rest counts in 512-byte units, like a DVA.
        let src = (at(0) & ((1u64 << 63) - 1)) << MINBLOCKSHIFT;
        let dst = Dva::from_words(at(8), at(16));
        Ok(Entry {
            src,
            size: dst.asize,
            dst_vdev: dst.vdev,
            dst_offset: dst.offset,
        })
    }
}

/// A piece of a read, after translation: where to go for those bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    /// Top-level vdev to read from. May itself be indirect: a pool that
    /// has had two vdevs removed can map one onto the other.
    pub vdev: u32,
    /// Offset within that vdev's allocatable space.
    pub offset: u64,
    /// Bytes to read there.
    pub size: u64,
}

/// A range of the removed vdev that the mapping does not cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unmapped {
    /// Where the gap starts, in the removed vdev's address space.
    pub offset: u64,
    /// How many bytes are unaccounted for from there.
    pub size: u64,
}

impl std::fmt::Display for Unmapped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} byte(s) at {:#x} are not in the removed vdev's mapping",
            self.size, self.offset
        )
    }
}

/// The whole mapping of one removed top-level vdev.
#[derive(Debug, Clone, Default)]
pub struct Mapping {
    entries: Vec<Entry>,
}

impl Mapping {
    /// Parse `count` entries from the object's data.
    ///
    /// `count` comes from the bonus and is trusted only as far as the
    /// data goes: a truncated read yields the entries that are there
    /// rather than an error, because a partial mapping still translates
    /// the ranges it covers and the ranges it does not are reported
    /// where they are used.
    pub fn parse(data: &[u8], count: u64, endian: Endian) -> Result<Mapping, ParseError> {
        let available = data.len() / ENTRY_SIZE;
        let n = usize::try_from(count).unwrap_or(usize::MAX).min(available);
        let mut entries = Vec::with_capacity(n);
        for i in 0..n {
            entries.push(Entry::parse(&data[i * ENTRY_SIZE..], endian)?);
        }
        // The array is written in source order and looked up by binary
        // search. Sorting a mapping that arrives out of order costs
        // nothing here and keeps the search honest on a damaged object.
        entries.sort_by_key(|e| e.src);
        Ok(Mapping { entries })
    }

    /// Build from entries already in hand (tests, and fixtures).
    pub fn from_entries(mut entries: Vec<Entry>) -> Mapping {
        entries.sort_by_key(|e| e.src);
        Mapping { entries }
    }

    /// How many entries the mapping has.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the mapping is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Bytes of source address space the entries cover.
    pub fn mapped_bytes(&self) -> u64 {
        self.entries
            .iter()
            .fold(0u64, |sum, e| sum.saturating_add(e.size))
    }

    /// Where to read `size` bytes at `offset` of the removed vdev.
    ///
    /// A single range can cross entries — the removal copies in pieces
    /// and each piece is mapped on its own — so this yields a segment
    /// per entry crossed, in order. The first gap is an error rather
    /// than a silently short read: bytes that are not in the mapping
    /// are not anywhere.
    pub fn remap(&self, offset: u64, size: u64) -> Result<Vec<Segment>, Unmapped> {
        let mut out = Vec::new();
        let mut at = offset;
        let mut left = size;
        while left > 0 {
            let e = self.entry_for(at).ok_or(Unmapped {
                offset: at,
                size: left,
            })?;
            let within = at - e.src;
            let take = (e.size - within).min(left);
            // An entry whose destination runs past the end of any
            // address space is damage, not a place to read from: the
            // bytes it claims to map are nowhere, which is what the
            // caller is told. (Found by the fuzzer: the addition
            // overflowed on a hostile entry.)
            let offset = e.dst_offset.checked_add(within).ok_or(Unmapped {
                offset: at,
                size: left,
            })?;
            out.push(Segment {
                vdev: e.dst_vdev,
                offset,
                size: take,
            });
            left -= take;
            at = match at.checked_add(take) {
                Some(next) => next,
                None if left == 0 => break,
                None => {
                    return Err(Unmapped {
                        offset: at,
                        size: left,
                    })
                }
            };
        }
        Ok(out)
    }

    /// The entry whose source range contains `offset`.
    fn entry_for(&self, offset: u64) -> Option<&Entry> {
        let i = self.entries.partition_point(|e| e.src <= offset);
        let e = self.entries.get(i.checked_sub(1)?)?;
        (offset < e.end()).then_some(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(src: u64, size: u64, vdev: u32, dst: u64) -> Entry {
        Entry {
            src,
            size,
            dst_vdev: vdev,
            dst_offset: dst,
        }
    }

    fn mapping() -> Mapping {
        Mapping::from_entries(vec![
            entry(0x0000, 0x1000, 1, 0x8000),
            entry(0x1000, 0x2000, 2, 0x4000),
            // A hole: nothing maps 0x3000..0x4000.
            entry(0x4000, 0x1000, 1, 0x9000),
        ])
    }

    #[test]
    fn a_range_inside_one_entry_is_one_segment() {
        let m = mapping();
        assert_eq!(
            m.remap(0x1200, 0x400).unwrap(),
            vec![Segment {
                vdev: 2,
                offset: 0x4200,
                size: 0x400
            }]
        );
    }

    #[test]
    fn a_range_crossing_entries_is_split_where_they_split_it() {
        let m = mapping();
        assert_eq!(
            m.remap(0x0c00, 0x1400).unwrap(),
            vec![
                Segment {
                    vdev: 1,
                    offset: 0x8c00,
                    size: 0x400
                },
                Segment {
                    vdev: 2,
                    offset: 0x4000,
                    size: 0x1000
                },
            ]
        );
    }

    #[test]
    fn a_gap_is_an_error_and_says_where_it_starts() {
        let m = mapping();
        assert_eq!(
            m.remap(0x2f00, 0x200),
            Err(Unmapped {
                offset: 0x3000,
                size: 0x100
            })
        );
        assert_eq!(
            m.remap(0x9000, 0x100),
            Err(Unmapped {
                offset: 0x9000,
                size: 0x100
            })
        );
    }

    #[test]
    fn an_entry_round_trips_through_its_on_disk_form() {
        // src in 512-byte units with the mark bit set, then the dst DVA:
        // asize 0x2000 (in 512-byte units), vdev 3, offset 0x40000.
        let mut buf = [0u8; ENTRY_SIZE];
        buf[0..8].copy_from_slice(&((1u64 << 63) | (0x1000 >> 9)).to_le_bytes());
        buf[8..16].copy_from_slice(&(((3u64) << 32) | (0x2000 >> 9)).to_le_bytes());
        buf[16..24].copy_from_slice(&(0x40000u64 >> 9).to_le_bytes());
        assert_eq!(
            Entry::parse(&buf, Endian::Little).unwrap(),
            entry(0x1000, 0x2000, 3, 0x40000)
        );
    }

    /// A bonus or an entry that is too short is refused with the sizes,
    /// not read with whatever happened to follow it in memory.
    #[test]
    fn a_short_bonus_or_entry_is_refused_by_size() {
        let short = [0u8; 20];
        assert_eq!(
            MappingPhys::parse(&short, Endian::Little).unwrap_err(),
            ParseError::Truncated {
                needed: PHYS_LEN,
                got: 20
            }
        );
        assert_eq!(
            Entry::parse(&short, Endian::Little).unwrap_err(),
            ParseError::Truncated {
                needed: ENTRY_SIZE,
                got: 20
            }
        );
        // Exactly enough is enough, and the fields land where they are.
        let mut bonus = [0u8; PHYS_LEN];
        bonus[0..8].copy_from_slice(&0x1_0000u64.to_le_bytes());
        bonus[8..16].copy_from_slice(&0x8000u64.to_le_bytes());
        bonus[16..24].copy_from_slice(&3u64.to_le_bytes());
        bonus[24..32].copy_from_slice(&17u64.to_le_bytes());
        assert_eq!(
            MappingPhys::parse(&bonus, Endian::Little).unwrap(),
            MappingPhys {
                max_offset: 0x1_0000,
                bytes_mapped: 0x8000,
                num_entries: 3,
                counts_object: 17
            }
        );
    }

    /// A partial mapping is not an error: what is there translates, and
    /// what is not is reported as a gap where it is looked up.
    #[test]
    fn a_partial_mapping_translates_what_it_has() {
        let mut data = vec![0u8; ENTRY_SIZE * 2 + 5];
        for (i, (src, dst)) in [(0x4000u64, 0x9000u64), (0x0u64, 0x8000u64)]
            .iter()
            .enumerate()
        {
            let at = i * ENTRY_SIZE;
            data[at..at + 8].copy_from_slice(&(src >> 9).to_le_bytes());
            data[at + 8..at + 16].copy_from_slice(&((1u64 << 32) | (0x1000 >> 9)).to_le_bytes());
            data[at + 16..at + 24].copy_from_slice(&(dst >> 9).to_le_bytes());
        }
        let m = Mapping::parse(&data, 3, Endian::Little).unwrap();
        assert_eq!(
            (m.len(), m.is_empty(), m.mapped_bytes()),
            (2, false, 0x2000)
        );
        // Written out of order, looked up in order.
        assert_eq!(m.remap(0x4100, 0x100).unwrap()[0].offset, 0x9100);
        assert_eq!(m.remap(0x100, 0x100).unwrap()[0].offset, 0x8100);
        assert!(m.remap(0x2000, 0x100).is_err());
        assert!(Mapping::default().is_empty());
    }

    #[test]
    fn the_count_in_the_bonus_never_reads_past_the_data() {
        let data = [0u8; ENTRY_SIZE * 2];
        let m = Mapping::parse(&data, 1000, Endian::Little).unwrap();
        assert_eq!(m.len(), 2);
    }

    /// An entry whose destination offset sits at the top of the address
    /// space is damage; asking for bytes through it is answered with
    /// "unmapped", not with a panic. The fuzzer found the addition.
    #[test]
    fn a_destination_past_the_end_of_the_address_space_is_unmapped() {
        let m = Mapping::from_entries(vec![Entry {
            src: 0,
            size: 8192,
            dst_vdev: 1,
            dst_offset: u64::MAX - 100,
        }]);
        assert_eq!(m.remap(0, 50).unwrap().len(), 1);
        assert!(m.remap(4096, 4096).is_err());
        // The sizes' sum is saturated rather than overflowed.
        let big = Mapping::from_entries(vec![
            Entry {
                src: 0,
                size: u64::MAX,
                dst_vdev: 0,
                dst_offset: 0,
            },
            Entry {
                src: u64::MAX,
                size: 1,
                dst_vdev: 0,
                dst_offset: 0,
            },
        ]);
        assert_eq!(big.mapped_bytes(), u64::MAX);
        // The last byte of the address space is one no entry can end
        // past, so it is unmapped; the byte before it reads.
        assert_eq!(big.remap(u64::MAX - 1, 1).map(|s| s.len()), Ok(1));
        assert!(big.remap(u64::MAX - 1, 2).is_err());
    }
}
