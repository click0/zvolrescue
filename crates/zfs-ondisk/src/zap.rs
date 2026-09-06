//! ZAP (ZFS Attribute Processor) blocks: name → value maps.
//!
//! Two on-disk forms, from OpenZFS `zap_impl.h` and `zap_leaf.h`:
//!
//! * **microzap** — a single block of 64-byte entries (`u64` values only);
//! * **fatzap** — a header block whose second half is an embedded pointer
//!   table (or a table stored in further blocks), pointing at leaf blocks
//!   made of 24-byte chunks that chain into entries, names and values.
//!
//! This module parses individual blocks; `zfs-read` stitches them.

use crate::{Endian, ParseError};

/// `ZBT_LEAF`.
pub const ZBT_LEAF: u64 = (1u64 << 63) | 0;
/// `ZBT_HEADER`.
pub const ZBT_HEADER: u64 = (1u64 << 63) | 1;
/// `ZBT_MICRO`.
pub const ZBT_MICRO: u64 = (1u64 << 63) | 3;
/// `ZAP_MAGIC` in the fatzap header.
pub const ZAP_MAGIC: u64 = 0x0002_F52A_B2AB;
/// `ZAP_LEAF_MAGIC`.
pub const ZAP_LEAF_MAGIC: u32 = 0x02AB_1EAF;
/// Size of one microzap entry.
pub const MZAP_ENT_SIZE: usize = 64;
/// Longest microzap name including NUL.
pub const MZAP_NAME_LEN: usize = 50;
/// Size of one leaf chunk.
pub const LEAF_CHUNKSIZE: usize = 24;
/// Payload bytes in one array chunk.
pub const LEAF_ARRAY_BYTES: usize = 21;
/// Leaf header size.
pub const LEAF_HEADER_SIZE: usize = 48;
/// `ZAP_CHUNK_ARRAY`.
pub const CHUNK_ARRAY: u8 = 251;
/// `ZAP_CHUNK_ENTRY`.
pub const CHUNK_ENTRY: u8 = 252;
/// `ZAP_CHUNK_FREE`.
pub const CHUNK_FREE: u8 = 253;
/// End-of-chain marker in leaf chunk links.
pub const CHAIN_END: u16 = 0xffff;

/// Which kind of ZAP block a buffer is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockType {
    /// Microzap block.
    Micro,
    /// Fatzap header block.
    Header,
    /// Fatzap leaf block.
    Leaf,
}

/// Identify a ZAP block by its first word, or `None` if it is not one.
pub fn block_type(buf: &[u8], endian: Endian) -> Option<BlockType> {
    match endian.u64_at(buf, 0)? {
        ZBT_MICRO => Some(BlockType::Micro),
        ZBT_HEADER => Some(BlockType::Header),
        ZBT_LEAF => Some(BlockType::Leaf),
        _ => None,
    }
}

/// A ZAP value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// One 64-bit integer.
    U64(u64),
    /// Several 64-bit integers.
    U64Array(Vec<u64>),
    /// Byte-sized integers, typically a NUL-terminated string.
    Bytes(Vec<u8>),
    /// Integers of another width, kept raw (big-endian per element).
    Ints {
        /// Bytes per element.
        intlen: u8,
        /// Raw big-endian element bytes.
        raw: Vec<u8>,
    },
}

impl Value {
    /// The value as a `u64` (first element of an array).
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::U64(v) => Some(*v),
            Value::U64Array(a) => a.first().copied(),
            _ => None,
        }
    }

    /// The value as a string with a trailing NUL stripped.
    pub fn as_str(&self) -> Option<String> {
        match self {
            Value::Bytes(b) => {
                let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
                Some(String::from_utf8_lossy(&b[..end]).into_owned())
            }
            _ => None,
        }
    }
}

/// One name/value pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Entry name.
    pub name: String,
    /// Entry value.
    pub value: Value,
    /// Collision differentiator.
    pub cd: u32,
}

/// Parse a microzap block into its non-empty entries.
pub fn parse_micro(buf: &[u8], endian: Endian) -> Result<Vec<Entry>, ParseError> {
    if block_type(buf, endian) != Some(BlockType::Micro) {
        return Err(ParseError::Malformed {
            what: "not a microzap block",
            at: 0,
        });
    }
    let mut out = Vec::new();
    for chunk in buf[MZAP_ENT_SIZE..].chunks_exact(MZAP_ENT_SIZE) {
        let name = &chunk[14..14 + MZAP_NAME_LEN];
        if name[0] == 0 {
            continue;
        }
        let end = name.iter().position(|&c| c == 0).unwrap_or(MZAP_NAME_LEN);
        let cd_bytes: [u8; 4] = chunk[8..12].try_into().expect("4 bytes");
        out.push(Entry {
            name: String::from_utf8_lossy(&name[..end]).into_owned(),
            value: Value::U64(endian.u64_at(chunk, 0).expect("64-byte chunk")),
            cd: match endian {
                Endian::Little => u32::from_le_bytes(cd_bytes),
                Endian::Big => u32::from_be_bytes(cd_bytes),
            },
        });
    }
    Ok(out)
}

/// Decoded fatzap header (`zap_phys_t`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FatHeader {
    /// First block of the external pointer table (`zt_blk`).
    pub ptrtbl_blk: u64,
    /// Blocks in the external pointer table; 0 means embedded.
    pub ptrtbl_numblks: u64,
    /// log2 of the number of pointers (`zt_shift`).
    pub ptrtbl_shift: u64,
    /// Next free block in the ZAP object.
    pub freeblk: u64,
    /// Number of leaf blocks.
    pub num_leafs: u64,
    /// Number of entries.
    pub num_entries: u64,
    /// Hash salt.
    pub salt: u64,
    /// Normalisation flags.
    pub normflags: u64,
    /// `zap_flags`.
    pub flags: u64,
}

/// Parse the fatzap header block.
pub fn parse_fat_header(buf: &[u8], endian: Endian) -> Result<FatHeader, ParseError> {
    if block_type(buf, endian) != Some(BlockType::Header) {
        return Err(ParseError::Malformed {
            what: "not a fatzap header block",
            at: 0,
        });
    }
    if buf.len() < 104 {
        return Err(ParseError::Truncated {
            needed: 104,
            got: buf.len(),
        });
    }
    let w = |o: usize| endian.u64_at(buf, o).expect("length checked");
    if w(8) != ZAP_MAGIC {
        return Err(ParseError::BadMagic(w(8)));
    }
    Ok(FatHeader {
        ptrtbl_blk: w(16),
        ptrtbl_numblks: w(24),
        ptrtbl_shift: w(32),
        freeblk: w(56),
        num_leafs: w(64),
        num_entries: w(72),
        salt: w(80),
        normflags: w(88),
        flags: w(96),
    })
}

/// The pointer table embedded in the second half of the header block:
/// leaf block ids, one per hash prefix.
pub fn embedded_ptrtbl(buf: &[u8], endian: Endian) -> Vec<u64> {
    let half = buf.len() / 2;
    buf[half..]
        .chunks_exact(8)
        .map(|c| endian.u64_at(c, 0).expect("8 bytes"))
        .collect()
}

/// Decode an external pointer-table block (raw `u64` array).
pub fn ptrtbl_block(buf: &[u8], endian: Endian) -> Vec<u64> {
    buf.chunks_exact(8)
        .map(|c| endian.u64_at(c, 0).expect("8 bytes"))
        .collect()
}

/// Number of chunks in a leaf of `1 << block_shift` bytes.
pub fn leaf_numchunks(block_shift: u32) -> usize {
    let bs = 1usize << block_shift;
    let hash_entries = 1usize << (block_shift.saturating_sub(5));
    (bs - 2 * hash_entries) / LEAF_CHUNKSIZE - 2
}

/// Byte offset of chunk 0 in a leaf of `1 << block_shift` bytes.
pub fn leaf_chunks_offset(block_shift: u32) -> usize {
    LEAF_HEADER_SIZE + 2 * (1usize << (block_shift.saturating_sub(5)))
}

/// Parse a fatzap leaf block into its entries (in chunk order).
pub fn parse_leaf(buf: &[u8], endian: Endian) -> Result<Vec<Entry>, ParseError> {
    if block_type(buf, endian) != Some(BlockType::Leaf) {
        return Err(ParseError::Malformed {
            what: "not a ZAP leaf block",
            at: 0,
        });
    }
    if !buf.len().is_power_of_two() || buf.len() < 1024 {
        return Err(ParseError::Malformed {
            what: "leaf block size not a power of two >= 1 KiB",
            at: 0,
        });
    }
    let block_shift = buf.len().trailing_zeros();
    let u16_at = |o: usize| -> Option<u16> {
        let b: [u8; 2] = buf.get(o..o + 2)?.try_into().ok()?;
        Some(match endian {
            Endian::Little => u16::from_le_bytes(b),
            Endian::Big => u16::from_be_bytes(b),
        })
    };
    let u32_at = |o: usize| -> Option<u32> {
        let b: [u8; 4] = buf.get(o..o + 4)?.try_into().ok()?;
        Some(match endian {
            Endian::Little => u32::from_le_bytes(b),
            Endian::Big => u32::from_be_bytes(b),
        })
    };
    if u32_at(24) != Some(ZAP_LEAF_MAGIC) {
        return Err(ParseError::BadMagic(u64::from(u32_at(24).unwrap_or(0))));
    }
    let base = leaf_chunks_offset(block_shift);
    let nchunks = leaf_numchunks(block_shift);
    let chunk = |i: u16| -> Option<&[u8]> {
        let i = i as usize;
        if i >= nchunks {
            return None;
        }
        buf.get(base + i * LEAF_CHUNKSIZE..base + (i + 1) * LEAF_CHUNKSIZE)
    };
    // Follow an array chain and collect `len` bytes.
    let read_array = |first: u16, len: usize| -> Result<Vec<u8>, ParseError> {
        let mut out = Vec::with_capacity(len);
        let mut cur = first;
        let mut hops = 0usize;
        while out.len() < len {
            let c = chunk(cur).ok_or(ParseError::Malformed {
                what: "ZAP array chunk index out of range",
                at: base,
            })?;
            if c[0] != CHUNK_ARRAY {
                return Err(ParseError::Malformed {
                    what: "ZAP array chain hits a non-array chunk",
                    at: base,
                });
            }
            let take = (len - out.len()).min(LEAF_ARRAY_BYTES);
            out.extend_from_slice(&c[1..1 + take]);
            let next: [u8; 2] = c[22..24].try_into().expect("2 bytes");
            cur = match endian {
                Endian::Little => u16::from_le_bytes(next),
                Endian::Big => u16::from_be_bytes(next),
            };
            hops += 1;
            if out.len() < len && (cur == CHAIN_END || hops > nchunks) {
                return Err(ParseError::Malformed {
                    what: "ZAP array chain ends early",
                    at: base,
                });
            }
        }
        Ok(out)
    };
    let mut out = Vec::new();
    for i in 0..nchunks {
        let Some(c) = chunk(i as u16) else { break };
        if c[0] != CHUNK_ENTRY {
            continue;
        }
        let at = base + i * LEAF_CHUNKSIZE;
        let intlen = c[1] as usize;
        let name_chunk = u16_at(at + 4).expect("in chunk");
        let name_numints = u16_at(at + 6).expect("in chunk") as usize;
        let value_chunk = u16_at(at + 8).expect("in chunk");
        let value_numints = u16_at(at + 10).expect("in chunk") as usize;
        let cd = u32_at(at + 12).expect("in chunk");
        let name_bytes = read_array(name_chunk, name_numints)?;
        let end = name_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_bytes.len());
        let name = String::from_utf8_lossy(&name_bytes[..end]).into_owned();
        let raw = read_array(value_chunk, intlen * value_numints)?;
        let value = match intlen {
            8 => {
                let ints: Vec<u64> = raw
                    .chunks_exact(8)
                    .map(|c| u64::from_be_bytes(c.try_into().expect("8 bytes")))
                    .collect();
                if ints.len() == 1 {
                    Value::U64(ints[0])
                } else {
                    Value::U64Array(ints)
                }
            }
            1 => Value::Bytes(raw),
            _ => Value::Ints {
                intlen: intlen as u8,
                raw,
            },
        };
        out.push(Entry { name, value, cd });
    }
    Ok(out)
}

/// Builders for fixtures: a microzap block and a single-leaf fatzap.
pub mod encode {
    use super::*;

    /// Build a microzap block of `size` bytes from `(name, value)` pairs.
    pub fn micro(size: usize, entries: &[(&str, u64)]) -> Vec<u8> {
        let mut b = vec![0u8; size];
        b[..8].copy_from_slice(&ZBT_MICRO.to_le_bytes());
        for (i, (name, value)) in entries.iter().enumerate() {
            let at = MZAP_ENT_SIZE * (1 + i);
            assert!(at + MZAP_ENT_SIZE <= size && name.len() < MZAP_NAME_LEN);
            b[at..at + 8].copy_from_slice(&value.to_le_bytes());
            b[at + 14..at + 14 + name.len()].copy_from_slice(name.as_bytes());
        }
        b
    }

    /// Build a fatzap header block of `size` bytes whose embedded pointer
    /// table maps every hash prefix to `leaf_blk`.
    pub fn fat_header(size: usize, leaf_blk: u64, num_entries: u64) -> Vec<u8> {
        let mut b = vec![0u8; size];
        let w = |b: &mut Vec<u8>, o: usize, v: u64| b[o..o + 8].copy_from_slice(&v.to_le_bytes());
        w(&mut b, 0, ZBT_HEADER);
        w(&mut b, 8, ZAP_MAGIC);
        let shift = (size / 16).trailing_zeros() as u64; // entries in the embedded table
        w(&mut b, 32, shift);
        w(&mut b, 56, leaf_blk + 1);
        w(&mut b, 64, 1);
        w(&mut b, 72, num_entries);
        let half = size / 2;
        for i in 0..(size / 16) {
            w(&mut b, half + i * 8, leaf_blk);
        }
        b
    }

    /// Build one leaf block of `size` bytes holding `entries`, whose values
    /// are `(intlen, big-endian element bytes)`.
    pub fn leaf(size: usize, entries: &[(&str, u8, Vec<u8>)]) -> Vec<u8> {
        let block_shift = size.trailing_zeros();
        let mut b = vec![0u8; size];
        b[..8].copy_from_slice(&ZBT_LEAF.to_le_bytes());
        b[24..28].copy_from_slice(&ZAP_LEAF_MAGIC.to_le_bytes());
        b[30..32].copy_from_slice(&(entries.len() as u16).to_le_bytes());
        let base = leaf_chunks_offset(block_shift);
        let nchunks = leaf_numchunks(block_shift);
        let mut next_chunk: u16 = 0;
        fn put_array(
            b: &mut [u8],
            base: usize,
            nchunks: usize,
            next_chunk: &mut u16,
            data: &[u8],
        ) -> u16 {
            if data.is_empty() {
                return CHAIN_END;
            }
            let first = *next_chunk;
            let mut pieces = data.chunks(LEAF_ARRAY_BYTES).peekable();
            while let Some(p) = pieces.next() {
                let at = base + *next_chunk as usize * LEAF_CHUNKSIZE;
                assert!((*next_chunk as usize) < nchunks);
                b[at] = CHUNK_ARRAY;
                b[at + 1..at + 1 + p.len()].copy_from_slice(p);
                let link = if pieces.peek().is_some() {
                    *next_chunk + 1
                } else {
                    CHAIN_END
                };
                b[at + 22..at + 24].copy_from_slice(&link.to_le_bytes());
                *next_chunk += 1;
            }
            first
        }
        for (name, intlen, value) in entries {
            let mut name_bytes = name.as_bytes().to_vec();
            name_bytes.push(0);
            let name_chunk = put_array(&mut b, base, nchunks, &mut next_chunk, &name_bytes);
            let value_chunk = put_array(&mut b, base, nchunks, &mut next_chunk, value);
            let at = base + next_chunk as usize * LEAF_CHUNKSIZE;
            b[at] = CHUNK_ENTRY;
            b[at + 1] = *intlen;
            b[at + 2..at + 4].copy_from_slice(&CHAIN_END.to_le_bytes());
            b[at + 4..at + 6].copy_from_slice(&name_chunk.to_le_bytes());
            b[at + 6..at + 8].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            b[at + 8..at + 10].copy_from_slice(&value_chunk.to_le_bytes());
            b[at + 10..at + 12]
                .copy_from_slice(&((value.len() / *intlen as usize) as u16).to_le_bytes());
            next_chunk += 1;
        }
        // Remaining chunks are free.
        for i in next_chunk as usize..nchunks {
            b[base + i * LEAF_CHUNKSIZE] = CHUNK_FREE;
        }
        b
    }
}

#[cfg(test)]
mod tests {
    use super::encode::{fat_header, leaf, micro};
    use super::*;

    #[test]
    fn microzap_entries() {
        let b = micro(
            4096,
            &[("root_dataset", 2), ("config", 3), ("features_for_read", 4)],
        );
        assert_eq!(block_type(&b, Endian::Little), Some(BlockType::Micro));
        let e = parse_micro(&b, Endian::Little).unwrap();
        assert_eq!(e.len(), 3);
        assert_eq!(e[0].name, "root_dataset");
        assert_eq!(e[0].value, Value::U64(2));
        assert_eq!(e[2].name, "features_for_read");
        assert!(parse_micro(&[0u8; 512], Endian::Little).is_err());
    }

    #[test]
    fn leaf_geometry_matches_openzfs() {
        // 16 KiB leaf: 512 hash entries, 638 chunks, chunks start at 1072.
        assert_eq!(leaf_numchunks(14), 638);
        assert_eq!(leaf_chunks_offset(14), 1072);
        assert_eq!(leaf_chunks_offset(14) + 638 * LEAF_CHUNKSIZE, 16384);
        // 4 KiB leaf.
        assert_eq!(leaf_numchunks(12), 158);
        assert_eq!(leaf_chunks_offset(12) + 158 * LEAF_CHUNKSIZE, 4096);
    }

    #[test]
    fn fat_header_and_leaf_roundtrip() {
        let h = fat_header(16384, 1, 3);
        let hdr = parse_fat_header(&h, Endian::Little).unwrap();
        assert_eq!(hdr.ptrtbl_numblks, 0);
        assert_eq!(hdr.ptrtbl_shift, 10);
        assert_eq!(hdr.num_entries, 3);
        let tbl = embedded_ptrtbl(&h, Endian::Little);
        assert_eq!(tbl.len(), 1024);
        assert!(tbl.iter().all(|&b| b == 1));

        let long_name = "a".repeat(100);
        let l = leaf(
            16384,
            &[
                ("vm", 8, 40u64.to_be_bytes().to_vec()),
                (
                    &long_name,
                    8,
                    [1u64, 2, 3].iter().flat_map(|v| v.to_be_bytes()).collect(),
                ),
                ("compression", 1, b"lz4\0".to_vec()),
                ("weird", 2, vec![0, 1, 0, 2]),
            ],
        );
        let e = parse_leaf(&l, Endian::Little).unwrap();
        assert_eq!(e.len(), 4);
        assert_eq!(e[0].name, "vm");
        assert_eq!(e[0].value.as_u64(), Some(40));
        assert_eq!(e[1].name, long_name);
        assert_eq!(e[1].value, Value::U64Array(vec![1, 2, 3]));
        assert_eq!(e[2].value.as_str().as_deref(), Some("lz4"));
        assert_eq!(
            e[3].value,
            Value::Ints {
                intlen: 2,
                raw: vec![0, 1, 0, 2]
            }
        );
    }

    #[test]
    fn broken_chains_are_errors_not_panics() {
        let mut l = leaf(4096, &[("name", 8, 7u64.to_be_bytes().to_vec())]);
        let base = leaf_chunks_offset(12);
        // Point the entry's name chain past the end of the block.
        let entry_at = base + 2 * LEAF_CHUNKSIZE;
        l[entry_at + 4..entry_at + 6].copy_from_slice(&5000u16.to_le_bytes());
        assert!(matches!(
            parse_leaf(&l, Endian::Little),
            Err(ParseError::Malformed { .. })
        ));
        // Break the value chain link.
        let mut l = leaf(
            4096,
            &[(
                "name",
                8,
                [1u64, 2, 3, 4]
                    .iter()
                    .flat_map(|v| v.to_be_bytes())
                    .collect(),
            )],
        );
        l[base + LEAF_CHUNKSIZE + 22..base + LEAF_CHUNKSIZE + 24]
            .copy_from_slice(&CHAIN_END.to_le_bytes());
        assert!(parse_leaf(&l, Endian::Little).is_err());
        // Wrong magic.
        let mut l = leaf(4096, &[]);
        l[24] ^= 1;
        assert!(matches!(
            parse_leaf(&l, Endian::Little),
            Err(ParseError::BadMagic(_))
        ));
        assert!(parse_leaf(&[0u8; 4096], Endian::Little).is_err());
    }
}
