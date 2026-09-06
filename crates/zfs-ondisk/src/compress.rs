//! Decompression of block payloads, per `ZIO_COMPRESS_*`.
//!
//! Every function takes the on-disk bytes (`psize` long) and the expected
//! logical size and returns exactly `lsize` bytes or an error. Nothing
//! here allocates more than `lsize` plus a bounded header, whatever the
//! input claims.

use std::fmt;
use std::io::Read;

use crate::blkptr::Compression;

/// Why a block could not be decompressed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecompressError {
    /// Algorithm not implemented in this build.
    Unsupported(Compression),
    /// The stream is malformed.
    Corrupt(&'static str),
    /// Decoded to a different size than `lsize`.
    SizeMismatch {
        /// Bytes expected.
        expected: usize,
        /// Bytes produced.
        got: usize,
    },
}

impl fmt::Display for DecompressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecompressError::Unsupported(c) => write!(f, "unsupported compression {}", c.name()),
            DecompressError::Corrupt(what) => write!(f, "corrupt compressed stream: {what}"),
            DecompressError::SizeMismatch { expected, got } => {
                write!(f, "decompressed to {got} bytes, expected {expected}")
            }
        }
    }
}

impl std::error::Error for DecompressError {}

/// `lzjb` (OpenZFS `lzjb.c`).
pub fn lzjb(src: &[u8], lsize: usize) -> Result<Vec<u8>, DecompressError> {
    const MATCH_BITS: u32 = 6;
    const MATCH_MIN: usize = 3;
    const OFFSET_MASK: usize = (1 << (16 - MATCH_BITS)) - 1;
    let mut dst = Vec::with_capacity(lsize);
    let mut s = 0usize;
    let mut copymap = 0u8;
    let mut copymask = 1u32 << 7;
    while dst.len() < lsize {
        copymask <<= 1;
        if copymask == 1 << 8 {
            copymask = 1;
            copymap = *src
                .get(s)
                .ok_or(DecompressError::Corrupt("lzjb: truncated copymap"))?;
            s += 1;
        }
        if copymap & copymask as u8 != 0 {
            let b0 = *src
                .get(s)
                .ok_or(DecompressError::Corrupt("lzjb: truncated match"))?
                as usize;
            let b1 = *src
                .get(s + 1)
                .ok_or(DecompressError::Corrupt("lzjb: truncated match"))?
                as usize;
            s += 2;
            let mut mlen = (b0 >> (8 - MATCH_BITS)) + MATCH_MIN;
            let offset = ((b0 << 8) | b1) & OFFSET_MASK;
            if offset == 0 || offset > dst.len() {
                return Err(DecompressError::Corrupt("lzjb: match before start"));
            }
            let start = dst.len() - offset;
            mlen = mlen.min(lsize - dst.len());
            // Byte-by-byte because the match may overlap the bytes being
            // produced (offset < mlen is the classic run encoding).
            for k in 0..mlen {
                let b = dst[start + k];
                dst.push(b);
            }
        } else {
            dst.push(
                *src.get(s)
                    .ok_or(DecompressError::Corrupt("lzjb: truncated literal"))?,
            );
            s += 1;
        }
    }
    Ok(dst)
}

/// `zle` with the default level of 64 (OpenZFS `zle.c`).
pub fn zle(src: &[u8], lsize: usize) -> Result<Vec<u8>, DecompressError> {
    const LEVEL: usize = 64;
    let mut dst = Vec::with_capacity(lsize);
    let mut s = 0usize;
    while s < src.len() && dst.len() < lsize {
        let len = 1 + src[s] as usize;
        s += 1;
        if len <= LEVEL {
            let end = s + len;
            if end > src.len() {
                return Err(DecompressError::Corrupt("zle: truncated literal run"));
            }
            let take = len.min(lsize - dst.len());
            dst.extend_from_slice(&src[s..s + take]);
            s = end;
        } else {
            let zeros = (len - LEVEL).min(lsize - dst.len());
            dst.resize(dst.len() + zeros, 0);
        }
    }
    check_size(dst, lsize)
}

/// `lz4`: a big-endian 4-byte compressed length followed by one LZ4 block.
pub fn lz4(src: &[u8], lsize: usize) -> Result<Vec<u8>, DecompressError> {
    if src.len() < 4 {
        return Err(DecompressError::Corrupt("lz4: missing length prefix"));
    }
    let clen = u32::from_be_bytes(src[..4].try_into().expect("4 bytes")) as usize;
    let body = src
        .get(4..4 + clen)
        .ok_or(DecompressError::Corrupt("lz4: length prefix beyond input"))?;
    let out = lz4_flex::block::decompress(body, lsize)
        .map_err(|_| DecompressError::Corrupt("lz4: invalid block"))?;
    check_size(out, lsize)
}

/// `gzip-N`: a zlib stream (OpenZFS uses `compress2`, not gzip framing).
pub fn gzip(src: &[u8], lsize: usize) -> Result<Vec<u8>, DecompressError> {
    let mut out = Vec::with_capacity(lsize);
    let mut dec = flate2::read::ZlibDecoder::new(src).take(lsize as u64 + 1);
    dec.read_to_end(&mut out)
        .map_err(|_| DecompressError::Corrupt("gzip: invalid zlib stream"))?;
    check_size(out, lsize)
}

/// `zstd`: OpenZFS prefixes the frame with an 8-byte header — big-endian
/// compressed length, then big-endian `version << 8 | level`.
pub fn zstd(src: &[u8], lsize: usize) -> Result<Vec<u8>, DecompressError> {
    if src.len() < 8 {
        return Err(DecompressError::Corrupt("zstd: missing header"));
    }
    let clen = u32::from_be_bytes(src[..4].try_into().expect("4 bytes")) as usize;
    let frame = src
        .get(8..8 + clen)
        .ok_or(DecompressError::Corrupt("zstd: length beyond input"))?;
    let mut dec = ruzstd::decoding::StreamingDecoder::new(frame)
        .map_err(|_| DecompressError::Corrupt("zstd: invalid frame header"))?;
    let mut out = Vec::with_capacity(lsize);
    dec.by_ref()
        .take(lsize as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| DecompressError::Corrupt("zstd: invalid frame"))?;
    check_size(out, lsize)
}

/// Level and library version recorded in a ZFS zstd header.
pub fn zstd_header(src: &[u8]) -> Option<(u8, u32)> {
    let raw = u32::from_be_bytes(src.get(4..8)?.try_into().ok()?);
    Some(((raw & 0xff) as u8, raw >> 8))
}

fn check_size(out: Vec<u8>, lsize: usize) -> Result<Vec<u8>, DecompressError> {
    if out.len() == lsize {
        Ok(out)
    } else {
        Err(DecompressError::SizeMismatch {
            expected: lsize,
            got: out.len(),
        })
    }
}

/// Decompress `src` according to `kind` into exactly `lsize` bytes.
///
/// `Off` copies (and pads or truncates to `lsize`, as ZFS reads a block
/// of `lsize` from a `psize == lsize` allocation); `Empty` yields zeros.
pub fn decompress(kind: Compression, src: &[u8], lsize: usize) -> Result<Vec<u8>, DecompressError> {
    match kind {
        Compression::Off => {
            let mut v = src[..src.len().min(lsize)].to_vec();
            v.resize(lsize, 0);
            Ok(v)
        }
        Compression::Empty => Ok(vec![0; lsize]),
        Compression::Lzjb => lzjb(src, lsize),
        Compression::Zle => zle(src, lsize),
        Compression::Lz4 => lz4(src, lsize),
        Compression::Gzip(_) => gzip(src, lsize),
        Compression::Zstd => zstd(src, lsize),
        Compression::Unknown(_) => Err(DecompressError::Unsupported(kind)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn sample() -> Vec<u8> {
        let mut v = Vec::new();
        for i in 0..4096u32 {
            v.extend((i % 37).to_le_bytes());
        }
        v.extend([0u8; 1000]);
        v.extend(b"the quick brown fox jumps over the lazy dog ".repeat(20));
        v
    }

    #[test]
    fn lzjb_handcrafted_streams() {
        // copymap 0b10: item 0 literal 'a', item 1 match len 11 offset 1.
        let s = [0x02u8, b'a', 0x20, 0x01];
        assert_eq!(lzjb(&s, 12).unwrap(), vec![b'a'; 12]);
        // Match reaching before the start of the output is corrupt.
        let s = [0x01u8, 0x20, 0x05];
        assert!(matches!(lzjb(&s, 8), Err(DecompressError::Corrupt(_))));
        // Truncated input.
        assert!(lzjb(&[0x00u8, b'x'], 4).is_err());
    }

    #[test]
    fn zle_handcrafted_streams() {
        let s = [2u8, b'x', b'y', b'z', 68];
        let mut want = b"xyz".to_vec();
        want.extend([0u8; 5]);
        assert_eq!(zle(&s, 8).unwrap(), want);
        assert!(matches!(
            zle(&s, 9),
            Err(DecompressError::SizeMismatch { .. })
        ));
        assert!(zle(&[5u8, b'a'], 6).is_err());
    }

    #[test]
    fn lz4_roundtrip_with_zfs_prefix() {
        let data = sample();
        let block = lz4_flex::block::compress(&data);
        let mut src = (block.len() as u32).to_be_bytes().to_vec();
        src.extend(&block);
        assert_eq!(lz4(&src, data.len()).unwrap(), data);
        assert!(lz4(&src[..src.len() - 10], data.len()).is_err());
        assert!(lz4(&src, data.len() + 1).is_err());
    }

    #[test]
    fn gzip_is_zlib_framed() {
        let data = sample();
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(6));
        enc.write_all(&data).unwrap();
        let src = enc.finish().unwrap();
        assert_eq!(gzip(&src, data.len()).unwrap(), data);
        assert!(gzip(&src, data.len() - 1).is_err());
        assert!(gzip(b"not zlib at all", 16).is_err());
    }

    #[test]
    fn zstd_raw_and_rle_frames_with_zfs_header() {
        // Frame: magic, FHD 0x20 (single segment, 1-byte FCS), FCS=5,
        // block header raw/last/size 5, "hello".
        let frame = [
            0x28u8, 0xb5, 0x2f, 0xfd, 0x20, 0x05, 0x29, 0x00, 0x00, b'h', b'e', b'l', b'l', b'o',
        ];
        let mut src = (frame.len() as u32).to_be_bytes().to_vec();
        src.extend(((10_500u32 << 8) | 3).to_be_bytes()); // version 1.4.5-ish, level 3
        src.extend(frame);
        assert_eq!(zstd(&src, 5).unwrap(), b"hello");
        assert_eq!(zstd_header(&src), Some((3, 10_500)));
        // RLE block: 'a' x 100.
        let frame = [0x28u8, 0xb5, 0x2f, 0xfd, 0x20, 100, 0x23, 0x03, 0x00, b'a'];
        let mut src = (frame.len() as u32).to_be_bytes().to_vec();
        src.extend(3u32.to_be_bytes());
        src.extend(frame);
        assert_eq!(zstd(&src, 100).unwrap(), vec![b'a'; 100]);
        assert!(zstd(&src, 99).is_err());
        assert!(zstd(&src[..6], 100).is_err());
    }

    #[test]
    fn dispatch_off_empty_unknown() {
        assert_eq!(decompress(Compression::Off, b"abc", 5).unwrap(), b"abc\0\0");
        assert_eq!(decompress(Compression::Empty, b"", 3).unwrap(), vec![0; 3]);
        assert!(matches!(
            decompress(Compression::Unknown(99), b"", 1),
            Err(DecompressError::Unsupported(_))
        ));
    }
}
