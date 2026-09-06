//! Embedded label checksums (`ZIO_CHECKSUM_LABEL`).
//!
//! Label nvlists and uberblock slots end with a `zio_eck_t`: a magic word
//! and a four-word checksum. OpenZFS computes SHA-256 over the whole
//! buffer with the checksum field replaced by a *verifier* — the byte
//! offset of the buffer on its vdev — so a block copied to another offset
//! fails verification.

use sha2::{Digest, Sha256};

use crate::Endian;

/// `ZEC_MAGIC` ("zio data bloc").
pub const ZEC_MAGIC: u64 = 0x0210_da7a_b10c_7a11;
/// Size of `zio_eck_t`: magic plus four checksum words.
pub const ECK_SIZE: usize = 40;

/// Outcome of verifying an embedded checksum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumStatus {
    /// Recomputed SHA-256 matches the stored words.
    Ok,
    /// Magic present but the checksum does not match: corrupted or moved.
    Bad,
    /// No `ZEC_MAGIC` at the end of the buffer: never written or overwritten.
    Missing,
}

impl ChecksumStatus {
    /// Short lowercase name for text and JSON output.
    pub fn as_str(self) -> &'static str {
        match self {
            ChecksumStatus::Ok => "ok",
            ChecksumStatus::Bad => "bad",
            ChecksumStatus::Missing => "missing",
        }
    }
}

/// Verify the embedded checksum of `buf`, which was stored at byte offset
/// `vdev_offset` on its vdev.
pub fn verify_label(buf: &[u8], vdev_offset: u64) -> ChecksumStatus {
    verify_embedded(buf, [vdev_offset, 0, 0, 0])
}

/// Verify the embedded checksum of a gang block header: the verifier is
/// the gang pointer's first DVA (vdev, byte offset) and its birth TXG
/// (`zio_checksum_gang_verifier`).
pub fn verify_gang_header(buf: &[u8], vdev: u64, offset: u64, birth: u64) -> ChecksumStatus {
    verify_embedded(buf, [vdev, offset, birth, 0])
}

/// Verify an embedded SHA-256 checksum with an explicit verifier.
pub fn verify_embedded(buf: &[u8], verifier: [u64; 4]) -> ChecksumStatus {
    if buf.len() < ECK_SIZE {
        return ChecksumStatus::Missing;
    }
    let eck = buf.len() - ECK_SIZE;
    let raw = Endian::Little.u64_at(buf, eck).expect("length checked");
    let endian = if raw == ZEC_MAGIC {
        Endian::Little
    } else if raw.swap_bytes() == ZEC_MAGIC {
        Endian::Big
    } else {
        return ChecksumStatus::Missing;
    };
    let word = |i: usize| endian.u64_at(buf, eck + 8 + i * 8).expect("length checked");
    let stored = [word(0), word(1), word(2), word(3)];

    let mut tmp = buf.to_vec();
    for (i, v) in verifier.iter().enumerate() {
        let bytes = match endian {
            Endian::Little => v.to_le_bytes(),
            Endian::Big => v.to_be_bytes(),
        };
        tmp[eck + 8 + i * 8..eck + 16 + i * 8].copy_from_slice(&bytes);
    }
    let digest = Sha256::digest(&tmp);
    let mut computed = [0u64; 4];
    for (i, w) in computed.iter_mut().enumerate() {
        *w = u64::from_be_bytes(digest[i * 8..i * 8 + 8].try_into().expect("32-byte digest"));
    }
    if computed == stored {
        ChecksumStatus::Ok
    } else {
        ChecksumStatus::Bad
    }
}

/// Write a valid embedded checksum into `buf` for `vdev_offset`.
///
/// Only for building test fixtures; the tool itself never writes evidence.
pub fn seal_label(buf: &mut [u8], vdev_offset: u64) {
    seal_embedded(buf, [vdev_offset, 0, 0, 0]);
}

/// Write a valid embedded checksum with an explicit verifier (fixtures).
pub fn seal_embedded(buf: &mut [u8], verifier: [u64; 4]) {
    assert!(buf.len() >= ECK_SIZE);
    let eck = buf.len() - ECK_SIZE;
    buf[eck..eck + 8].copy_from_slice(&ZEC_MAGIC.to_le_bytes());
    for (i, v) in verifier.iter().enumerate() {
        buf[eck + 8 + i * 8..eck + 16 + i * 8].copy_from_slice(&v.to_le_bytes());
    }
    let digest = Sha256::digest(&*buf);
    for i in 0..4 {
        let w = u64::from_be_bytes(digest[i * 8..i * 8 + 8].try_into().expect("32-byte digest"));
        buf[eck + 8 + i * 8..eck + 16 + i * 8].copy_from_slice(&w.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_then_verify() {
        let mut b = vec![0x5au8; 1024];
        seal_label(&mut b, 0x2_0000);
        assert_eq!(verify_label(&b, 0x2_0000), ChecksumStatus::Ok);
        // A block moved to a different offset must fail.
        assert_eq!(verify_label(&b, 0x3_0000), ChecksumStatus::Bad);
        // A flipped data byte must fail.
        b[10] ^= 1;
        assert_eq!(verify_label(&b, 0x2_0000), ChecksumStatus::Bad);
    }

    #[test]
    fn missing_magic() {
        assert_eq!(verify_label(&[0u8; 1024], 0), ChecksumStatus::Missing);
        assert_eq!(verify_label(&[0u8; 8], 0), ChecksumStatus::Missing);
    }
}

// ---------------------------------------------------------------------------
// Data block checksums (the algorithms named in blkptr_t)
// ---------------------------------------------------------------------------

use sha2::Sha512_256;

use crate::blkptr::Checksum;

/// `fletcher2` over 64-bit words, read in the writer's byte order.
///
/// Defined only for lengths that are a multiple of 16 bytes; a trailing
/// partial pair is ignored, as in OpenZFS.
pub fn fletcher2(data: &[u8], endian: Endian) -> [u64; 4] {
    let (mut a0, mut a1, mut b0, mut b1) = (0u64, 0u64, 0u64, 0u64);
    for pair in data.chunks_exact(16) {
        let w0 = endian.u64_at(pair, 0).expect("16-byte chunk");
        let w1 = endian.u64_at(pair, 8).expect("16-byte chunk");
        a0 = a0.wrapping_add(w0);
        a1 = a1.wrapping_add(w1);
        b0 = b0.wrapping_add(a0);
        b1 = b1.wrapping_add(a1);
    }
    [a0, a1, b0, b1]
}

/// `fletcher4` over 32-bit words, read in the writer's byte order.
///
/// Defined only for lengths that are a multiple of 4 bytes; a trailing
/// partial word is ignored, as in OpenZFS.
pub fn fletcher4(data: &[u8], endian: Endian) -> [u64; 4] {
    let (mut a, mut b, mut c, mut d) = (0u64, 0u64, 0u64, 0u64);
    for word in data.chunks_exact(4) {
        let bytes: [u8; 4] = word.try_into().expect("4-byte chunk");
        let w = match endian {
            Endian::Little => u32::from_le_bytes(bytes),
            Endian::Big => u32::from_be_bytes(bytes),
        } as u64;
        a = a.wrapping_add(w);
        b = b.wrapping_add(a);
        c = c.wrapping_add(b);
        d = d.wrapping_add(c);
    }
    [a, b, c, d]
}

fn digest_words(digest: &[u8]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for (i, w) in out.iter_mut().enumerate() {
        *w = u64::from_be_bytes(digest[i * 8..i * 8 + 8].try_into().expect("32 bytes"));
    }
    out
}

/// `sha256` as four big-endian words.
pub fn sha256(data: &[u8]) -> [u64; 4] {
    digest_words(&Sha256::digest(data))
}

/// `sha512`: OpenZFS uses SHA-512/256 (distinct IV, 256-bit output).
pub fn sha512_256(data: &[u8]) -> [u64; 4] {
    digest_words(&Sha512_256::digest(data))
}

/// Result of checking a data block against its block pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verify {
    /// Recomputed checksum matches.
    Ok,
    /// Recomputed checksum differs: the block is damaged or stale.
    Mismatch,
    /// The block pointer says `off`: nothing to check.
    NotChecked,
    /// Algorithm not implemented in this build (skein, edonr, blake3, …).
    Unsupported,
}

/// Compute the checksum `kind` over `data` written in `endian` order, or
/// `None` when the algorithm is not implemented.
pub fn compute(kind: Checksum, data: &[u8], endian: Endian) -> Option<[u64; 4]> {
    match kind {
        Checksum::Fletcher2 => Some(fletcher2(data, endian)),
        Checksum::Fletcher4 => Some(fletcher4(data, endian)),
        Checksum::Sha256 => Some(sha256(data)),
        Checksum::Sha512 => Some(sha512_256(data)),
        _ => None,
    }
}

/// Verify `data` against the checksum words stored in its block pointer.
pub fn verify(kind: Checksum, data: &[u8], endian: Endian, expected: &[u64; 4]) -> Verify {
    match kind {
        Checksum::Off => Verify::NotChecked,
        _ => match compute(kind, data, endian) {
            Some(c) if c == *expected => Verify::Ok,
            Some(_) => Verify::Mismatch,
            None => Verify::Unsupported,
        },
    }
}

#[cfg(test)]
mod data_tests {
    use super::*;

    #[test]
    fn fletcher4_small_vectors() {
        assert_eq!(fletcher4(&[], Endian::Little), [0; 4]);
        assert_eq!(fletcher4(&1u32.to_le_bytes(), Endian::Little), [1, 1, 1, 1]);
        let mut d = Vec::new();
        d.extend(1u32.to_le_bytes());
        d.extend(2u32.to_le_bytes());
        assert_eq!(fletcher4(&d, Endian::Little), [3, 4, 5, 6]);
        // The same bytes seen as big-endian words give a different sum.
        assert_ne!(fletcher4(&d, Endian::Big), [3, 4, 5, 6]);
        // Sums wrap instead of overflowing.
        let big = vec![0xffu8; 1 << 20];
        let _ = fletcher4(&big, Endian::Little);
    }

    #[test]
    fn fletcher2_small_vectors() {
        let mut d = Vec::new();
        d.extend(1u64.to_le_bytes());
        d.extend(2u64.to_le_bytes());
        d.extend(3u64.to_le_bytes());
        d.extend(4u64.to_le_bytes());
        // a0 = 1+3, a1 = 2+4, b0 = 1 + 4, b1 = 2 + 6
        assert_eq!(fletcher2(&d, Endian::Little), [4, 6, 5, 8]);
    }

    #[test]
    fn sha_vectors() {
        let abc = sha256(b"abc");
        assert_eq!(abc[0], 0xba78_16bf_8f01_cfea);
        assert_eq!(abc[3], 0xb410_ff61_f200_15ad);
        let abc = sha512_256(b"abc");
        assert_eq!(abc[0], 0x5304_8e26_8194_1ef9);
        assert_eq!(abc[3], 0xe0e2_f131_07e7_af23);
    }

    #[test]
    fn verify_dispatch() {
        let data = b"hello zfs block".to_vec();
        let ok = sha256(&data);
        assert_eq!(
            verify(Checksum::Sha256, &data, Endian::Little, &ok),
            Verify::Ok
        );
        assert_eq!(
            verify(Checksum::Sha256, &data, Endian::Little, &[0; 4]),
            Verify::Mismatch
        );
        assert_eq!(
            verify(Checksum::Off, &data, Endian::Little, &[0; 4]),
            Verify::NotChecked
        );
        assert_eq!(
            verify(Checksum::Blake3, &data, Endian::Little, &[0; 4]),
            Verify::Unsupported
        );
        let f = fletcher4(&data[..12], Endian::Big);
        assert_eq!(
            verify(Checksum::Fletcher4, &data[..12], Endian::Big, &f),
            Verify::Ok
        );
    }
}
