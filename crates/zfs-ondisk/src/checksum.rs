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
    let verifier = [vdev_offset, 0, 0, 0];
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
    assert!(buf.len() >= ECK_SIZE);
    let eck = buf.len() - ECK_SIZE;
    buf[eck..eck + 8].copy_from_slice(&ZEC_MAGIC.to_le_bytes());
    let verifier = [vdev_offset, 0, 0, 0];
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
