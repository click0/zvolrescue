//! Pure parsers for ZFS on-disk structures.
//!
//! This crate performs no I/O and allocates nothing beyond the parsed
//! values. Every parser takes a byte slice and returns either a typed value
//! or a [`ParseError`]; malformed input is a normal, non-panicking outcome
//! because the input of a recovery tool is hostile by definition.
//!
//! Layout constants and field offsets follow OpenZFS
//! (`include/sys/vdev_impl.h`, `include/sys/uberblock_impl.h`,
//! `include/sys/spa.h`).

pub mod blkptr;
pub mod checksum;
pub mod compress;
pub mod dmu;
pub mod draid;
pub mod dsl;
pub mod error;
pub mod label;
pub mod nvlist;
pub mod part;
pub mod raidz;
pub mod skein;
pub mod uberblock;
pub mod zap;
pub mod zeropoint;

pub use error::ParseError;

/// Byte order of an on-disk structure, detected from its magic number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    /// Little-endian (x86, aarch64 in practice).
    Little,
    /// Big-endian (historic SPARC pools).
    Big,
}

impl Endian {
    /// Read a `u64` at `offset` in the given byte order.
    ///
    /// Returns `None` when the slice is too short.
    pub fn u64_at(self, buf: &[u8], offset: usize) -> Option<u64> {
        let bytes: [u8; 8] = buf.get(offset..offset + 8)?.try_into().ok()?;
        Some(match self {
            Endian::Little => u64::from_le_bytes(bytes),
            Endian::Big => u64::from_be_bytes(bytes),
        })
    }
}
