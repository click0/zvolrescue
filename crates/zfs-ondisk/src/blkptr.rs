//! Block pointers (`blkptr_t`, 128 bytes).
//!
//! Bit layout from OpenZFS `include/sys/spa.h`. Three DVAs address up to
//! three copies of the block; `blk_prop` packs sizes, compression,
//! checksum, object type and level; two birth TXGs and the checksum follow.
//! Embedded block pointers (`X` bit) carry up to 112 bytes of payload in
//! place of the DVAs and checksum.

use crate::{Endian, ParseError};

/// Size of a block pointer in bytes.
pub const SIZE: usize = 128;
/// Sector shift used by every size and offset field.
pub const MINBLOCKSHIFT: u32 = 9;
/// Payload capacity of an embedded block pointer.
pub const EMBEDDED_PAYLOAD: usize = 112;
/// Bytes a leaf vdev reserves in front of its allocatable space: two
/// labels plus the boot block (`VDEV_LABEL_START_SIZE`). DVA offsets are
/// relative to the end of this area.
pub const LABEL_START_SIZE: u64 = 4 * 1024 * 1024;

/// Extract `len` bits starting at `low` from `x`.
fn bits(x: u64, low: u32, len: u32) -> u64 {
    (x >> low) & ((1u64 << len) - 1)
}

/// One data virtual address: a copy of the block on one top-level vdev.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Dva {
    /// Top-level vdev id.
    pub vdev: u32,
    /// Byte offset within the vdev's allocatable space (add
    /// [`LABEL_START_SIZE`] for the physical offset on a leaf).
    pub offset: u64,
    /// Allocated size in bytes, including RAIDZ parity.
    pub asize: u64,
    /// Gang block: the address points at a `zio_gbh_phys_t` of sub-pointers.
    pub gang: bool,
}

impl Dva {
    /// Unallocated: both words zero.
    pub fn is_empty(&self) -> bool {
        self.vdev == 0 && self.offset == 0 && self.asize == 0 && !self.gang
    }

    fn parse(w0: u64, w1: u64) -> Dva {
        Dva {
            asize: bits(w0, 0, 24) << MINBLOCKSHIFT,
            vdev: bits(w0, 32, 32) as u32,
            offset: bits(w1, 0, 63) << MINBLOCKSHIFT,
            gang: bits(w1, 63, 1) != 0,
        }
    }
}

/// `ZIO_COMPRESS_*` codes that matter for reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// No compression (`off`, or `empty` for an all-zero block).
    Off,
    /// A block that is entirely zeros (`ZIO_COMPRESS_EMPTY`).
    Empty,
    /// `lzjb`.
    Lzjb,
    /// `gzip-N`, N in 1..=9.
    Gzip(u8),
    /// `zle`.
    Zle,
    /// `lz4`.
    Lz4,
    /// `zstd`.
    Zstd,
    /// Any code this reader does not know.
    Unknown(u8),
}

impl Compression {
    /// Decode a `ZIO_COMPRESS_*` code.
    pub fn from_code(c: u8) -> Compression {
        match c {
            0..=2 => Compression::Off,
            3 => Compression::Lzjb,
            4 => Compression::Empty,
            5..=13 => Compression::Gzip(c - 4),
            14 => Compression::Zle,
            15 => Compression::Lz4,
            16 => Compression::Zstd,
            other => Compression::Unknown(other),
        }
    }

    /// Name as `zfs get compression` would print it.
    pub fn name(&self) -> String {
        match self {
            Compression::Off => "off".into(),
            Compression::Empty => "empty".into(),
            Compression::Lzjb => "lzjb".into(),
            Compression::Gzip(n) => format!("gzip-{n}"),
            Compression::Zle => "zle".into(),
            Compression::Lz4 => "lz4".into(),
            Compression::Zstd => "zstd".into(),
            Compression::Unknown(c) => format!("unknown-{c}"),
        }
    }
}

/// `ZIO_CHECKSUM_*` codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Checksum {
    /// No checksum (`off`).
    Off,
    /// Embedded label checksum (labels and uberblocks only).
    Label,
    /// Gang block header.
    GangHeader,
    /// ZIL block, old and new variants.
    Zilog,
    /// `fletcher2`.
    Fletcher2,
    /// `fletcher4`.
    Fletcher4,
    /// `sha256`.
    Sha256,
    /// RAIDZ parity placeholder (`noparity`).
    NoParity,
    /// `sha512` (truncated to 256 bits).
    Sha512,
    /// `skein`.
    Skein,
    /// `edonr`.
    Edonr,
    /// `blake3`.
    Blake3,
    /// Any code this reader does not know.
    Unknown(u8),
}

impl Checksum {
    /// Decode a `ZIO_CHECKSUM_*` code.
    pub fn from_code(c: u8) -> Checksum {
        match c {
            0..=2 => Checksum::Off,
            3 => Checksum::Label,
            4 => Checksum::GangHeader,
            5 | 9 => Checksum::Zilog,
            6 => Checksum::Fletcher2,
            7 => Checksum::Fletcher4,
            8 => Checksum::Sha256,
            10 => Checksum::NoParity,
            11 => Checksum::Sha512,
            12 => Checksum::Skein,
            13 => Checksum::Edonr,
            14 => Checksum::Blake3,
            other => Checksum::Unknown(other),
        }
    }

    /// The `ZIO_CHECKSUM_*` code (for fixtures and reports).
    pub fn code(&self) -> u8 {
        match self {
            Checksum::Off => 2,
            Checksum::Label => 3,
            Checksum::GangHeader => 4,
            Checksum::Zilog => 5,
            Checksum::Fletcher2 => 6,
            Checksum::Fletcher4 => 7,
            Checksum::Sha256 => 8,
            Checksum::NoParity => 10,
            Checksum::Sha512 => 11,
            Checksum::Skein => 12,
            Checksum::Edonr => 13,
            Checksum::Blake3 => 14,
            Checksum::Unknown(c) => *c,
        }
    }

    /// `ZCHECKSUM_FLAG_DEDUP`: strong enough for dedup. OpenZFS keeps
    /// such checksums whole under encryption instead of folding them.
    /// `edonr` is salted but *not* dedup-capable (`zio_checksum_table`),
    /// so its words fold like fletcher's.
    pub fn dedup_capable(&self) -> bool {
        matches!(
            self,
            Checksum::Sha256 | Checksum::Sha512 | Checksum::Skein | Checksum::Blake3
        )
    }

    /// Name as `zfs get checksum` would print it.
    pub fn name(&self) -> String {
        match self {
            Checksum::Off => "off".into(),
            Checksum::Label => "label".into(),
            Checksum::GangHeader => "gang_header".into(),
            Checksum::Zilog => "zilog".into(),
            Checksum::Fletcher2 => "fletcher2".into(),
            Checksum::Fletcher4 => "fletcher4".into(),
            Checksum::Sha256 => "sha256".into(),
            Checksum::NoParity => "noparity".into(),
            Checksum::Sha512 => "sha512".into(),
            Checksum::Skein => "skein".into(),
            Checksum::Edonr => "edonr".into(),
            Checksum::Blake3 => "blake3".into(),
            Checksum::Unknown(c) => format!("unknown-{c}"),
        }
    }
}

/// A decoded block pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlkPtr {
    /// The three DVAs; unused ones are empty.
    pub dva: [Dva; 3],
    /// Logical (uncompressed) size in bytes.
    pub lsize: u64,
    /// Physical (compressed) size in bytes.
    pub psize: u64,
    /// Compression of the on-disk bytes.
    pub compression: Compression,
    /// Raw compression code.
    pub compression_code: u8,
    /// Checksum algorithm.
    pub checksum: Checksum,
    /// Raw checksum code.
    pub checksum_code: u8,
    /// `dmu_object_type_t` of the object this block belongs to.
    pub object_type: u8,
    /// Indirection level: 0 = data, N = N-th level indirect block.
    pub level: u8,
    /// Byte order the block was written in.
    pub endian: Endian,
    /// Encrypted (`E` bit).
    pub encrypted: bool,
    /// Deduplicated (`D` bit).
    pub dedup: bool,
    /// Embedded data (`X` bit); see [`BlkPtr::embedded_payload`].
    pub embedded: bool,
    /// Embedded type (`BP_EMBEDDED_TYPE_*`) when `embedded`.
    pub embedded_type: u8,
    /// TXG in which the block was allocated (`0` = same as `birth`).
    pub physical_birth: u64,
    /// TXG in which the block's contents were written.
    pub birth: u64,
    /// Number of non-hole blocks below (for indirect blocks) or 1.
    pub fill: u64,
    /// Stored checksum words.
    pub cksum: [u64; 4],
    /// Raw bytes, kept for embedded payload extraction and verification.
    raw: [u8; SIZE],
}

impl BlkPtr {
    /// Parse a 128-byte block pointer written in `endian` byte order.
    ///
    /// Callers know the byte order from the containing structure (the
    /// uberblock's magic, or the parent block's `B` bit); a pointer's own
    /// `B` bit is decoded and reported but not trusted for its own parsing.
    pub fn parse(buf: &[u8], endian: Endian) -> Result<BlkPtr, ParseError> {
        if buf.len() < SIZE {
            return Err(ParseError::Truncated {
                needed: SIZE,
                got: buf.len(),
            });
        }
        let w = |i: usize| endian.u64_at(buf, i * 8).expect("length checked");
        let prop = w(6);
        let embedded = bits(prop, 39, 1) != 0;
        let byteorder = if bits(prop, 63, 1) == 1 {
            Endian::Little
        } else {
            Endian::Big
        };
        let (lsize, psize, embedded_type) = if embedded {
            (
                bits(prop, 0, 25) + 1,
                bits(prop, 25, 7) + 1,
                bits(prop, 40, 8) as u8,
            )
        } else {
            (
                (bits(prop, 0, 16) + 1) << MINBLOCKSHIFT,
                (bits(prop, 16, 16) + 1) << MINBLOCKSHIFT,
                0,
            )
        };
        let compression_code = bits(prop, 32, 7) as u8;
        let checksum_code = if embedded { 0 } else { bits(prop, 40, 8) as u8 };
        let object_type = bits(prop, 48, 8) as u8;
        let level = bits(prop, 56, 5) as u8;
        let encrypted = bits(prop, 61, 1) != 0;
        let hole = !embedded && w(0) == 0 && w(1) == 0;
        // `BP_IS_ENCRYPTED`: ciphertext block whose DVA[2] slot carries the
        // salt and IV, and whose fill count is 32 bits (IV2 above it).
        let ciphertext = encrypted
            && !hole
            && !embedded
            && level == 0
            && crate::dmu::ot::is_encrypted(object_type);
        let mut raw = [0u8; SIZE];
        raw.copy_from_slice(&buf[..SIZE]);
        Ok(BlkPtr {
            dva: if embedded {
                [Dva::default(); 3]
            } else {
                [
                    Dva::parse(w(0), w(1)),
                    Dva::parse(w(2), w(3)),
                    if ciphertext {
                        Dva::default()
                    } else {
                        Dva::parse(w(4), w(5))
                    },
                ]
            },
            lsize,
            psize,
            compression: Compression::from_code(compression_code),
            compression_code,
            checksum: Checksum::from_code(checksum_code),
            checksum_code,
            object_type,
            level,
            endian: byteorder,
            encrypted,
            dedup: bits(prop, 62, 1) != 0,
            embedded,
            embedded_type,
            physical_birth: if embedded { 0 } else { bits(w(9), 0, 63) },
            birth: bits(w(10), 0, 63),
            fill: if embedded {
                1
            } else if ciphertext {
                bits(w(11), 0, 32)
            } else {
                w(11)
            },
            cksum: if embedded {
                [0; 4]
            } else {
                [w(12), w(13), w(14), w(15)]
            },
            raw,
        })
    }

    /// A hole: nothing allocated, reads as zeros.
    pub fn is_hole(&self) -> bool {
        !self.embedded && self.dva[0].is_empty()
    }

    /// `BP_USES_CRYPT`: the block belongs to an encrypted dataset. Its
    /// checksum words 2 and 3 hold a MAC, so only words 0 and 1 verify.
    pub fn uses_crypt(&self) -> bool {
        self.encrypted && !self.embedded && !self.is_hole()
    }

    /// `BP_IS_ENCRYPTED`: the payload on disk is ciphertext (level-0 block
    /// of an encrypted object type). Indirect and MOS-style blocks of an
    /// encrypted dataset are only authenticated and read in the clear.
    pub fn is_encrypted(&self) -> bool {
        self.uses_crypt() && self.level == 0 && crate::dmu::ot::is_encrypted(self.object_type)
    }

    /// Salt, IV (96 bits as two words: 64 + 32) of an encrypted block,
    /// from the DVA[2] slot and the top of the fill word.
    pub fn crypt_params(&self) -> Option<(u64, u64, u32)> {
        if !self.is_encrypted() {
            return None;
        }
        let w = |i: usize| self.endian.u64_at(&self.raw, i * 8).expect("128 bytes");
        Some((w(4), w(5), bits(w(11), 32, 32) as u32))
    }

    /// Effective allocation TXG (`BP_GET_PHYSICAL_BIRTH` semantics).
    pub fn physical_birth_or_logical(&self) -> u64 {
        if self.physical_birth == 0 {
            self.birth
        } else {
            self.physical_birth
        }
    }

    /// Non-empty DVAs in order.
    pub fn dvas(&self) -> impl Iterator<Item = &Dva> {
        self.dva.iter().filter(|d| !d.is_empty())
    }

    /// The compressed payload of an embedded block pointer: the 14 words
    /// of the pointer other than `blk_prop` and `blk_birth`, in order.
    /// Returns `None` for ordinary pointers. Decompress with
    /// [`BlkPtr::compression`] to `lsize` bytes.
    pub fn embedded_payload(&self) -> Option<Vec<u8>> {
        if !self.embedded {
            return None;
        }
        let mut out = Vec::with_capacity(EMBEDDED_PAYLOAD);
        for word in [0usize, 1, 2, 3, 4, 5, 7, 8, 9, 11, 12, 13, 14, 15] {
            out.extend_from_slice(&self.raw[word * 8..word * 8 + 8]);
        }
        out.truncate(self.psize as usize);
        Some(out)
    }

    /// The raw 128 bytes.
    pub fn raw(&self) -> &[u8; SIZE] {
        &self.raw
    }
}

/// Size of a gang block header (`SPA_GANGBLOCKSIZE`).
pub const GANG_HEADER_SIZE: usize = 512;
/// Block pointers in a gang header (`SPA_GBH_NBLKPTRS`).
pub const GANG_NBLKPTRS: usize = 3;

/// Parse the child pointers of a gang block header (`zio_gbh_phys_t`):
/// three block pointers, filler, and an embedded checksum tail that the
/// caller verifies with `checksum::verify_gang_header`.
pub fn parse_gang_header(buf: &[u8], endian: Endian) -> Result<Vec<BlkPtr>, ParseError> {
    if buf.len() < GANG_HEADER_SIZE {
        return Err(ParseError::Truncated {
            needed: GANG_HEADER_SIZE,
            got: buf.len(),
        });
    }
    (0..GANG_NBLKPTRS)
        .map(|i| BlkPtr::parse(&buf[i * SIZE..(i + 1) * SIZE], endian))
        .collect()
}

/// Logical birth TXG of the block, or `None` if the slice is too short.
pub fn logical_birth(bp: &[u8], endian: Endian) -> Option<u64> {
    if bp.len() < SIZE {
        return None;
    }
    endian.u64_at(bp, 80).map(|w| bits(w, 0, 63))
}

/// Encoder mirroring the `BP_SET_*` macros, for building test fixtures.
///
/// The tool never writes evidence; this exists so readers can be tested
/// against pointers assembled independently of the parser.
pub mod encode {
    use super::*;

    /// Sixteen little-endian words of a block pointer under construction.
    #[derive(Debug, Clone, Default)]
    pub struct Builder(pub [u64; 16]);

    fn set(word: &mut u64, low: u32, len: u32, v: u64) {
        let mask = ((1u64 << len) - 1) << low;
        *word = (*word & !mask) | ((v << low) & mask);
    }

    impl Builder {
        /// Empty pointer flagged as written by a little-endian host.
        pub fn new() -> Self {
            let mut b = Builder([0; 16]);
            set(&mut b.0[6], 63, 1, 1); // little-endian writer
            b
        }
        /// Set DVA `i`.
        pub fn dva(mut self, i: usize, vdev: u32, offset: u64, asize: u64, gang: bool) -> Self {
            set(&mut self.0[i * 2], 0, 24, asize >> MINBLOCKSHIFT);
            set(&mut self.0[i * 2], 32, 32, vdev as u64);
            set(&mut self.0[i * 2 + 1], 0, 63, offset >> MINBLOCKSHIFT);
            set(&mut self.0[i * 2 + 1], 63, 1, gang as u64);
            self
        }
        /// Set logical and physical sizes in bytes (multiples of 512).
        pub fn sizes(mut self, lsize: u64, psize: u64) -> Self {
            set(&mut self.0[6], 0, 16, (lsize >> MINBLOCKSHIFT) - 1);
            set(&mut self.0[6], 16, 16, (psize >> MINBLOCKSHIFT) - 1);
            self
        }
        /// Set compression, checksum, object type and level codes.
        pub fn props(mut self, comp: u8, cksum: u8, otype: u8, level: u8) -> Self {
            set(&mut self.0[6], 32, 7, comp as u64);
            set(&mut self.0[6], 40, 8, cksum as u64);
            set(&mut self.0[6], 48, 8, otype as u64);
            set(&mut self.0[6], 56, 5, level as u64);
            self
        }
        /// Set the encrypted and dedup bits.
        pub fn flags(mut self, encrypted: bool, dedup: bool) -> Self {
            set(&mut self.0[6], 61, 1, encrypted as u64);
            set(&mut self.0[6], 62, 1, dedup as u64);
            self
        }
        /// Set physical birth, logical birth and fill.
        pub fn births(mut self, phys: u64, logical: u64, fill: u64) -> Self {
            self.0[9] = phys;
            self.0[10] = logical;
            self.0[11] = fill;
            self
        }
        /// Set the checksum words.
        pub fn cksum(mut self, c: [u64; 4]) -> Self {
            self.0[12..16].copy_from_slice(&c);
            self
        }
        /// Turn into an embedded pointer carrying `payload` (≤ 112 bytes).
        pub fn embedded(mut self, payload: &[u8], lsize: u64, comp: u8, otype: u8) -> Self {
            self.0[6] = 0;
            set(&mut self.0[6], 63, 1, 1);
            set(&mut self.0[6], 39, 1, 1);
            set(&mut self.0[6], 0, 25, lsize - 1);
            set(&mut self.0[6], 25, 7, payload.len() as u64 - 1);
            set(&mut self.0[6], 32, 7, comp as u64);
            set(&mut self.0[6], 48, 8, otype as u64);
            let words = [0usize, 1, 2, 3, 4, 5, 7, 8, 9, 11, 12, 13, 14, 15];
            let mut padded = payload.to_vec();
            padded.resize(EMBEDDED_PAYLOAD, 0);
            for (n, w) in words.iter().enumerate() {
                self.0[*w] =
                    u64::from_le_bytes(padded[n * 8..n * 8 + 8].try_into().expect("8 bytes"));
            }
            self
        }
        /// Serialise in the given byte order.
        pub fn bytes(&self, endian: Endian) -> [u8; SIZE] {
            let mut out = [0u8; SIZE];
            for (i, w) in self.0.iter().enumerate() {
                let b = match endian {
                    Endian::Little => w.to_le_bytes(),
                    Endian::Big => w.to_be_bytes(),
                };
                out[i * 8..i * 8 + 8].copy_from_slice(&b);
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::encode::Builder;
    use super::*;

    #[test]
    fn decodes_regular_pointer() {
        let raw = Builder::new()
            .dva(0, 1, 0x1000_0000, 0x4000, false)
            .dva(1, 0, 0x2000, 0x4000, true)
            .sizes(128 * 1024, 16 * 1024)
            .props(15, 7, 19, 2)
            .flags(false, true)
            .births(0, 4816230, 37)
            .cksum([1, 2, 3, 4])
            .bytes(Endian::Little);
        let bp = BlkPtr::parse(&raw, Endian::Little).unwrap();
        assert_eq!(
            bp.dva[0],
            Dva {
                vdev: 1,
                offset: 0x1000_0000,
                asize: 0x4000,
                gang: false
            }
        );
        assert_eq!(
            bp.dva[1],
            Dva {
                vdev: 0,
                offset: 0x2000,
                asize: 0x4000,
                gang: true
            }
        );
        assert!(bp.dva[2].is_empty());
        assert_eq!(bp.dvas().count(), 2);
        assert_eq!((bp.lsize, bp.psize), (128 * 1024, 16 * 1024));
        assert_eq!(bp.compression, Compression::Lz4);
        assert_eq!(bp.checksum, Checksum::Fletcher4);
        assert_eq!((bp.object_type, bp.level), (19, 2));
        assert!(bp.dedup && !bp.encrypted && !bp.embedded && !bp.is_hole());
        assert_eq!(bp.birth, 4816230);
        assert_eq!(bp.physical_birth_or_logical(), 4816230);
        assert_eq!(bp.fill, 37);
        assert_eq!(bp.cksum, [1, 2, 3, 4]);
        assert_eq!(bp.endian, Endian::Little);
        assert_eq!(logical_birth(&raw, Endian::Little), Some(4816230));
    }

    #[test]
    fn big_endian_pointer_parses_when_told_so() {
        let raw = Builder::new()
            .dva(0, 3, 0x8000, 0x200, false)
            .sizes(512, 512)
            .props(2, 8, 1, 0)
            .births(10, 12, 1)
            .bytes(Endian::Big);
        let bp = BlkPtr::parse(&raw, Endian::Big).unwrap();
        assert_eq!(bp.dva[0].vdev, 3);
        assert_eq!(bp.dva[0].offset, 0x8000);
        assert_eq!(bp.compression, Compression::Off);
        assert_eq!(bp.checksum, Checksum::Sha256);
        assert_eq!(bp.physical_birth_or_logical(), 10);
    }

    #[test]
    fn hole_and_truncation() {
        let bp = BlkPtr::parse(&[0u8; SIZE], Endian::Little).unwrap();
        assert!(bp.is_hole());
        assert_eq!(bp.lsize, 512); // field 0 => 1 sector
        assert!(matches!(
            BlkPtr::parse(&[0u8; 100], Endian::Little),
            Err(ParseError::Truncated {
                needed: SIZE,
                got: 100
            })
        ));
    }

    #[test]
    fn embedded_payload_roundtrip() {
        let payload: Vec<u8> = (0..100u8).collect();
        // births() writes words 9 and 11, which an embedded pointer uses
        // for payload, so it must come first; only word 10 (birth) survives.
        let raw = Builder::new()
            .births(0, 77, 0)
            .embedded(&payload, 4096, 15, 19)
            .bytes(Endian::Little);
        let bp = BlkPtr::parse(&raw, Endian::Little).unwrap();
        assert!(bp.embedded && !bp.is_hole());
        assert_eq!(bp.lsize, 4096);
        assert_eq!(bp.psize, 100);
        assert_eq!(bp.compression, Compression::Lz4);
        assert_eq!(bp.birth, 77);
        assert_eq!(bp.embedded_payload().unwrap(), payload);
    }

    #[test]
    fn encrypted_pointer_hides_salt_and_narrows_fill() {
        // Level-0 block of an encrypted type: DVA[2] is salt/IV, fill 32-bit.
        let raw = encode::Builder::new()
            .dva(0, 0, 0x1000, 0x2000, false)
            .dva(1, 1, 0x3000, 0x2000, false)
            .dva(2, 7, 0x1234_5678 << 9, 0x9999, false) // salt / IV words
            .sizes(4096, 4096)
            .props(2, 7, 23, 0)
            .flags(true, false)
            .births(10, 10, (0xabcd_u64 << 32) | 1)
            .bytes(Endian::Little);
        let bp = BlkPtr::parse(&raw, Endian::Little).unwrap();
        assert!(bp.uses_crypt() && bp.is_encrypted());
        assert_eq!(bp.dvas().count(), 2);
        assert_eq!(bp.fill, 1);
        let (salt, _iv, iv2) = bp.crypt_params().unwrap();
        assert_ne!(salt, 0);
        assert_eq!(iv2, 0xabcd);
        // An indirect block of the same object is only authenticated.
        let raw = encode::Builder::new()
            .dva(0, 0, 0x1000, 0x2000, false)
            .sizes(4096, 4096)
            .props(2, 7, 23, 1)
            .flags(true, false)
            .births(10, 10, 5)
            .bytes(Endian::Little);
        let bp = BlkPtr::parse(&raw, Endian::Little).unwrap();
        assert!(bp.uses_crypt() && !bp.is_encrypted());
        assert_eq!(bp.fill, 5);
        assert!(bp.crypt_params().is_none());
    }

    #[test]
    fn code_names() {
        assert_eq!(Compression::from_code(9).name(), "gzip-5");
        assert_eq!(Compression::from_code(16).name(), "zstd");
        assert_eq!(Compression::from_code(99).name(), "unknown-99");
        assert_eq!(Checksum::from_code(14).name(), "blake3");
        assert_eq!(Checksum::from_code(6).name(), "fletcher2");
    }
}
