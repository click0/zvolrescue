//! What a dataset property's number means (SPEC F-14).
//!
//! A dataset's properties live in a ZAP whose values are mostly plain
//! integers, and an integer is not an answer: `checksum = 8` tells an
//! operator nothing that `checksum = sha256` does not tell them better.
//!
//! Only three properties are decoded here, and each for a reason that
//! can be pointed at:
//!
//! * `checksum` and `dedup` carry a `zio_checksum` code — the same
//!   enumeration a block pointer carries, which [`Checksum::from_code`]
//!   already decodes on every block this tool reads and the cross-check
//!   compares against `zdb`.
//! * `compression` carries a `zio_compress` code in its low seven bits
//!   and, for `zstd`, a level above them. The split is not remembered
//!   but measured: across the five pools the cross-check builds and two
//!   more with vdevs removed, fifteen distinct values appear, and every
//!   one of them either fits in seven bits (`2`, `3`, `14`, `15` — on,
//!   lzjb, zle, lz4) or has exactly `16` — `zstd` — in those seven bits
//!   with 1..=19 or 100..=120 above. Nothing else produced a value with
//!   a high part at all.
//!
//! Everything else keeps its number. A property whose meaning this
//! build cannot show its working for is better read as the number the
//! pool actually holds than as a name that might be the wrong one.

use crate::blkptr::{Checksum, Compression};

/// Bits of a `compression` property value that hold the algorithm.
const COMPRESS_CODE_BITS: u32 = 7;

/// `ZIO_CHECKSUM_VERIFY` in a `dedup` property value: dedup is on with
/// that checksum, and matching blocks are compared byte for byte before
/// one is dropped. It is the only bit ever seen above the checksum code
/// in a measured `dedup` value (`264` = sha256 and `268` = skein, both
/// alongside bare `12` and `14`).
const DEDUP_VERIFY: u64 = 0x100;

/// A property value's meaning, where this build can give one.
///
/// `None` means the number stands as it is — not that it is wrong, and
/// not that it is unknown: most properties *are* numbers (`copies`,
/// `recordsize`, every on/off flag) and reading them as anything else
/// would be invention.
pub fn describe(name: &str, value: u64) -> Option<String> {
    match name {
        "checksum" => Some(Checksum::from_code(code_of(value)).name()),
        "dedup" => {
            let algorithm = Checksum::from_code(code_of(value)).name();
            Some(if value & DEDUP_VERIFY != 0 {
                format!("{algorithm},verify")
            } else {
                algorithm
            })
        }
        "compression" => {
            let algorithm =
                Compression::from_code(code_of(value) & ((1 << COMPRESS_CODE_BITS) - 1)).name();
            let level = value >> COMPRESS_CODE_BITS;
            Some(if level == 0 {
                algorithm
            } else {
                format!("{algorithm}-{level}")
            })
        }
        _ => None,
    }
}

/// The low byte of a property value, which is where every code this
/// build decodes lives.
fn code_of(value: u64) -> u8 {
    (value & 0xff) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `compression` value seen on the seven pools this build has
    /// been measured against, and what the split says each one is.
    #[test]
    fn the_compression_values_real_pools_carry_all_decode() {
        let measured: &[(u64, &str)] = &[
            (2, "off"),
            (3, "lzjb"),
            (14, "zle"),
            (15, "lz4"),
            (144, "zstd-1"),
            (1040, "zstd-8"),
            (1296, "zstd-10"),
            (2192, "zstd-17"),
            (2320, "zstd-18"),
            (13200, "zstd-103"),
            (13584, "zstd-106"),
            (13840, "zstd-108"),
            (14352, "zstd-112"),
            (14480, "zstd-113"),
            (14736, "zstd-115"),
            (14864, "zstd-116"),
            (15120, "zstd-118"),
            (15248, "zstd-119"),
            (15376, "zstd-120"),
        ];
        for (value, want) in measured {
            assert_eq!(
                describe("compression", *value).as_deref(),
                Some(*want),
                "compression = {value}"
            );
        }
    }

    #[test]
    fn checksum_and_dedup_share_the_block_pointers_own_enumeration() {
        assert_eq!(describe("checksum", 8).as_deref(), Some("sha256"));
        assert_eq!(describe("checksum", 6).as_deref(), Some("fletcher2"));
        assert_eq!(describe("dedup", 12).as_deref(), Some("skein"));
        assert_eq!(describe("dedup", 264).as_deref(), Some("sha256,verify"));
        assert_eq!(describe("dedup", 268).as_deref(), Some("skein,verify"));
    }

    /// A number this build cannot show its working for stays a number.
    #[test]
    fn everything_else_keeps_the_number_the_pool_holds() {
        assert_eq!(describe("copies", 3), None);
        assert_eq!(describe("recordsize", 65536), None);
        assert_eq!(describe("sync", 1), None);
        assert_eq!(describe("org.example:ticket", 7), None);
    }
}
