//! Uberblocks: the per-TXG root pointers kept in a ring inside each label.

use crate::{blkptr, Endian, ParseError};

/// `UBERBLOCK_MAGIC` ("oo-ba-bloc").
pub const MAGIC: u64 = 0x00ba_b10c;
/// Minimum uberblock slot size is `1 << UBERBLOCK_SHIFT` (1 KiB).
pub const UBERBLOCK_SHIFT: u32 = 10;
/// Maximum slot size is `1 << MAX_UBERBLOCK_SHIFT` (8 KiB).
pub const MAX_UBERBLOCK_SHIFT: u32 = 13;

/// Bytes covered by [`Uberblock::parse`]: five `u64`, the root block
/// pointer, and five more `u64` (software version, MMP fields, checkpoint).
pub const PARSED_LEN: usize = 5 * 8 + blkptr::SIZE + 5 * 8;

/// A decoded uberblock. Field names follow `uberblock_t` without the `ub_` prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uberblock {
    /// Byte order the uberblock was written in.
    pub endian: Endian,
    /// SPA version (5000 for feature-flag pools).
    pub version: u64,
    /// Transaction group this uberblock commits.
    pub txg: u64,
    /// Sum of all vdev GUIDs; used to detect a mismatched device set.
    pub guid_sum: u64,
    /// Unix time the TXG was synced.
    pub timestamp: u64,
    /// Raw root block pointer (MOS objset).
    pub rootbp: [u8; blkptr::SIZE],
    /// Software version that wrote the uberblock.
    pub software_version: u64,
    /// MMP magic (`0xa11cea11`) when multihost is enabled, else 0.
    pub mmp_magic: u64,
    /// MMP delay.
    pub mmp_delay: u64,
    /// MMP configuration word.
    pub mmp_config: u64,
    /// TXG of the pool checkpoint, if any.
    pub checkpoint_txg: u64,
}

impl Uberblock {
    /// Parse the first [`PARSED_LEN`] bytes of an uberblock slot.
    ///
    /// Byte order is detected from the magic. A zeroed slot yields
    /// `ParseError::BadMagic(0)`.
    pub fn parse(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < PARSED_LEN {
            return Err(ParseError::Truncated {
                needed: PARSED_LEN,
                got: buf.len(),
            });
        }
        let raw_le = Endian::Little.u64_at(buf, 0).expect("length checked");
        let endian = if raw_le == MAGIC {
            Endian::Little
        } else if raw_le.swap_bytes() == MAGIC {
            Endian::Big
        } else {
            return Err(ParseError::BadMagic(raw_le));
        };
        let u = |i: usize| endian.u64_at(buf, i * 8).expect("length checked");
        let mut rootbp = [0u8; blkptr::SIZE];
        rootbp.copy_from_slice(&buf[40..40 + blkptr::SIZE]);
        let tail = 40 + blkptr::SIZE;
        let t = |n: usize| endian.u64_at(buf, tail + n * 8).expect("length checked");
        Ok(Uberblock {
            endian,
            version: u(1),
            txg: u(2),
            guid_sum: u(3),
            timestamp: u(4),
            rootbp,
            software_version: t(0),
            mmp_magic: t(1),
            mmp_delay: t(2),
            mmp_config: t(3),
            checkpoint_txg: t(4),
        })
    }

    /// Logical birth TXG recorded in the root block pointer.
    pub fn rootbp_birth(&self) -> u64 {
        blkptr::logical_birth(&self.rootbp, self.endian).unwrap_or(0)
    }
}

/// Iterate over the slots of an uberblock ring with the given slot shift.
///
/// Yields `(slot index, parse result)` for every slot; zeroed or corrupt
/// slots appear as `Err` so callers can report ring health.
pub fn ring_slots(
    ring: &[u8],
    shift: u32,
) -> impl Iterator<Item = (usize, Result<Uberblock, ParseError>)> + '_ {
    let slot = 1usize << shift.clamp(UBERBLOCK_SHIFT, MAX_UBERBLOCK_SHIFT);
    ring.chunks_exact(slot)
        .enumerate()
        .map(|(i, chunk)| (i, Uberblock::parse(chunk)))
}

/// The uberblock OpenZFS would import from: highest TXG, then latest timestamp.
pub fn best<'a, I>(ubs: I) -> Option<&'a Uberblock>
where
    I: IntoIterator<Item = &'a Uberblock>,
{
    ubs.into_iter().max_by_key(|u| (u.txg, u.timestamp))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(endian: Endian, txg: u64, ts: u64) -> Vec<u8> {
        let mut v = vec![0u8; 1024];
        let put = |v: &mut Vec<u8>, off: usize, x: u64| {
            let b = match endian {
                Endian::Little => x.to_le_bytes(),
                Endian::Big => x.to_be_bytes(),
            };
            v[off..off + 8].copy_from_slice(&b);
        };
        put(&mut v, 0, MAGIC);
        put(&mut v, 8, 5000);
        put(&mut v, 16, txg);
        put(&mut v, 24, 0xdead_beef);
        put(&mut v, 32, ts);
        put(&mut v, 40 + 80, txg); // rootbp birth
        put(&mut v, 40 + 128, 5000);
        v
    }

    #[test]
    fn parses_little_endian() {
        let u = Uberblock::parse(&slot(Endian::Little, 42, 1_700_000_000)).unwrap();
        assert_eq!(u.endian, Endian::Little);
        assert_eq!(u.version, 5000);
        assert_eq!(u.txg, 42);
        assert_eq!(u.guid_sum, 0xdead_beef);
        assert_eq!(u.timestamp, 1_700_000_000);
        assert_eq!(u.rootbp_birth(), 42);
        assert_eq!(u.software_version, 5000);
        assert_eq!(u.mmp_magic, 0);
    }

    #[test]
    fn parses_big_endian() {
        let u = Uberblock::parse(&slot(Endian::Big, 7, 9)).unwrap();
        assert_eq!(u.endian, Endian::Big);
        assert_eq!(u.txg, 7);
        assert_eq!(u.rootbp_birth(), 7);
    }

    #[test]
    fn rejects_zero_and_garbage() {
        assert_eq!(Uberblock::parse(&[0u8; 1024]), Err(ParseError::BadMagic(0)));
        let mut g = vec![0xa5u8; 1024];
        g[0] = 1;
        assert!(matches!(Uberblock::parse(&g), Err(ParseError::BadMagic(_))));
        assert_eq!(
            Uberblock::parse(&[0u8; 10]),
            Err(ParseError::Truncated {
                needed: PARSED_LEN,
                got: 10
            })
        );
    }

    #[test]
    fn ring_iteration_and_best() {
        let mut ring = Vec::new();
        ring.extend(slot(Endian::Little, 10, 100));
        ring.extend(vec![0u8; 1024]);
        ring.extend(slot(Endian::Little, 12, 300));
        ring.extend(slot(Endian::Little, 12, 200));
        let parsed: Vec<_> = ring_slots(&ring, UBERBLOCK_SHIFT).collect();
        assert_eq!(parsed.len(), 4);
        assert!(parsed[1].1.is_err());
        let ok: Vec<Uberblock> = parsed.into_iter().filter_map(|(_, r)| r.ok()).collect();
        let b = best(&ok).unwrap();
        assert_eq!((b.txg, b.timestamp), (12, 300));
    }
}
