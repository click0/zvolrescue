//! Block pointer (`blkptr_t`) layout.
//!
//! Only the fields needed by the label/uberblock tooling are decoded so
//! far; DVA and property decoding arrive with the `zio` layer.

use crate::Endian;

/// Size of a block pointer in bytes.
pub const SIZE: usize = 128;

/// Offset of `blk_birth` (the logical birth TXG) inside a block pointer.
const BIRTH_OFFSET: usize = 80;

/// Logical birth TXG of the block, or `None` if the slice is too short.
pub fn logical_birth(bp: &[u8], endian: Endian) -> Option<u64> {
    if bp.len() < SIZE {
        return None;
    }
    endian.u64_at(bp, BIRTH_OFFSET)
}
