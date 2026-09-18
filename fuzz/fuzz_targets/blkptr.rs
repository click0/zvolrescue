//! A block pointer and a gang header, in both byte orders, and the
//! carver's plausibility checks on what parsed.
#![no_main]

use libfuzzer_sys::fuzz_target;
use zfs_ondisk::{blkptr, carve, Endian};

fuzz_target!(|data: &[u8]| {
    for endian in [Endian::Little, Endian::Big] {
        if let Ok(bp) = blkptr::BlkPtr::parse(data, endian) {
            let _ = carve::plausible_blkptr(&bp);
        }
        if let Ok(bps) = blkptr::parse_gang_header(data, endian) {
            let _ = carve::plausible_indirect(&bps, 1);
        }
    }
});
