//! A microzap block, a fat ZAP header and a fat ZAP leaf, in both byte
//! orders.
#![no_main]

use libfuzzer_sys::fuzz_target;
use zfs_ondisk::{zap, Endian};

fuzz_target!(|data: &[u8]| {
    for endian in [Endian::Little, Endian::Big] {
        let _ = zap::parse_micro(data, endian);
        let _ = zap::parse_fat_header(data, endian);
        let _ = zap::parse_leaf(data, endian);
    }
});
