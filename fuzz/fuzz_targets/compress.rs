//! Every decompressor on hostile input: the first byte picks the
//! algorithm, the next three the claimed logical size (capped at 1 MiB
//! so the run stays fast), the rest is the "compressed" block.
#![no_main]

use libfuzzer_sys::fuzz_target;
use zfs_ondisk::blkptr::Compression;
use zfs_ondisk::compress;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let kind = Compression::from_code(data[0] % 20);
    let lsize = u32::from_le_bytes([data[1], data[2], data[3], 0]) as usize;
    let lsize = lsize.min(1 << 20);
    let src = &data[4..];
    let _ = compress::decompress(kind, src, lsize);
    let _ = compress::zstd_header(src);
});
