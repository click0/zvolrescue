//! How fast the pure-Rust zstd decoder reads OpenZFS zstd blocks
//! (SPEC §12 Q3, D-8).
//!
//!     cargo run --release -p zfs-ondisk --example zstd-bench -- DIR [ROUNDS]
//!
//! `DIR` holds pairs `NAME.raw` / `NAME.zst`: a block as it was and the
//! zstd frame of it, as the `zstd` command writes one. Each frame is
//! given the framing OpenZFS gives it — the 8-byte header of compressed
//! length and level/version, the frame with its magic stripped — and
//! decoded through the same [`zfs_ondisk::compress::zstd`] the reader
//! uses, `ROUNDS` times (default 5). Every decode is checked against the
//! `.raw` block: a decoder that was fast and wrong would not be worth
//! measuring. It prints the blocks, the bytes, the ratio and the
//! decoded MB/s of the best round. tests/zstd-bench.sh makes the pairs
//! and runs libzstd's own benchmark on the same bytes next to it.

use std::fs;
use std::time::Instant;

use zfs_ondisk::compress;

/// A `zstd` command's frame, framed the way OpenZFS stores one: the
/// compressed length, the level in the top byte of a word whose low 24
/// bits are the library version, and the frame without its magic.
fn zfs_framed(frame: &[u8], level: u8) -> Vec<u8> {
    let magicless = frame
        .strip_prefix(&[0x28, 0xb5, 0x2f, 0xfd])
        .unwrap_or(frame);
    let mut out = Vec::with_capacity(magicless.len() + 8);
    out.extend_from_slice(&(magicless.len() as u32).to_be_bytes());
    out.extend_from_slice(&(((level as u32) << 24) | 10505).to_be_bytes());
    out.extend_from_slice(magicless);
    out
}

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = args.next().expect("DIR of NAME.raw / NAME.zst pairs");
    let rounds: usize = args.next().map(|r| r.parse().expect("ROUNDS")).unwrap_or(5);
    let level: u8 = std::env::var("ZSTD_LEVEL")
        .ok()
        .and_then(|l| l.parse().ok())
        .unwrap_or(3);

    let mut names: Vec<_> = fs::read_dir(&dir)
        .expect("DIR")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "zst"))
        .collect();
    names.sort();
    assert!(!names.is_empty(), "no .zst blocks in {dir}");
    let blocks: Vec<(Vec<u8>, Vec<u8>)> = names
        .iter()
        .map(|p| {
            let raw = fs::read(p.with_extension("raw")).expect("NAME.raw next to NAME.zst");
            let frame = fs::read(p).expect("NAME.zst");
            (raw, zfs_framed(&frame, level))
        })
        .collect();
    let raw_bytes: usize = blocks.iter().map(|(r, _)| r.len()).sum();
    let framed_bytes: usize = blocks.iter().map(|(_, f)| f.len()).sum();

    let mut best = 0.0f64;
    for _ in 0..rounds {
        let t = Instant::now();
        for (raw, framed) in &blocks {
            let out = compress::zstd(framed, raw.len()).expect("a frame the reader decodes");
            assert!(out == *raw, "decoded bytes differ from the block");
        }
        let rate = raw_bytes as f64 / t.elapsed().as_secs_f64() / 1e6;
        best = best.max(rate);
    }
    println!(
        "ruzstd: {} blocks, {} bytes from {} compressed ({:.2}x), best of {rounds}: {best:.0} MB/s decoded",
        blocks.len(),
        raw_bytes,
        framed_bytes,
        raw_bytes as f64 / framed_bytes as f64,
    );
    println!("mbs {best:.0}");
}
