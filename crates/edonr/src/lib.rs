//! Edon-R 512, the hash behind the OpenZFS `edonr` checksum.
//!
//! This is a port of `module/icp/algs/edonr/edonr.c` from OpenZFS
//! (Copyright 2005-2012 Jose Antonio Gómez Tapia et al. / illumos; the
//! tweaked SHA-3 submission), and is therefore licensed under the CDDL
//! 1.0 rather than the BSD licence of the rest of this repository. It is
//! kept in its own crate so that boundary stays visible.
//!
//! Only the pieces ZFS uses are here: byte-granular input, the 512-bit
//! digest, and the salted MAC construction of `edonr_zfs.c`.

const BLOCK_BYTES: usize = 128;
/// Initial double pipe (`i512p2`).
const IV: [u64; 16] = [
    0x8081828384858687,
    0x88898a8b8c8d8e8f,
    0x9091929394959697,
    0x98999a9b9c9d9e9f,
    0xa0a1a2a3a4a5a6a7,
    0xa8a9aaabacadaeaf,
    0xb0b1b2b3b4b5b6b7,
    0xb8b9babbbcbdbebf,
    0xc0c1c2c3c4c5c6c7,
    0xc8c9cacbcccdcecf,
    0xd0d1d2d3d4d5d6d7,
    0xd8d9dadbdcdddedf,
    0xe0e1e2e3e4e5e6e7,
    0xe8e9eaebecedeeef,
    0xf0f1f2f3f4f5f6f7,
    0xf8f9fafbfcfdfeff,
];
const A: u64 = 0xaaaa_aaaa_aaaa_aaaa;

#[inline(always)]
fn ls1(x: [u64; 8]) -> [u64; 8] {
    let [x0, x1, x2, x3, x4, x5, x6, x7] = x;
    let z1 = x0.wrapping_add(x4);
    let z2 = x1.wrapping_add(x7);
    let z5 = z1.wrapping_add(z2);
    let z3 = x2.wrapping_add(x3);
    let z4 = x5.wrapping_add(x6);
    let z6 = z3.wrapping_add(z4);
    [
        A.wrapping_add(z5).wrapping_add(x2),
        z5.wrapping_add(x3).rotate_left(5),
        z5.wrapping_add(x6).rotate_left(15),
        z6.wrapping_add(x7).rotate_left(22),
        z6.wrapping_add(x1).rotate_left(31),
        z1.wrapping_add(z3).wrapping_add(x5).rotate_left(40),
        z2.wrapping_add(z4).wrapping_add(x0).rotate_left(50),
        z6.wrapping_add(x4).rotate_left(59),
    ]
}

#[inline(always)]
fn ls2(y: [u64; 8]) -> [u64; 8] {
    let [y0, y1, y2, y3, y4, y5, y6, y7] = y;
    let z1 = y0.wrapping_add(y1);
    let z2 = y2.wrapping_add(y5);
    let z6 = z1.wrapping_add(z2);
    let z3 = y3.wrapping_add(y4);
    let z5 = z1.wrapping_add(z3);
    let z4 = y6.wrapping_add(y7);
    let z8 = z3.wrapping_add(z4);
    let z7 = z2.wrapping_add(z4);
    [
        (!A).wrapping_add(z6).wrapping_add(y7),
        z5.wrapping_add(y6).rotate_left(10),
        z6.wrapping_add(y3).rotate_left(19),
        z8.wrapping_add(y2).rotate_left(29),
        z5.wrapping_add(y5).rotate_left(36),
        z7.wrapping_add(y4).rotate_left(44),
        z7.wrapping_add(y1).rotate_left(48),
        z8.wrapping_add(y0).rotate_left(55),
    ]
}

/// One quasigroup e-transformation: `QEF_512(LS1(x), LS2(y))`.
#[inline(always)]
fn qef(x: [u64; 8], y: [u64; 8]) -> [u64; 8] {
    let s = ls1(x);
    let t = ls2(y);
    let z1 = s[0] ^ s[4];
    let z5 = t[0] ^ t[1];
    let z8 = t[6] ^ t[7];
    let z3 = s[2] ^ s[3];
    let z7 = t[3] ^ t[4];
    let z4 = s[5] ^ s[6];
    let z6 = t[2] ^ t[5];
    let z2 = s[1] ^ s[7];
    [
        (z1 ^ s[1]).wrapping_add(z5 ^ t[5]),
        (z1 ^ s[7]).wrapping_add(t[2] ^ z8),
        (z2 ^ s[6]).wrapping_add(z5 ^ t[3]),
        (z3 ^ s[4]).wrapping_add(t[0] ^ z7),
        (s[0] ^ z2).wrapping_add(t[1] ^ z6),
        (s[3] ^ z4).wrapping_add(z7 ^ t[6]),
        (s[2] ^ z4).wrapping_add(z6 ^ t[7]),
        (z3 ^ s[5]).wrapping_add(t[4] ^ z8),
    ]
}

fn rev(w: &[u64]) -> [u64; 8] {
    let mut out = [0u64; 8];
    for (i, o) in out.iter_mut().enumerate() {
        *o = w[7 - i];
    }
    out
}

fn arr(w: &[u64]) -> [u64; 8] {
    w.try_into().expect("8 words")
}

/// Compress one 128-byte block (as 16 little-endian words) into the pipe.
fn q512(pipe: &mut [u64; 16], d: &[u64; 16]) {
    let lo = arr(&d[..8]);
    let hi = arr(&d[8..]);
    // First row.
    let mut p = qef(rev(&d[8..]), lo);
    let mut q = qef(p, hi);
    // Second row.
    p = qef(arr(&pipe[8..]), p);
    q = qef(p, q);
    // Third row.
    p = qef(p, arr(&pipe[..8]));
    q = qef(q, p);
    // Fourth row.
    p = qef(rev(&d[..8]), p);
    q = qef(p, q);
    // Edon-R tweak on the original SHA-3 submission.
    for i in 0..8 {
        pipe[i] ^= d[8 + i] ^ p[i];
        pipe[8 + i] ^= d[i] ^ q[i];
    }
}

/// Incremental Edon-R 512 state (`EdonRState`), byte-granular input.
#[derive(Clone)]
pub struct EdonR512 {
    pipe: [u64; 16],
    buf: [u8; BLOCK_BYTES],
    buffered: usize,
    total_bytes: u64,
}

impl Default for EdonR512 {
    fn default() -> Self {
        Self::new()
    }
}

impl EdonR512 {
    /// `EdonRInit`.
    pub fn new() -> Self {
        EdonR512 {
            pipe: IV,
            buf: [0; BLOCK_BYTES],
            buffered: 0,
            total_bytes: 0,
        }
    }

    fn compress(&mut self, block: &[u8]) {
        let mut d = [0u64; 16];
        for (i, w) in d.iter_mut().enumerate() {
            *w = u64::from_le_bytes(block[i * 8..i * 8 + 8].try_into().expect("8 bytes"));
        }
        q512(&mut self.pipe, &d);
    }

    /// `EdonRUpdate` (whole bytes). Every complete block is compressed at
    /// once; up to 127 bytes stay buffered.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total_bytes += data.len() as u64;
        if self.buffered > 0 {
            let n = (BLOCK_BYTES - self.buffered).min(data.len());
            self.buf[self.buffered..self.buffered + n].copy_from_slice(&data[..n]);
            self.buffered += n;
            data = &data[n..];
            if self.buffered == BLOCK_BYTES {
                let b = self.buf;
                self.compress(&b);
                self.buffered = 0;
            }
        }
        while data.len() >= BLOCK_BYTES {
            self.compress(&data[..BLOCK_BYTES]);
            data = &data[BLOCK_BYTES..];
        }
        self.buf[self.buffered..self.buffered + data.len()].copy_from_slice(data);
        self.buffered += data.len();
    }

    /// `EdonRFinal`: pad (0x80, zeros, 64-bit bit count) and return the
    /// 64-byte digest (`DoublePipe[8..16]`, little-endian words).
    pub fn finish(mut self) -> [u8; 64] {
        let bits = self.total_bytes.wrapping_mul(8);
        let mut tail = [0u8; 2 * BLOCK_BYTES];
        tail[..self.buffered].copy_from_slice(&self.buf[..self.buffered]);
        tail[self.buffered] = 0x80;
        let len = if self.buffered < 120 {
            BLOCK_BYTES
        } else {
            2 * BLOCK_BYTES
        };
        tail[len - 8..len].copy_from_slice(&bits.to_le_bytes());
        for chunk in tail[..len].chunks(BLOCK_BYTES) {
            self.compress(chunk);
        }
        let mut out = [0u8; 64];
        for (i, w) in self.pipe[8..].iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        out
    }
}

/// `EdonRHash`: one-shot digest.
pub fn hash(data: &[u8]) -> [u8; 64] {
    let mut h = EdonR512::new();
    h.update(data);
    h.finish()
}

/// The OpenZFS `edonr` checksum: the pool's 32-byte salt is expanded to a
/// full block `H(salt) || H(H(salt))` and fed first (`abd_checksum_edonr_tmpl_init`),
/// then the data; the first 32 bytes of the digest are the checksum words
/// in the writer's native byte order.
pub fn zfs_checksum(salt: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut block = [0u8; BLOCK_BYTES];
    let h1 = hash(salt);
    block[..64].copy_from_slice(&h1);
    block[64..].copy_from_slice(&hash(&h1));
    let mut h = EdonR512::new();
    h.update(&block);
    h.update(data);
    h.finish()[..32].try_into().expect("32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incremental_matches_one_shot_across_block_boundaries() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 13 % 251) as u8).collect();
        let one = hash(&data);
        for step in [1usize, 7, 64, 120, 127, 128, 129, 300] {
            let mut h = EdonR512::new();
            for chunk in data.chunks(step) {
                h.update(chunk);
            }
            assert_eq!(h.finish(), one, "step {step}");
        }
        assert_ne!(hash(&data[..999]), one);
        // Two-block padding path (>= 120 buffered bytes).
        for n in [119usize, 120, 127, 128] {
            let a = hash(&data[..n]);
            let mut h = EdonR512::new();
            h.update(&data[..n / 2]);
            h.update(&data[n / 2..n]);
            assert_eq!(h.finish(), a);
        }
    }

    #[test]
    fn salted_checksum_depends_on_salt_and_data() {
        let a = zfs_checksum(&[1; 32], b"data");
        assert_ne!(a, zfs_checksum(&[2; 32], b"data"));
        assert_ne!(a, zfs_checksum(&[1; 32], b"date"));
        assert_eq!(a, zfs_checksum(&[1; 32], b"data"));
    }
}
