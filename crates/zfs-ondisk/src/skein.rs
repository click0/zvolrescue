//! Skein-512 (Threefish-512 in UBI mode), as OpenZFS uses it for the
//! `skein` checksum: Skein-512-256 keyed with the pool's 32-byte
//! checksum salt (`Skein_512_InitExt` with a key, sequential tree info).
//!
//! Straight port of the reference algorithm (Ferguson et al., Skein 1.3),
//! kept small: single 64-byte block pipeline, no tree hashing.

const KS_PARITY: u64 = 0x1BD1_1BDA_A9FC_1A22;
const SCHEMA_VER: u64 = (1 << 32) | 0x3341_4853; // "SHA3", version 1
const FLAG_FIRST: u64 = 1 << 62;
const FLAG_FINAL: u64 = 1 << 63;
const TYPE_KEY: u64 = 0;
const TYPE_CFG: u64 = 4;
const TYPE_MSG: u64 = 48;
const TYPE_OUT: u64 = 63;

/// Rotation constants `R_512_{row}_{k}`.
const ROT: [[u32; 4]; 8] = [
    [46, 36, 19, 37],
    [33, 27, 14, 42],
    [17, 49, 36, 39],
    [44, 9, 54, 56],
    [39, 30, 34, 24],
    [13, 50, 10, 17],
    [25, 29, 39, 43],
    [8, 35, 56, 22],
];
/// Word pairs mixed in each of the four round shapes.
const MIX: [[(usize, usize); 4]; 4] = [
    [(0, 1), (2, 3), (4, 5), (6, 7)],
    [(2, 1), (4, 7), (6, 5), (0, 3)],
    [(4, 1), (6, 3), (0, 5), (2, 7)],
    [(6, 1), (0, 7), (2, 5), (4, 3)],
];

/// Incremental Skein-512 state.
#[derive(Clone)]
pub struct Skein512 {
    x: [u64; 8],
    t: [u64; 2],
    buf: [u8; 64],
    bcnt: usize,
    hash_bits: u64,
}

fn threefish_ubi(x: &mut [u64; 8], t: &mut [u64; 2], block: &[u8], byte_count: u64) {
    let mut w = [0u64; 8];
    for (i, word) in w.iter_mut().enumerate() {
        *word = u64::from_le_bytes(block[i * 8..i * 8 + 8].try_into().expect("8 bytes"));
    }
    t[0] = t[0].wrapping_add(byte_count);
    let mut ks = [0u64; 9];
    ks[..8].copy_from_slice(x);
    ks[8] = x.iter().fold(KS_PARITY, |a, b| a ^ b);
    let ts = [t[0], t[1], t[0] ^ t[1]];
    let inject = |v: &mut [u64; 8], s: usize| {
        for (i, word) in v.iter_mut().enumerate() {
            *word = word.wrapping_add(ks[(s + i) % 9]);
        }
        v[5] = v[5].wrapping_add(ts[s % 3]);
        v[6] = v[6].wrapping_add(ts[(s + 1) % 3]);
        v[7] = v[7].wrapping_add(s as u64);
    };
    let mut v = w;
    inject(&mut v, 0);
    for d in 0..72 {
        for (k, &(a, b)) in MIX[d % 4].iter().enumerate() {
            v[a] = v[a].wrapping_add(v[b]);
            v[b] = v[b].rotate_left(ROT[d % 8][k]) ^ v[a];
        }
        if d % 4 == 3 {
            inject(&mut v, d / 4 + 1);
        }
    }
    for i in 0..8 {
        x[i] = v[i] ^ w[i];
    }
    t[1] &= !FLAG_FIRST;
}

impl Skein512 {
    fn start_type(&mut self, kind: u64, final_: bool) {
        self.t = [
            0,
            (kind << 56) | FLAG_FIRST | if final_ { FLAG_FINAL } else { 0 },
        ];
        self.bcnt = 0;
    }

    /// New hash of `hash_bits` output bits, optionally keyed (MAC mode)
    /// as `Skein_512_InitExt` with sequential tree info.
    pub fn new(hash_bits: u64, key: &[u8]) -> Self {
        let mut s = Skein512 {
            x: [0; 8],
            t: [0; 2],
            buf: [0; 64],
            bcnt: 0,
            hash_bits: 512,
        };
        if !key.is_empty() {
            s.start_type(TYPE_KEY, false);
            s.update(key);
            s.final_pad();
        }
        s.hash_bits = hash_bits;
        s.start_type(TYPE_CFG, true);
        let mut cfg = [0u8; 64];
        cfg[..8].copy_from_slice(&SCHEMA_VER.to_le_bytes());
        cfg[8..16].copy_from_slice(&hash_bits.to_le_bytes());
        // cfg[16..24]: tree info = 0 (sequential).
        threefish_ubi(&mut s.x, &mut s.t, &cfg, 32);
        s.start_type(TYPE_MSG, false);
        s
    }

    /// Absorb bytes. The last (possibly full) block is held for `finish`.
    pub fn update(&mut self, mut msg: &[u8]) {
        if msg.len() + self.bcnt > 64 {
            if self.bcnt > 0 {
                let n = 64 - self.bcnt;
                self.buf[self.bcnt..].copy_from_slice(&msg[..n]);
                msg = &msg[n..];
                let buf = self.buf;
                threefish_ubi(&mut self.x, &mut self.t, &buf, 64);
                self.bcnt = 0;
            }
            while msg.len() > 64 {
                threefish_ubi(&mut self.x, &mut self.t, &msg[..64], 64);
                msg = &msg[64..];
            }
        }
        self.buf[self.bcnt..self.bcnt + msg.len()].copy_from_slice(msg);
        self.bcnt += msg.len();
    }

    /// Process the held block with the FINAL flag (chaining value only).
    fn final_pad(&mut self) {
        self.t[1] |= FLAG_FINAL;
        for b in &mut self.buf[self.bcnt..] {
            *b = 0;
        }
        let buf = self.buf;
        threefish_ubi(&mut self.x, &mut self.t, &buf, self.bcnt as u64);
    }

    /// Finish and return the digest (`hash_bits / 8` bytes).
    pub fn finish(mut self) -> Vec<u8> {
        self.final_pad();
        let bytes = (self.hash_bits as usize).div_ceil(8);
        let chain = self.x;
        let mut out = Vec::with_capacity(bytes);
        let mut i = 0u64;
        while out.len() < bytes {
            let mut ctr = [0u8; 64];
            ctr[..8].copy_from_slice(&i.to_le_bytes());
            self.x = chain;
            self.start_type(TYPE_OUT, true);
            threefish_ubi(&mut self.x, &mut self.t, &ctr, 8);
            for w in self.x.iter() {
                out.extend_from_slice(&w.to_le_bytes());
            }
            i += 1;
        }
        out.truncate(bytes);
        out
    }
}

/// Skein-512-256 keyed with `key`, as `zio_checksum_skein_native`
/// computes it with the pool salt: 32 bytes.
pub fn skein_512_256_mac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = Skein512::new(256, key);
    h.update(data);
    h.finish().try_into().expect("32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn known_answers_unkeyed() {
        // Skein 1.3 reference vectors for the empty message.
        assert_eq!(
            hex(&Skein512::new(256, &[]).finish()),
            "39ccc4554a8b31853b9de7a1fe638a24cce6b35a55f2431009e18780335d2621"
        );
        assert_eq!(
            hex(&Skein512::new(512, &[]).finish()),
            "bc5b4c50925519c290cc634277ae3d6257212395cba733bbad37a4af0fa06af41fca7903d06564fea7a2d3730dbdb80c1f85562dfcc070334ea4d1d9e72cba7a"
        );
        // 0xff single byte, Skein-512-512 (reference KAT).
        let mut h = Skein512::new(512, &[]);
        h.update(&[0xff]);
        assert_eq!(
            hex(&h.finish()),
            "71b7bce6fe6452227b9ced6014249e5bf9a9754c3ad618ccc4e0aae16b316cc8ca698d864307ed3e80b6ef1570812ac5272dc409b5a012df2a579102f340617a"
        );
    }

    #[test]
    fn incremental_matches_one_shot() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7 % 251) as u8).collect();
        let one = skein_512_256_mac(b"salt", &data);
        let mut h = Skein512::new(256, b"salt");
        for chunk in data.chunks(17) {
            h.update(chunk);
        }
        assert_eq!(h.finish(), one);
        assert_ne!(skein_512_256_mac(b"other", &data), one);
        // Exactly one block held back correctly.
        let mut h = Skein512::new(256, &[]);
        h.update(&data[..64]);
        let mut g = Skein512::new(256, &[]);
        g.update(&data[..30]);
        g.update(&data[30..64]);
        assert_eq!(h.finish(), g.finish());
    }
}
