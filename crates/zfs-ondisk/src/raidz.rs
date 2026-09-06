//! RAIDZ layout and parity mathematics.
//!
//! [`map`] reproduces `vdev_raidz_map_alloc()` from OpenZFS: how one
//! block at a top-level-vdev offset is spread over the children as parity
//! and data columns, including the "big columns" that hold the remainder,
//! the skip sectors that pad a stripe to a multiple of `nparity + 1`, and
//! the parity/data swap every 1 MiB that single-parity RAIDZ carries for
//! historical reasons.
//!
//! Parity follows `vdev_raidz_generate_parity_pqr()`: P is the XOR of the
//! data columns, Q and R are Horner sums with generators 2 and 4 in
//! GF(2^8) with the polynomial `x^8 + x^4 + x^3 + x^2 + 1` (0x11d).
//! [`reconstruct`] solves for up to `nparity` missing columns from any
//! subset of surviving parities with Gaussian elimination in that field.

/// One column of a RAIDZ stripe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    /// Child vdev index this column lives on.
    pub devidx: u64,
    /// Byte offset on that child (add the leaf's label start).
    pub offset: u64,
    /// Bytes of this column; zero for a column that is only skipped.
    pub size: u64,
}

/// How a block is laid out on a RAIDZ vdev.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Map {
    /// Columns in stripe order: `nparity` parity columns, then data.
    pub cols: Vec<Column>,
    /// Number of parity columns (`rm_firstdatacol`).
    pub nparity: usize,
    /// Columns actually accessed (`rm_cols`); the rest are skip padding.
    pub acols: usize,
    /// Columns that carry an extra sector (`rm_bigcols`).
    pub bigcols: usize,
    /// Bytes allocated on disk including parity and skip sectors.
    pub asize: u64,
    /// Skip sectors (`rm_nskip`).
    pub nskip: u64,
}

impl Map {
    /// Data columns in order.
    pub fn data(&self) -> &[Column] {
        &self.cols[self.nparity..self.acols]
    }

    /// Parity columns in order (P, Q, R).
    pub fn parity(&self) -> &[Column] {
        &self.cols[..self.nparity]
    }
}

/// Lay out `psize` bytes (a multiple of `1 << ashift`) at top-level
/// offset `offset` on a RAIDZ of `dcols` children with `nparity` parity.
pub fn map(offset: u64, psize: u64, ashift: u32, dcols: u64, nparity: u64) -> Map {
    let unit = 1u64 << ashift;
    let b = offset >> ashift;
    let s = psize.div_ceil(unit);
    let f = b % dcols;
    let o = (b / dcols) << ashift;
    let ndata = dcols - nparity;
    let q = s / ndata;
    let r = s - q * ndata;
    let bc = if r == 0 { 0 } else { r + nparity };
    let tot = s + nparity * (q + u64::from(r != 0));
    let (acols, scols) = if q == 0 {
        (bc, dcols.min(bc.div_ceil(nparity + 1) * (nparity + 1)))
    } else {
        (dcols, dcols)
    };
    let mut cols = Vec::with_capacity(scols as usize);
    let mut asize = 0u64;
    for c in 0..scols {
        let mut col = f + c;
        let mut coff = o;
        if col >= dcols {
            col -= dcols;
            coff += unit;
        }
        let size = if c >= acols {
            0
        } else if c < bc {
            (q + 1) << ashift
        } else {
            q << ashift
        };
        asize += size;
        cols.push(Column {
            devidx: col,
            offset: coff,
            size,
        });
    }
    debug_assert_eq!(asize, tot << ashift);
    let group = (nparity + 1) << ashift;
    let rm_asize = asize.div_ceil(group) * group;
    let nskip = tot.div_ceil(nparity + 1) * (nparity + 1) - tot;
    // Single-parity RAIDZ swaps parity and the first data column every
    // 1 MiB of top-level offset (an on-disk format quirk kept forever).
    if nparity == 1 && offset & (1 << 20) != 0 && cols.len() >= 2 {
        let (d0, o0) = (cols[0].devidx, cols[0].offset);
        cols[0].devidx = cols[1].devidx;
        cols[0].offset = cols[1].offset;
        cols[1].devidx = d0;
        cols[1].offset = o0;
    }
    Map {
        cols,
        nparity: nparity as usize,
        acols: acols as usize,
        bigcols: bc as usize,
        asize: rm_asize,
        nskip,
    }
}

// ---------------------------------------------------------------------------
// GF(2^8) with polynomial 0x11d, as vdev_raidz_pow2 / vdev_raidz_log2
// ---------------------------------------------------------------------------

/// Multiply in GF(2^8).
pub fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        let carry = a & 0x80 != 0;
        a <<= 1;
        if carry {
            a ^= 0x1d;
        }
        b >>= 1;
    }
    p
}

/// `base ^ exp` in GF(2^8).
pub fn gf_pow(base: u8, mut exp: u32) -> u8 {
    let mut result = 1u8;
    let mut b = base;
    while exp > 0 {
        if exp & 1 != 0 {
            result = gf_mul(result, b);
        }
        b = gf_mul(b, b);
        exp >>= 1;
    }
    result
}

/// Multiplicative inverse in GF(2^8) (`a != 0`).
pub fn gf_inv(a: u8) -> u8 {
    // a^(2^8 - 2) = a^254
    gf_pow(a, 254)
}

/// Coefficient of data column `i` (of `ndata`) in parity row `row`
/// (0 = P, 1 = Q, 2 = R), matching the Horner evaluation order of
/// `vdev_raidz_generate_parity_pqr`.
pub fn coefficient(row: usize, i: usize, ndata: usize) -> u8 {
    let e = (ndata - 1 - i) as u32;
    match row {
        0 => 1,
        1 => gf_pow(2, e),
        _ => gf_pow(4, e),
    }
}

/// Compute parity columns for `data` (columns in order, possibly of
/// different lengths: shorter ones count as zero-padded). Returns
/// `nparity` columns, each as long as the longest data column.
#[allow(clippy::needless_range_loop)]
pub fn generate_parity(data: &[Vec<u8>], nparity: usize) -> Vec<Vec<u8>> {
    let len = data.iter().map(Vec::len).max().unwrap_or(0);
    let mut out = vec![vec![0u8; len]; nparity];
    for pos in 0..len {
        let mut p = 0u8;
        let mut q = 0u8;
        let mut r = 0u8;
        for (i, col) in data.iter().enumerate() {
            let d = col.get(pos).copied().unwrap_or(0);
            if i == 0 {
                p = d;
                q = d;
                r = d;
            } else {
                p ^= d;
                q = gf_mul(q, 2) ^ d;
                r = gf_mul(r, 4) ^ d;
            }
        }
        out[0][pos] = p;
        if nparity > 1 {
            out[1][pos] = q;
        }
        if nparity > 2 {
            out[2][pos] = r;
        }
    }
    out
}

/// Why reconstruction is impossible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconstructError {
    /// More columns missing than parities available.
    TooManyMissing {
        /// Missing data columns.
        missing: usize,
        /// Surviving parity columns.
        parities: usize,
    },
    /// The chosen parity rows are linearly dependent for these columns.
    Singular,
}

/// Rebuild the data columns listed in `missing` (indices into `data`)
/// from the surviving data columns and the parity columns given in
/// `parity` (`None` for a parity column that is itself unavailable).
/// `data[missing[k]]` is overwritten with the reconstructed bytes; its
/// current length is the length reconstructed.
#[allow(clippy::needless_range_loop)]
pub fn reconstruct(
    data: &mut [Vec<u8>],
    parity: &[Option<Vec<u8>>],
    missing: &[usize],
) -> Result<(), ReconstructError> {
    let k = missing.len();
    if k == 0 {
        return Ok(());
    }
    let rows: Vec<usize> = parity
        .iter()
        .enumerate()
        .filter_map(|(r, p)| p.as_ref().map(|_| r))
        .collect();
    if rows.len() < k {
        return Err(ReconstructError::TooManyMissing {
            missing: k,
            parities: rows.len(),
        });
    }
    let ndata = data.len();
    let len = data.iter().map(Vec::len).max().unwrap_or(0);
    // Coefficient matrix A (rows × k) for the unknown columns.
    let a: Vec<Vec<u8>> = rows
        .iter()
        .map(|&r| missing.iter().map(|&i| coefficient(r, i, ndata)).collect())
        .collect();
    // Invert the first k independent rows by Gauss-Jordan on [A | I].
    let (sel, inv) = invert_rows(&a, k).ok_or(ReconstructError::Singular)?;
    for pos in 0..len {
        // Syndromes: parity minus the contribution of known columns.
        let mut syn = vec![0u8; k];
        for (j, &ri) in sel.iter().enumerate() {
            let r = rows[ri];
            let mut s = parity[r].as_ref().expect("selected rows exist")[pos];
            for i in 0..ndata {
                if missing.contains(&i) {
                    continue;
                }
                let d = data[i].get(pos).copied().unwrap_or(0);
                s ^= gf_mul(coefficient(r, i, ndata), d);
            }
            syn[j] = s;
        }
        for (m, &col) in missing.iter().enumerate() {
            if pos >= data[col].len() {
                continue;
            }
            let mut v = 0u8;
            for (j, &s) in syn.iter().enumerate() {
                v ^= gf_mul(inv[m][j], s);
            }
            data[col][pos] = v;
        }
    }
    Ok(())
}

/// Pick `k` rows of `a` forming an invertible k×k matrix and return
/// their indices with the inverse.
fn invert_rows(a: &[Vec<u8>], k: usize) -> Option<(Vec<usize>, Vec<Vec<u8>>)> {
    // Try row subsets in order (there are at most C(3,k) ≤ 3).
    let n = a.len();
    let mut subsets: Vec<Vec<usize>> = Vec::new();
    fn choose(start: usize, n: usize, k: usize, cur: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
        if cur.len() == k {
            out.push(cur.clone());
            return;
        }
        for i in start..n {
            cur.push(i);
            choose(i + 1, n, k, cur, out);
            cur.pop();
        }
    }
    choose(0, n, k, &mut Vec::new(), &mut subsets);
    for sel in subsets {
        let mut m: Vec<Vec<u8>> = sel.iter().map(|&r| a[r].clone()).collect();
        let mut inv: Vec<Vec<u8>> = (0..k)
            .map(|i| (0..k).map(|j| u8::from(i == j)).collect())
            .collect();
        let mut ok = true;
        for c in 0..k {
            let Some(pivot) = (c..k).find(|&r| m[r][c] != 0) else {
                ok = false;
                break;
            };
            m.swap(c, pivot);
            inv.swap(c, pivot);
            let f = gf_inv(m[c][c]);
            for j in 0..k {
                m[c][j] = gf_mul(m[c][j], f);
                inv[c][j] = gf_mul(inv[c][j], f);
            }
            for r in 0..k {
                if r != c && m[r][c] != 0 {
                    let g = m[r][c];
                    for j in 0..k {
                        m[r][j] ^= gf_mul(g, m[c][j]);
                        inv[r][j] ^= gf_mul(g, inv[c][j]);
                    }
                }
            }
        }
        if ok {
            return Some((sel, inv));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf_basics() {
        assert_eq!(gf_pow(2, 8), 0x1d); // x^8 = x^4 + x^3 + x^2 + 1
        assert_eq!(gf_mul(2, 0x80), 0x1d);
        assert_eq!(gf_pow(2, 255), 1); // 2 generates the multiplicative group
        for a in 1..=255u8 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1, "inverse of {a}");
        }
    }

    #[test]
    fn map_raidz1_full_stripes() {
        // 3 children, raidz1, ashift 9: a 2048-byte block at offset 0.
        let m = map(0, 2048, 9, 3, 1);
        assert_eq!(m.nparity, 1);
        assert_eq!(m.acols, 3);
        assert_eq!(m.bigcols, 0);
        assert_eq!(m.nskip, 0);
        assert_eq!(m.asize, 3072);
        let sizes: Vec<u64> = m.cols.iter().map(|c| c.size).collect();
        assert_eq!(sizes, vec![1024, 1024, 1024]);
        let devs: Vec<u64> = m.cols.iter().map(|c| c.devidx).collect();
        assert_eq!(devs, vec![0, 1, 2]);
        assert!(m.cols.iter().all(|c| c.offset == 0));
        // Next block starts at sector 6: f = 0 again, o = 2 sectors.
        let m = map(6 * 512, 2048, 9, 3, 1);
        assert!(m.cols.iter().all(|c| c.offset == 1024));
    }

    #[test]
    fn map_wraps_and_big_columns() {
        // 4 children raidz1, ashift 9, 512*5 bytes at sector 1:
        // s=5, ndata=3, q=1, r=2, bc=3, tot=5+1*2=7, acols=4.
        let m = map(512, 5 * 512, 9, 4, 1);
        assert_eq!(m.bigcols, 3);
        let sizes: Vec<u64> = m.cols.iter().map(|c| c.size).collect();
        assert_eq!(sizes, vec![1024, 1024, 1024, 512]);
        let devs: Vec<u64> = m.cols.iter().map(|c| c.devidx).collect();
        assert_eq!(devs, vec![1, 2, 3, 0]);
        let offs: Vec<u64> = m.cols.iter().map(|c| c.offset).collect();
        assert_eq!(offs, vec![0, 0, 0, 512]); // wrapped column moves one sector down
        assert_eq!(m.nskip, 1); // 7 sectors padded to 8
        assert_eq!(m.asize, 8 * 512);
    }

    #[test]
    fn map_partial_stripe_and_skip_columns() {
        // 5 children raidz2, ashift 12, one 4 KiB sector at offset 0:
        // s=1, ndata=3, q=0, r=1, bc=3, acols=3, scols=min(5, roundup(3,3))=3.
        let m = map(0, 4096, 12, 5, 2);
        assert_eq!(m.acols, 3);
        assert_eq!(m.cols.len(), 3);
        assert_eq!(m.data().len(), 1);
        assert_eq!(m.parity().len(), 2);
        assert_eq!(m.asize, 3 * 4096);
        assert_eq!(m.nskip, 0);
        // Two sectors: s=2, r=2, bc=4, acols=4, scols=min(5, roundup(4,3)=6)=5.
        let m = map(0, 8192, 12, 5, 2);
        assert_eq!(m.acols, 4);
        assert_eq!(m.cols.len(), 5);
        assert_eq!(m.cols[4].size, 0);
        assert_eq!(m.nskip, 2); // tot 4 -> 6
        assert_eq!(m.asize, 6 * 4096);
    }

    #[test]
    fn raidz1_swaps_parity_past_one_mebibyte() {
        let lo = map(0, 4096, 12, 3, 1);
        assert_eq!((lo.cols[0].devidx, lo.cols[1].devidx), (0, 1));
        // At 1 MiB: b = 256, f = 256 % 3 = 1, so parity would sit on child 1
        // and data on child 2; single parity swaps them.
        let hi = map(1 << 20, 4096, 12, 3, 1);
        assert_eq!((hi.cols[0].devidx, hi.cols[1].devidx), (2, 1));
        // raidz2 never swaps: b = 256, f = 0.
        let hi2 = map(1 << 20, 4096, 12, 4, 2);
        assert_eq!((hi2.cols[0].devidx, hi2.cols[1].devidx), (0, 1));
    }

    fn sample_data(n: usize, len: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| {
                (0..len)
                    .map(|j| ((i * 131 + j * 7 + 3) % 251) as u8)
                    .collect()
            })
            .collect()
    }

    #[test]
    fn parity_roundtrip_all_loss_patterns() {
        for nparity in 1..=3usize {
            for ndata in 1..=4usize {
                let data = sample_data(ndata, 96);
                let parity = generate_parity(&data, nparity);
                // Every subset of up to nparity data columns missing, with
                // every subset of parities surviving that is large enough.
                for mask in 1u32..(1 << ndata) {
                    let missing: Vec<usize> = (0..ndata).filter(|i| mask & (1 << i) != 0).collect();
                    if missing.len() > nparity {
                        continue;
                    }
                    for pmask in 1u32..(1 << nparity) {
                        let avail: Vec<Option<Vec<u8>>> = (0..nparity)
                            .map(|r| (pmask & (1 << r) != 0).then(|| parity[r].clone()))
                            .collect();
                        let navail = avail.iter().filter(|p| p.is_some()).count();
                        let mut work = data.clone();
                        for &m in &missing {
                            work[m] = vec![0xee; 96];
                        }
                        let res = reconstruct(&mut work, &avail, &missing);
                        if navail < missing.len() {
                            assert!(matches!(res, Err(ReconstructError::TooManyMissing { .. })));
                        } else {
                            assert_eq!(
                                res,
                                Ok(()),
                                "np={nparity} nd={ndata} miss={missing:?} pmask={pmask:b}"
                            );
                            assert_eq!(
                                work, data,
                                "np={nparity} nd={ndata} miss={missing:?} pmask={pmask:b}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn short_columns_are_zero_padded() {
        let mut data = vec![vec![1u8; 8], vec![2u8; 8], vec![3u8; 4]];
        let parity = generate_parity(&data, 2);
        assert_eq!(parity[0].len(), 8);
        // P over the padded tail is 1 ^ 2 ^ 0.
        assert_eq!(parity[0][7], 3);
        let orig = data.clone();
        data[2] = vec![0; 4];
        reconstruct(&mut data, &[Some(parity[0].clone()), None], &[2]).unwrap();
        assert_eq!(data, orig);
        data[0] = vec![0; 8];
        data[2] = vec![0; 4];
        reconstruct(
            &mut data,
            &[Some(parity[0].clone()), Some(parity[1].clone())],
            &[0, 2],
        )
        .unwrap();
        assert_eq!(data, orig);
    }
}
