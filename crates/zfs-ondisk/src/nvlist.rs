//! XDR-encoded name/value lists (`nvlist_pack(…, NV_ENCODE_XDR)`).
//!
//! This is the encoding of the pool configuration stored in every vdev
//! label. Layout, from OpenZFS `nvpair.c`:
//!
//! ```text
//! header   : encoding (1 = XDR), endian, 2 reserved bytes
//! nvlist   : i32 version, u32 nvflag, then pairs, then two zero i32
//! pair     : i32 encoded size (includes these two ints), i32 decoded size,
//!            XDR string name, i32 type, i32 nelem, value
//! ```
//!
//! All integers are big-endian (XDR). Fixed-width arrays carry an extra
//! element count before their elements; byte arrays and string arrays do
//! not. Every pair's encoded size is authoritative for where the next pair
//! starts, so an unknown or damaged value never desynchronises the parser.

use crate::ParseError;

/// Maximum nesting depth accepted (labels use 3–4).
pub const MAX_DEPTH: usize = 32;
/// Maximum pairs per list accepted (labels use tens).
pub const MAX_PAIRS: usize = 1 << 16;

/// A decoded nvpair value. Variants mirror `data_type_t`.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `DATA_TYPE_BOOLEAN`: a flag whose presence is the value.
    Boolean,
    /// `DATA_TYPE_BOOLEAN_VALUE`.
    Bool(bool),
    /// `BYTE`, `INT8`, `UINT8`, `INT16`, `UINT16`, `INT32`, `UINT32` widened.
    Int(i64),
    /// `UINT64`.
    Uint64(u64),
    /// `INT64`, `HRTIME`.
    Int64(i64),
    /// `DOUBLE`.
    Double(f64),
    /// `STRING`.
    String(String),
    /// `BYTE_ARRAY`.
    Bytes(Vec<u8>),
    /// All fixed-width signed/unsigned integer arrays narrower than 64 bits.
    IntArray(Vec<i64>),
    /// `UINT64_ARRAY`.
    Uint64Array(Vec<u64>),
    /// `INT64_ARRAY`.
    Int64Array(Vec<i64>),
    /// `BOOLEAN_ARRAY`.
    BoolArray(Vec<bool>),
    /// `STRING_ARRAY`.
    StringArray(Vec<String>),
    /// `NVLIST`.
    List(NvList),
    /// `NVLIST_ARRAY`.
    ListArray(Vec<NvList>),
    /// A type this parser does not decode; the pair was skipped by size.
    Unknown {
        /// Raw `data_type_t` code.
        type_code: i32,
        /// Element count as encoded.
        nelem: i32,
    },
}

/// An ordered list of named values.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NvList {
    /// `nvl_version`.
    pub version: i32,
    /// `nvl_nvflag` (`NV_UNIQUE_NAME` = 1).
    pub flags: u32,
    /// Pairs in encoded order.
    pub pairs: Vec<(String, Value)>,
}

impl NvList {
    /// First value with this name.
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.pairs.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    /// `u64` value (also accepts narrower integers).
    pub fn u64(&self, name: &str) -> Option<u64> {
        match self.get(name)? {
            Value::Uint64(v) => Some(*v),
            Value::Int(v) | Value::Int64(v) => u64::try_from(*v).ok(),
            _ => None,
        }
    }

    /// String value.
    pub fn str(&self, name: &str) -> Option<&str> {
        match self.get(name)? {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// Nested list value.
    pub fn list(&self, name: &str) -> Option<&NvList> {
        match self.get(name)? {
            Value::List(l) => Some(l),
            _ => None,
        }
    }

    /// Nested list-array value.
    pub fn list_array(&self, name: &str) -> Option<&[NvList]> {
        match self.get(name)? {
            Value::ListArray(l) => Some(l),
            _ => None,
        }
    }

    /// `u64` array value.
    pub fn u64_array(&self, name: &str) -> Option<&[u64]> {
        match self.get(name)? {
            Value::Uint64Array(l) => Some(l),
            _ => None,
        }
    }

    /// True if a `DATA_TYPE_BOOLEAN` flag or a `true` boolean value is present.
    pub fn flag(&self, name: &str) -> bool {
        matches!(
            self.get(name),
            Some(Value::Boolean) | Some(Value::Bool(true))
        )
    }
}

/// XDR encoding byte in the packed header.
pub const NV_ENCODE_XDR: u8 = 1;

/// Parse a packed nvlist (header included), as stored in `vdev_phys`.
pub fn parse_packed(buf: &[u8]) -> Result<NvList, ParseError> {
    if buf.len() < 4 {
        return Err(ParseError::Truncated {
            needed: 4,
            got: buf.len(),
        });
    }
    if buf[0] != NV_ENCODE_XDR {
        return Err(ParseError::Malformed {
            what: "XDR encoding byte",
            at: 0,
        });
    }
    let mut cur = Cursor { buf, pos: 4 };
    parse_list(&mut cur, 0)
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn need(&self, n: usize, what: &'static str) -> Result<(), ParseError> {
        if self.pos.checked_add(n).is_some_and(|e| e <= self.buf.len()) {
            Ok(())
        } else {
            Err(ParseError::Malformed { what, at: self.pos })
        }
    }

    fn u32(&mut self, what: &'static str) -> Result<u32, ParseError> {
        self.need(4, what)?;
        let v = u32::from_be_bytes(self.buf[self.pos..self.pos + 4].try_into().expect("4"));
        self.pos += 4;
        Ok(v)
    }

    fn i32(&mut self, what: &'static str) -> Result<i32, ParseError> {
        self.u32(what).map(|v| v as i32)
    }

    fn u64(&mut self, what: &'static str) -> Result<u64, ParseError> {
        self.need(8, what)?;
        let v = u64::from_be_bytes(self.buf[self.pos..self.pos + 8].try_into().expect("8"));
        self.pos += 8;
        Ok(v)
    }

    /// XDR opaque: `n` bytes padded to a multiple of four.
    fn opaque(&mut self, n: usize, what: &'static str) -> Result<&[u8], ParseError> {
        let padded = n
            .checked_add(3)
            .map(|x| x & !3)
            .ok_or(ParseError::Malformed { what, at: self.pos })?;
        self.need(padded, what)?;
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += padded;
        Ok(s)
    }

    fn string(&mut self, what: &'static str) -> Result<String, ParseError> {
        let n = self.u32(what)? as usize;
        let bytes = self.opaque(n, what)?;
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }

    /// Element count of an `xdr_array`, checked against the declared `nelem`
    /// and against the bytes that remain.
    fn count(
        &mut self,
        nelem: i32,
        elsize: usize,
        what: &'static str,
    ) -> Result<usize, ParseError> {
        let n = self.u32(what)? as usize;
        if nelem < 0 || n != nelem as usize {
            return Err(ParseError::Malformed {
                what,
                at: self.pos - 4,
            });
        }
        let bytes = n
            .checked_mul(elsize)
            .ok_or(ParseError::Malformed { what, at: self.pos })?;
        self.need(bytes, what)?;
        Ok(n)
    }
}

fn parse_list(cur: &mut Cursor<'_>, depth: usize) -> Result<NvList, ParseError> {
    if depth > MAX_DEPTH {
        return Err(ParseError::Malformed {
            what: "nesting deeper than MAX_DEPTH",
            at: cur.pos,
        });
    }
    let version = cur.i32("nvlist version")?;
    let flags = cur.u32("nvlist flags")?;
    let mut pairs = Vec::new();
    loop {
        let pair_start = cur.pos;
        let encoded = cur.i32("nvpair encoded size")?;
        let _decoded = cur.i32("nvpair decoded size")?;
        if encoded == 0 {
            break;
        }
        if pairs.len() >= MAX_PAIRS {
            return Err(ParseError::Malformed {
                what: "more pairs than MAX_PAIRS",
                at: pair_start,
            });
        }
        let encoded = usize::try_from(encoded).map_err(|_| ParseError::Malformed {
            what: "negative nvpair size",
            at: pair_start,
        })?;
        let pair_end = pair_start
            .checked_add(encoded)
            .filter(|&e| e <= cur.buf.len() && encoded >= 16);
        let Some(pair_end) = pair_end else {
            return Err(ParseError::Malformed {
                what: "nvpair size beyond buffer",
                at: pair_start,
            });
        };
        // Parse the pair inside its own bounds so a bad value cannot read
        // past the pair, then continue from the authoritative end.
        let mut inner = Cursor {
            buf: &cur.buf[..pair_end],
            pos: cur.pos,
        };
        let name = inner.string("nvpair name")?;
        let type_code = inner.i32("nvpair type")?;
        let nelem = inner.i32("nvpair nelem")?;
        let value = parse_value(&mut inner, type_code, nelem, depth)?;
        pairs.push((name, value));
        cur.pos = pair_end;
    }
    Ok(NvList {
        version,
        flags,
        pairs,
    })
}

fn parse_value(
    cur: &mut Cursor<'_>,
    type_code: i32,
    nelem: i32,
    depth: usize,
) -> Result<Value, ParseError> {
    let what = "nvpair value";
    Ok(match type_code {
        1 => Value::Boolean,
        21 => Value::Bool(cur.u32(what)? != 0),
        2 | 22 | 23 | 3 | 4 | 5 | 6 => {
            let raw = cur.i32(what)?;
            Value::Int(match type_code {
                2 | 23 => i64::from(raw as u32 as u8),
                22 => i64::from(raw as i8),
                3 => i64::from(raw as i16),
                4 => i64::from(raw as u16),
                6 => i64::from(raw as u32),
                _ => i64::from(raw),
            })
        }
        7 | 18 => Value::Int64(cur.u64(what)? as i64),
        8 => Value::Uint64(cur.u64(what)?),
        27 => Value::Double(f64::from_bits(cur.u64(what)?)),
        9 => Value::String(cur.string(what)?),
        10 => {
            let n =
                usize::try_from(nelem).map_err(|_| ParseError::Malformed { what, at: cur.pos })?;
            Value::Bytes(cur.opaque(n, what)?.to_vec())
        }
        11..=14 | 25 | 26 => {
            let n = cur.count(nelem, 4, what)?;
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                let raw = cur.i32(what)?;
                v.push(match type_code {
                    11 => i64::from(raw as i16),
                    12 => i64::from(raw as u16),
                    14 => i64::from(raw as u32),
                    25 => i64::from(raw as i8),
                    26 => i64::from(raw as u32 as u8),
                    _ => i64::from(raw),
                });
            }
            Value::IntArray(v)
        }
        24 => {
            let n = cur.count(nelem, 4, what)?;
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                v.push(cur.u32(what)? != 0);
            }
            Value::BoolArray(v)
        }
        15 | 16 => {
            let n = cur.count(nelem, 8, what)?;
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                v.push(cur.u64(what)?);
            }
            if type_code == 16 {
                Value::Uint64Array(v)
            } else {
                Value::Int64Array(v.into_iter().map(|x| x as i64).collect())
            }
        }
        17 => {
            let n =
                usize::try_from(nelem).map_err(|_| ParseError::Malformed { what, at: cur.pos })?;
            let mut v = Vec::new();
            for _ in 0..n {
                v.push(cur.string(what)?);
            }
            Value::StringArray(v)
        }
        19 => Value::List(parse_list(cur, depth + 1)?),
        20 => {
            let n =
                usize::try_from(nelem).map_err(|_| ParseError::Malformed { what, at: cur.pos })?;
            let mut v = Vec::new();
            for _ in 0..n {
                v.push(parse_list(cur, depth + 1)?);
            }
            Value::ListArray(v)
        }
        _ => Value::Unknown { type_code, nelem },
    })
}

/// Minimal XDR encoder, sufficient to build label fixtures for tests.
///
/// The tool itself never writes evidence; this exists so parsers can be
/// tested against an independent encoding of known values.
pub mod encode {
    use super::{NvList, Value};

    fn pad4(v: &mut Vec<u8>) {
        while v.len() % 4 != 0 {
            v.push(0);
        }
    }

    fn put_string(v: &mut Vec<u8>, s: &str) {
        v.extend((s.len() as u32).to_be_bytes());
        v.extend(s.as_bytes());
        pad4(v);
    }

    fn put_list(v: &mut Vec<u8>, l: &NvList) {
        v.extend(l.version.to_be_bytes());
        v.extend(l.flags.to_be_bytes());
        for (name, value) in &l.pairs {
            let mut body = Vec::new();
            put_string(&mut body, name);
            let (type_code, nelem): (i32, i32) = match value {
                Value::Boolean => (1, 0),
                Value::Bool(_) => (21, 1),
                Value::Int(_) => (5, 1),
                Value::Uint64(_) => (8, 1),
                Value::Int64(_) => (7, 1),
                Value::Double(_) => (27, 1),
                Value::String(_) => (9, 1),
                Value::Bytes(b) => (10, b.len() as i32),
                Value::IntArray(a) => (13, a.len() as i32),
                Value::Uint64Array(a) => (16, a.len() as i32),
                Value::Int64Array(a) => (15, a.len() as i32),
                Value::BoolArray(a) => (24, a.len() as i32),
                Value::StringArray(a) => (17, a.len() as i32),
                Value::List(_) => (19, 1),
                Value::ListArray(a) => (20, a.len() as i32),
                Value::Unknown { type_code, nelem } => (*type_code, *nelem),
            };
            body.extend(type_code.to_be_bytes());
            body.extend(nelem.to_be_bytes());
            match value {
                Value::Boolean | Value::Unknown { .. } => {}
                Value::Bool(b) => body.extend((*b as u32).to_be_bytes()),
                Value::Int(i) => body.extend((*i as i32).to_be_bytes()),
                Value::Uint64(u) => body.extend(u.to_be_bytes()),
                Value::Int64(i) => body.extend(i.to_be_bytes()),
                Value::Double(d) => body.extend(d.to_bits().to_be_bytes()),
                Value::String(s) => put_string(&mut body, s),
                Value::Bytes(b) => {
                    body.extend(b);
                    pad4(&mut body);
                }
                Value::IntArray(a) => {
                    body.extend((a.len() as u32).to_be_bytes());
                    for i in a {
                        body.extend((*i as i32).to_be_bytes());
                    }
                }
                Value::Uint64Array(a) => {
                    body.extend((a.len() as u32).to_be_bytes());
                    for u in a {
                        body.extend(u.to_be_bytes());
                    }
                }
                Value::Int64Array(a) => {
                    body.extend((a.len() as u32).to_be_bytes());
                    for i in a {
                        body.extend(i.to_be_bytes());
                    }
                }
                Value::BoolArray(a) => {
                    body.extend((a.len() as u32).to_be_bytes());
                    for b in a {
                        body.extend((*b as u32).to_be_bytes());
                    }
                }
                Value::StringArray(a) => {
                    for s in a {
                        put_string(&mut body, s);
                    }
                }
                Value::List(l) => put_list(&mut body, l),
                Value::ListArray(a) => {
                    for l in a {
                        put_list(&mut body, l);
                    }
                }
            }
            let encoded = (body.len() + 8) as i32;
            v.extend(encoded.to_be_bytes());
            v.extend(encoded.to_be_bytes()); // decoded size: any non-zero value
            v.extend(body);
        }
        v.extend(0i32.to_be_bytes());
        v.extend(0i32.to_be_bytes());
    }

    /// Pack `list` with the 4-byte XDR header, as `nvlist_pack` would.
    pub fn pack(list: &NvList) -> Vec<u8> {
        let mut v = vec![super::NV_ENCODE_XDR, 1, 0, 0];
        put_list(&mut v, list);
        v
    }

    /// Convenience builder for `NV_UNIQUE_NAME` lists.
    pub fn list(pairs: Vec<(&str, Value)>) -> NvList {
        NvList {
            version: 0,
            flags: 1,
            pairs: pairs.into_iter().map(|(n, v)| (n.to_string(), v)).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::encode::{list, pack};
    use super::*;

    fn sample() -> NvList {
        list(vec![
            ("name", Value::String("tank".into())),
            ("pool_guid", Value::Uint64(0xdead_beef_cafe_f00d)),
            ("txg", Value::Uint64(4816230)),
            ("flag", Value::Boolean),
            ("ok", Value::Bool(true)),
            ("small", Value::Int(-7)),
            ("bytes", Value::Bytes(vec![1, 2, 3])),
            ("ints", Value::IntArray(vec![1, -2, 3])),
            ("hole_array", Value::Uint64Array(vec![1, 5])),
            ("names", Value::StringArray(vec!["a".into(), "bcd".into()])),
            (
                "vdev_tree",
                Value::List(list(vec![
                    ("type", Value::String("mirror".into())),
                    ("ashift", Value::Uint64(12)),
                    (
                        "children",
                        Value::ListArray(vec![
                            list(vec![("guid", Value::Uint64(1))]),
                            list(vec![("guid", Value::Uint64(2))]),
                        ]),
                    ),
                ])),
            ),
        ])
    }

    #[test]
    fn roundtrip() {
        let packed = pack(&sample());
        let parsed = parse_packed(&packed).unwrap();
        assert_eq!(parsed, sample());
        assert_eq!(parsed.str("name"), Some("tank"));
        assert_eq!(parsed.u64("txg"), Some(4816230));
        assert!(parsed.flag("flag") && parsed.flag("ok"));
        let tree = parsed.list("vdev_tree").unwrap();
        assert_eq!(tree.u64("ashift"), Some(12));
        assert_eq!(tree.list_array("children").unwrap().len(), 2);
        assert_eq!(parsed.u64_array("hole_array"), Some(&[1u64, 5][..]));
    }

    #[test]
    fn trailing_garbage_is_ignored() {
        let mut packed = pack(&sample());
        packed.extend([0xffu8; 100]);
        assert_eq!(parse_packed(&packed).unwrap(), sample());
    }

    #[test]
    fn unknown_type_is_skipped_by_size() {
        let l = list(vec![
            ("a", Value::Uint64(1)),
            (
                "weird",
                Value::Unknown {
                    type_code: 99,
                    nelem: 0,
                },
            ),
            ("b", Value::Uint64(2)),
        ]);
        let parsed = parse_packed(&pack(&l)).unwrap();
        assert_eq!(parsed.u64("b"), Some(2));
        assert!(matches!(
            parsed.get("weird"),
            Some(Value::Unknown { type_code: 99, .. })
        ));
    }

    #[test]
    fn rejects_bad_header_and_truncation() {
        assert!(matches!(
            parse_packed(&[]),
            Err(ParseError::Truncated { .. })
        ));
        assert!(matches!(
            parse_packed(&[2, 1, 0, 0]),
            Err(ParseError::Malformed { .. })
        ));
        let packed = pack(&sample());
        for cut in [4usize, 12, 20, 40, packed.len() - 3] {
            assert!(parse_packed(&packed[..cut]).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn size_field_cannot_escape_buffer() {
        let mut packed = pack(&list(vec![("a", Value::Uint64(1))]));
        // Inflate the first pair's encoded size past the end.
        packed[12..16].copy_from_slice(&0x7fff_ffffu32.to_be_bytes());
        assert!(parse_packed(&packed).is_err());
        // A value claiming a huge array count must not allocate or read past.
        let mut packed = pack(&list(vec![("a", Value::Uint64Array(vec![1]))]));
        let pos = packed.len() - 8 - 8 - 4; // count field of the array
        packed[pos..pos + 4].copy_from_slice(&0xffff_fff0u32.to_be_bytes());
        assert!(parse_packed(&packed).is_err());
    }
}
