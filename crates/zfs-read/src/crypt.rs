//! Keys of encrypted datasets (phase 3): turn the user's key material into
//! the 32-byte wrapping key the way `libzfs_crypto.c` does (raw, hex, or
//! passphrase through PBKDF2-HMAC-SHA1 with the dataset's salt and
//! iteration count), then unwrap the master and HMAC keys as
//! `zio_crypt_key_unwrap` does: AES-256 in the dataset's mode (GCM or CCM),
//! nonce `DSL_CRYPTO_IV`, tag `DSL_CRYPTO_MAC`, and the key GUID (plus
//! suite and version for on-disk key version 1) as associated data.
//!
//! Everything here is pure Rust (RustCrypto); nothing is written anywhere.

use std::fmt;

use aes::{Aes128, Aes192, Aes256};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm};
use ccm::consts::{U12, U16};
use ccm::Ccm;
use hkdf::Hkdf;
use hmac::Hmac;
use sha1::Sha1;
use sha2::Sha512;
use zfs_ondisk::blkptr::BlkPtr;
use zfs_ondisk::dmu::{ot, DNODE_SIZE};

use crate::dsl::Encryption;

/// `ZIO_DATA_SALT_LEN`.
pub const SALT_LEN: usize = 8;
/// `ZIO_DATA_IV_LEN`.
pub const IV_LEN: usize = 12;
/// `ZIO_DATA_MAC_LEN`.
pub const MAC_LEN: usize = 16;

/// `WRAPPING_KEY_LEN`.
pub const WRAPPING_KEY_LEN: usize = 32;
/// `SHA512_HMAC_KEYLEN`.
pub const HMAC_KEY_LEN: usize = 64;

/// What the user handed over, before derivation.
#[derive(Clone)]
pub enum KeyMaterial {
    /// `keyformat=raw`: exactly 32 bytes.
    Raw(Vec<u8>),
    /// `keyformat=hex`: 64 hex digits.
    Hex(String),
    /// `keyformat=passphrase`: the passphrase itself.
    Passphrase(String),
}

impl fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print key material.
        match self {
            KeyMaterial::Raw(_) => write!(f, "KeyMaterial::Raw(..)"),
            KeyMaterial::Hex(_) => write!(f, "KeyMaterial::Hex(..)"),
            KeyMaterial::Passphrase(_) => write!(f, "KeyMaterial::Passphrase(..)"),
        }
    }
}

impl KeyMaterial {
    /// `keyformat` code this material is for (1 raw, 2 hex, 3 passphrase).
    pub fn keyformat(&self) -> u64 {
        match self {
            KeyMaterial::Raw(_) => 1,
            KeyMaterial::Hex(_) => 2,
            KeyMaterial::Passphrase(_) => 3,
        }
    }

    /// Parse a `--key` spec: `raw:FILE` (32 bytes), `hex:HEXSTRING` or
    /// `hex:@FILE`, `passphrase:FILE` (the passphrase is the file's
    /// content; one trailing newline is dropped). `prompt` is handled by
    /// the caller with [`KeyMaterial::prompt`], as it needs the dataset's
    /// key format.
    pub fn from_spec(spec: &str) -> Result<KeyMaterial, CryptError> {
        let (kind, rest) = spec.split_once(':').ok_or_else(|| {
            CryptError::Spec("expected raw:FILE, hex:HEX|@FILE, passphrase:FILE or prompt".into())
        })?;
        let read =
            |path: &str| std::fs::read(path).map_err(|e| CryptError::Spec(format!("{path}: {e}")));
        let text = |arg: &str| -> Result<String, CryptError> {
            let bytes = if let Some(path) = arg.strip_prefix('@') {
                read(path)?
            } else {
                arg.as_bytes().to_vec()
            };
            let mut s = String::from_utf8(bytes)
                .map_err(|_| CryptError::Spec("key text is not UTF-8".into()))?;
            if s.ends_with('\n') {
                s.pop();
                if s.ends_with('\r') {
                    s.pop();
                }
            }
            Ok(s)
        };
        match kind {
            "raw" => {
                let bytes = read(rest)?;
                if bytes.len() != WRAPPING_KEY_LEN {
                    return Err(CryptError::Spec(format!(
                        "raw key must be exactly {WRAPPING_KEY_LEN} bytes, {rest} has {}",
                        bytes.len()
                    )));
                }
                Ok(KeyMaterial::Raw(bytes))
            }
            "hex" => Ok(KeyMaterial::Hex(text(rest)?)),
            "passphrase" => Ok(KeyMaterial::Passphrase(text(&format!("@{rest}"))?)),
            other => Err(CryptError::Spec(format!("unknown key format {other:?}"))),
        }
    }

    /// Read the key from standard input in the dataset's format: 32 raw
    /// bytes, or one line of hex digits or passphrase. The terminal echo
    /// is not disabled; prefer a file spec when others can see the screen.
    pub fn prompt(keyformat: Option<u64>) -> Result<KeyMaterial, CryptError> {
        use std::io::Read;
        let mut stdin = std::io::stdin().lock();
        let fail = |e: std::io::Error| CryptError::Spec(format!("stdin: {e}"));
        let line = |stdin: &mut std::io::StdinLock<'_>| -> Result<String, CryptError> {
            let mut s = String::new();
            std::io::BufRead::read_line(stdin, &mut s).map_err(fail)?;
            while s.ends_with('\n') || s.ends_with('\r') {
                s.pop();
            }
            Ok(s)
        };
        match keyformat {
            Some(1) => {
                let mut b = vec![0u8; WRAPPING_KEY_LEN];
                stdin.read_exact(&mut b).map_err(fail)?;
                Ok(KeyMaterial::Raw(b))
            }
            Some(2) => Ok(KeyMaterial::Hex(line(&mut stdin)?)),
            Some(3) => Ok(KeyMaterial::Passphrase(line(&mut stdin)?)),
            other => Err(CryptError::Metadata(format!(
                "unknown keyformat {other:?}: cannot prompt"
            ))),
        }
    }
}

/// Failure to derive or unwrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptError {
    /// The `--key` spec itself.
    Spec(String),
    /// Material does not match the dataset's `keyformat`.
    FormatMismatch {
        /// The dataset's keyformat name.
        expected: String,
        /// What was supplied.
        got: String,
    },
    /// The on-disk crypto metadata is incomplete or malformed.
    Metadata(String),
    /// Unsupported suite code.
    Suite(u64),
    /// The wrapping key does not open the dataset (MAC mismatch).
    WrongKey,
}

impl fmt::Display for CryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptError::Spec(s) => write!(f, "key: {s}"),
            CryptError::FormatMismatch { expected, got } => {
                write!(
                    f,
                    "dataset expects a {expected} key, a {got} key was supplied"
                )
            }
            CryptError::Metadata(s) => write!(f, "encryption metadata: {s}"),
            CryptError::Suite(c) => write!(f, "unsupported encryption suite {c}"),
            CryptError::WrongKey => write!(f, "MAC does not verify: wrong key or damaged data"),
        }
    }
}

impl std::error::Error for CryptError {}

/// Derive the 32-byte wrapping key (`derive_key` in libzfs).
pub fn wrapping_key(
    material: &KeyMaterial,
    enc: &Encryption,
) -> Result<[u8; WRAPPING_KEY_LEN], CryptError> {
    if enc.keyformat != Some(material.keyformat()) {
        return Err(CryptError::FormatMismatch {
            expected: enc.keyformat_name(),
            got: match material {
                KeyMaterial::Raw(_) => "raw",
                KeyMaterial::Hex(_) => "hex",
                KeyMaterial::Passphrase(_) => "passphrase",
            }
            .into(),
        });
    }
    let mut key = [0u8; WRAPPING_KEY_LEN];
    match material {
        KeyMaterial::Raw(b) => key.copy_from_slice(b),
        KeyMaterial::Hex(h) => {
            let h = h.trim();
            if h.len() != 2 * WRAPPING_KEY_LEN || !h.bytes().all(|c| c.is_ascii_hexdigit()) {
                return Err(CryptError::Spec(format!(
                    "hex key must be {} hex digits",
                    2 * WRAPPING_KEY_LEN
                )));
            }
            for (i, k) in key.iter_mut().enumerate() {
                *k = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).expect("checked hex");
            }
        }
        KeyMaterial::Passphrase(p) => {
            let iters = enc
                .pbkdf2_iters
                .filter(|&i| i > 0)
                .ok_or_else(|| CryptError::Metadata("pbkdf2iters missing or zero".into()))?;
            // The salt is the little-endian bytes of the stored uint64.
            let salt = enc
                .pbkdf2_salt
                .ok_or_else(|| CryptError::Metadata("pbkdf2salt missing".into()))?
                .to_le_bytes();
            let iters = u32::try_from(iters)
                .map_err(|_| CryptError::Metadata("pbkdf2iters out of range".into()))?;
            pbkdf2::pbkdf2::<Hmac<Sha1>>(p.as_bytes(), &salt, iters, &mut key)
                .map_err(|_| CryptError::Metadata("pbkdf2 failed".into()))?;
        }
    }
    Ok(key)
}

/// The unwrapped keys of one encryption root.
#[derive(Clone, PartialEq, Eq)]
pub struct DatasetKeys {
    /// `DSL_CRYPTO_SUITE` (which also fixes the master key length).
    pub suite: u64,
    /// Key GUID, to match datasets sharing this key.
    pub key_guid: u64,
    /// On-disk key version (0 or 1).
    pub version: u64,
    /// Master key (16, 24 or 32 bytes by suite).
    pub master: Vec<u8>,
    /// HMAC key (64 bytes) for the objset MACs.
    pub hmac: Vec<u8>,
}

impl fmt::Debug for DatasetKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DatasetKeys {{ suite: {}, key_guid: {:#x}, version: {}, master: [{} bytes], hmac: [{} bytes] }}",
            self.suite,
            self.key_guid,
            self.version,
            self.master.len(),
            self.hmac.len()
        )
    }
}

/// Key length in bytes of `zio_crypt_table[suite]`.
pub fn suite_key_len(suite: u64) -> Option<usize> {
    match suite {
        3 | 6 => Some(16),
        4 | 7 => Some(24),
        5 | 8 => Some(32),
        _ => None,
    }
}

/// Whether the suite is AES-CCM (else AES-GCM).
fn suite_is_ccm(suite: u64) -> bool {
    (3..=5).contains(&suite)
}

/// AEAD decrypt in the suite's mode with a 16-, 24- or 32-byte key
/// (the key length picks AES-128/192/256, as the ICP does); `ct` carries
/// the 16-byte tag appended. Returns the plaintext or `WrongKey`.
pub(crate) fn aead_open(
    suite: u64,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ct_with_tag: &[u8],
) -> Result<Vec<u8>, CryptError> {
    let payload = Payload {
        msg: ct_with_tag,
        aad,
    };
    let nonce: &[u8; IV_LEN] = nonce
        .try_into()
        .map_err(|_| CryptError::Metadata("nonce is not 12 bytes".into()))?;
    let bad = |_| CryptError::Metadata("bad key length".into());
    let wrong = |_| CryptError::WrongKey;
    let n = nonce.into();
    match (suite_is_ccm(suite), key.len()) {
        (true, 16) => Ccm::<Aes128, U16, U12>::new_from_slice(key)
            .map_err(bad)?
            .decrypt(n, payload)
            .map_err(wrong),
        (true, 24) => Ccm::<Aes192, U16, U12>::new_from_slice(key)
            .map_err(bad)?
            .decrypt(n, payload)
            .map_err(wrong),
        (true, _) => Ccm::<Aes256, U16, U12>::new_from_slice(key)
            .map_err(bad)?
            .decrypt(n, payload)
            .map_err(wrong),
        (false, 16) => Aes128Gcm::new_from_slice(key)
            .map_err(bad)?
            .decrypt(n, payload)
            .map_err(wrong),
        (false, 24) => AesGcm::<Aes192, U12>::new_from_slice(key)
            .map_err(bad)?
            .decrypt(n, payload)
            .map_err(wrong),
        (false, _) => Aes256Gcm::new_from_slice(key)
            .map_err(bad)?
            .decrypt(n, payload)
            .map_err(wrong),
    }
}

/// Per-block encryption key: `hkdf_sha512(master, salt = none, info =
/// the block's 8-byte salt)` truncated to the suite's key length.
pub fn derive_block_key(keys: &DatasetKeys, salt: &[u8; SALT_LEN]) -> Vec<u8> {
    let hk = Hkdf::<Sha512>::new(None, &keys.master);
    let mut out = vec![0u8; keys.master.len()];
    hk.expand(salt, &mut out)
        .expect("key length below HKDF limit");
    out
}

/// Salt, IV and MAC of an encrypted block as `zio_crypt_decode_params_bp`
/// and `zio_crypt_decode_mac_bp` produce them (little-endian bytes of the
/// pointer words; a byteswapped pointer has already been read in its own
/// order, so the bytes come out the same).
pub fn block_params(bp: &BlkPtr) -> Option<([u8; SALT_LEN], [u8; IV_LEN], [u8; MAC_LEN])> {
    let (salt, iv1, iv2) = bp.crypt_params()?;
    let mut iv = [0u8; IV_LEN];
    iv[..8].copy_from_slice(&iv1.to_le_bytes());
    iv[8..].copy_from_slice(&iv2.to_le_bytes());
    Some((salt.to_le_bytes(), iv, block_mac(bp)))
}

/// `zio_crypt_decode_mac_bp`: checksum words 2 and 3, zero for objsets.
fn block_mac(bp: &BlkPtr) -> [u8; MAC_LEN] {
    let mut mac = [0u8; MAC_LEN];
    if bp.object_type != ot::OBJSET {
        mac[..8].copy_from_slice(&bp.cksum[2].to_le_bytes());
        mac[8..].copy_from_slice(&bp.cksum[3].to_le_bytes());
    }
    mac
}

/// `blkptr_auth_buf_t` of a pointer found inside a dnode: the portable
/// part of `blk_prop` (little-endian), the MAC, and (key version 1) an
/// 8-byte pad. `zio_crypt_bp_zero_nonportable_blkprop` decides what is
/// portable.
fn blkptr_auth_buf(raw: &[u8], version: u64, endian: zfs_ondisk::Endian) -> Vec<u8> {
    let bp = BlkPtr::parse(raw, endian);
    let mut prop = endian.u64_at(raw, 6 * 8).unwrap_or(0);
    let mut mac = [0u8; MAC_LEN];
    if let Ok(bp) = &bp {
        mac = block_mac(bp);
        let clear = |prop: &mut u64, low: u32, len: u32| {
            let mask = if len == 64 {
                u64::MAX
            } else {
                ((1u64 << len) - 1) << low
            };
            *prop &= !mask;
        };
        if version == 0 {
            clear(&mut prop, 62, 1); // dedup
            clear(&mut prop, 40, 8); // checksum
            clear(&mut prop, 16, 16); // psize -> SPA_MINBLOCKSIZE
        } else if bp.is_hole() {
            prop = 0;
        } else {
            if bp.level != 0 {
                clear(&mut prop, 63, 1); // byteorder
                clear(&mut prop, 32, 7); // compress
                clear(&mut prop, 16, 16); // psize
            }
            clear(&mut prop, 62, 1);
            clear(&mut prop, 40, 8);
        }
    }
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&prop.to_le_bytes());
    out.extend_from_slice(&mac);
    if version != 0 {
        out.extend_from_slice(&[0u8; 8]);
    }
    out
}

/// Decrypt one block of an encrypted dataset with its dataset keys. `ct`
/// is the on-disk (still compressed) payload of `psize` bytes; the result
/// has the same length and decompresses with the pointer's algorithm.
/// Dnode blocks (`DMU_OT_DNODE`) are partly plaintext: only the bonus
/// buffers of encrypted bonus types are ciphertext, everything else is
/// authenticated as associated data (`zio_crypt_init_uios_dnode`).
pub fn decrypt_block(keys: &DatasetKeys, bp: &BlkPtr, ct: &[u8]) -> Result<Vec<u8>, CryptError> {
    let (salt, iv, mac) = block_params(bp)
        .ok_or_else(|| CryptError::Metadata("pointer is not an encrypted block".into()))?;
    let key = derive_block_key(keys, &salt);
    match bp.object_type {
        ot::DNODE => decrypt_dnode_block(keys, bp, ct, &key, &iv, &mac),
        9 => Err(CryptError::Metadata(
            "ZIL blocks are not decrypted (nothing to recover there)".into(),
        )),
        _ => {
            let mut msg = ct.to_vec();
            msg.extend_from_slice(&mac);
            aead_open(keys.suite, &key, &iv, &[], &msg)
        }
    }
}

fn decrypt_dnode_block(
    keys: &DatasetKeys,
    bp: &BlkPtr,
    ct: &[u8],
    key: &[u8],
    iv: &[u8; IV_LEN],
    mac: &[u8; MAC_LEN],
) -> Result<Vec<u8>, CryptError> {
    let endian = bp.endian;
    let mut aad = Vec::with_capacity(ct.len());
    let mut cipher = Vec::new();
    // (offset, len) of every bonus region that is ciphertext, in order.
    let mut regions: Vec<(usize, usize)> = Vec::new();
    let max = ct.len() / DNODE_SIZE;
    let mut i = 0usize;
    while i < max {
        let at = i * DNODE_SIZE;
        let dn = &ct[at..at + DNODE_SIZE];
        let dn_type = dn[0];
        let nblkptr = dn[3] as usize;
        let bonustype = dn[4];
        let flags = dn[7];
        let bonuslen = u16::from_le_bytes([dn[10], dn[11]]);
        let extra = dn[12] as usize;
        let slots = (extra + 1).min(max - i);
        let total = slots * DNODE_SIZE;
        // Core: 64 bytes with only the portable flag and no dn_used.
        let mut core = dn[..64].to_vec();
        core[7] = flags & 0x04; // DNODE_CRYPT_PORTABLE_FLAGS_MASK
        core[24..32].fill(0); // dn_used
        aad.extend_from_slice(&core);
        for j in 0..nblkptr {
            let off = 64 + j * 128;
            if off + 128 <= total {
                aad.extend_from_slice(&blkptr_auth_buf(
                    &ct[at + off..at + off + 128],
                    keys.version,
                    endian,
                ));
            }
        }
        // DN_BONUS: right after the dn_nblkptr block pointers.
        let bonus_start = 64 + nblkptr * 128;
        let bonus_end = if flags & 0x04 != 0 {
            aad.extend_from_slice(&blkptr_auth_buf(
                &ct[at + total - 128..at + total],
                keys.version,
                endian,
            ));
            total - 128
        } else {
            total
        };
        if bonus_start < bonus_end {
            let len = bonus_end - bonus_start;
            if dn_type != 0 && ot::is_encrypted(bonustype) && bonuslen != 0 {
                regions.push((at + bonus_start, len));
                cipher.extend_from_slice(&ct[at + bonus_start..at + bonus_end]);
            } else {
                aad.extend_from_slice(&ct[at + bonus_start..at + bonus_end]);
            }
        }
        i += slots;
    }
    let mut out = ct.to_vec();
    if cipher.is_empty() {
        // no_crypt: nothing encrypted in this block; still authenticated.
        cipher.extend_from_slice(mac);
        aead_open(keys.suite, key, iv, &aad, &cipher)?;
        return Ok(out);
    }
    cipher.extend_from_slice(mac);
    let plain = aead_open(keys.suite, key, iv, &aad, &cipher)?;
    let mut pos = 0;
    for (off, len) in regions {
        out[off..off + len].copy_from_slice(&plain[pos..pos + len]);
        pos += len;
    }
    Ok(out)
}

/// `zio_crypt_key_unwrap`: recover the master and HMAC keys with the
/// wrapping key. A wrong key fails the MAC and yields `WrongKey`.
pub fn unwrap_keys(
    enc: &Encryption,
    wkey: &[u8; WRAPPING_KEY_LEN],
) -> Result<DatasetKeys, CryptError> {
    let keylen = suite_key_len(enc.suite).ok_or(CryptError::Suite(enc.suite))?;
    if enc.wrapped_master_key.len() < keylen {
        return Err(CryptError::Metadata(format!(
            "wrapped master key has {} bytes, suite needs {keylen}",
            enc.wrapped_master_key.len()
        )));
    }
    if enc.wrapped_hmac_key.len() < HMAC_KEY_LEN || enc.mac.len() != 16 || enc.iv.len() != 12 {
        return Err(CryptError::Metadata(
            "wrapped HMAC key, MAC or IV has the wrong length".into(),
        ));
    }
    let mut ct = Vec::with_capacity(keylen + HMAC_KEY_LEN + 16);
    ct.extend_from_slice(&enc.wrapped_master_key[..keylen]);
    ct.extend_from_slice(&enc.wrapped_hmac_key[..HMAC_KEY_LEN]);
    ct.extend_from_slice(&enc.mac);
    let mut aad = Vec::with_capacity(24);
    aad.extend_from_slice(&enc.key_guid.to_le_bytes());
    if enc.key_version != 0 {
        aad.extend_from_slice(&enc.suite.to_le_bytes());
        aad.extend_from_slice(&enc.key_version.to_le_bytes());
    }
    let plain = aead_open(enc.suite, wkey, &enc.iv, &aad, &ct)?;
    Ok(DatasetKeys {
        suite: enc.suite,
        key_guid: enc.key_guid,
        version: enc.key_version,
        master: plain[..keylen].to_vec(),
        hmac: plain[keylen..].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::AeadInPlace;

    fn enc_with(suite: u64, version: u64, keyformat: u64) -> Encryption {
        Encryption {
            crypto_key_obj: 22,
            suite,
            key_guid: 0x2af3_f5e0_7d4d_c227,
            key_version: version,
            root_ddobj: 9,
            keyformat: Some(keyformat),
            keylocation: None,
            pbkdf2_iters: Some(1000),
            pbkdf2_salt: Some(0x0102_0304_0506_0708),
            iv: vec![9; 12],
            mac: Vec::new(),
            wrapped_master_key: Vec::new(),
            wrapped_hmac_key: Vec::new(),
        }
    }

    /// Wrap like zio_crypt_key_wrap does, to have something to unwrap.
    fn wrap(enc: &mut Encryption, wkey: &[u8; 32], master: &[u8], hmac: &[u8; 64]) {
        let mut aad = enc.key_guid.to_le_bytes().to_vec();
        if enc.key_version != 0 {
            aad.extend_from_slice(&enc.suite.to_le_bytes());
            aad.extend_from_slice(&enc.key_version.to_le_bytes());
        }
        let mut buf = master.to_vec();
        buf.extend_from_slice(hmac);
        let nonce: [u8; 12] = enc.iv.clone().try_into().unwrap();
        let tag = if suite_is_ccm(enc.suite) {
            Ccm::<Aes256, U16, U12>::new_from_slice(wkey)
                .unwrap()
                .encrypt_in_place_detached((&nonce).into(), &aad, &mut buf)
                .unwrap()
        } else {
            Aes256Gcm::new_from_slice(wkey)
                .unwrap()
                .encrypt_in_place_detached((&nonce).into(), &aad, &mut buf)
                .unwrap()
        };
        enc.wrapped_master_key = buf[..master.len()].to_vec();
        enc.wrapped_master_key.resize(32, 0); // stored as MASTER_KEY_MAX_LEN
        enc.wrapped_hmac_key = buf[master.len()..].to_vec();
        enc.mac = tag.to_vec();
    }

    #[test]
    fn unwrap_gcm_and_ccm_both_versions() {
        let wkey = [0x42u8; 32];
        let hmac = [7u8; 64];
        for (suite, keylen) in [(8u64, 32usize), (6, 16), (5, 32), (4, 24)] {
            for version in [0u64, 1] {
                let master: Vec<u8> = (0..keylen as u8).collect();
                let mut enc = enc_with(suite, version, 1);
                wrap(&mut enc, &wkey, &master, &hmac);
                let keys = unwrap_keys(&enc, &wkey).unwrap();
                assert_eq!(keys.master, master, "suite {suite} v{version}");
                assert_eq!(keys.hmac, hmac.to_vec());
                assert_eq!(unwrap_keys(&enc, &[0x43; 32]), Err(CryptError::WrongKey));
                // A tampered MAC is a wrong key too.
                let mut bad = enc.clone();
                bad.mac[0] ^= 1;
                assert_eq!(unwrap_keys(&bad, &wkey), Err(CryptError::WrongKey));
            }
        }
    }

    #[test]
    fn wrapping_key_formats() {
        let raw = enc_with(8, 1, 1);
        let k = wrapping_key(&KeyMaterial::Raw(vec![5; 32]), &raw).unwrap();
        assert_eq!(k, [5; 32]);
        assert!(matches!(
            wrapping_key(&KeyMaterial::Hex("00".repeat(32)), &raw),
            Err(CryptError::FormatMismatch { .. })
        ));
        let hex = enc_with(8, 1, 2);
        let k = wrapping_key(&KeyMaterial::Hex(format!("{}\n", "0a".repeat(32))), &hex).unwrap();
        assert_eq!(k, [0x0a; 32]);
        assert!(wrapping_key(&KeyMaterial::Hex("zz".repeat(32)), &hex).is_err());
        // PBKDF2-HMAC-SHA1("password", salt = LE bytes of 0x0102030405060708, 1000, 32)
        let pw = enc_with(8, 1, 3);
        let k = wrapping_key(&KeyMaterial::Passphrase("password".into()), &pw).unwrap();
        let mut expect = [0u8; 32];
        pbkdf2::pbkdf2::<Hmac<Sha1>>(b"password", &[8, 7, 6, 5, 4, 3, 2, 1], 1000, &mut expect)
            .unwrap();
        assert_eq!(k, expect);
        assert_ne!(k, [0; 32]);
    }

    #[test]
    fn block_key_and_normal_block_roundtrip() {
        use aes_gcm::aead::AeadInPlace;
        use zfs_ondisk::blkptr::encode::Builder;
        use zfs_ondisk::Endian;
        let keys = DatasetKeys {
            suite: 8,
            key_guid: 1,
            version: 1,
            master: (0..32u8).collect(),
            hmac: vec![0; 64],
        };
        let salt = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let k = derive_block_key(&keys, &salt);
        assert_eq!(k.len(), 32);
        assert_ne!(k, derive_block_key(&keys, &[0; 8]));
        // Build a zvol data pointer: salt/IV words in DVA[2], IV2 in fill.
        let iv1 = 0x1111_2222_3333_4444u64;
        let iv2 = 0x5555_6666u32;
        let plain = vec![0xabu8; 4096];
        let mut buf = plain.clone();
        let mut iv = [0u8; 12];
        iv[..8].copy_from_slice(&iv1.to_le_bytes());
        iv[8..].copy_from_slice(&iv2.to_le_bytes());
        let tag = Aes256Gcm::new_from_slice(&k)
            .unwrap()
            .encrypt_in_place_detached((&iv).into(), &[], &mut buf)
            .unwrap();
        let mac = [
            u64::from_le_bytes(tag[..8].try_into().unwrap()),
            u64::from_le_bytes(tag[8..].try_into().unwrap()),
        ];
        let raw = Builder::new()
            .dva(0, 0, 0x1000, 0x1000, false)
            .dva(2, 0, 0, 0, false)
            .sizes(4096, 4096)
            .props(2, 7, 23, 0)
            .flags(true, false)
            .births(10, 10, (u64::from(iv2) << 32) | 1)
            .cksum([0, 0, mac[0], mac[1]])
            .bytes(Endian::Little);
        let mut raw = raw;
        raw[4 * 8..5 * 8].copy_from_slice(&u64::from_le_bytes(salt).to_le_bytes());
        raw[5 * 8..6 * 8].copy_from_slice(&iv1.to_le_bytes());
        let bp = BlkPtr::parse(&raw, Endian::Little).unwrap();
        assert!(bp.is_encrypted());
        assert_eq!(decrypt_block(&keys, &bp, &buf).unwrap(), plain);
        let mut bad = buf.clone();
        bad[0] ^= 1;
        assert_eq!(decrypt_block(&keys, &bp, &bad), Err(CryptError::WrongKey));
    }

    #[test]
    fn key_spec_parsing() {
        let dir = std::env::temp_dir().join(format!("zr-keyspec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let raw = dir.join("raw.key");
        std::fs::write(&raw, [1u8; 32]).unwrap();
        assert!(matches!(
            KeyMaterial::from_spec(&format!("raw:{}", raw.display())).unwrap(),
            KeyMaterial::Raw(b) if b == vec![1u8; 32]
        ));
        std::fs::write(&raw, [1u8; 31]).unwrap();
        assert!(KeyMaterial::from_spec(&format!("raw:{}", raw.display())).is_err());
        let pw = dir.join("pw");
        std::fs::write(&pw, "secret\n").unwrap();
        assert!(matches!(
            KeyMaterial::from_spec(&format!("passphrase:{}", pw.display())).unwrap(),
            KeyMaterial::Passphrase(p) if p == "secret"
        ));
        std::fs::write(&pw, "0a".repeat(32) + "\n").unwrap();
        assert!(matches!(
            KeyMaterial::from_spec(&format!("hex:@{}", pw.display())).unwrap(),
            KeyMaterial::Hex(h) if h.len() == 64
        ));
        assert!(matches!(
            KeyMaterial::from_spec("hex:abcd").unwrap(),
            KeyMaterial::Hex(h) if h == "abcd"
        ));
        assert!(KeyMaterial::from_spec("pem:x").is_err());
        assert!(KeyMaterial::from_spec("nocolon").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
