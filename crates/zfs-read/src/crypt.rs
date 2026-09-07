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

use aes::Aes256;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use ccm::consts::{U12, U16};
use ccm::Ccm;
use hmac::Hmac;
use sha1::Sha1;

use crate::dsl::Encryption;

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
    /// `hex:@FILE`, `passphrase:STRING` or `passphrase:@FILE` (one line;
    /// a trailing newline is dropped).
    pub fn from_spec(spec: &str) -> Result<KeyMaterial, CryptError> {
        let (kind, rest) = spec.split_once(':').ok_or_else(|| {
            CryptError::Spec("expected raw:FILE, hex:HEX or passphrase:TEXT".into())
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
            "passphrase" => Ok(KeyMaterial::Passphrase(text(rest)?)),
            other => Err(CryptError::Spec(format!("unknown key format {other:?}"))),
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
            CryptError::WrongKey => write!(f, "wrong key: the wrapped keys' MAC does not verify"),
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

/// AEAD decrypt with a 32-byte key in the suite's mode; `ct` carries the
/// tag appended. Returns the plaintext or `WrongKey`.
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
    let nonce: &[u8; 12] = nonce
        .try_into()
        .map_err(|_| CryptError::Metadata("nonce is not 12 bytes".into()))?;
    if suite_is_ccm(suite) {
        let c = Ccm::<Aes256, U16, U12>::new_from_slice(key)
            .map_err(|_| CryptError::Metadata("bad key length".into()))?;
        c.decrypt(nonce.into(), payload)
            .map_err(|_| CryptError::WrongKey)
    } else {
        let c = Aes256Gcm::new_from_slice(key)
            .map_err(|_| CryptError::Metadata("bad key length".into()))?;
        c.decrypt(nonce.into(), payload)
            .map_err(|_| CryptError::WrongKey)
    }
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
            KeyMaterial::from_spec(&format!("passphrase:@{}", pw.display())).unwrap(),
            KeyMaterial::Passphrase(p) if p == "secret"
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
