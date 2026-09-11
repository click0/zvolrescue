//! Signing a report, and checking the signature (R-07).
//!
//! A report is a document about evidence; a signature is what makes it a
//! document from a *named* examiner rather than a file anyone could have
//! written. Ed25519 over the exact bytes of `report.json`, which is the
//! same thing `verify` reads, so there is no canonicalisation step to
//! disagree about.
//!
//! The keys are in the form OpenSSL writes and reads — PKCS#8 for the
//! private key, SubjectPublicKeyInfo for the public one, both PEM — and
//! the signature is the raw 64 bytes. That is deliberate: a signature
//! only this tool can check is not much of a signature, and a third
//! party with no copy of `zvolreport` can verify one with
//!
//! ```text
//! openssl pkeyutl -verify -pubin -inkey key.pub -rawin \
//!     -in report.json -sigfile report.json.sig
//! ```

use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// The DER prefix of a PKCS#8 v1 Ed25519 private key: a 46-byte
/// SEQUENCE, version 0, the `id-Ed25519` algorithm (OID 1.3.101.112),
/// then an OCTET STRING wrapping a 32-byte OCTET STRING — the seed.
const PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// The DER prefix of an Ed25519 SubjectPublicKeyInfo: a 42-byte
/// SEQUENCE, the same algorithm, then a BIT STRING of 32 bytes with no
/// unused bits.
const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64 of `data`, wrapped at 64 characters the way PEM wants it.
fn b64_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for (i, chunk) in data.chunks(3).enumerate() {
        if i > 0 && i % 16 == 0 {
            out.push('\n');
        }
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(char::from(B64[(n >> 18) as usize & 63]));
        out.push(char::from(B64[(n >> 12) as usize & 63]));
        out.push(if chunk.len() > 1 {
            char::from(B64[(n >> 6) as usize & 63])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(B64[n as usize & 63])
        } else {
            '='
        });
    }
    out
}

/// Decode base64, ignoring whitespace, refusing anything else.
fn b64_decode(text: &str) -> Result<Vec<u8>, String> {
    let mut bits = 0u32;
    let mut have = 0u32;
    let mut pad = 0usize;
    let mut out = Vec::new();
    for c in text.chars() {
        if c.is_ascii_whitespace() {
            continue;
        }
        if c == '=' {
            pad += 1;
            continue;
        }
        if pad > 0 {
            return Err("base64 data after the padding".into());
        }
        let Some(v) = B64.iter().position(|&b| char::from(b) == c) else {
            return Err(format!("{c:?} is not base64"));
        };
        bits = (bits << 6) | v as u32;
        have += 6;
        if have >= 8 {
            have -= 8;
            out.push((bits >> have) as u8);
        }
    }
    if pad > 2 {
        return Err("too much base64 padding".into());
    }
    Ok(out)
}

/// Pull the body out of a PEM block with the given label.
fn pem_body(text: &str, label: &str) -> Result<Vec<u8>, String> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = text
        .find(&begin)
        .ok_or_else(|| format!("no {begin} line"))?
        + begin.len();
    let stop = text[start..]
        .find(&end)
        .ok_or_else(|| format!("no {end} line"))?
        + start;
    b64_decode(&text[start..stop])
}

/// Wrap `der` in a PEM block.
fn pem(label: &str, der: &[u8]) -> String {
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        b64_encode(der)
    )
}

/// Read a PKCS#8 Ed25519 private key, in PEM or bare DER.
///
/// OpenSSL writes PEM by default and DER with `-outform DER`; both are
/// the same 48 bytes underneath, so both are read rather than making the
/// operator convert one into the other in the middle of a recovery.
pub fn read_private(path: &Path) -> Result<SigningKey, String> {
    let raw = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let der = match std::str::from_utf8(&raw) {
        Ok(text) if text.contains("-----BEGIN") => {
            if text.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
                return Err(format!(
                    "{}: the key is passphrase-protected; this build reads unencrypted PKCS#8 \
                     (openssl pkey -in KEY -out PLAIN)",
                    path.display()
                ));
            }
            pem_body(text, "PRIVATE KEY").map_err(|e| format!("{}: {e}", path.display()))?
        }
        _ => raw,
    };
    if der.len() != PKCS8_PREFIX.len() + 32 || der[..PKCS8_PREFIX.len()] != PKCS8_PREFIX {
        return Err(format!(
            "{}: not an unencrypted PKCS#8 Ed25519 private key",
            path.display()
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&der[PKCS8_PREFIX.len()..]);
    Ok(SigningKey::from_bytes(&seed))
}

/// Read an Ed25519 SubjectPublicKeyInfo, in PEM or bare DER.
pub fn read_public(path: &Path) -> Result<VerifyingKey, String> {
    let raw = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let der = match std::str::from_utf8(&raw) {
        Ok(text) if text.contains("-----BEGIN") => {
            pem_body(text, "PUBLIC KEY").map_err(|e| format!("{}: {e}", path.display()))?
        }
        _ => raw,
    };
    if der.len() != SPKI_PREFIX.len() + 32 || der[..SPKI_PREFIX.len()] != SPKI_PREFIX {
        return Err(format!("{}: not an Ed25519 public key", path.display()));
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&der[SPKI_PREFIX.len()..]);
    VerifyingKey::from_bytes(&bytes).map_err(|e| format!("{}: {e}", path.display()))
}

/// The PEM of a private key, as OpenSSL would have written it.
fn private_pem(key: &SigningKey) -> String {
    let mut der = PKCS8_PREFIX.to_vec();
    der.extend_from_slice(&key.to_bytes());
    pem("PRIVATE KEY", &der)
}

/// The PEM of the matching public key.
pub fn public_pem(key: &VerifyingKey) -> String {
    let mut der = SPKI_PREFIX.to_vec();
    der.extend_from_slice(key.as_bytes());
    pem("PUBLIC KEY", &der)
}

/// Where the signature of `report` lives when nobody said otherwise.
pub fn beside(report: &Path) -> PathBuf {
    let mut p = report.as_os_str().to_os_string();
    p.push(".sig");
    PathBuf::from(p)
}

/// Sign `bytes` and write the raw 64-byte signature.
pub fn write_signature(key: &SigningKey, bytes: &[u8], to: &Path) -> Result<(), String> {
    let sig: Signature = key.sign(bytes);
    std::fs::write(to, sig.to_bytes()).map_err(|e| format!("{}: {e}", to.display()))
}

/// Check a signature file against `bytes`.
///
/// `verify_strict` rather than `verify`: it refuses the small-order
/// public keys under which one signature can verify for more than one
/// key, which is exactly the ambiguity a chain of custody must not have.
pub fn check(key: &VerifyingKey, bytes: &[u8], sig_path: &Path) -> Result<(), String> {
    let raw = std::fs::read(sig_path).map_err(|e| format!("{}: {e}", sig_path.display()))?;
    let bytes64: [u8; 64] = raw.as_slice().try_into().map_err(|_| {
        format!(
            "{}: a signature is 64 bytes, this file is {}",
            sig_path.display(),
            raw.len()
        )
    })?;
    let sig = Signature::from_bytes(&bytes64);
    key.verify_strict(bytes, &sig)
        .map_err(|_| "the signature does not match this report and this key".to_string())
}

/// Generate a key pair and write both halves.
///
/// The seed comes from the operating system's own randomness rather than
/// from a generator this workspace would have to be trusted about.
pub fn keygen(private: &Path, public: &Path) -> Result<VerifyingKey, String> {
    let seed = os_random_32()?;
    let key = SigningKey::from_bytes(&seed);
    write_private(private, &private_pem(&key))?;
    let pubkey = key.verifying_key();
    std::fs::write(public, public_pem(&pubkey))
        .map_err(|e| format!("{}: {e}", public.display()))?;
    Ok(pubkey)
}

/// Write the private key so that only its owner can read it.
#[cfg(unix)]
fn write_private(path: &Path, pem: &str) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(pem.as_bytes())
        .map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(not(unix))]
fn write_private(path: &Path, pem: &str) -> Result<(), String> {
    std::fs::write(path, pem).map_err(|e| format!("{}: {e}", path.display()))
}

/// 32 bytes from the operating system.
fn os_random_32() -> Result<[u8; 32], String> {
    use std::io::Read;
    let mut seed = [0u8; 32];
    let mut f = std::fs::File::open("/dev/urandom").map_err(|e| format!("/dev/urandom: {e}"))?;
    f.read_exact(&mut seed)
        .map_err(|e| format!("/dev/urandom: {e}"))?;
    if seed == [0u8; 32] {
        return Err("/dev/urandom returned nothing but zeros".into());
    }
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one key pair RFC 8032 §7.1 publishes, so the wiring is
    /// checked against the standard rather than against itself.
    const RFC8032_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const RFC8032_PUBLIC: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];

    #[test]
    fn base64_round_trips_at_every_remainder() {
        for n in 0..=64usize {
            let data: Vec<u8> = (0..n).map(|i| (i * 7 + 1) as u8).collect();
            let text = b64_encode(&data);
            assert_eq!(b64_decode(&text).unwrap(), data, "n = {n}");
        }
    }

    #[test]
    fn base64_matches_a_known_answer() {
        assert_eq!(b64_encode(b"zvolrescue"), "enZvbHJlc2N1ZQ==");
        assert_eq!(b64_decode("enZvbHJlc2N1ZQ==").unwrap(), b"zvolrescue");
    }

    #[test]
    fn the_rfc_key_pair_comes_out_of_the_rfc_seed() {
        let key = SigningKey::from_bytes(&RFC8032_SEED);
        assert_eq!(key.verifying_key().as_bytes(), &RFC8032_PUBLIC);
    }

    #[test]
    fn a_key_pair_survives_pem() {
        let key = SigningKey::from_bytes(&RFC8032_SEED);
        let dir = std::env::temp_dir().join(format!("zvolreport-pem-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let priv_path = dir.join("k");
        let pub_path = dir.join("k.pub");
        std::fs::write(&priv_path, private_pem(&key)).unwrap();
        std::fs::write(&pub_path, public_pem(&key.verifying_key())).unwrap();
        assert_eq!(read_private(&priv_path).unwrap().to_bytes(), RFC8032_SEED);
        assert_eq!(read_public(&pub_path).unwrap().as_bytes(), &RFC8032_PUBLIC);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_changed_byte_breaks_the_signature() {
        let key = SigningKey::from_bytes(&RFC8032_SEED);
        let dir = std::env::temp_dir().join(format!("zvolreport-sig-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sig = dir.join("report.json.sig");
        write_signature(&key, b"{\"report_version\":1}", &sig).unwrap();
        let pubkey = key.verifying_key();
        check(&pubkey, b"{\"report_version\":1}", &sig).unwrap();
        assert!(check(&pubkey, b"{\"report_version\":2}", &sig).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn another_key_does_not_verify_it() {
        let mine = SigningKey::from_bytes(&RFC8032_SEED);
        let theirs = SigningKey::from_bytes(&[9u8; 32]);
        let dir = std::env::temp_dir().join(format!("zvolreport-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sig = dir.join("s");
        write_signature(&mine, b"a report", &sig).unwrap();
        assert!(check(&theirs.verifying_key(), b"a report", &sig).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_signature_that_is_not_64_bytes_is_refused_by_length() {
        let dir = std::env::temp_dir().join(format!("zvolreport-len-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sig = dir.join("s");
        std::fs::write(&sig, [0u8; 63]).unwrap();
        let key = SigningKey::from_bytes(&RFC8032_SEED).verifying_key();
        let e = check(&key, b"x", &sig).unwrap_err();
        assert!(e.contains("64 bytes"), "{e}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_passphrase_protected_key_says_so() {
        let dir = std::env::temp_dir().join(format!("zvolreport-enc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("k");
        std::fs::write(
            &path,
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n",
        )
        .unwrap();
        let e = read_private(&path).unwrap_err();
        assert!(e.contains("passphrase-protected"), "{e}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn keygen_writes_a_pair_that_signs_and_verifies() {
        let dir = std::env::temp_dir().join(format!("zvolreport-gen-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let priv_path = dir.join("k");
        let pub_path = dir.join("k.pub");
        let pubkey = keygen(&priv_path, &pub_path).unwrap();
        let sig = dir.join("s");
        write_signature(&read_private(&priv_path).unwrap(), b"evidence", &sig).unwrap();
        check(&read_public(&pub_path).unwrap(), b"evidence", &sig).unwrap();
        assert_eq!(
            read_public(&pub_path).unwrap().as_bytes(),
            pubkey.as_bytes()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&priv_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
