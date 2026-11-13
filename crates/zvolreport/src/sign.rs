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
    let raw = read_small(path)?;
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
    let raw = read_small(path)?;
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

/// A key file: a regular file, read up to a size no key comes near.
/// `--key /dev/zero` was read until memory ran out, and a fifo waited
/// for a writer.
fn read_small(path: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read;
    const MAX: u64 = 64 << 10;
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!(
            "{}: not a file, so not a key; not read",
            path.display()
        ));
    }
    let mut raw = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(MAX + 1).read_to_end(&mut raw))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if raw.len() as u64 > MAX {
        return Err(format!(
            "{}: {} bytes, more than any key is; not read",
            path.display(),
            meta.len()
        ));
    }
    Ok(raw)
}

/// Check a signature file against `bytes`.
///
/// `verify_strict` rather than `verify`: it refuses the small-order
/// public keys under which one signature can verify for more than one
/// key, which is exactly the ambiguity a chain of custody must not have.
pub fn check(key: &VerifyingKey, bytes: &[u8], sig_path: &Path) -> Result<(), String> {
    use std::io::Read;
    let shown = sig_path.display();
    // A signature is a file of 64 bytes, and nothing else is read as
    // one: `--signature /dev/zero` was read until memory ran out, and a
    // fifo waited for ever for a writer.
    let meta = std::fs::metadata(sig_path).map_err(|e| format!("{shown}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{shown}: not a file, so not a signature; not read"));
    }
    let mut raw = Vec::with_capacity(65);
    std::fs::File::open(sig_path)
        .and_then(|f| f.take(65).read_to_end(&mut raw))
        .map_err(|e| format!("{shown}: {e}"))?;
    let bytes64: [u8; 64] = raw.as_slice().try_into().map_err(|_| {
        format!(
            "{shown}: a signature is 64 bytes, this file is {}",
            meta.len()
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
    let pubkey = key.verifying_key();
    // A pair or nothing, and nothing lost on the way. The private half
    // went first, and a public half that could not be written left a
    // private key with no pair; then the public half went first and was
    // taken back when the private one failed — and with `--force` what
    // it was taken back from was the key that had been there, gone.
    // Both halves are written beside their places first, under names
    // nothing else has — a fixed `KEY.new` was removed first, whoever's
    // it was — and only then put there; the key that was there is kept
    // under another such name until both are, and put back if the
    // second one cannot be: a directory at the public name left the new
    // private key in place of the old one and no public half for it.
    let private_tmp = unused_beside(private, "new")?;
    let public_tmp = match unused_beside(public, "new") {
        Ok(p) => p,
        Err(e) => {
            let _ = std::fs::remove_file(&private_tmp);
            return Err(e);
        }
    };
    let written = write_private(&private_tmp, &private_pem(&key)).and_then(|()| {
        write_over(&public_tmp, public_pem(&pubkey).as_bytes())
            .map_err(|e| format!("{}: {e}", public.display()))
    });
    let placed = written.and_then(|()| place_pair(&private_tmp, private, &public_tmp, public));
    if placed.is_err() {
        let _ = std::fs::remove_file(&private_tmp);
        let _ = std::fs::remove_file(&public_tmp);
    }
    placed.map(|()| pubkey)
}

/// Put the private half and then the public half in place, and put the
/// private key that was there back when the public half cannot follow.
fn place_pair(
    private_tmp: &Path,
    private: &Path,
    public_tmp: &Path,
    public: &Path,
) -> Result<(), String> {
    let kept = if std::fs::symlink_metadata(private).is_ok() {
        let keep = unused_name(private, "old")?;
        std::fs::hard_link(private, &keep).map_err(|e| format!("{}: {e}", private.display()))?;
        Some(keep)
    } else {
        None
    };
    let result = std::fs::rename(private_tmp, private)
        .map_err(|e| format!("{}: {e}", private.display()))
        .and_then(|()| {
            std::fs::rename(public_tmp, public).map_err(|e| {
                // The new private key is not left without its pair: the
                // old one goes back, or, where there was none, the new
                // one goes.
                let undone = match &kept {
                    Some(keep) => std::fs::rename(keep, private),
                    None => std::fs::remove_file(private),
                };
                match undone {
                    Ok(()) => format!("{}: {e}", public.display()),
                    Err(u) => format!(
                        "{}: {e}; and {} could not be put back as it was: {u}",
                        public.display(),
                        private.display()
                    ),
                }
            })
        });
    if let Some(keep) = &kept {
        let _ = std::fs::remove_file(keep);
    }
    result
}

/// A name beside `path` that nothing has: `KEY.new-PID-N`, made empty
/// here so that no other run takes it.
fn unused_beside(path: &Path, what: &str) -> Result<PathBuf, String> {
    let p = unused_name(path, what)?;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&p)
        .map_err(|e| format!("{}: {e}", p.display()))?;
    Ok(p)
}

/// A name beside `path`, `KEY.WHAT-PID-N`, that is not there now.
fn unused_name(path: &Path, what: &str) -> Result<PathBuf, String> {
    for n in 0..1000u32 {
        let mut p = path.as_os_str().to_owned();
        p.push(format!(".{what}-{}-{n}", std::process::id()));
        let p = PathBuf::from(p);
        if std::fs::symlink_metadata(&p).is_err() {
            return Ok(p);
        }
    }
    Err(format!("{}: no free name beside it", path.display()))
}

/// Write a file this run made empty for it (`unused_beside`).
fn write_over(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)?
        .write_all(bytes)
}

/// Write the private key so that only its owner can read it.
#[cfg(unix)]
fn write_private(path: &Path, pem: &str) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(format!("{}: {e}", path.display()));
        }
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    // `mode` applies to a file this call creates. One that was there —
    // replaced with `keygen --force` — keeps the bits it had, and a key
    // written into a 0644 file is readable by everyone: set them here,
    // before a byte of the key goes in.
    f.set_permissions(std::fs::Permissions::from_mode(0o600))
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

    /// A key written over a file that was there — `keygen --force` —
    /// is owner-only too: the creation mode alone left a 0644 file 0644.
    #[cfg(unix)]
    #[test]
    fn a_replaced_private_key_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("zvolreport-regen-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let priv_path = dir.join("k");
        std::fs::write(&priv_path, "old").unwrap();
        std::fs::set_permissions(&priv_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        keygen(&priv_path, &dir.join("k.pub")).unwrap();
        let mode = std::fs::metadata(&priv_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A key pair is made beside files that are not this run's — a
    /// `k.new`, a `k.pub.new` — without touching them; and when the
    /// public half cannot be put in place, the private key that was
    /// there is put back, and nothing of the run is left.
    #[test]
    fn keygen_takes_nothing_it_did_not_make() {
        let dir = std::env::temp_dir().join(format!("zvolreport-keygen-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (k, k_pub) = (dir.join("k"), dir.join("k.pub"));
        std::fs::write(dir.join("k.new"), "someone's").unwrap();
        std::fs::write(dir.join("k.pub.new"), "someone else's").unwrap();
        keygen(&k, &k_pub).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join("k.new")).unwrap(),
            "someone's"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("k.pub.new")).unwrap(),
            "someone else's"
        );

        let old = std::fs::read(&k).unwrap();
        let blocked = dir.join("blocked.pub");
        std::fs::create_dir(&blocked).unwrap();
        std::fs::write(blocked.join("x"), "").unwrap();
        assert!(keygen(&k, &blocked).is_err());
        assert_eq!(std::fs::read(&k).unwrap(), old, "the key that was there");
        let mut left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(left, ["blocked.pub", "k", "k.new", "k.pub", "k.pub.new"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Only a regular file is read as a signature or a key, and only so
    /// far: `/dev/zero` was read until memory ran out.
    #[cfg(unix)]
    #[test]
    fn a_signature_or_key_that_is_not_a_file_is_not_read() {
        let key = SigningKey::from_bytes(&RFC8032_SEED).verifying_key();
        let e = check(&key, b"x", Path::new("/dev/zero")).unwrap_err();
        assert!(e.contains("not a file"), "{e}");
        let e = read_public(Path::new("/dev/zero")).unwrap_err();
        assert!(e.contains("not a file"), "{e}");
    }
}
