//! Hashing an image as it is written (SPEC F-53).
//!
//! SHA-256 is what this tool records and what its own reports check
//! back. MD5 and SHA-1 are here for a different reason: an extracted
//! image usually leaves for somewhere else, and what is waiting there
//! may be an acquisition log, a case-management system or a hashset
//! that only speaks one of those. Recomputing a digest over a
//! multi-terabyte image afterwards costs another full read of it, so
//! the moment to take them is while the bytes are going past.
//!
//! Neither is offered as a check on whether the image is *right*. MD5
//! and SHA-1 both have practical collision attacks, which matters when
//! someone may have chosen the bytes; it does not matter for lining an
//! image up against a record written before this tool touched it, which
//! is what they are for.

use std::fmt::Write as _;

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// Which digests to take besides SHA-256, which is always taken.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Extra {
    /// Also compute MD5.
    pub md5: bool,
    /// Also compute SHA-1.
    pub sha1: bool,
}

impl Extra {
    /// Nothing beyond SHA-256.
    pub fn none() -> Extra {
        Extra::default()
    }

    /// Parse a comma-separated list such as `md5,sha1`.
    ///
    /// `sha256` is accepted and does nothing: it is always computed, and
    /// refusing to name it would be pedantry. An unknown name is an
    /// error rather than a silence, because a digest the operator asked
    /// for and did not get is the one thing worse than not asking.
    pub fn parse(list: &str) -> Result<Extra, String> {
        let mut extra = Extra::default();
        for name in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            match name.to_ascii_lowercase().as_str() {
                "md5" => extra.md5 = true,
                "sha1" | "sha-1" => extra.sha1 = true,
                "sha256" | "sha-256" => {}
                other => {
                    return Err(format!(
                        "unknown digest {other:?}: want md5, sha1 or sha256"
                    ))
                }
            }
        }
        Ok(extra)
    }
}

/// Digests being taken over one image, in a single pass.
#[derive(Debug, Clone)]
pub struct Digests {
    sha256: Sha256,
    sha1: Option<Sha1>,
    md5: Option<Md5>,
}

impl Digests {
    /// Start over an empty image.
    pub fn new(extra: Extra) -> Digests {
        Digests {
            sha256: Sha256::new(),
            sha1: extra.sha1.then(Sha1::new),
            md5: extra.md5.then(Md5::new),
        }
    }

    /// Feed the next bytes of the image, in order.
    pub fn update(&mut self, bytes: &[u8]) {
        self.sha256.update(bytes);
        if let Some(h) = self.sha1.as_mut() {
            h.update(bytes);
        }
        if let Some(h) = self.md5.as_mut() {
            h.update(bytes);
        }
    }

    /// Finish, as lowercase hex.
    pub fn finish(self) -> DigestSet {
        DigestSet {
            sha256: hex(&self.sha256.finalize()),
            sha1: self.sha1.map(|h| hex(&h.finalize())),
            md5: self.md5.map(|h| hex(&h.finalize())),
        }
    }
}

/// What the digests came to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DigestSet {
    /// SHA-256, always.
    pub sha256: String,
    /// SHA-1, when it was asked for.
    pub sha1: Option<String>,
    /// MD5, when it was asked for.
    pub md5: Option<String>,
}

impl DigestSet {
    /// Each digest present, as `(name, hex)`, strongest first.
    pub fn named(&self) -> Vec<(&'static str, &str)> {
        let mut out = vec![("sha256", self.sha256.as_str())];
        if let Some(h) = &self.sha1 {
            out.push(("sha1", h.as_str()));
        }
        if let Some(h) = &self.md5 {
            out.push(("md5", h.as_str()));
        }
        out
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published vectors, so that what this records is what another
    /// tool will compute over the same bytes. MD5 is RFC 1321's own
    /// suite; SHA-1 and SHA-256 are the FIPS 180 examples.
    #[test]
    fn the_digests_agree_with_the_published_vectors() {
        let all = Extra {
            md5: true,
            sha1: true,
        };
        let of = |input: &[u8]| {
            let mut d = Digests::new(all);
            d.update(input);
            d.finish()
        };

        let empty = of(b"");
        assert_eq!(
            empty.md5.as_deref(),
            Some("d41d8cd98f00b204e9800998ecf8427e")
        );
        assert_eq!(
            empty.sha1.as_deref(),
            Some("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        );
        assert_eq!(
            empty.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let abc = of(b"abc");
        assert_eq!(abc.md5.as_deref(), Some("900150983cd24fb0d6963f7d28e17f72"));
        assert_eq!(
            abc.sha1.as_deref(),
            Some("a9993e364706816aba3e25717850c26c9cd0d89d")
        );
        assert_eq!(
            abc.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// Fed in pieces or all at once comes to the same thing — which is
    /// what lets an image be hashed block by block as it is written.
    #[test]
    fn feeding_in_pieces_matches_feeding_it_whole() {
        let extra = Extra {
            md5: true,
            sha1: true,
        };
        let data: Vec<u8> = (0..=255u8).cycle().take(10_000).collect();
        let mut whole = Digests::new(extra);
        whole.update(&data);
        let mut pieces = Digests::new(extra);
        for chunk in data.chunks(997) {
            pieces.update(chunk);
        }
        assert_eq!(whole.finish(), pieces.finish());
    }

    #[test]
    fn only_what_was_asked_for_is_computed() {
        let mut only_sha256 = Digests::new(Extra::none());
        only_sha256.update(b"abc");
        let got = only_sha256.finish();
        assert_eq!(got.md5, None);
        assert_eq!(got.sha1, None);
        assert_eq!(got.named().len(), 1);

        let mut with_md5 = Digests::new(Extra {
            md5: true,
            sha1: false,
        });
        with_md5.update(b"abc");
        let got = with_md5.finish();
        assert_eq!(got.md5.as_deref(), Some("900150983cd24fb0d6963f7d28e17f72"));
        assert_eq!(got.sha1, None);
        assert_eq!(
            got.named(),
            vec![
                (
                    "sha256",
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                ),
                ("md5", "900150983cd24fb0d6963f7d28e17f72"),
            ]
        );
    }

    #[test]
    fn the_list_is_parsed_and_a_name_that_is_not_a_digest_is_refused() {
        assert_eq!(Extra::parse("").unwrap(), Extra::none());
        assert_eq!(
            Extra::parse("md5").unwrap(),
            Extra {
                md5: true,
                sha1: false
            }
        );
        assert_eq!(
            Extra::parse("SHA-1, md5 ").unwrap(),
            Extra {
                md5: true,
                sha1: true
            }
        );
        // Naming the one that is always taken is allowed and idle.
        assert_eq!(Extra::parse("sha256").unwrap(), Extra::none());
        assert_eq!(
            Extra::parse("md5,crc32").unwrap_err(),
            "unknown digest \"crc32\": want md5, sha1 or sha256"
        );
    }
}
