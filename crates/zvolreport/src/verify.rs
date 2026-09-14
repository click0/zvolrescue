//! `zvolreport verify` — is every file still the file the report says?
//!
//! Recompute the SHA-256 of everything the report recorded a hash for:
//! the outputs, which are always hashed, and the evidence, which is
//! hashed only when someone asked for it. Anything that no longer
//! matches is a FAIL and the run exits 4 (R-04).

use std::path::{Path, PathBuf};

use serde::Serialize;
use zvol_common::evidence::{digests_of, Extra};
use zvol_common::{exit, Format, Global};

use crate::model::{Report, REPORT_VERSION};

/// Options of a `verify` run.
pub struct Options {
    pub report: PathBuf,
    pub evidence_root: Option<PathBuf>,
    pub outputs_root: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub signature: Option<PathBuf>,
}

/// What became of one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// The file is there and hashes to what was recorded.
    Pass,
    /// The file is there and hashes to something else.
    Fail,
    /// The file is not where it was looked for.
    Missing,
    /// Nothing was recorded to check it against.
    Unhashed,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::Missing => "MISSING",
            Status::Unhashed => "-",
        }
    }
}

/// One line of the verdict.
#[derive(Debug, Clone, Serialize)]
pub struct Checked {
    /// `evidence` or `output`.
    pub kind: &'static str,
    /// Which digest this row is about. A file with legacy digests
    /// recorded beside its SHA-256 (SPEC F-53) gets a row for each: a
    /// hash that is written down and never checked back is decoration.
    pub algorithm: &'static str,
    /// Where the file was looked for, after any `--*-root`.
    pub path: PathBuf,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recorded: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub found: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// What became of the report's own signature (R-07).
#[derive(Debug, Clone, Serialize)]
pub struct Signed {
    /// The public key it was checked against.
    pub key: PathBuf,
    /// Where the signature was looked for.
    pub path: PathBuf,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Serialize)]
struct VerifyOut {
    report: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<Signed>,
    checked: Vec<Checked>,
    passed: usize,
    failed: usize,
    missing: usize,
    unhashed: usize,
}

/// Where to look for a file the report names.
///
/// The disks are rarely mounted where they were when the evidence was
/// taken, so a root re-bases the recorded path onto it: the file name
/// under the root, and — when the recorded path was absolute — the whole
/// path joined under it, whichever exists.
fn locate(recorded: &Path, root: Option<&PathBuf>) -> PathBuf {
    let Some(root) = root else {
        return recorded.to_path_buf();
    };
    let joined = root.join(recorded.strip_prefix("/").unwrap_or(recorded));
    if joined.exists() {
        return joined;
    }
    match recorded.file_name() {
        Some(name) => root.join(name),
        None => joined,
    }
}

/// What the report recorded about one file.
struct Recorded<'a> {
    sha256: Option<&'a String>,
    sha1: Option<&'a String>,
    md5: Option<&'a String>,
}

/// Check a file against every digest the report recorded for it.
///
/// The file is read once and each recorded digest is taken in that
/// pass, so checking an image with three of them costs no more reading
/// than checking it with one.
fn check(kind: &'static str, path: &Path, recorded: &Recorded<'_>) -> Vec<Checked> {
    let want: Vec<(&'static str, &String)> = [
        ("sha256", recorded.sha256),
        ("sha1", recorded.sha1),
        ("md5", recorded.md5),
    ]
    .into_iter()
    .filter_map(|(name, v)| v.map(|v| (name, v)))
    .collect();
    if want.is_empty() {
        return vec![Checked {
            kind,
            algorithm: "sha256",
            path: path.to_path_buf(),
            status: Status::Unhashed,
            recorded: None,
            found: None,
            detail: Some("no hash was recorded when it was read".into()),
        }];
    }
    let extra = Extra {
        sha1: recorded.sha1.is_some(),
        md5: recorded.md5.is_some(),
    };
    let got = match digests_of(path, extra) {
        Err(e) => {
            return want
                .into_iter()
                .map(|(algorithm, w)| Checked {
                    kind,
                    algorithm,
                    path: path.to_path_buf(),
                    status: Status::Missing,
                    recorded: Some(w.clone()),
                    found: None,
                    detail: Some(e.to_string()),
                })
                .collect()
        }
        Ok(got) => got,
    };
    let computed = got.named();
    want.into_iter()
        .map(|(algorithm, w)| {
            let found = computed
                .iter()
                .find(|(name, _)| *name == algorithm)
                .map(|(_, hex)| (*hex).to_string());
            Checked {
                kind,
                algorithm,
                path: path.to_path_buf(),
                status: if found.as_ref() == Some(w) {
                    Status::Pass
                } else {
                    Status::Fail
                },
                recorded: Some(w.clone()),
                found,
                detail: None,
            }
        })
        .collect()
}

/// Run `verify`.
pub fn run(g: &Global, opts: &Options) -> u8 {
    let text = match std::fs::read_to_string(&opts.report) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("zvolreport: {}: {e}", opts.report.display());
            return exit::EVIDENCE;
        }
    };
    // The signature is checked before anything else is read out of the
    // document, because it says whether this is the report that was
    // written at all; a hash table out of a file somebody edited proves
    // less than nothing. It covers the bytes, so it needs no parse.
    let signature = match (&opts.key, &opts.signature) {
        (None, None) => None,
        (None, Some(_)) => {
            eprintln!("zvolreport: --signature says where to look; --key says what to check with");
            return exit::USAGE;
        }
        (Some(keyfile), sig) => {
            let path = sig
                .clone()
                .unwrap_or_else(|| crate::sign::beside(&opts.report));
            let key = match crate::sign::read_public(keyfile) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("zvolreport: {e}");
                    return exit::USAGE;
                }
            };
            let (status, detail) = if !path.exists() {
                (
                    Status::Missing,
                    Some("no signature beside the report".into()),
                )
            } else {
                match crate::sign::check(&key, text.as_bytes(), &path) {
                    Ok(()) => (Status::Pass, None),
                    Err(e) => (Status::Fail, Some(e)),
                }
            };
            Some(Signed {
                key: keyfile.clone(),
                path,
                status,
                detail,
            })
        }
    };

    // Only now is the document read as a report. A tampered one often
    // stops being JSON at all, and "not a report" would be a confusing
    // way to say "somebody changed this": the signature is over the
    // bytes, so it can answer that first and does.
    let report: Report = match serde_json::from_str(&text) {
        Ok(r) => r,
        Err(e) => {
            if let Some(s) = &signature {
                if s.status != Status::Pass {
                    eprintln!(
                        "zvolreport: {}: signature {} — {}",
                        opts.report.display(),
                        s.status.as_str(),
                        s.detail.as_deref().unwrap_or("no detail")
                    );
                    return exit::PARTIAL;
                }
                eprintln!(
                    "zvolreport: {}: the signature matches, but the document is not a report",
                    opts.report.display()
                );
            }
            eprintln!("zvolreport: {}: not a report: {e}", opts.report.display());
            return exit::EVIDENCE;
        }
    };
    if report.report_version != REPORT_VERSION {
        eprintln!(
            "zvolreport: {}: report format version {}; this build reads version {REPORT_VERSION}",
            opts.report.display(),
            report.report_version
        );
        return exit::EVIDENCE;
    }

    let mut checked = Vec::new();
    for e in &report.evidence {
        let path = locate(&e.file.path, opts.evidence_root.as_ref());
        checked.extend(check(
            "evidence",
            &path,
            &Recorded {
                sha256: e.file.sha256.as_ref(),
                sha1: e.file.sha1.as_ref(),
                md5: e.file.md5.as_ref(),
            },
        ));
    }
    for o in &report.outputs {
        let path = locate(&o.path, opts.outputs_root.as_ref());
        checked.extend(check(
            "output",
            &path,
            &Recorded {
                sha256: o.sha256.as_ref(),
                sha1: o.sha1.as_ref(),
                md5: o.md5.as_ref(),
            },
        ));
    }

    let count = |s: Status| checked.iter().filter(|c| c.status == s).count();
    let out = VerifyOut {
        report: opts.report.clone(),
        passed: count(Status::Pass),
        failed: count(Status::Fail),
        missing: count(Status::Missing),
        unhashed: count(Status::Unhashed),
        signature,
        checked,
    };
    match g.format {
        Format::Json => println!(
            "{}",
            serde_json::to_string_pretty(&out).expect("serialisable")
        ),
        Format::Text => {
            println!("{:<9} {:<9} {:<7} FILE", "KIND", "RESULT", "DIGEST");
            if let Some(s) = &out.signature {
                println!(
                    "{:<9} {:<9} {:<7} {}",
                    "signature",
                    s.status.as_str(),
                    "ed25519",
                    s.path.display()
                );
                println!("{:<9} {:<9} {:<7}   key {}", "", "", "", s.key.display());
                if let Some(d) = &s.detail {
                    println!("{:<9} {:<9} {:<7}   {d}", "", "", "");
                }
            }
            for c in &out.checked {
                println!(
                    "{:<9} {:<9} {:<7} {}",
                    c.kind,
                    c.status.as_str(),
                    c.algorithm,
                    c.path.display()
                );
                if let Some(d) = &c.detail {
                    println!("{:<9} {:<9} {:<7}   {d}", "", "", "");
                }
                if c.status == Status::Fail {
                    println!(
                        "{:<9} {:<9} {:<7}   recorded {}",
                        "",
                        "",
                        "",
                        c.recorded.as_deref().unwrap_or("—")
                    );
                    println!(
                        "{:<9} {:<9} {:<7}   found    {}",
                        "",
                        "",
                        "",
                        c.found.as_deref().unwrap_or("—")
                    );
                }
            }
            println!(
                "{} passed, {} failed, {} missing, {} with nothing to check against",
                out.passed, out.failed, out.missing, out.unhashed
            );
        }
    }
    // A file that is gone is as much a break in the chain as one that
    // changed: neither can be shown to be what the report says.
    let signature_broken = out
        .signature
        .as_ref()
        .is_some_and(|s| s.status != Status::Pass);
    if out.failed > 0 || out.missing > 0 || signature_broken {
        exit::PARTIAL
    } else {
        0
    }
}

/// `check`: every digest a record carries is checked back, one row
/// each, and the four states are told apart (SPEC F-53, R-0x).
#[cfg(test)]
mod check_tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("zvolreport-verify-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn image(dir: &Path) -> PathBuf {
        let p = dir.join("vol.img");
        fs::write(&p, b"the bytes of a volume, such as they are").expect("write");
        p
    }

    fn all_three(p: &Path) -> (String, String, String) {
        let d = digests_of(
            p,
            Extra {
                md5: true,
                sha1: true,
            },
        )
        .expect("hash");
        (d.sha256, d.sha1.expect("sha1"), d.md5.expect("md5"))
    }

    fn algorithms(rows: &[Checked]) -> Vec<&'static str> {
        rows.iter().map(|c| c.algorithm).collect()
    }

    #[test]
    fn every_recorded_digest_is_checked_and_passes() {
        let dir = scratch("pass");
        let p = image(&dir);
        let (h256, h1, h5) = all_three(&p);
        let rows = check(
            "output",
            &p,
            &Recorded {
                sha256: Some(&h256),
                sha1: Some(&h1),
                md5: Some(&h5),
            },
        );
        assert_eq!(algorithms(&rows), vec!["sha256", "sha1", "md5"]);
        assert!(rows.iter().all(|c| c.status == Status::Pass), "{rows:?}");
        assert!(rows.iter().all(|c| c.found == c.recorded));
    }

    #[test]
    fn one_changed_byte_fails_every_recorded_digest() {
        let dir = scratch("fail");
        let p = image(&dir);
        let (h256, h1, h5) = all_three(&p);
        let mut bytes = fs::read(&p).expect("read");
        bytes[3] ^= 0x01;
        fs::write(&p, bytes).expect("tamper");
        let rows = check(
            "output",
            &p,
            &Recorded {
                sha256: Some(&h256),
                sha1: Some(&h1),
                md5: Some(&h5),
            },
        );
        assert_eq!(rows.len(), 3);
        for c in &rows {
            assert!(c.status == Status::Fail, "{c:?}");
            assert!(c.found.is_some() && c.found != c.recorded, "{c:?}");
        }
    }

    #[test]
    fn a_file_that_is_gone_is_missing_for_every_digest() {
        let dir = scratch("missing");
        let p = image(&dir);
        let (h256, h1, h5) = all_three(&p);
        fs::remove_file(&p).expect("remove");
        let rows = check(
            "output",
            &p,
            &Recorded {
                sha256: Some(&h256),
                sha1: Some(&h1),
                md5: Some(&h5),
            },
        );
        assert_eq!(rows.len(), 3);
        assert!(rows
            .iter()
            .all(|c| c.status == Status::Missing && c.found.is_none()));
        assert!(rows.iter().all(|c| c.detail.is_some()));
    }

    #[test]
    fn nothing_recorded_is_one_row_with_nothing_to_check_against() {
        let dir = scratch("unhashed");
        let p = image(&dir);
        let rows = check(
            "evidence",
            &p,
            &Recorded {
                sha256: None,
                sha1: None,
                md5: None,
            },
        );
        assert_eq!(rows.len(), 1);
        assert!(rows[0].status == Status::Unhashed);
        assert!(rows[0].recorded.is_none() && rows[0].found.is_none());
    }

    /// Only what was recorded is checked: a record with SHA-256 and MD5
    /// gets two rows, and SHA-1 is neither computed nor mentioned.
    #[test]
    fn only_the_digests_recorded_are_checked() {
        let dir = scratch("subset");
        let p = image(&dir);
        let (h256, _, h5) = all_three(&p);
        let rows = check(
            "output",
            &p,
            &Recorded {
                sha256: Some(&h256),
                sha1: None,
                md5: Some(&h5),
            },
        );
        assert_eq!(algorithms(&rows), vec!["sha256", "md5"]);
        assert!(rows.iter().all(|c| c.status == Status::Pass));
    }
}
