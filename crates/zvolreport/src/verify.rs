//! `zvolreport verify` — is every file still the file the report says?
//!
//! Recompute the SHA-256 of everything the report recorded a hash for:
//! the outputs, which are always hashed, and the evidence, which is
//! hashed only when someone asked for it. Anything that no longer
//! matches is a FAIL and the run exits 4 (R-04).

use std::path::{Path, PathBuf};

use serde::Serialize;
use zvol_common::evidence::sha256_of;
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

fn check(kind: &'static str, path: &Path, recorded: Option<&String>) -> Checked {
    let Some(want) = recorded else {
        return Checked {
            kind,
            path: path.to_path_buf(),
            status: Status::Unhashed,
            recorded: None,
            found: None,
            detail: Some("no hash was recorded when it was read".into()),
        };
    };
    match sha256_of(path) {
        Err(e) => Checked {
            kind,
            path: path.to_path_buf(),
            status: Status::Missing,
            recorded: Some(want.clone()),
            found: None,
            detail: Some(e.to_string()),
        },
        Ok(got) => Checked {
            kind,
            path: path.to_path_buf(),
            status: if &got == want {
                Status::Pass
            } else {
                Status::Fail
            },
            recorded: Some(want.clone()),
            found: Some(got),
            detail: None,
        },
    }
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
        checked.push(check("evidence", &path, e.file.sha256.as_ref()));
    }
    for o in &report.outputs {
        let path = locate(&o.path, opts.outputs_root.as_ref());
        checked.push(check("output", &path, o.sha256.as_ref()));
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
            println!("{:<9} {:<9} FILE", "KIND", "RESULT");
            if let Some(s) = &out.signature {
                println!(
                    "{:<9} {:<9} {}",
                    "signature",
                    s.status.as_str(),
                    s.path.display()
                );
                println!("{:<9} {:<9}   key {}", "", "", s.key.display());
                if let Some(d) = &s.detail {
                    println!("{:<9} {:<9}   {d}", "", "");
                }
            }
            for c in &out.checked {
                println!(
                    "{:<9} {:<9} {}",
                    c.kind,
                    c.status.as_str(),
                    c.path.display()
                );
                if let Some(d) = &c.detail {
                    println!("{:<9} {:<9}   {d}", "", "");
                }
                if c.status == Status::Fail {
                    println!(
                        "{:<9} {:<9}   recorded {}",
                        "",
                        "",
                        c.recorded.as_deref().unwrap_or("—")
                    );
                    println!(
                        "{:<9} {:<9}   found    {}",
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
