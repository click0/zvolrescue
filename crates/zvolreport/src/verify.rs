//! `zvolreport verify` — is every file still the file the report says?
//!
//! Recompute the SHA-256 of everything the report recorded a hash for:
//! the outputs, which are always hashed, and the evidence, which is
//! hashed only when someone asked for it. Anything that no longer
//! matches is a FAIL and the run exits 4 (R-04).

use std::path::{Path, PathBuf};

use serde::Serialize;
use zvol_common::evidence::{digests_of_prefix, Extra};
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
/// Every file a report names, where `verify` will look for it: the logs
/// it was built from — where they were recorded and beside the report,
/// where verify looks when they are not — the evidence, the outputs, and
/// the signature. They are read and hashed, so a log may not be written
/// over one; read before the logs are opened. A report that cannot be
/// read names nothing but its signature, and the run says why later.
pub fn named_files(
    report: &Path,
    evidence_root: Option<&PathBuf>,
    outputs_root: Option<&PathBuf>,
    signature: Option<&PathBuf>,
) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = vec![signature
        .cloned()
        .unwrap_or_else(|| crate::sign::beside(report))];
    let Some(r) = std::fs::read_to_string(report)
        .ok()
        .and_then(|t| serde_json::from_str::<Report>(&t).ok())
    else {
        return v;
    };
    for l in &r.logs {
        v.push(l.path.clone());
        if let (Some(dir), Some(name)) = (report.parent(), l.path.file_name()) {
            v.push(dir.join(name));
        }
    }
    v.extend(
        r.evidence
            .iter()
            .map(|e| locate(&e.file.path, evidence_root)),
    );
    v.extend(r.outputs.iter().map(|o| locate(&o.path, outputs_root)));
    v
}

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
    /// Its size, where the report has one: all there is to check when
    /// no hash was taken.
    size: Option<u64>,
    /// Hash only this many bytes from the start: an image written to a
    /// device is the device's first bytes, not the whole device.
    prefix: Option<u64>,
    /// What it was: a file, or a device.
    kind: Option<zvol_common::evidence::Kind>,
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
        // No hash to check against is not nothing to check: a file that
        // is gone is missing, and one whose size changed has changed. A
        // deleted member and one truncated to nothing both passed.
        let row =
            |status, algorithm, recorded: Option<String>, found: Option<String>, detail: String| {
                vec![Checked {
                    kind,
                    algorithm,
                    path: path.to_path_buf(),
                    status,
                    recorded,
                    found,
                    detail: Some(detail),
                }]
            };
        use zvol_common::evidence::Kind;
        let now = Kind::of(path);
        return match std::fs::metadata(path) {
            Err(e) => row(
                Status::Missing,
                "-",
                None,
                None,
                format!("{e}; no hash was recorded when it was read"),
            ),
            // What it is now against what it was: a directory or a fifo
            // where an image was had "the size recorded" by default and
            // passed.
            Ok(_) if recorded.kind.is_some_and(|k| k != Kind::Other && k != now) => row(
                Status::Fail,
                "kind",
                recorded.kind.map(|k| format!("{k:?}").to_lowercase()),
                Some(format!("{now:?}").to_lowercase()),
                format!(
                    "no hash was recorded when it was read, and it is not what it was: {}",
                    if now == Kind::Other { "neither a file nor a device now" } else { "a different kind of file now" }
                ),
            ),
            Ok(_) if now == Kind::Device
                && recorded
                    .size
                    .is_some_and(|s| s != zvol_common::evidence::FileRef::stat(path).size) =>
            {
                row(
                    Status::Fail,
                    "size",
                    recorded.size.map(|s| s.to_string()),
                    Some(zvol_common::evidence::FileRef::stat(path).size.to_string()),
                    "no hash was recorded when it was read, and the device is not the size recorded"
                        .into(),
                )
            }
            Ok(m) if m.is_file() && recorded.size.is_some_and(|s| s != m.len()) => row(
                Status::Fail,
                "size",
                recorded.size.map(|s| s.to_string()),
                Some(m.len().to_string()),
                "no hash was recorded when it was read, and the size is not the one recorded"
                    .into(),
            ),
            Ok(_) => row(
                Status::Unhashed,
                "sha256",
                None,
                None,
                "present, at the size recorded; no hash was recorded when it was read".into(),
            ),
        };
    }
    let extra = Extra {
        sha1: recorded.sha1.is_some(),
        md5: recorded.md5.is_some(),
    };
    let got = match digests_of_prefix(path, extra, recorded.prefix) {
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

/// Build the report again from its logs, as `build` would (R-03), and
/// compare all of it — every section, and nothing besides them: the
/// logs, tools, hosts, evidence, commands, pools, outputs, extractions
/// and warnings. Five of them were compared, and a report whose pools,
/// tools or warnings were edited, or that carried a section of its own,
/// was a `report PASS`. A report built by another version of zvolreport
/// can differ too, and the detail says so.
fn against_logs(at: &Path, report: &Report, logs: &[(&crate::model::LogRef, PathBuf)]) -> Checked {
    let mut read = Vec::new();
    for (recorded, path) in logs {
        let limit = (recorded.bytes > 0).then_some(recorded.bytes);
        match crate::build::read_log_prefix(path, limit) {
            Ok(r) => read.push((
                crate::model::LogRef {
                    path: recorded.path.clone(),
                    records: r.records.len(),
                    sha256: recorded.sha256.clone(),
                    bytes: recorded.bytes,
                    left_out: r.left_out.iter().map(|(n, _)| *n).collect(),
                },
                r.records,
            )),
            Err(e) => {
                return Checked {
                    kind: "report",
                    algorithm: "logs",
                    path: at.to_path_buf(),
                    status: Status::Fail,
                    recorded: None,
                    found: None,
                    detail: Some(format!("a log it was built from cannot be read: {e}")),
                }
            }
        }
    }
    let opts = crate::build::Options {
        logs: Vec::new(),
        output: PathBuf::new(),
        md: None,
        case: report.case.clone(),
        examiner: report.examiner.clone(),
        notes: report.notes.clone(),
        sign: None,
        signature: None,
    };
    let again = crate::build::assemble(&read, &opts);
    let built = serde_json::to_value(&again).expect("serialisable");
    // The report as it is in the file, not as this build reads it: a
    // field this build does not know is still in the file.
    let said = std::fs::read(at)
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .unwrap_or_else(|| serde_json::to_value(report).expect("serialisable"));
    let empty = serde_json::Map::new();
    let sections: std::collections::BTreeSet<&String> = said
        .as_object()
        .unwrap_or(&empty)
        .keys()
        .chain(built.as_object().unwrap_or(&empty).keys())
        .collect();
    let differs = sections
        .into_iter()
        .map(String::as_str)
        .find_map(|section| {
            let (a, b) = (&said[section], &built[section]);
            if a == b {
                return None;
            }
            if !a.is_array() && !b.is_array() {
                let show = |v: &serde_json::Value| {
                    if v.is_null() {
                        "nothing".to_string()
                    } else {
                        v.to_string().chars().take(160).collect()
                    }
                };
                return Some(format!(
                    "{section}: the report says {}, its logs say {}",
                    show(a),
                    show(b)
                ));
            }
            let (xs, ys) = (a.as_array(), b.as_array());
            let (xs, ys) = (
                xs.map(Vec::as_slice).unwrap_or(&[]),
                ys.map(Vec::as_slice).unwrap_or(&[]),
            );
            let i = (0..xs.len().max(ys.len()))
                .find(|&i| xs.get(i) != ys.get(i))
                .unwrap_or(0);
            let show = |v: Option<&serde_json::Value>| {
                let t = v.map_or_else(|| "nothing".to_string(), serde_json::Value::to_string);
                if t.chars().count() > 160 {
                    format!("{}…", t.chars().take(160).collect::<String>())
                } else {
                    t
                }
            };
            Some(format!(
                "{section}[{i}]: the report says {}, its logs say {}",
                show(xs.get(i)),
                show(ys.get(i))
            ))
        });
    Checked {
        kind: "report",
        algorithm: "logs",
        path: at.to_path_buf(),
        status: if differs.is_some() {
            Status::Fail
        } else {
            Status::Pass
        },
        recorded: None,
        found: None,
        detail: differs.map(|d| {
            format!("{d} (edited since it was built, or built by another version of zvolreport)")
        }),
    }
}

/// Run `verify`.
pub fn run(g: &Global, opts: &Options) -> u8 {
    // Bytes, not text: a report with one byte that is not UTF-8 was
    // refused as unreadable (exit 2) before the signature over those
    // very bytes could say it had been changed (exit 4).
    let bytes = match std::fs::read(&opts.report) {
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
                match crate::sign::check(&key, &bytes, &path) {
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
    let parsed = std::str::from_utf8(&bytes)
        .map_err(|e| format!("not text: {e}"))
        .and_then(|t| serde_json::from_str::<Report>(t).map_err(|e| e.to_string()));
    let report: Report = match parsed {
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
    // Unsigned, a report is checked against its logs and nothing else: a
    // signature lying beside it and not asked about is said to be there.
    if signature.is_none() {
        let sig = crate::sign::beside(&opts.report);
        if sig.exists() {
            checked.push(Checked {
                kind: "signature",
                algorithm: "ed25519",
                path: sig,
                status: Status::Unhashed,
                recorded: None,
                found: None,
                detail: Some("not checked: give --key with the public key to check it".into()),
            });
        }
    }
    // The logs the report was built from carry its chain (R-01): one
    // deleted or edited since is a break in it. A log not where it was
    // recorded is looked for beside the report.
    let mut found_logs = Vec::new();
    for l in &report.logs {
        let path = if l.path.exists() {
            l.path.clone()
        } else {
            match (opts.report.parent(), l.path.file_name()) {
                (Some(dir), Some(name)) if dir.join(name).exists() => dir.join(name),
                _ => l.path.clone(),
            }
        };
        // The log as it was when the report was built: what was
        // appended since is other runs', and is said, not counted
        // against the report.
        let mut rows = check(
            "log",
            &path,
            &Recorded {
                sha256: Some(&l.sha256),
                sha1: None,
                md5: None,
                size: None,
                prefix: (l.bytes > 0).then_some(l.bytes),
                kind: None,
            },
        );
        let now = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        for r in rows.iter_mut().filter(|r| r.status == Status::Pass) {
            if l.bytes > 0 && now > l.bytes {
                r.detail = Some(format!(
                    "{} byte(s) appended since the report was built; they are not in it",
                    now - l.bytes
                ));
            }
        }
        if l.bytes > 0 && now < l.bytes {
            for r in &mut rows {
                r.status = Status::Fail;
                r.detail = Some(format!(
                    "{now} byte(s), shorter than the {} the report was built from",
                    l.bytes
                ));
            }
        }
        if rows.iter().all(|c| c.status == Status::Pass) {
            found_logs.push((l, path.clone()));
        }
        checked.extend(rows);
    }
    // And the report is checked against the logs: a log that hashes to
    // what the report recorded proves nothing about the rest of the
    // report unless the rest is what that log says. An unsigned report
    // with an image's hash edited to match a changed image passed, its
    // log untouched and still holding the old hash.
    if found_logs.len() == report.logs.len() {
        checked.push(against_logs(&opts.report, &report, &found_logs));
    } else {
        checked.push(Checked {
            kind: "report",
            algorithm: "logs",
            path: opts.report.clone(),
            status: Status::Unhashed,
            recorded: None,
            found: None,
            detail: Some(
                "not checked against its logs: a log it was built from is missing or changed"
                    .into(),
            ),
        });
    }
    for e in &report.evidence {
        let path = locate(&e.file.path, opts.evidence_root.as_ref());
        checked.extend(check(
            "evidence",
            &path,
            &Recorded {
                sha256: e.file.sha256.as_ref(),
                sha1: e.file.sha1.as_ref(),
                md5: e.file.md5.as_ref(),
                size: Some(e.file.size),
                prefix: None,
                kind: e.file.kind,
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
                size: Some(o.size),
                prefix: o
                    .kind
                    .is_some_and(zvol_common::evidence::Kind::is_device)
                    .then_some(o.size),
                kind: o.kind,
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
                // Only where there is something to show: a report that
                // no longer matches its logs has no one value of each,
                // and printed "recorded —" and "found —" under its reason.
                if c.status == Status::Fail && (c.recorded.is_some() || c.found.is_some()) {
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
    let code = if out.failed > 0 || out.missing > 0 || signature_broken {
        exit::PARTIAL
    } else {
        0
    };
    // What was read to say so: the report, the key and signature, and
    // every file checked (`--evidence-log`, `--hash-inputs`).
    let mut read: Vec<PathBuf> = vec![opts.report.clone()];
    read.extend(opts.key.iter().cloned());
    read.extend(out.signature.iter().map(|s| s.path.clone()));
    for c in &out.checked {
        if !read.contains(&c.path) {
            read.push(c.path.clone());
        }
    }
    let json = serde_json::to_value(&out).expect("serialisable");
    g.log_evidence("zvolreport", &json, code, &read, Vec::new())
}

/// `check`: every digest a record carries is checked back, one row
/// each, and the four states are told apart (SPEC F-53, R-0x).
#[cfg(test)]
mod check_tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use zvol_common::evidence::digests_of;

    fn scratch(name: &str) -> zvol_common::scratch::Scratch {
        zvol_common::scratch::Scratch::new("zvolreport-verify", name)
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
                size: None,
                prefix: None,
                kind: None,
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
                size: None,
                prefix: None,
                kind: None,
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
                size: None,
                prefix: None,
                kind: None,
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
                size: Some(fs::metadata(&p).unwrap().len()),
                prefix: None,
                kind: None,
            },
        );
        assert_eq!(rows.len(), 1);
        assert!(rows[0].status == Status::Unhashed);
        assert!(rows[0].recorded.is_none() && rows[0].found.is_none());
    }

    /// With no hash recorded there is still something to check: whether
    /// the file is there, and whether it is the size it was. A member
    /// deleted, and one truncated to nothing, both used to pass.
    #[test]
    fn with_nothing_hashed_a_file_gone_or_resized_is_still_seen() {
        let dir = scratch("unhashed-gone");
        let p = image(&dir);
        let size = fs::metadata(&p).unwrap().len();
        let none = |size| Recorded {
            sha256: None,
            sha1: None,
            md5: None,
            size,
            prefix: None,
            kind: None,
        };
        fs::write(&p, b"").unwrap();
        let rows = check("evidence", &p, &none(Some(size)));
        assert!(rows[0].status == Status::Fail, "{rows:?}");
        assert_eq!(rows[0].algorithm, "size");
        fs::remove_file(&p).unwrap();
        let rows = check("evidence", &p, &none(Some(size)));
        assert!(rows[0].status == Status::Missing, "{rows:?}");
    }

    /// An image on a device is the device's first bytes: only that many
    /// are hashed, and what lies past them on the device is no change.
    #[test]
    fn an_image_on_a_device_is_checked_over_its_own_bytes() {
        let dir = scratch("prefix");
        let p = dir.join("dev.raw");
        let mut bytes = b"the bytes of a volume, such as they are".to_vec();
        let image = bytes.len() as u64;
        fs::write(dir.join("img"), &bytes).unwrap();
        let (h256, _, _) = all_three(&dir.join("img"));
        bytes.extend_from_slice(&[0xaa; 4096]);
        fs::write(&p, &bytes).unwrap();
        let recorded = |prefix| Recorded {
            sha256: Some(&h256),
            sha1: None,
            md5: None,
            size: Some(image),
            prefix,
            kind: None,
        };
        let rows = check("output", &p, &recorded(Some(image)));
        assert!(rows[0].status == Status::Pass, "{rows:?}");
        let rows = check("output", &p, &recorded(None));
        assert!(rows[0].status == Status::Fail, "{rows:?}");
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
                size: None,
                prefix: None,
                kind: None,
            },
        );
        assert_eq!(algorithms(&rows), vec!["sha256", "md5"]);
        assert!(rows.iter().all(|c| c.status == Status::Pass));
    }
}
