//! `zvolreport build` — evidence logs into one report (R-01…R-03, R-06).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use zvol_common::evidence::{self, Record, FORMAT_VERSION};
use zvol_common::{exit, Format, Global};

use crate::model::REPORT_VERSION;
use crate::model::{Command, Evidence, Extraction, FileRef, LogRef, Pool, Report, ToolRef};

/// Options of a `build` run.
pub struct Options {
    pub logs: Vec<PathBuf>,
    pub output: PathBuf,
    pub md: Option<PathBuf>,
    pub case: Option<String>,
    pub examiner: Option<String>,
    pub notes: Vec<String>,
    pub sign: Option<PathBuf>,
    pub signature: Option<PathBuf>,
}

/// One evidence log, as `build` and `verify` read it.
pub(crate) struct ReadLog {
    pub records: Vec<Record>,
    /// Lines that are not records, by number, with what is wrong with
    /// each.
    pub left_out: Vec<(usize, String)>,
    /// SHA-256 of the very bytes the records were read from.
    pub sha256: String,
}

/// Read one evidence log.
///
/// A record whose format version is not the one this build understands
/// is refused by name and line, not skipped: a report that quietly left
/// out what it could not read would be worse than no report (R-01).
///
/// A line that is not JSON at all is what a run killed while it wrote
/// leaves behind, and refusing the whole log for it lost every record
/// around it. Such a line is left out by number, and the report says so
/// (exit 4); a file of which no line is a record is not an evidence log.
///
/// The hash is of the bytes read, once: hashed by a second read, a
/// record appended in between was covered by the hash but missing from
/// the report, and `verify` passed the log.
pub(crate) fn read_log(path: &Path) -> Result<ReadLog, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let sha256 = evidence::sha256_hex(&bytes);
    let mut records = Vec::new();
    let mut left_out = Vec::new();
    for (i, raw) in bytes.split(|&b| b == b'\n').enumerate() {
        let n = i + 1;
        let Ok(line) = std::str::from_utf8(raw) else {
            left_out.push((n, "not text: cut short inside a character".to_string()));
            continue;
        };
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                left_out.push((n, format!("not a JSON object: {e}")));
                continue;
            }
        };
        match value.get("v").and_then(serde_json::Value::as_u64) {
            Some(v) if v == u64::from(FORMAT_VERSION) => {}
            Some(v) => {
                return Err(format!(
                    "{}:{n}: evidence record format version {v}; this build reads version {FORMAT_VERSION}",
                    path.display()
                ))
            }
            None => {
                return Err(format!(
                    "{}:{n}: no record format version; not an evidence log",
                    path.display()
                ))
            }
        }
        records.push(
            serde_json::from_value(value).map_err(|e| format!("{}:{n}: {e}", path.display()))?,
        );
    }
    if records.is_empty() {
        if let Some((n, why)) = left_out.first() {
            return Err(format!(
                "{}:{n}: {why}; no line of it is an evidence record",
                path.display()
            ));
        }
    }
    Ok(ReadLog {
        records,
        left_out,
        sha256,
    })
}

/// Read a `u64` out of a tool's own JSON document without trusting it to
/// be there: `result` is whatever that tool printed, and an older or
/// newer one may not have printed this.
fn u64_at(v: &serde_json::Value, key: &str) -> Option<u64> {
    v.get(key).and_then(serde_json::Value::as_u64)
}

fn str_at(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

/// The pools a `scan` record described.
fn pools_of(result: &serde_json::Value) -> Vec<Pool> {
    let Some(list) = result.get("pools").and_then(serde_json::Value::as_array) else {
        return Vec::new();
    };
    // The TXG window is the span of what the members verified, which the
    // devices report and the pool does not.
    let window = result
        .get("devices")
        .and_then(serde_json::Value::as_array)
        .map(|devs| {
            let oldest = devs.iter().filter_map(|d| u64_at(d, "oldest_txg")).min();
            let newest = devs.iter().filter_map(|d| u64_at(d, "newest_txg")).max();
            (oldest, newest)
        })
        .unwrap_or((None, None));
    list.iter()
        .filter_map(|p| {
            Some(Pool {
                name: str_at(p, "name")?,
                guid: str_at(p, "guid").unwrap_or_default(),
                state: str_at(p, "state"),
                txg_window: match window {
                    (Some(a), Some(b)) => Some([a, b]),
                    _ => None,
                },
                readable: p
                    .get("readable")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
            })
        })
        .collect()
}

/// The extractions a `dump` record described.
fn extractions_of(result: &serde_json::Value) -> Vec<Extraction> {
    let Some(list) = result.get("volumes").and_then(serde_json::Value::as_array) else {
        return Vec::new();
    };
    list.iter()
        .filter_map(|v| {
            Some(Extraction {
                dataset: str_at(v, "dataset")?,
                txg: u64_at(v, "txg").unwrap_or(0),
                output: PathBuf::from(str_at(v, "output")?),
                size: u64_at(v, "volsize").unwrap_or(0),
                sha256: str_at(v, "sha256"),
                sha1: str_at(v, "sha1"),
                md5: str_at(v, "md5"),
                // A salvaged block kept what its member would give and
                // zeroed the rest: not read whole either.
                errors: u64_at(v, "blocks_zeroed")
                    .unwrap_or(0)
                    .saturating_add(u64_at(v, "blocks_salvaged").unwrap_or(0)),
                aborted: v
                    .get("aborted")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
                interrupted_at: u64_at(v, "interrupted_at"),
                stopped_by_medium: str_at(v, "stopped_by_medium"),
            })
        })
        .collect()
}

/// Build the report. Pure: everything in it comes from the records.
pub fn assemble(records: &[(LogRef, Vec<Record>)], opts: &Options) -> Report {
    let mut evidence_by_path: BTreeMap<PathBuf, Evidence> = BTreeMap::new();
    let mut tools: Vec<ToolRef> = Vec::new();
    let mut hosts: Vec<String> = Vec::new();
    let mut commands: Vec<Command> = Vec::new();
    let mut pools: Vec<Pool> = Vec::new();
    let mut extractions: Vec<Extraction> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    // A file written more than once (a `--resume`d dump) keeps the last
    // hash: that is what is on disk now.
    let mut outputs: BTreeMap<PathBuf, FileRef> = BTreeMap::new();
    for (log, _) in records {
        for n in &log.left_out {
            warnings.push(format!(
                "{}:{n} is not a record (a run that ended while it wrote leaves part of a line) and is left out",
                log.path.display()
            ));
        }
    }

    // Chronological, and deterministic when two records share a second:
    // a log is appended to, so its own order is the order things ran,
    // and that is what breaks the tie (R-02, R-03).
    let mut flat: Vec<(u64, usize, usize, &Record)> = records
        .iter()
        .enumerate()
        .flat_map(|(log, (_, rs))| {
            rs.iter()
                .enumerate()
                .map(move |(line, r)| (r.ts, log, line, r))
        })
        .collect();
    flat.sort_by_key(|(ts, log, line, _)| (*ts, *log, *line));

    for (_, _, _, r) in flat {
        let tool = ToolRef {
            tool: r.tool.clone(),
            version: r.version.clone(),
        };
        if !tools.contains(&tool) {
            tools.push(tool);
        }
        if let Some(h) = &r.host {
            if !hosts.contains(h) {
                hosts.push(h.clone());
            }
        }
        commands.push(Command {
            ts: r.ts,
            tool: r.tool.clone(),
            version: r.version.clone(),
            host: r.host.clone(),
            argv: r.argv.clone(),
            status: r.status,
        });
        for i in &r.inputs {
            let e = evidence_by_path
                .entry(i.path.clone())
                .or_insert_with(|| Evidence {
                    file: FileRef {
                        path: i.path.clone(),
                        kind: i.kind,
                        size: i.size,
                        sha256: i.sha256.clone(),
                        // Inputs are evidence, never written here, so
                        // nothing takes a legacy digest of one.
                        sha1: None,
                        md5: None,
                    },
                    read_by: Vec::new(),
                });
            // A hash recorded once is kept; a second run without
            // `--hash-inputs` must not erase it.
            if e.file.sha256.is_none() {
                e.file.sha256 = i.sha256.clone();
            } else if let (Some(a), Some(b)) = (&e.file.sha256, &i.sha256) {
                if a != b {
                    warnings.push(format!(
                        "{}: hashed differently by two runs ({a} then {b}): the evidence changed between them",
                        i.path.display()
                    ));
                }
            }
            if e.file.size != i.size {
                warnings.push(format!(
                    "{}: {} bytes in one record and {} in another",
                    i.path.display(),
                    e.file.size,
                    i.size
                ));
            }
            if !e.read_by.contains(&r.tool) {
                e.read_by.push(r.tool.clone());
            }
            // F-68: worth saying in the report, because a reader
            // deciding what this document is worth cares whether the
            // work was done against copies or against the disks.
            if i.kind.is_some_and(zvol_common::evidence::Kind::is_device) {
                let note = format!(
                    "{}: read as a device, not as an image: this recovery was done against the evidence itself",
                    i.path.display()
                );
                if !warnings.contains(&note) {
                    warnings.push(note);
                }
            }
        }
        for o in &r.outputs {
            outputs.insert(
                o.path.clone(),
                FileRef {
                    path: o.path.clone(),
                    kind: o.kind,
                    size: o.size,
                    sha256: o.sha256.clone(),
                    sha1: o.sha1.clone(),
                    md5: o.md5.clone(),
                },
            );
        }
        for p in pools_of(&r.result) {
            if !pools.iter().any(|q| q.guid == p.guid && q.name == p.name) {
                pools.push(p);
            }
        }
        extractions.extend(extractions_of(&r.result));
        if r.status != 0 {
            warnings.push(format!(
                "{} exited {} : {}",
                r.tool,
                r.status,
                r.argv.join(" ")
            ));
        }
    }

    // R-06: what a reader should not have to notice for themselves.
    for e in &extractions {
        if e.aborted {
            warnings.push(format!(
                "{}: the extraction stopped early; {} is not the whole volume",
                e.dataset,
                e.output.display()
            ));
        }
        if let Some(at) = e.interrupted_at {
            warnings.push(format!(
                "{}: the extraction was interrupted at block {at}; {} is not the whole volume (--resume continues it)",
                e.dataset,
                e.output.display()
            ));
        }
        if let Some(why) = &e.stopped_by_medium {
            warnings.push(format!(
                "{}: a device refused a read and the extraction stopped ({why}); {} is not the whole volume",
                e.dataset,
                e.output.display()
            ));
        }
        if e.errors > 0 {
            warnings.push(format!(
                "{}: {} block(s) could not be read whole and were written as zeros, in whole or in part",
                e.dataset, e.errors
            ));
        }
        if e.sha256.is_none() {
            warnings.push(format!(
                "{}: no hash was recorded for {}",
                e.dataset,
                e.output.display()
            ));
        }
        if let Some(w) = pools.iter().find_map(|p| p.txg_window) {
            if e.txg < w[0] || e.txg > w[1] {
                warnings.push(format!(
                    "{}: extracted at txg {} , outside the window {}–{} the scan recorded",
                    e.dataset, e.txg, w[0], w[1]
                ));
            }
        }
    }
    let versions: Vec<&ToolRef> = tools.iter().collect();
    for t in &versions {
        if let Some(other) = versions
            .iter()
            .find(|o| o.tool == t.tool && o.version != t.version)
        {
            let w = format!(
                "{} appears as {} and {}: the report mixes runs of different builds",
                t.tool, t.version, other.version
            );
            if !warnings.contains(&w) {
                warnings.push(w);
            }
        }
    }
    warnings.sort();
    warnings.dedup();

    Report {
        report_version: REPORT_VERSION,
        case: opts.case.clone(),
        examiner: opts.examiner.clone(),
        notes: opts.notes.clone(),
        logs: records.iter().map(|(l, _)| l.clone()).collect(),
        tools,
        hosts,
        evidence: evidence_by_path.into_values().collect(),
        commands,
        pools,
        outputs: outputs.into_values().collect(),
        extractions,
        warnings,
    }
}

/// Run `build`.
pub fn run(g: &Global, opts: &Options) -> u8 {
    // Nothing a build writes may be a log it reads or the key it signs
    // with — `build case.jsonl -o case.jsonl` replaced the evidence log
    // with the report about it — nor another file it writes.
    let signature = opts.sign.as_ref().map(|_| {
        opts.signature
            .clone()
            .unwrap_or_else(|| crate::sign::beside(&opts.output))
    });
    let mut reads = opts.logs.clone();
    reads.extend(opts.sign.iter().cloned());
    let writes: Vec<(&str, &std::path::Path)> = [
        ("-o", Some(opts.output.as_path())),
        ("--md", opts.md.as_deref()),
        ("--signature", signature.as_deref()),
    ]
    .into_iter()
    .filter_map(|(flag, p)| p.map(|p| (flag, p)))
    .collect();
    let guard = zvol_common::WriteGuard::new(g, &reads);
    for (i, (flag, path)) in writes.iter().enumerate() {
        if let Err(code) = guard.refuse("zvolreport", flag, path) {
            return code;
        }
        if let Some((other, _)) = writes[..i]
            .iter()
            .find(|(_, o)| zvol_common::same_file(path, o))
        {
            eprintln!(
                "zvolreport: {flag} {} is also where {other} goes",
                path.display()
            );
            return exit::USAGE;
        }
    }
    let mut logs = Vec::new();
    for path in &opts.logs {
        let read = match read_log(path) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("zvolreport: {e}");
                return exit::EVIDENCE;
            }
        };
        for (n, why) in &read.left_out {
            eprintln!(
                "zvolreport: {}:{n}: {why}; left out of the report",
                path.display()
            );
        }
        logs.push((
            LogRef {
                path: path.clone(),
                records: read.records.len(),
                sha256: read.sha256,
                left_out: read.left_out.iter().map(|(n, _)| *n).collect(),
            },
            read.records,
        ));
    }
    let status = if logs.iter().any(|(l, _)| !l.left_out.is_empty()) {
        exit::PARTIAL
    } else {
        0
    };
    let report = assemble(&logs, opts);

    let json = serde_json::to_string_pretty(&report).expect("serialisable") + "\n";
    if let Err(e) = std::fs::write(&opts.output, &json) {
        eprintln!("zvolreport: {}: {e}", opts.output.display());
        return exit::USAGE;
    }
    if let Some(md) = &opts.md {
        if let Err(e) = std::fs::write(md, crate::markdown::render(&report)) {
            eprintln!("zvolreport: {}: {e}", md.display());
            return exit::USAGE;
        }
    }
    // The signature covers `report.json` and nothing else. The Markdown
    // is a rendering of it, not a second document to be trusted on its
    // own, and R-03 is what lets a doubter re-render it themselves.
    let mut signed = None;
    if let Some(keyfile) = &opts.sign {
        let key = match crate::sign::read_private(keyfile) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("zvolreport: {e}");
                return exit::USAGE;
            }
        };
        let to = opts
            .signature
            .clone()
            .unwrap_or_else(|| crate::sign::beside(&opts.output));
        if let Err(e) = crate::sign::write_signature(&key, json.as_bytes(), &to) {
            eprintln!("zvolreport: {e}");
            return exit::USAGE;
        }
        signed = Some(to);
    } else if opts.signature.is_some() {
        eprintln!("zvolreport: --signature says where to write one; --sign says what with");
        return exit::USAGE;
    }
    match g.format {
        Format::Json => print!("{json}"),
        Format::Text => {
            println!(
                "{} record(s) from {} log(s): {} command(s), {} piece(s) of evidence, {} extraction(s)",
                report.commands.len(),
                report.logs.len(),
                report.commands.len(),
                report.evidence.len(),
                report.extractions.len()
            );
            for w in &report.warnings {
                println!("  warning: {w}");
            }
            println!("wrote {}", opts.output.display());
            if let Some(md) = &opts.md {
                println!("wrote {}", md.display());
            }
            if let Some(sig) = &signed {
                println!("wrote {}", sig.display());
            }
        }
    }
    // The run is evidence too: which logs a report was built from, and
    // the hashes of what it wrote (`--evidence-log`, `--hash-inputs`).
    // The report itself stays a function of the logs alone (R-03).
    let written = [Some(&opts.output), opts.md.as_ref(), signed.as_ref()]
        .into_iter()
        .flatten()
        .filter_map(|p| evidence::FileRef::hashed(p).ok())
        .collect();
    let summary = serde_json::json!({
        "report": opts.output,
        "logs": opts.logs,
        "commands": report.commands.len(),
        "warnings": report.warnings.len(),
    });
    g.log_evidence("zvolreport", &summary, status, &reads, written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zvol_common::evidence::FileRef as EvFileRef;

    fn opts() -> Options {
        Options {
            logs: Vec::new(),
            output: PathBuf::from("/dev/null"),
            md: None,
            case: Some("42".into()),
            examiner: None,
            notes: Vec::new(),
            sign: None,
            signature: None,
        }
    }

    fn record(tool: &str, ts: u64, status: u8, result: serde_json::Value) -> Record {
        Record {
            v: FORMAT_VERSION,
            ts,
            tool: tool.into(),
            version: "0.2.0".into(),
            host: Some("rescue1".into()),
            argv: vec![tool.into()],
            inputs: vec![EvFileRef {
                path: PathBuf::from("/dev/sda1"),
                // None on purpose: a record written before F-68 existed
                // says nothing about what it read, and the build must
                // not invent an answer for it.
                kind: None,
                size: 100,
                sha256: None,
                sha1: None,
                md5: None,
            }],
            outputs: Vec::new(),
            result,
            incidents: Vec::new(),
            status,
        }
    }

    fn log(records: Vec<Record>) -> Vec<(LogRef, Vec<Record>)> {
        vec![(
            LogRef {
                path: PathBuf::from("case.jsonl"),
                records: records.len(),
                sha256: "00".into(),
                left_out: Vec::new(),
            },
            records,
        )]
    }

    fn scan(txgs: (u64, u64)) -> serde_json::Value {
        serde_json::json!({
            "devices": [{"path": "/dev/sda1", "oldest_txg": txgs.0, "newest_txg": txgs.1}],
            "pools": [{"name": "tank", "guid": "0x1", "state": "ACTIVE", "readable": true}],
        })
    }

    fn dump(txg: u64, zeroed: u64, aborted: bool) -> serde_json::Value {
        serde_json::json!({
            "volumes": [{
                "dataset": "tank/vm/disk0", "txg": txg, "output": "/case/disk0.img",
                "volsize": 1024, "sha256": "ab", "blocks_zeroed": zeroed, "aborted": aborted,
            }]
        })
    }

    /// A line a killed run left half-written is left out by number, with
    /// the records around it kept; the hash is of the bytes read. A file
    /// with no record in it is still no evidence log.
    #[test]
    fn a_torn_line_is_left_out_and_the_rest_read() {
        let dir = std::env::temp_dir().join(format!("zvolreport-torn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let line = |r: &Record| serde_json::to_string(r).unwrap();
        let a = line(&record("zvolrescue", 1, 0, scan((1, 2))));
        let b = line(&record("zvolrescue", 2, 0, scan((1, 2))));
        let mut text = format!("{a}\n{}\n{b}\n", &a[..a.len() / 2]).into_bytes();
        // Cut inside a character: not even text.
        text.extend_from_slice("{\"note\":\"é".as_bytes().split_last().unwrap().1);
        text.push(b'\n');
        let log = dir.join("case.jsonl");
        std::fs::write(&log, &text).unwrap();
        let read = read_log(&log).unwrap();
        assert_eq!(read.records.len(), 2);
        assert_eq!(
            read.left_out.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            [2, 4]
        );
        assert_eq!(read.sha256, evidence::sha256_hex(&text));
        std::fs::write(&log, "not a log\nat all\n").unwrap();
        assert!(read_log(&log).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_pool_and_its_txg_window_come_from_the_scan() {
        let r = assemble(
            &log(vec![record("zvolrescue", 10, 0, scan((5, 9)))]),
            &opts(),
        );
        assert_eq!(r.pools.len(), 1);
        assert_eq!(r.pools[0].name, "tank");
        assert_eq!(r.pools[0].txg_window, Some([5, 9]));
        assert_eq!(r.evidence[0].read_by, ["zvolrescue"]);
    }

    /// R-03: the same records and flags give the same report. Nothing in
    /// it may come from the clock or from the order a map happened to
    /// iterate in.
    #[test]
    fn building_the_same_records_twice_gives_the_same_bytes() {
        let records = log(vec![
            record("zvolrescue", 10, 0, scan((5, 9))),
            record("zvoltimeline", 11, 0, serde_json::json!({})),
            record("zvolrescue", 12, 0, dump(9, 0, false)),
        ]);
        let a = serde_json::to_string(&assemble(&records, &opts())).expect("serialisable");
        let b = serde_json::to_string(&assemble(&records, &opts())).expect("serialisable");
        assert_eq!(a, b);
    }

    /// Two records in the same second keep the order the log has them
    /// in: a log is appended to, so that order is the order they ran.
    #[test]
    fn records_sharing_a_second_keep_the_order_of_the_log() {
        let r = assemble(
            &log(vec![
                record("zvoltimeline", 7, 0, serde_json::json!({})),
                record("zvolrescue", 7, 0, dump(9, 0, false)),
            ]),
            &opts(),
        );
        assert_eq!(
            r.commands
                .iter()
                .map(|c| c.tool.as_str())
                .collect::<Vec<_>>(),
            ["zvoltimeline", "zvolrescue"]
        );
    }

    #[test]
    fn an_extraction_outside_the_scanned_window_is_a_warning() {
        let r = assemble(
            &log(vec![
                record("zvolrescue", 10, 0, scan((5, 9))),
                record("zvolrescue", 11, 0, dump(4, 0, false)),
            ]),
            &opts(),
        );
        assert!(
            r.warnings.iter().any(|w| w.contains("outside the window")),
            "{:?}",
            r.warnings
        );
    }

    #[test]
    fn zeroed_blocks_and_an_aborted_extraction_are_warnings() {
        let r = assemble(
            &log(vec![record("zvolrescue", 11, 0, dump(9, 3, true))]),
            &opts(),
        );
        assert!(r.warnings.iter().any(|w| w.contains("written as zeros")));
        assert!(r.warnings.iter().any(|w| w.contains("stopped early")));
        assert_eq!(r.extractions[0].errors, 3);
    }

    /// An extraction a signal or a device stopped, or one with blocks
    /// kept only in part, is not the whole volume, and the report says so
    /// — it used to read `errors: 0, aborted: false` for a dump cut at
    /// block 599 of 4096.
    #[test]
    fn an_interrupted_or_salvaged_extraction_is_not_complete() {
        let mut d = dump(9, 1, false);
        let v = &mut d["volumes"][0];
        v["blocks_salvaged"] = serde_json::json!(2);
        v["interrupted_at"] = serde_json::json!(599);
        v["stopped_by_medium"] = serde_json::json!("ada1 refused a read");
        let r = assemble(&log(vec![record("zvolrescue", 11, 6, d)]), &opts());
        let e = &r.extractions[0];
        assert_eq!(e.errors, 3);
        assert_eq!(e.interrupted_at, Some(599));
        assert!(!e.complete());
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains("interrupted at block 599")),
            "{:?}",
            r.warnings
        );
        assert!(r
            .warnings
            .iter()
            .any(|w| w.contains("a device refused a read")));
        assert!(assemble(
            &log(vec![record("zvolrescue", 11, 0, dump(9, 0, false))]),
            &opts()
        )
        .extractions[0]
            .complete());
    }

    #[test]
    fn a_command_that_failed_is_a_warning() {
        let r = assemble(
            &log(vec![record("zvolrescue", 11, 3, serde_json::json!({}))]),
            &opts(),
        );
        assert!(r.warnings.iter().any(|w| w.contains("exited 3")));
    }

    /// Evidence hashed by one run and not by another keeps the hash: the
    /// later record says nothing about it, not that it is unknown.
    #[test]
    fn a_hash_recorded_once_is_not_erased_by_a_run_that_did_not_hash() {
        let mut hashed = record("zvolrescue", 10, 0, serde_json::json!({}));
        hashed.inputs[0].sha256 = Some("cafe".into());
        let r = assemble(
            &log(vec![
                hashed,
                record("zvoltimeline", 11, 0, serde_json::json!({})),
            ]),
            &opts(),
        );
        assert_eq!(r.evidence[0].file.sha256.as_deref(), Some("cafe"));
        assert_eq!(r.evidence[0].read_by, ["zvolrescue", "zvoltimeline"]);
    }

    /// The same file hashing differently in two runs means the evidence
    /// changed while it was being examined. That has to be said loudly.
    #[test]
    fn evidence_that_changed_between_runs_is_a_warning() {
        let mut first = record("zvolrescue", 10, 0, serde_json::json!({}));
        first.inputs[0].sha256 = Some("cafe".into());
        let mut second = record("zvolrescue", 11, 0, serde_json::json!({}));
        second.inputs[0].sha256 = Some("beef".into());
        let r = assemble(&log(vec![first, second]), &opts());
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains("the evidence changed")),
            "{:?}",
            r.warnings
        );
    }

    /// F-68: a reader deciding what a report is worth cares whether the
    /// work was done against copies or against the disks themselves, so
    /// the report says which — once per piece of evidence, however many
    /// runs read it.
    #[test]
    fn a_recovery_done_against_the_disks_is_said_so_in_the_report() {
        let on_a_device = |tool: &str, ts: u64| {
            let mut r = record(tool, ts, 0, serde_json::json!({}));
            r.inputs[0].kind = Some(zvol_common::evidence::Kind::Device);
            r
        };
        let logs = log(vec![
            on_a_device("zvolrescue", 10),
            on_a_device("zvoltimeline", 11),
        ]);
        let report = assemble(&logs, &opts());
        let said: Vec<&String> = report
            .warnings
            .iter()
            .filter(|w| w.contains("read as a device"))
            .collect();
        assert_eq!(said.len(), 1, "{:?}", report.warnings);
        assert!(said[0].contains("/dev/sda1"), "{:?}", said);
        assert_eq!(
            report.evidence[0].file.kind,
            Some(zvol_common::evidence::Kind::Device)
        );

        // An image says nothing, and neither does a record from before
        // the field existed.
        for kind in [Some(zvol_common::evidence::Kind::File), None] {
            let mut r = record("zvolrescue", 10, 0, serde_json::json!({}));
            r.inputs[0].kind = kind;
            let quiet = assemble(&log(vec![r]), &opts());
            assert!(
                !quiet
                    .warnings
                    .iter()
                    .any(|w| w.contains("read as a device")),
                "{kind:?}: {:?}",
                quiet.warnings
            );
        }
    }

    #[test]
    fn runs_of_different_builds_are_a_warning() {
        let mut old = record("zvolrescue", 10, 0, serde_json::json!({}));
        old.version = "0.1.0".into();
        let r = assemble(
            &log(vec![
                old,
                record("zvolrescue", 11, 0, serde_json::json!({})),
            ]),
            &opts(),
        );
        assert!(
            r.warnings.iter().any(|w| w.contains("different builds")),
            "{:?}",
            r.warnings
        );
        assert_eq!(r.tools.len(), 2);
    }

    /// A build may not write over a log it reads, nor two of its own
    /// files over each other; nothing is written when it refuses.
    #[test]
    fn a_report_is_never_written_over_its_own_inputs() {
        let dir = std::env::temp_dir().join(format!("zvolreport-over-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("case.jsonl");
        std::fs::write(&log, "").unwrap();
        let g = Global {
            format: zvol_common::Format::Text,
            verbose: 0,
            quiet: true,
            evidence_log: None,
            hash_inputs: false,
            no_color: false,
            debug: false,
            debug_log: None,
        };
        let over_log = Options {
            logs: vec![log.clone()],
            output: log.clone(),
            ..opts()
        };
        assert_eq!(run(&g, &over_log), exit::REFUSED);
        assert_eq!(std::fs::read(&log).unwrap(), b"");
        let md_over_json = Options {
            logs: vec![log.clone()],
            output: dir.join("r.json"),
            md: Some(dir.join("r.json")),
            ..opts()
        };
        assert_eq!(run(&g, &md_over_json), exit::USAGE);
        assert!(!dir.join("r.json").exists());
        std::fs::remove_dir_all(&dir).ok();
    }
}
