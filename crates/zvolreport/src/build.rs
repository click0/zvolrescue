//! `zvolreport build` — evidence logs into one report (R-01…R-03, R-06).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zvol_common::{errln, outln};

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
    /// How many bytes those are.
    pub bytes: u64,
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
    read_log_prefix(path, None)
}

/// [`read_log`] of the first `limit` bytes alone: the log as it was when
/// a report was built from it, whatever was appended since.
pub(crate) fn read_log_prefix(path: &Path, limit: Option<u64>) -> Result<ReadLog, String> {
    let mut bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if let Some(n) = limit {
        bytes.truncate(usize::try_from(n).unwrap_or(usize::MAX));
    }
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
        // Nothing at all — an empty file, `/dev/null` — is no log of a
        // case: a report built from it said every log hashed as recorded
        // over no record, and `verify` passed it.
        return Err(format!(
            "{}: empty; no evidence record in it",
            path.display()
        ));
    }
    Ok(ReadLog {
        records,
        left_out,
        sha256,
        bytes: bytes.len() as u64,
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

fn flag(v: &serde_json::Value, key: &str) -> Option<bool> {
    v.get(key).and_then(serde_json::Value::as_bool)
}

/// The pools a `scan` record described.
fn pools_of(result: &serde_json::Value) -> Vec<Pool> {
    let Some(list) = result.get("pools").and_then(serde_json::Value::as_array) else {
        return Vec::new();
    };
    let devices: &[serde_json::Value] = result
        .get("devices")
        .and_then(serde_json::Value::as_array)
        .map_or(&[], Vec::as_slice);
    // The TXG window is the span of what the members verified, which the
    // devices report and the pool does not — this pool's members: taken
    // over every device scanned, two pools on one scan shared one window,
    // the span of both.
    let window = |p: &serde_json::Value| {
        let own: Option<Vec<&str>> = p
            .get("devices")
            .and_then(serde_json::Value::as_array)
            .map(|v| v.iter().filter_map(serde_json::Value::as_str).collect());
        let members = devices.iter().filter(|d| {
            own.as_ref().is_none_or(|own| {
                d.get("path")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|path| own.contains(&path))
            })
        });
        let oldest = members
            .clone()
            .filter_map(|d| u64_at(d, "oldest_txg"))
            .min();
        let newest = members.filter_map(|d| u64_at(d, "newest_txg")).max();
        match (oldest, newest) {
            (Some(a), Some(b)) => Some([a, b]),
            _ => None,
        }
    };
    list.iter()
        .filter_map(|p| {
            Some(Pool {
                name: str_at(p, "name")?,
                guid: str_at(p, "guid").unwrap_or_default(),
                state: str_at(p, "state"),
                txg_window: window(p),
                readable: p
                    .get("readable")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
            })
        })
        .collect()
}

/// Where a path a record names is: relative to the directory the run
/// was started in, when the record says which. Taken as it was written,
/// a relative path was looked for wherever `verify` happened to run.
fn at_cwd(r: &Record, p: &Path) -> PathBuf {
    match &r.cwd {
        Some(dir) if p.is_relative() => dir.join(p),
        _ => p.to_path_buf(),
    }
}

/// The extraction a `zvolfiles extract` or `zvolfiles objects` record
/// describes: a tree of files rather than an image, listed in a manifest
/// — `objects.json` for objects — that is among the record's outputs
/// with every file it wrote. It was in no section of the report, and
/// `verify` checked the manifest and none of the files; an `objects`
/// run was in none even after.
fn tree_extraction(r: &Record) -> Option<Extraction> {
    let result = &r.result;
    let (files, listed_in) = match result.get("files").and_then(serde_json::Value::as_array) {
        Some(f) => (f, "manifest"),
        None => (result.get("objects")?.as_array()?, "objects"),
    };
    let output = at_cwd(r, Path::new(&str_at(result, "output")?));
    let manifest = r
        .outputs
        .iter()
        .map(|o| (at_cwd(r, &o.path), o))
        .find(|(p, _)| {
            p.parent() == Some(output.as_path())
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(listed_in) && n.ends_with(".json"))
        });
    let written: Vec<&serde_json::Value> = files
        .iter()
        .filter(|f| f.get("sha256").is_some_and(serde_json::Value::is_string))
        .collect();
    let count = |key: &str| u64_at(result, key).unwrap_or(0);
    // What the run could not look at, in its own words: objects whose
    // block of the object array did not read, and newer transaction
    // groups it passed over because they did not read. Neither was in
    // the report: an `objects` run short of 32 objects, and an `extract`
    // that wrote the dataset as an older group had it — empty — were
    // whole extractions, "0 errors", for the generic "exited 4" alone.
    let list = |key: &str| {
        result
            .get(key)
            .and_then(serde_json::Value::as_array)
            .map_or(&[][..], Vec::as_slice)
    };
    let mut unread: Vec<String> = list("unread")
        .iter()
        .map(|u| {
            let (first, last) = (u64_at(u, "first"), u64_at(u, "last"));
            let why = str_at(u, "reason").unwrap_or_else(|| "did not read".into());
            match (first, last) {
                (Some(a), Some(b)) if a != b => {
                    format!("objects {a}–{b} were not looked at: {why}")
                }
                (Some(a), _) => format!("object {a} was not looked at: {why}"),
                _ => format!("part of it was not looked at: {why}"),
            }
        })
        .collect();
    unread.extend(
        list("passed_over")
            .iter()
            .filter(|p| p.get("unread").and_then(serde_json::Value::as_bool) == Some(true))
            .map(|p| {
                format!(
                    "a newer transaction group did not read and was passed over for an older one: {}",
                    str_at(p, "reason").unwrap_or_else(|| {
                        format!("txg {}", u64_at(p, "txg").unwrap_or(0))
                    })
                )
            }),
    );
    Some(Extraction {
        dataset: str_at(result, "dataset")?,
        txg: u64_at(result, "txg").unwrap_or(0),
        output: manifest.as_ref().map_or(output.clone(), |(p, _)| p.clone()),
        size: written.iter().filter_map(|f| u64_at(f, "size")).sum(),
        sha256: manifest.and_then(|(_, o)| o.sha256.clone()),
        sha1: None,
        md5: None,
        errors: count("incomplete").saturating_add(count("failed")),
        unverified: count("unverified_blocks"),
        unreplayed: unreplayed_of(result),
        // A signal ended it: not every file or object was looked at.
        aborted: result.get("stopped").is_some_and(|s| !s.is_null())
            || result
                .get("interrupted")
                .and_then(serde_json::Value::as_bool)
                == Some(true),
        interrupted_at: None,
        stopped_by_medium: None,
        output_failed: None,
        carved: false,
        kept: false,
        unread,
        overwritten_by: None,
        finished: None,
        pool_guid: None,
        files: Some(written.len() as u64),
    })
}

/// The records an extraction's `intent_log` says were not applied.
fn unreplayed_of(v: &serde_json::Value) -> u64 {
    v.get("intent_log")
        .and_then(|l| u64_at(l, "unreplayed"))
        .unwrap_or(0)
}

/// The extractions a `dump` record described.
fn extractions_of(result: &serde_json::Value) -> Vec<Extraction> {
    let Some(list) = result.get("volumes").and_then(serde_json::Value::as_array) else {
        return Vec::new();
    };
    let pool_guid = str_at(result, "pool_guid");
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
                unverified: u64_at(v, "blocks_unverified").unwrap_or(0),
                unreplayed: unreplayed_of(v),
                aborted: v
                    .get("aborted")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
                interrupted_at: u64_at(v, "interrupted_at"),
                stopped_by_medium: str_at(v, "stopped_by_medium"),
                output_failed: str_at(v, "output_failed"),
                carved: flag(v, "carved").unwrap_or(false),
                kept: flag(v, "kept").unwrap_or(false),
                unread: Vec::new(),
                overwritten_by: None,
                finished: flag(v, "output_finished"),
                pool_guid: pool_guid.clone(),
                files: None,
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
    // The command that wrote each output last, and the command each
    // extraction is of: what tells an extraction whose file a later run
    // wrote over.
    let mut last_writer: BTreeMap<PathBuf, usize> = BTreeMap::new();
    let mut extracted_by: Vec<usize> = Vec::new();
    for (log, _) in records {
        for n in &log.left_out {
            warnings.push(format!(
                "{}:{n} is not a record (a run that ended while it wrote leaves part of a line) and is left out",
                log.path.display()
            ));
        }
    }

    // A run writes its record to one log. The same record in a second
    // log is a copy of the first — `build case.jsonl copy-of-case.jsonl`
    // — and counting it again put every command, extraction and warning
    // in the report twice. Within one log, two equal records are two
    // runs, and both stay.
    let mut first_seen: BTreeMap<String, usize> = BTreeMap::new();
    let mut copies: BTreeMap<(usize, usize), usize> = BTreeMap::new();
    let mut flat: Vec<(u64, usize, usize, &Record)> = Vec::new();
    for (log, (_, rs)) in records.iter().enumerate() {
        for (line, r) in rs.iter().enumerate() {
            let key = serde_json::to_string(r).expect("serialisable");
            match first_seen.get(&key) {
                Some(&earlier) if earlier != log => {
                    *copies.entry((log, earlier)).or_default() += 1;
                    continue;
                }
                Some(_) => {}
                None => {
                    first_seen.insert(key, log);
                }
            }
            flat.push((r.ts, log, line, r));
        }
    }
    for ((log, earlier), n) in copies {
        warnings.push(format!(
            "{}: {n} record(s) also in {}; each is counted once",
            records[log].0.path.display(),
            records[earlier].0.path.display()
        ));
    }
    // Chronological, and deterministic when two records share a second:
    // a log is appended to, so its own order is the order things ran,
    // and that is what breaks the tie (R-02, R-03).
    flat.sort_by_key(|(ts, log, line, _)| (*ts, *log, *line));

    let mut seen_tools: std::collections::BTreeSet<ToolRef> = std::collections::BTreeSet::new();
    let mut seen_hosts: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for (_, _, _, r) in flat {
        // In the order first met, each once: looked for in the list
        // itself, a log of a hundred thousand hosts or builds took a
        // minute.
        let tool = ToolRef {
            tool: r.tool.clone(),
            version: r.version.clone(),
        };
        if seen_tools.insert(tool.clone()) {
            tools.push(tool);
        }
        if let Some(h) = &r.host {
            if seen_hosts.insert(h.as_str()) {
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
            let path = at_cwd(r, &i.path);
            // What zvolreport read is the case's paperwork — a report,
            // its signature, the key, the logs — and what a `verify`
            // hashed, outputs among it. None of it is evidence of the
            // case because zvolreport read it: taken as such, a report
            // built over one a `verify` had read named the earlier
            // report as evidence, at its earlier size, and failed its
            // own check the moment it was written; and the private key
            // a build signed with was listed, and hashed by `verify`.
            // What is already evidence it adds itself to as a reader.
            if r.tool == "zvolreport" && !evidence_by_path.contains_key(&path) {
                continue;
            }
            let e = evidence_by_path
                .entry(path.clone())
                .or_insert_with(|| Evidence {
                    file: FileRef {
                        path: path.clone(),
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
                // Once, however many records read it: the warnings
                // are sorted and each kept once at the end.
                warnings.push(note);
            }
        }
        // What a build wrote is a report, which the next build replaces
        // and which is checked by its signature and its logs: as an
        // output of the case it failed the moment it was built again.
        let written = (r.tool != "zvolreport").then_some(&r.outputs);
        for o in written.into_iter().flatten() {
            let path = at_cwd(r, &o.path);
            last_writer.insert(path.clone(), commands.len() - 1);
            outputs.insert(
                path.clone(),
                FileRef {
                    path,
                    kind: o.kind,
                    size: o.size,
                    sha256: o.sha256.clone(),
                    sha1: o.sha1.clone(),
                    md5: o.md5.clone(),
                },
            );
        }
        for p in pools_of(&r.result) {
            match pools
                .iter_mut()
                .find(|q| q.guid == p.guid && q.name == p.name)
            {
                // Scanned twice: the window is what either scan saw.
                Some(q) => {
                    q.txg_window = match (q.txg_window, p.txg_window) {
                        (Some(a), Some(b)) => Some([a[0].min(b[0]), a[1].max(b[1])]),
                        (a, b) => a.or(b),
                    }
                }
                None => pools.push(p),
            }
        }
        if r.tool == "zvolfiles" {
            extractions.extend(tree_extraction(r));
        } else {
            let of_run: Vec<Extraction> = extractions_of(&r.result)
                .into_iter()
                .map(|mut e| {
                    e.output = at_cwd(r, &e.output);
                    e
                })
                .collect();
            // Newer transaction groups that name the dataset and do not
            // read it, passed over for the one extracted: the image is
            // of an older state than the pool's, and the report gave
            // the group it was taken at without a word of why.
            if let Some(first) = of_run.first() {
                for u in r
                    .result
                    .get("unreadable_at")
                    .and_then(serde_json::Value::as_array)
                    .map_or(&[][..], Vec::as_slice)
                {
                    warnings.push(format!(
                        "{}: txg {} names it and does not read it ({}); extracted at the older txg {}",
                        first.dataset,
                        u64_at(u, "txg").unwrap_or(0),
                        str_at(u, "error").unwrap_or_else(|| "no reason recorded".into()),
                        first.txg
                    ));
                }
            }
            extractions.extend(of_run);
        }
        // Read from a header found in raw space and no uberblock (SPEC
        // F-64): what was extracted is verified block by block as any
        // other, and the report says what the header is not vouched
        // for by.
        if let Some(root) = r.result.get("carved_root").filter(|c| c.is_object()) {
            warnings.push(format!(
                "{}: the pool was read from the object-set header at byte {} of {} (--roots), not from an uberblock: no checksum vouches for that header, and when its transaction group was written is not known : {}",
                r.tool,
                u64_at(root, "offset").unwrap_or(0),
                str_at(root, "member").unwrap_or_else(|| "a member".into()),
                r.argv.join(" ")
            ));
        }
        extracted_by.resize(extractions.len(), commands.len() - 1);
        if r.status != 0 {
            warnings.push(format!(
                "{} exited {} : {}",
                r.tool,
                r.status,
                r.argv.join(" ")
            ));
        }
    }

    // An extraction whose output a later run wrote over: the file holds
    // what that run wrote, under the hash that run recorded, and the
    // extraction stayed in the report as it was — its size, its hash,
    // "complete" — with `verify` passing the file. Not one stopped early
    // that a later run of the same image went on with: that is the same
    // image, and is said below.
    let later = crate::model::later_of_the_same(&extractions);
    for i in 0..extractions.len() {
        let e = &extractions[i];
        let (Some(&writer), Some(now)) = (last_writer.get(&e.output), outputs.get(&e.output))
        else {
            continue;
        };
        let changed = match (&e.sha256, &now.sha256) {
            (Some(a), Some(b)) => a != b,
            _ => false,
        };
        if writer > extracted_by[i] && changed && !later[i].gone_on_with {
            let by = &commands[writer];
            extractions[i].overwritten_by = Some(format!(
                "{} at {}",
                by.tool,
                zvol_common::timefmt::iso8601(by.ts)
            ));
        }
    }

    // R-06: what a reader should not have to notice for themselves.
    for (i, e) in extractions.iter().enumerate() {
        if let Some(by) = &e.overwritten_by {
            warnings.push(format!(
                "{}: {} was written again by {by}; what this extraction wrote there{} is no longer in it",
                e.dataset,
                e.output.display(),
                e.sha256
                    .as_ref()
                    .map_or(String::new(), |h| format!(" (sha256 {h})"))
            ));
        }
        for what in &e.unread {
            warnings.push(format!("{}: {what}", e.dataset));
        }
        // Interrupted, then finished by `--resume`: what is in the file
        // now is the whole volume, and saying it is not was wrong.
        if later[i].finished {
            warnings.push(format!(
                "{}: the extraction into {} stopped early; a later run wrote the whole volume there",
                e.dataset,
                e.output.display()
            ));
        } else {
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
            if let Some(why) = &e.output_failed {
                // An output that refused a block was still finished to
                // the blocks before it, and the hash recorded is that
                // image's: "not that of the file" was said of it all the
                // same, of a hash `verify` then passed. It is said where
                // the record does not say the output was finished.
                warnings.push(format!(
                    "{}: {why}; {} is not the whole volume{}",
                    e.dataset,
                    e.output.display(),
                    if e.finished == Some(true) {
                        ": it is the blocks before that, which is what the hash recorded is of"
                    } else {
                        ", and the hash recorded is not known to be that of the file"
                    }
                ));
            }
        }
        if e.errors > 0 {
            warnings.push(format!(
                "{}: {} block(s) could not be read whole and were written as zeros, in whole or in part",
                e.dataset, e.errors
            ));
        }
        if e.unreplayed > 0 {
            warnings.push(format!(
                "{}: its intent log held {} record(s) that were not applied: {} is the dataset as txg {} left it, without the writes they hold",
                e.dataset,
                e.unreplayed,
                e.output.display(),
                e.txg
            ));
        }
        if e.unverified > 0 {
            warnings.push(format!(
                "{}: {} block(s) carry no checksum (checksum=off) and were written as the members gave them: read, and verified by nothing",
                e.dataset, e.unverified
            ));
        }
        if e.sha256.is_none() {
            warnings.push(format!(
                "{}: no hash was recorded for {}",
                e.dataset,
                e.output.display()
            ));
        }
        // Against the pool the extraction read: the first pool's window
        // was the one every extraction was held to. A record that names
        // no pool is held to the only one, or to none.
        let pool = match &e.pool_guid {
            Some(g) => pools.iter().find(|p| &p.guid == g),
            None if pools.len() == 1 => pools.first(),
            None => None,
        };
        if let Some(w) = pool.and_then(|p| p.txg_window) {
            if e.txg < w[0] || e.txg > w[1] {
                warnings.push(if e.carved {
                    format!(
                        "{}: carved, its dnode born at txg {}, outside the window {}–{} the scan recorded: no uberblock on the members leads to it",
                        e.dataset, e.txg, w[0], w[1]
                    )
                } else {
                    format!(
                        "{}: extracted at txg {}, outside the window {}–{} the scan recorded",
                        e.dataset, e.txg, w[0], w[1]
                    )
                });
            }
        }
    }
    // Each build of a tool against the first other build of it met.
    let mut builds: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for t in &tools {
        builds.entry(&t.tool).or_default().push(&t.version);
    }
    for t in &tools {
        let of_tool = &builds[t.tool.as_str()];
        if let Some(other) = of_tool.iter().take(2).find(|v| **v != t.version) {
            warnings.push(format!(
                "{} appears as {} and {}: the report mixes runs of different builds",
                t.tool, t.version, other
            ));
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
            errln!(
                "zvolreport: {flag} {} is also where {other} goes",
                path.display()
            );
            return exit::USAGE;
        }
    }
    let mut logs = Vec::new();
    for (i, path) in opts.logs.iter().enumerate() {
        // The same log named twice is read once.
        if let Some(earlier) = opts.logs[..i]
            .iter()
            .find(|e| zvol_common::same_file(path, e))
        {
            errln!(
                "zvolreport: {} is {} again; read once",
                path.display(),
                earlier.display()
            );
            continue;
        }
        let read = match read_log(path) {
            Ok(r) => r,
            Err(e) => {
                errln!("zvolreport: {e}");
                return exit::EVIDENCE;
            }
        };
        for (n, why) in &read.left_out {
            errln!(
                "zvolreport: {}:{n}: {why}; left out of the report",
                path.display()
            );
        }
        logs.push((
            LogRef {
                // Where it is, not where `build` happened to run: named
                // relative, a report checked from anywhere else hashed
                // whatever file of that name was there.
                path: std::path::absolute(path).unwrap_or_else(|_| path.clone()),
                records: read.records.len(),
                sha256: read.sha256,
                bytes: read.bytes,
                left_out: read.left_out.iter().map(|(n, _)| *n).collect(),
            },
            read.records,
        ));
    }
    // Nor over anything the logs name: the evidence every run read and
    // what every run wrote. `build case.jsonl -o member0.img` replaced a
    // pool member with the report, exit 0. A report an earlier build
    // wrote is the one exception: building again over it is the point —
    // and so is one a `verify` read, with its signature: once the log
    // held a verify of the report, the next build over it was refused.
    let named: Vec<PathBuf> = logs
        .iter()
        .flat_map(|(_, records)| records)
        .flat_map(|r| {
            let written = (r.tool != "zvolreport").then_some(&r.outputs);
            let report_files: Vec<PathBuf> = if r.tool == "zvolreport" {
                [
                    str_at(&r.result, "report"),
                    r.result.get("signature").and_then(|s| str_at(s, "path")),
                ]
                .into_iter()
                .flatten()
                .map(|p| at_cwd(r, Path::new(&p)))
                .collect()
            } else {
                Vec::new()
            };
            r.inputs
                .iter()
                .chain(written.into_iter().flatten())
                .map(move |f| at_cwd(r, &f.path))
                .filter(move |p| !report_files.contains(p))
        })
        // Each once: a member every record names is one file to hold
        // the outputs against, not one per record.
        .collect::<std::collections::BTreeSet<PathBuf>>()
        .into_iter()
        .collect();
    let mut all = reads.clone();
    all.extend(named.iter().cloned());
    let guard = zvol_common::WriteGuard::new(g, &all);
    for (flag, path) in &writes {
        if let Some(n) = named.iter().find(|n| zvol_common::same_file(path, n)) {
            errln!(
                "zvolreport: refusing {flag} {}: it is {}, which the logs name as evidence or as an output of the case",
                path.display(),
                n.display()
            );
            return exit::REFUSED;
        }
        if let Err(code) = guard.refuse("zvolreport", flag, path) {
            return code;
        }
    }
    let status = if logs.iter().any(|(l, _)| !l.left_out.is_empty()) {
        exit::PARTIAL
    } else {
        0
    };
    // The key is read before anything is written: one that could not be
    // read failed the run after the report and its Markdown had been
    // written over, with the signature beside them now of another
    // report.
    let key = match &opts.sign {
        Some(keyfile) => match crate::sign::read_private(keyfile) {
            Ok(k) => Some(k),
            Err(e) => {
                errln!("zvolreport: {e}");
                return exit::USAGE;
            }
        },
        None if opts.signature.is_some() => {
            errln!("zvolreport: --signature says where to write one; --sign says what with");
            return exit::USAGE;
        }
        None => None,
    };
    let report = assemble(&logs, opts);

    let json = serde_json::to_string_pretty(&report).expect("serialisable") + "\n";
    if let Err(e) = std::fs::write(&opts.output, &json) {
        errln!("zvolreport: {}: {e}", opts.output.display());
        return exit::USAGE;
    }
    if let Some(md) = &opts.md {
        if let Err(e) = std::fs::write(md, crate::markdown::render(&report)) {
            errln!("zvolreport: {}: {e}", md.display());
            return exit::USAGE;
        }
    }
    // The signature covers `report.json` and nothing else. The Markdown
    // is a rendering of it, not a second document to be trusted on its
    // own, and R-03 is what lets a doubter re-render it themselves.
    let mut signed = None;
    if let (Some(key), Some(to)) = (&key, &signature) {
        if let Err(e) = crate::sign::write_signature(key, json.as_bytes(), to) {
            errln!("zvolreport: {e}");
            return exit::USAGE;
        }
        signed = Some(to.clone());
    }
    match g.format {
        Format::Json => print!("{json}"),
        Format::Text => {
            outln!(
                "{} record(s) from {} log(s): {} command(s), {} piece(s) of evidence, {} extraction(s)",
                report.commands.len(),
                report.logs.len(),
                report.commands.len(),
                report.evidence.len(),
                report.extractions.len()
            );
            for w in &report.warnings {
                outln!("  warning: {w}");
            }
            outln!("wrote {}", opts.output.display());
            if let Some(md) = &opts.md {
                outln!("wrote {}", md.display());
            }
            if let Some(sig) = &signed {
                outln!("wrote {}", sig.display());
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
            cwd: None,
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
            layout: None,
            status,
        }
    }

    fn log(records: Vec<Record>) -> Vec<(LogRef, Vec<Record>)> {
        vec![(
            LogRef {
                path: PathBuf::from("case.jsonl"),
                records: records.len(),
                sha256: "00".into(),
                bytes: 0,
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

    /// A `zvolfiles objects` run is an extraction, as an `extract` run
    /// is: its index and its objects are the tree it wrote.
    #[test]
    fn an_objects_run_is_an_extraction() {
        let mut r = record(
            "zvolfiles",
            11,
            4,
            serde_json::json!({
                "dataset": "tank/fs", "txg": 9, "output": "/case/objs",
                "objects": [
                    {"object": 2, "type": "plain file contents", "size": 10, "sha256": "aa", "errors": 0},
                    {"object": 3, "type": "plain file contents", "size": 5, "sha256": "bb", "errors": 1},
                ],
                "written": 2, "incomplete": 1, "interrupted": true,
            }),
        );
        r.outputs.push(EvFileRef {
            path: PathBuf::from("/case/objs/objects.json"),
            kind: None,
            size: 300,
            sha256: Some("cc".into()),
            sha1: None,
            md5: None,
        });
        let rep = assemble(&log(vec![r]), &opts());
        assert_eq!(rep.extractions.len(), 1, "{:?}", rep.extractions);
        let e = &rep.extractions[0];
        assert_eq!(e.output, PathBuf::from("/case/objs/objects.json"));
        assert_eq!((e.files, e.size, e.errors), (Some(2), 15, 1));
        assert!(!e.complete(), "a signal ended it");
    }

    /// An image its output would not finish is not the whole volume:
    /// the record said so, and the report showed it complete with the
    /// hash of the whole volume.
    #[test]
    fn an_output_that_failed_is_not_complete() {
        let mut d = dump(9, 0, false);
        d["volumes"][0]["output_failed"] =
            serde_json::json!("the output could not be finished to 1048576 bytes: EIO");
        let r = assemble(&log(vec![record("zvolrescue", 11, 6, d)]), &opts());
        assert!(!r.extractions[0].complete());
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains("could not be finished") && w.contains("not the whole volume")),
            "{:?}",
            r.warnings
        );
    }

    /// An extraction of a dataset whose intent log held records that
    /// were not applied is the dataset without them, and the report
    /// says so: the count on the extraction, and a warning.
    #[test]
    fn records_left_in_the_intent_log_are_said() {
        let mut d = dump(9, 0, false);
        d["volumes"][0]["intent_log"] = serde_json::json!({"unreplayed": 3, "write_bytes": 4096});
        let r = assemble(&log(vec![record("zvolrescue", 11, 4, d)]), &opts());
        let e = &r.extractions[0];
        assert_eq!(e.unreplayed, 3);
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains("its intent log held 3 record(s)")),
            "{:?}",
            r.warnings
        );
        assert_eq!(serde_json::to_value(e).unwrap()["unreplayed"], 3);
        let r = assemble(
            &log(vec![record("zvolrescue", 11, 0, dump(9, 0, false))]),
            &opts(),
        );
        assert!(serde_json::to_value(&r.extractions[0])
            .unwrap()
            .get("unreplayed")
            .is_none());
    }

    /// Blocks that carry no checksum (`checksum=off`) are read whole and
    /// verified by nothing: the image is complete, has no errors, and is
    /// not one read through its checksums — which the report says. A
    /// record of before the count existed says nothing, and a report
    /// built from it has no such field.
    #[test]
    fn an_image_with_blocks_nothing_verified_says_so() {
        let mut d = dump(9, 0, false);
        d["volumes"][0]["blocks_unverified"] = serde_json::json!(192);
        let r = assemble(&log(vec![record("zvolrescue", 11, 0, d)]), &opts());
        let e = &r.extractions[0];
        assert_eq!((e.errors, e.unverified), (0, 192));
        assert!(e.complete());
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains("192 block(s) carry no checksum")),
            "{:?}",
            r.warnings
        );
        let json = serde_json::to_value(e).unwrap();
        assert_eq!(json["unverified"], 192);

        let r = assemble(
            &log(vec![record("zvolrescue", 11, 0, dump(9, 0, false))]),
            &opts(),
        );
        assert_eq!(r.extractions[0].unverified, 0);
        assert!(serde_json::to_value(&r.extractions[0])
            .unwrap()
            .get("unverified")
            .is_none());
        assert!(!r.warnings.iter().any(|w| w.contains("no checksum")));
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

    /// A report a `verify` read, and its signature, can be built over
    /// again, as a report a build wrote can; the key it was checked with
    /// and the files it checked cannot. Once the log held a verify of
    /// the report, every later build over it was refused.
    #[test]
    fn a_verified_report_can_be_built_again() {
        let dir = std::env::temp_dir().join(format!("zvolreport-again-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let report = dir.join("r.json");
        let key = dir.join("k.pub");
        let mut v = record(
            "zvolreport",
            5,
            0,
            serde_json::json!({
                "report": report.display().to_string(),
                "signature": {"key": key.display().to_string(),
                              "path": dir.join("r.json.sig").display().to_string()},
                "checked": [],
            }),
        );
        v.inputs = [&report, &dir.join("r.json.sig"), &key]
            .into_iter()
            .map(|p| EvFileRef {
                path: p.clone(),
                kind: None,
                size: 1,
                sha256: None,
                sha1: None,
                md5: None,
            })
            .collect();
        let log = dir.join("case.jsonl");
        std::fs::write(&log, format!("{}\n", serde_json::to_string(&v).unwrap())).unwrap();
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
        let to = |output: &Path| Options {
            logs: vec![log.clone()],
            output: output.to_path_buf(),
            ..opts()
        };
        assert_eq!(run(&g, &to(&report)), 0);
        assert!(report.exists());
        std::fs::write(&key, "key").unwrap();
        assert_eq!(run(&g, &to(&key)), exit::REFUSED);
        assert_eq!(std::fs::read(&key).unwrap(), b"key");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Each pool's window is its own members', and an extraction is held
    /// to the window of the pool it read. One window over every device
    /// scanned, checked against whichever pool came first, warned about
    /// a TXG that was in its own pool's window and kept quiet about one
    /// that was not.
    #[test]
    fn each_extraction_is_held_to_its_own_pools_window() {
        let scan = serde_json::json!({
            "devices": [
                {"path": "/dev/a", "oldest_txg": 100, "newest_txg": 120},
                {"path": "/dev/b", "oldest_txg": 500, "newest_txg": 520},
            ],
            "pools": [
                {"name": "old", "guid": "0x1", "readable": true, "devices": ["/dev/a"]},
                {"name": "new", "guid": "0x2", "readable": true, "devices": ["/dev/b"]},
            ],
        });
        let dump = |guid: &str, txg: u64| {
            serde_json::json!({
                "pool_guid": guid,
                "volumes": [{"dataset": "new/vol", "txg": txg, "output": "/case/v.img",
                             "volsize": 1, "sha256": "ab", "blocks_zeroed": 0}],
            })
        };
        let r = assemble(
            &log(vec![
                record("zvolrescue", 1, 0, scan),
                record("zvolrescue", 2, 0, dump("0x2", 510)),
                record("zvolrescue", 3, 0, dump("0x2", 110)),
            ]),
            &opts(),
        );
        let windows: Vec<_> = r.pools.iter().map(|p| p.txg_window).collect();
        assert_eq!(windows, [Some([100, 120]), Some([500, 520])]);
        let outside: Vec<_> = r
            .warnings
            .iter()
            .filter(|w| w.contains("outside the window"))
            .collect();
        assert_eq!(outside.len(), 1, "{:?}", r.warnings);
        assert!(outside[0].contains("txg 110"), "{outside:?}");
    }

    /// Interrupted, then finished by `--resume`: the report says the
    /// file holds the whole volume now, not that it does not.
    #[test]
    fn an_extraction_finished_later_is_not_called_partial() {
        let interrupted = serde_json::json!({
            "volumes": [{"dataset": "tank/vm/disk0", "txg": 9, "output": "/case/disk0.img",
                         "volsize": 1024, "sha256": "aa", "blocks_zeroed": 0,
                         "interrupted_at": 3}]
        });
        let r = assemble(
            &log(vec![
                record("zvolrescue", 10, 6, interrupted.clone()),
                record("zvolrescue", 11, 0, dump(9, 0, false)),
            ]),
            &opts(),
        );
        assert!(
            !r.warnings
                .iter()
                .any(|w| w.contains("not the whole volume")),
            "{:?}",
            r.warnings
        );
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains("a later run wrote the whole volume")),
            "{:?}",
            r.warnings
        );
        assert!(r.finished_later(0) && !r.finished_later(1));
        let md = crate::markdown::render(&r);
        assert!(md.contains("finished by a later run"), "{md}");
        // Never finished, it still is not the whole volume.
        let r = assemble(
            &log(vec![record("zvolrescue", 10, 6, interrupted)]),
            &opts(),
        );
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains("not the whole volume")),
            "{:?}",
            r.warnings
        );
    }

    fn out(path: &str, sha256: &str) -> EvFileRef {
        EvFileRef {
            path: PathBuf::from(path),
            kind: None,
            size: 1024,
            sha256: Some(sha256.into()),
            sha1: None,
            md5: None,
        }
    }

    /// A dump record that wrote `/case/disk0.img` under `sha256`.
    fn dumped(ts: u64, txg: u64, sha256: &str) -> Record {
        let mut d = dump(txg, 0, false);
        d["volumes"][0]["sha256"] = sha256.into();
        let mut r = record("zvolrescue", ts, 0, d);
        r.outputs.push(out("/case/disk0.img", sha256));
        r
    }

    /// An extraction whose output a later run wrote over is not in the
    /// file any more, and the report says which run did: it stayed there
    /// with its size and hash, "complete", the file passing `verify`
    /// under the later run's hash. A run stopped early that a later one
    /// of the same image went on with is the same image still.
    #[test]
    fn an_output_a_later_run_wrote_over_is_no_longer_the_extractions() {
        let mut timeline = record("zvoltimeline", 20, 0, serde_json::json!({"events": []}));
        timeline.outputs.push(out("/case/disk0.img", "ee"));
        let r = assemble(&log(vec![dumped(10, 9, "aa"), timeline]), &opts());
        let e = &r.extractions[0];
        assert_eq!(
            e.overwritten_by.as_deref(),
            Some("zvoltimeline at 1970-01-01T00:00:20Z")
        );
        assert!(
            r.warnings.iter().any(|w| w.contains(
                "/case/disk0.img was written again by zvoltimeline at 1970-01-01T00:00:20Z; what this extraction wrote there (sha256 aa) is no longer in it"
            )),
            "{:?}",
            r.warnings
        );
        assert!(
            crate::markdown::render(&r).contains("no — written over by a later run"),
            "{}",
            crate::markdown::render(&r)
        );
        // The same volume at another TXG into the same file: the first
        // image is gone, the second is there.
        let r = assemble(
            &log(vec![dumped(10, 9, "aa"), dumped(20, 8, "bb")]),
            &opts(),
        );
        assert!(r.extractions[0].overwritten_by.is_some());
        assert!(r.extractions[1].overwritten_by.is_none());
        // Written again as it was — a run repeated — it is there still.
        let r = assemble(
            &log(vec![dumped(10, 9, "aa"), dumped(20, 9, "aa")]),
            &opts(),
        );
        assert!(r.extractions.iter().all(|e| e.overwritten_by.is_none()));
        // Interrupted, then gone on with by `--resume`: one image.
        let mut first = dumped(10, 9, "aa");
        first.result["volumes"][0]["interrupted_at"] = 3.into();
        let r = assemble(&log(vec![first, dumped(20, 9, "bb")]), &opts());
        assert!(
            r.extractions.iter().all(|e| e.overwritten_by.is_none()),
            "{:?}",
            r.warnings
        );
        assert!(r.finished_later(0));
    }

    /// What a `zvolfiles` run could not look at is in the report, and
    /// the extraction is not whole: objects whose block of the object
    /// array did not read, and newer transaction groups that did not
    /// read and were passed over. Both were whole extractions, "0
    /// errors", under the generic "exited 4".
    #[test]
    fn what_a_run_could_not_look_at_is_in_the_report() {
        let objects = record(
            "zvolfiles",
            11,
            4,
            serde_json::json!({
                "dataset": "sp/fs", "txg": 19, "output": "/case/objs",
                "objects": [{"object": 2, "size": 10, "sha256": "aa"}],
                "written": 1, "incomplete": 0,
                "unread": [{"first": 32, "last": 63, "block": 1,
                            "reason": "their dnode block 1 could not be read"}],
            }),
        );
        let extract = record(
            "zvolfiles",
            12,
            4,
            serde_json::json!({
                "dataset": "sp/fs", "txg": 6, "output": "/case/tree", "files": [],
                "written": 0, "incomplete": 0, "failed": 0,
                "passed_over": [
                    {"txg": 19, "reason": "sp/fs at txg 19: every copy failed its checksum", "unread": true},
                    {"txg": 7, "reason": "txg 7: no dataset sp/fs", "unread": false},
                ],
            }),
        );
        let r = assemble(&log(vec![objects, extract]), &opts());
        let (o, x) = (&r.extractions[0], &r.extractions[1]);
        assert_eq!(
            o.unread,
            ["objects 32–63 were not looked at: their dnode block 1 could not be read"]
        );
        assert_eq!(
            x.unread,
            ["a newer transaction group did not read and was passed over for an older one: sp/fs at txg 19: every copy failed its checksum"]
        );
        assert!(!o.complete() && !x.complete());
        assert!(o.ran_to_its_end() && x.ran_to_its_end());
        for said in [&o.unread[0], &x.unread[0]] {
            assert!(
                r.warnings.contains(&format!("sp/fs: {said}")),
                "{:?}",
                r.warnings
            );
        }
        assert!(
            crate::markdown::render(&r).contains("no — not all of it could be read"),
            "{}",
            crate::markdown::render(&r)
        );
    }

    /// A newer transaction group that names a volume and does not read
    /// it, passed over by `dump` for the one extracted, is said.
    #[test]
    fn a_dump_from_an_older_txg_than_the_one_that_did_not_read_says_so() {
        let mut d = dump(9, 0, false);
        d["unreadable_at"] = serde_json::json!([
            {"txg": 12, "stage": "dataset", "error": "object set: every copy failed its checksum"}
        ]);
        let r = assemble(&log(vec![record("zvolrescue", 11, 0, d)]), &opts());
        assert!(
            r.warnings.contains(
                &"tank/vm/disk0: txg 12 names it and does not read it (object set: every copy failed its checksum); extracted at the older txg 9"
                    .to_string()
            ),
            "{:?}",
            r.warnings
        );
    }

    /// A run that read the pool from a header found in raw space and no
    /// uberblock (`--roots`) is said in the report: what it extracted
    /// is verified like any other, and the header it started from is
    /// vouched for by nothing.
    #[test]
    fn a_run_that_read_from_a_header_found_in_raw_space_says_so() {
        let mut d = dump(9, 0, false);
        assert!(
            assemble(&log(vec![record("zvolrescue", 11, 0, d.clone())]), &opts())
                .warnings
                .iter()
                .all(|w| !w.contains("--roots"))
        );
        d["carved_root"] =
            serde_json::json!({"member": "/case/a.img", "offset": 6365184, "found": "plaintext"});
        let r = assemble(&log(vec![record("zvolrescue", 11, 0, d)]), &opts());
        assert!(
            r.warnings.iter().any(|w| w.starts_with(
                "zvolrescue: the pool was read from the object-set header at byte 6365184 of /case/a.img (--roots), not from an uberblock: no checksum vouches for that header"
            )),
            "{:?}",
            r.warnings
        );
    }

    /// What zvolreport itself read is the case's paperwork, not its
    /// evidence. A report built over one a `verify` had read took the
    /// earlier report, its signature, the logs and — from the build's
    /// own record — the private key for evidence, and an output `verify`
    /// had hashed too: it failed its own check the moment it was
    /// written. What is evidence already has zvolreport among its
    /// readers.
    #[test]
    fn what_zvolreport_read_is_not_evidence_of_the_case() {
        let read = |path: &str| EvFileRef {
            path: PathBuf::from(path),
            kind: None,
            size: 100,
            sha256: None,
            sha1: None,
            md5: None,
        };
        let mut build = record(
            "zvolreport",
            20,
            0,
            serde_json::json!({"report": "/case/report.json"}),
        );
        build.inputs = vec![read("/case/case.jsonl"), read("/case/k.key")];
        build.outputs.push(out("/case/report.json", "r1"));
        let mut verify = record(
            "zvolreport",
            30,
            0,
            serde_json::json!({"report": "/case/report.json"}),
        );
        verify.inputs = vec![
            read("/case/report.json"),
            read("/case/report.json.sig"),
            read("/case/k.key.pub"),
            read("/case/case.jsonl"),
            read("/dev/sda1"),
            read("/case/disk0.img"),
        ];
        let r = assemble(&log(vec![dumped(10, 9, "aa"), build, verify]), &opts());
        let evidence: Vec<(&std::path::Path, &[String])> = r
            .evidence
            .iter()
            .map(|e| (e.file.path.as_path(), e.read_by.as_slice()))
            .collect();
        assert_eq!(
            evidence,
            [(
                std::path::Path::new("/dev/sda1"),
                &["zvolrescue".to_string(), "zvolreport".to_string()][..]
            )]
        );
        assert_eq!(r.outputs.len(), 1, "{:?}", r.outputs);
        assert_eq!(r.commands.len(), 3);
    }

    /// An image a `dump -r --resume` kept is said to be kept: the run
    /// read nothing of the pool for it, and it was one more extraction,
    /// "complete", like the ones that did.
    #[test]
    fn a_kept_image_is_said_to_be_kept() {
        let mut d = dump(9, 0, false);
        d["volumes"][0]["kept"] = true.into();
        let r = assemble(&log(vec![record("zvolrescue", 11, 0, d)]), &opts());
        assert!(r.extractions[0].kept && r.extractions[0].complete());
        assert!(
            crate::markdown::render(&r).contains("yes — kept, as an earlier run left it"),
            "{}",
            crate::markdown::render(&r)
        );
        assert_eq!(
            serde_json::to_value(&r.extractions[0]).unwrap()["kept"],
            true
        );
        let plain = assemble(
            &log(vec![record("zvolrescue", 11, 0, dump(9, 0, false))]),
            &opts(),
        );
        let v = serde_json::to_value(&plain.extractions[0]).unwrap();
        for absent in ["kept", "unread", "overwritten_by", "finished", "output_hex"] {
            assert!(v.get(absent).is_none(), "{absent} in {v}");
        }
    }

    /// An output that refused a block was still finished to the blocks
    /// before it, and the hash recorded is that image's: it was said not
    /// to be the file's all the same, of a hash `verify` then passed.
    /// Where the record does not say the output was finished, the hash
    /// is not known to be the file's — which is all that is known.
    #[test]
    fn what_is_said_of_the_hash_of_a_failed_output_is_what_the_record_bears_out() {
        let said = |finished: Option<bool>| {
            let mut d = dump(9, 0, false);
            d["volumes"][0]["output_failed"] =
                "the output refused block 12800, at byte 104857600: ENOSPC".into();
            d["volumes"][0]["interrupted_at"] = 12800.into();
            if let Some(f) = finished {
                d["volumes"][0]["output_finished"] = f.into();
            }
            assemble(&log(vec![record("zvolrescue", 11, 6, d)]), &opts())
                .warnings
                .into_iter()
                .find(|w| w.contains("refused block"))
                .expect("a warning of it")
        };
        assert!(
            said(Some(true)).ends_with(
                "/case/disk0.img is not the whole volume: it is the blocks before that, which is what the hash recorded is of"
            ),
            "{}",
            said(Some(true))
        );
        for unknown in [Some(false), None] {
            assert!(
                said(unknown)
                    .ends_with("and the hash recorded is not known to be that of the file"),
                "{}",
                said(unknown)
            );
        }
    }

    /// A path that is not text is written with its bytes beside it and
    /// read back as it was: a build run from a directory so named ended
    /// in a panic over the report it could not write.
    #[cfg(unix)]
    #[test]
    fn a_path_that_is_not_text_is_written_and_read_back() {
        use std::os::unix::ffi::OsStrExt;
        let odd = PathBuf::from(std::ffi::OsStr::from_bytes(&[b'/', b'c', 0xfe, b'/', b'l']));
        let mut logs = log(vec![record("zvolrescue", 11, 0, dump(9, 0, false))]);
        logs[0].0.path = odd.clone();
        let mut r = assemble(&logs, &opts());
        r.extractions[0].output = odd.clone();
        let json = serde_json::to_string(&r).expect("a report of it");
        let back: Report = serde_json::from_str(&json).expect("read back");
        assert_eq!(back.logs[0].path, odd);
        assert_eq!(back.extractions[0].output, odd);
        assert!(
            json.contains("\"path_hex\":\"2f63fe2f6c\"") && json.contains("\"output_hex\""),
            "{json}"
        );
    }

    /// What came after each extraction is found in one pass, and is
    /// what asking each one against all that follow finds: of every
    /// image, runs that stopped early and runs that did not, in every
    /// order.
    #[test]
    fn what_came_after_an_extraction_is_found_in_one_pass() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let extractions: Vec<Extraction> = (0..400)
            .map(|_| {
                let mut d = dump(next() % 2, 0, false);
                d["volumes"][0]["dataset"] = format!("tank/v{}", next() % 5).into();
                d["volumes"][0]["output"] = format!("/case/o{}.img", next() % 3).into();
                if next() % 3 != 0 {
                    d["volumes"][0]["interrupted_at"] = 7.into();
                }
                extractions_of(&d).remove(0)
            })
            .collect();
        let same = |a: &Extraction, b: &Extraction| {
            a.dataset == b.dataset && a.txg == b.txg && a.output == b.output
        };
        let found = crate::model::later_of_the_same(&extractions);
        for (i, e) in extractions.iter().enumerate() {
            let after = || extractions[i + 1..].iter().filter(|l| same(e, l));
            let want = crate::model::Later {
                finished: !e.ran_to_its_end() && after().any(Extraction::ran_to_its_end),
                gone_on_with: !e.ran_to_its_end() && after().next().is_some(),
            };
            assert_eq!(found[i], want, "extraction {i}");
        }
        assert!(found.iter().any(|l| l.finished) && found.iter().any(|l| !l.gone_on_with));
    }

    /// Hosts and builds are listed once each, in the order first met,
    /// and each build of a tool is held against the first other build of
    /// it — what looking each up in the list itself gave, in a time that
    /// grew with the square of how many there were.
    #[test]
    fn hosts_and_builds_are_listed_once_in_the_order_met() {
        let mut records = Vec::new();
        for (i, (host, version)) in [("b", "2"), ("a", "1"), ("b", "1"), ("c", "3"), ("a", "2")]
            .iter()
            .enumerate()
        {
            let mut r = record("zvolrescue", 10 + i as u64, 0, serde_json::json!({}));
            r.host = Some(host.to_string());
            r.version = version.to_string();
            records.push(r);
        }
        let r = assemble(&log(records), &opts());
        assert_eq!(r.hosts, ["b", "a", "c"]);
        let versions: Vec<&str> = r.tools.iter().map(|t| t.version.as_str()).collect();
        assert_eq!(versions, ["2", "1", "3"]);
        let mixed: Vec<&String> = r
            .warnings
            .iter()
            .filter(|w| w.contains("mixes runs of different builds"))
            .collect();
        assert_eq!(
            mixed,
            [
                "zvolrescue appears as 1 and 2: the report mixes runs of different builds",
                "zvolrescue appears as 2 and 1: the report mixes runs of different builds",
                "zvolrescue appears as 3 and 2: the report mixes runs of different builds",
            ]
        );
    }

    /// A copy of a log built alongside it counts each record once and
    /// says so; two equal records in one log are two runs.
    #[test]
    fn a_record_in_two_logs_is_counted_once() {
        let one = record("zvolrescue", 10, 0, dump(9, 0, false));
        let mut logs = log(vec![one.clone(), one.clone()]);
        let mut copy = log(vec![one]);
        copy[0].0.path = PathBuf::from("copy.jsonl");
        logs.extend(copy);
        let r = assemble(&logs, &opts());
        assert_eq!(r.commands.len(), 2);
        assert_eq!(r.extractions.len(), 2);
        assert!(
            r.warnings
                .iter()
                .any(|w| w.starts_with("copy.jsonl: 1 record(s) also in case.jsonl")),
            "{:?}",
            r.warnings
        );
    }
}
