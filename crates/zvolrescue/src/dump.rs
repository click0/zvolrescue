//! `dump`: extract a volume — or every volume under a dataset with `-r` —
//! to raw sparse images.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zfs_read::crypt::{unwrap_keys, wrapping_key, DatasetKeys, KeyMaterial};
use zfs_read::dsl::{open_mos, walk, Dataset, DatasetTree, Encryption};
use zfs_read::pool::{select_uberblock, uberblock_candidates, Candidate, TxgSelect};
use zfs_read::zio::PoolReader;
use zfs_read::zvol::{extract_from, open_volume, volume_facts, OnError, Report};
use zvolrescue_io::{refuse_if_evidence, SparseFile};

use zvol_common::members::{choose_pool, open_members};
use zvol_common::timefmt::iso8601;
use zvol_common::{evidence, exit, Format, Global, PoolSpec};

/// Options of the `dump` command.
pub struct Options {
    /// Dataset name (a volume, or with `recursive` the root of a tree).
    pub dataset: String,
    /// Output image path, or a directory with `recursive`.
    pub output: PathBuf,
    /// Exact TXG; default is the newest that still has the dataset.
    pub txg: Option<u64>,
    /// Abort on the first unreadable block.
    pub strict: bool,
    /// Encryption key spec (phase 3).
    pub key: Option<String>,
    /// Continue an interrupted extraction.
    pub resume: bool,
    /// Extract every volume under `dataset`.
    pub recursive: bool,
}

#[derive(Debug, Serialize)]
struct BadOut {
    blkid: u64,
    offset: u64,
    len: u64,
    reason: String,
}

#[derive(Debug, Serialize)]
struct DumpOut {
    dataset: String,
    dataset_guid: String,
    txg: u64,
    time: String,
    output: PathBuf,
    volsize: u64,
    blocksize: u64,
    blocks_total: u64,
    blocks_read: u64,
    blocks_holes: u64,
    blocks_zeroed: u64,
    bytes_written: u64,
    resumed_from_block: u64,
    strict: bool,
    aborted: bool,
    sha256: String,
    seconds: f64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    bad: Vec<BadOut>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
    /// Encryption suite the volume was decrypted with.
    #[serde(skip_serializing_if = "Option::is_none")]
    encryption: Option<String>,
}

#[derive(Debug, Serialize)]
struct RunOut {
    pool: String,
    pool_guid: String,
    members: Vec<PathBuf>,
    /// TXGs that were walked before the dataset was found (newest first).
    txgs_searched: Vec<u64>,
    recursive: bool,
    volumes: Vec<DumpOut>,
    /// Datasets under the tree that were skipped (not volumes) or failed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    skipped: Vec<String>,
}

/// Resume state written next to the output image.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct ResumeState {
    version: u32,
    dataset: String,
    dataset_guid: String,
    txg: u64,
    volsize: u64,
    blocksize: u64,
    /// Blocks `0..blocks_done` are complete in the output.
    blocks_done: u64,
}

fn resume_path(output: &Path) -> PathBuf {
    let mut p = output.as_os_str().to_owned();
    p.push(".resume.json");
    PathBuf::from(p)
}

fn find_dataset<'c>(
    reader: &PoolReader<'_>,
    candidates: &'c [Candidate],
    sel: Option<u64>,
    pool_name: &str,
    name: &str,
    searched: &mut Vec<u64>,
) -> Result<(&'c Candidate, DatasetTree), u8> {
    let pick: Vec<&Candidate> = match sel {
        Some(txg) => match select_uberblock(candidates, TxgSelect::Exact(txg)) {
            Some(c) => vec![c],
            None => {
                eprintln!(
                    "zvolrescue: no verified uberblock for txg {txg}; available: {}",
                    candidates
                        .iter()
                        .map(|c| c.ub.txg.to_string())
                        .collect::<Vec<_>>()
                        .join(" ")
                );
                return Err(exit::UNRECOVERABLE);
            }
        },
        None => candidates.iter().collect(),
    };
    let mut last_err = None;
    for c in pick {
        searched.push(c.ub.txg);
        match open_mos(reader, &c.ub).and_then(|mos| walk(&mos, pool_name)) {
            Ok(tree) => {
                if tree.get(name).is_some() {
                    return Ok((c, tree));
                }
            }
            Err(e) => last_err = Some(format!("txg {}: {e}", c.ub.txg)),
        }
    }
    match last_err {
        Some(e) if searched.len() == 1 => eprintln!("zvolrescue: cannot read the pool at {e}"),
        _ => eprintln!(
            "zvolrescue: dataset {name:?} not found at any of {} verified TXG(s){}",
            searched.len(),
            last_err
                .map(|e| format!(" (last error: {e})"))
                .unwrap_or_default()
        ),
    }
    Err(exit::UNRECOVERABLE)
}

/// Turn `--key` into the dataset keys of `enc`, or explain what is
/// missing. No key, an unparsable spec, the wrong format and a wrong key
/// are all exit `USAGE`: the pool is fine, the input is not.
fn unlock(ds: &Dataset, enc: &Encryption, spec: Option<&str>) -> Result<DatasetKeys, u8> {
    let Some(spec) = spec else {
        eprintln!(
            "zvolrescue: {} is encrypted ({}, keyformat {}{}); supply --key raw:FILE | hex:HEX | passphrase:FILE | prompt",
            ds.name,
            enc.suite_name(),
            enc.keyformat_name(),
            enc.keylocation
                .as_ref()
                .map_or(String::new(), |l| format!(", keylocation {l}"))
        );
        return Err(exit::USAGE);
    };
    let material = if spec == "prompt" {
        eprint!("{} ({}) key: ", ds.name, enc.keyformat_name());
        KeyMaterial::prompt(enc.keyformat)
    } else {
        KeyMaterial::from_spec(spec)
    };
    material
        .and_then(|m| wrapping_key(&m, enc))
        .and_then(|w| unwrap_keys(enc, &w))
        .map_err(|e| {
            eprintln!("zvolrescue: {}: {e}", ds.name);
            exit::USAGE
        })
}

/// Extract one volume to `output`. `Err(code)` is a hard failure; a
/// completed-with-errors extraction is an `Ok` report with `aborted` set.
#[allow(clippy::too_many_arguments)]
fn dump_one(
    g: &Global,
    reader: &PoolReader<'_>,
    ds: &Dataset,
    txg: u64,
    time: &str,
    output: &Path,
    strict: bool,
    resume: bool,
) -> Result<DumpOut, u8> {
    let (obj, _) = match open_volume(reader, ds) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("zvolrescue: {}: {e}", ds.name);
            return Err(exit::UNRECOVERABLE);
        }
    };
    // list could not read the size of an encrypted volume; with the
    // keys installed it is readable now.
    let volsize = match ds.volsize {
        Some(v) => v,
        None if reader.has_keys() => match volume_facts(reader, ds) {
            Ok((v, _)) => v,
            Err(e) => {
                eprintln!("zvolrescue: {}: volume size: {e}", ds.name);
                return Err(exit::UNRECOVERABLE);
            }
        },
        None => {
            eprintln!(
                "zvolrescue: {}: volsize unknown ({})",
                ds.name,
                ds.warnings.join("; ")
            );
            return Err(exit::UNRECOVERABLE);
        }
    };
    let blocksize = obj.dnode().datablksz();
    let state_path = resume_path(output);
    let expected_state = ResumeState {
        version: 1,
        dataset: ds.name.clone(),
        dataset_guid: format!("{:#018x}", ds.guid),
        txg,
        volsize,
        blocksize,
        blocks_done: 0,
    };

    // Where to start, and the hash of what is already there.
    let mut start_block = 0u64;
    let mut hasher = Sha256::new();
    let mut sink = if resume {
        let state: Option<ResumeState> = std::fs::read(&state_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok());
        match state {
            Some(s) if ResumeState { blocks_done: 0, ..s.clone_for_compare() } == expected_state => {
                start_block = s.blocks_done;
                let prefix = start_block * blocksize;
                match std::fs::File::open(output) {
                    Ok(mut f) => {
                        let mut left = prefix;
                        let mut buf = vec![0u8; 1 << 20];
                        while left > 0 {
                            let n = (left as usize).min(buf.len());
                            if f.read_exact(&mut buf[..n]).is_err() {
                                eprintln!(
                                    "zvolrescue: {}: shorter than the {prefix} bytes the resume state claims; starting over",
                                    output.display()
                                );
                                start_block = 0;
                                hasher = Sha256::new();
                                break;
                            }
                            hasher.update(&buf[..n]);
                            left -= n as u64;
                        }
                    }
                    Err(e) => {
                        eprintln!("zvolrescue: cannot read {} to resume: {e}; starting over", output.display());
                        start_block = 0;
                    }
                }
                if !g.quiet {
                    eprintln!("  resuming {} at block {start_block}", ds.name);
                }
                if start_block > 0 {
                    SparseFile::open_existing(output)
                } else {
                    SparseFile::create(output)
                }
            }
            Some(_) => {
                eprintln!(
                    "zvolrescue: {} describes a different dataset/txg/size than {}; starting over",
                    state_path.display(),
                    ds.name
                );
                SparseFile::create(output)
            }
            None => SparseFile::create(output),
        }
    } else {
        SparseFile::create(output)
    }
    .map_err(|e| {
        eprintln!("zvolrescue: cannot open {}: {e}", output.display());
        exit::USAGE
    })?;

    let started = Instant::now();
    let quiet = g.quiet;
    let mut last_report = Instant::now();
    let mut last_state = Instant::now();
    let state_file = state_path.clone();
    let progress = |done: u64, total: u64| {
        if !quiet && (last_report.elapsed().as_secs() >= 2 || done == total) {
            eprint!("\r  {} {done}/{total} blocks", ds.name);
            let _ = std::io::stderr().flush();
            last_report = Instant::now();
        }
        if last_state.elapsed().as_secs() >= 5 && done < total {
            let s = ResumeState {
                blocks_done: done,
                ..expected_state.clone_for_compare()
            };
            if let Ok(json) = serde_json::to_vec(&s) {
                let _ = std::fs::write(&state_file, json);
            }
            last_state = Instant::now();
        }
    };
    let on_error = if strict {
        OnError::Abort
    } else {
        OnError::Zero
    };
    let report: Report = match extract_from(
        &obj,
        volsize,
        &mut sink,
        on_error,
        start_block,
        hasher,
        progress,
    ) {
        Ok(r) => r,
        Err(e) => {
            if !quiet {
                eprintln!();
            }
            eprintln!("zvolrescue: {}: extraction failed: {e}", ds.name);
            return Err(exit::UNRECOVERABLE);
        }
    };
    if !quiet {
        eprintln!();
    }
    if report.aborted {
        // Leave a state file so --resume can continue past the fix.
        let done = report.bad.first().map(|b| b.blkid).unwrap_or(start_block);
        let s = ResumeState {
            blocks_done: done,
            ..expected_state.clone_for_compare()
        };
        if let Ok(json) = serde_json::to_vec(&s) {
            let _ = std::fs::write(&state_path, json);
        }
    } else {
        let _ = std::fs::remove_file(&state_path);
    }
    Ok(DumpOut {
        dataset: ds.name.clone(),
        dataset_guid: format!("{:#018x}", ds.guid),
        txg,
        time: time.to_string(),
        output: output.to_path_buf(),
        volsize: report.volsize,
        blocksize: report.blocksize,
        blocks_total: report.blocks_total,
        blocks_read: report.blocks_read,
        blocks_holes: report.blocks_holes,
        blocks_zeroed: report.blocks_zeroed,
        bytes_written: report.bytes_written,
        resumed_from_block: start_block,
        strict,
        aborted: report.aborted,
        sha256: report.sha256.clone(),
        seconds: started.elapsed().as_secs_f64(),
        bad: report
            .bad
            .iter()
            .map(|b| BadOut {
                blkid: b.blkid,
                offset: b.offset,
                len: b.len,
                reason: b.reason.clone(),
            })
            .collect(),
        warnings: ds
            .warnings
            .iter()
            .filter(|w| !(reader.has_keys() && w.contains("encrypted block: no key")))
            .cloned()
            .collect(),
        encryption: ds.encryption.as_ref().map(Encryption::suite_name),
    })
}

impl ResumeState {
    fn clone_for_compare(&self) -> ResumeState {
        ResumeState {
            version: self.version,
            dataset: self.dataset.clone(),
            dataset_guid: self.dataset_guid.clone(),
            txg: self.txg,
            volsize: self.volsize,
            blocksize: self.blocksize,
            blocks_done: self.blocks_done,
        }
    }
}

fn print_text(out: &RunOut) {
    for v in &out.volumes {
        println!(
            "{}: {} bytes from {} at txg {} ({}) -> {}{}",
            v.dataset,
            v.volsize,
            out.pool,
            v.txg,
            v.time,
            v.output.display(),
            if v.resumed_from_block > 0 {
                format!(" (resumed at block {})", v.resumed_from_block)
            } else {
                String::new()
            }
        );
        println!(
            "  blocks: {} total, {} read, {} holes, {} zeroed (unreadable); {} bytes written in {:.1}s",
            v.blocks_total, v.blocks_read, v.blocks_holes, v.blocks_zeroed, v.bytes_written, v.seconds
        );
        println!("  sha256: {}", v.sha256);
        if let Some(e) = &v.encryption {
            println!("  decrypted: {e}");
        }
        for w in &v.warnings {
            println!("  warning: {w}");
        }
        for b in &v.bad {
            println!(
                "  unreadable: blkid {} offset {} len {}: {}",
                b.blkid, b.offset, b.len, b.reason
            );
        }
        if v.aborted {
            println!("  ABORTED at the first unreadable block (--strict); the image is incomplete, --resume continues after a repair");
        } else if !v.bad.is_empty() {
            println!(
                "  WARNING: {} unreadable block(s) were written as zeros; rerun with --strict to refuse partial output",
                v.bad.len()
            );
        }
    }
    for s in &out.skipped {
        println!("skipped: {s}");
    }
    if out.recursive {
        println!(
            "{} volume(s) written; manifest in the output directory",
            out.volumes.len()
        );
    }
}

/// Run `dump`.
pub fn run(g: &Global, spec: &PoolSpec, opts: &Options) -> u8 {
    let members = match open_members(spec) {
        Ok(m) => m,
        Err(code) => return code,
    };
    if let Err(e) = refuse_if_evidence(&opts.output, &members.paths) {
        eprintln!("zvolrescue: refusing to write: {e}");
        return exit::REFUSED;
    }
    let pool = match choose_pool(members.pools.clone(), spec.pool_guid.as_deref()) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let candidates = uberblock_candidates(&members.scans, &pool);
    if candidates.is_empty() {
        eprintln!("zvolrescue: no verified uberblocks on the scanned members");
        return exit::UNRECOVERABLE;
    }
    let reader = PoolReader::new(&pool, members.devices()).with_base_offsets(&members.bases());
    let mut searched = Vec::new();
    let (chosen, tree) = match find_dataset(
        &reader,
        &candidates,
        opts.txg,
        &pool.name,
        &opts.dataset,
        &mut searched,
    ) {
        Ok(x) => x,
        Err(code) => return code,
    };
    let txg = chosen.ub.txg;
    let time = iso8601(chosen.ub.timestamp);

    // Which datasets, and where each one goes.
    let targets: Vec<(&Dataset, PathBuf)> = if opts.recursive {
        if let Err(e) = std::fs::create_dir_all(&opts.output) {
            eprintln!(
                "zvolrescue: cannot create directory {}: {e}",
                opts.output.display()
            );
            return exit::USAGE;
        }
        let prefix = format!("{}/", opts.dataset);
        tree.datasets
            .iter()
            .filter(|d| !d.snapshot && (d.name == opts.dataset || d.name.starts_with(&prefix)))
            .map(|d| {
                (
                    d,
                    opts.output
                        .join(format!("{}.img", d.name.replace('/', "_"))),
                )
            })
            .collect()
    } else {
        vec![(
            tree.get(&opts.dataset).expect("found above"),
            opts.output.clone(),
        )]
    };

    let mut out = RunOut {
        pool: pool.name.clone(),
        pool_guid: format!("{:#018x}", pool.guid),
        members: members.paths.clone(),
        txgs_searched: searched,
        recursive: opts.recursive,
        volumes: Vec::new(),
        skipped: Vec::new(),
    };
    let mut code = 0u8;
    let mut key_cache: std::collections::BTreeMap<u64, DatasetKeys> = Default::default();
    for (ds, output) in targets {
        if opts.recursive && ds.kind != Some(zfs_ondisk::dmu::ObjsetType::Zvol) {
            out.skipped.push(format!("{}: not a volume", ds.name));
            continue;
        }
        reader.set_keys(None);
        if let Some(enc) = &ds.encryption {
            let keys = match key_cache.get(&enc.crypto_key_obj) {
                Some(k) => k.clone(),
                None => match unlock(ds, enc, opts.key.as_deref()) {
                    Ok(k) => {
                        key_cache.insert(enc.crypto_key_obj, k.clone());
                        k
                    }
                    Err(c) => {
                        if opts.recursive {
                            out.skipped
                                .push(format!("{}: encrypted, not unlocked (exit {c})", ds.name));
                            code = code.max(c);
                            continue;
                        }
                        return c;
                    }
                },
            };
            if !g.quiet && g.format == Format::Text {
                println!(
                    "  {}: unlocked ({}, key guid {:#x})",
                    ds.name,
                    enc.suite_name(),
                    keys.key_guid
                );
            }
            reader.set_keys(Some(keys));
        }
        match dump_one(
            g,
            &reader,
            ds,
            txg,
            &time,
            &output,
            opts.strict,
            opts.resume,
        ) {
            Ok(v) => {
                if v.aborted {
                    code = exit::PARTIAL;
                }
                out.volumes.push(v);
            }
            Err(c) => {
                if opts.recursive {
                    out.skipped.push(format!("{}: failed (exit {c})", ds.name));
                    code = code.max(c);
                } else {
                    return c;
                }
            }
        }
    }
    let json = serde_json::to_value(&out).expect("serialisable");
    if opts.recursive {
        let manifest = opts.output.join("manifest.json");
        if let Err(e) = std::fs::write(
            &manifest,
            serde_json::to_string_pretty(&json).expect("serialisable"),
        ) {
            eprintln!("zvolrescue: cannot write {}: {e}", manifest.display());
            code = code.max(exit::USAGE);
        }
    }
    match g.format {
        Format::Json => println!(
            "{}",
            serde_json::to_string_pretty(&json).expect("serialisable")
        ),
        Format::Text => print_text(&out),
    }
    let code = if code == 0 && members.any_failed() {
        exit::EVIDENCE
    } else {
        code
    };
    // Every image this run wrote, with the hash `dump` already computed
    // over it — there is no reason to read a 32 GiB image back to hash
    // what was just hashed on the way out. The manifest of a bulk run is
    // small enough to hash here.
    let mut written: Vec<evidence::FileRef> = out
        .volumes
        .iter()
        .map(|v| evidence::FileRef::known(&v.output, &v.sha256))
        .collect();
    if opts.recursive {
        let manifest = opts.output.join("manifest.json");
        if let Ok(f) = evidence::FileRef::hashed(&manifest) {
            written.push(f);
        }
    }
    g.log_evidence("zvolrescue", &json, code, &members.paths, written)
}
