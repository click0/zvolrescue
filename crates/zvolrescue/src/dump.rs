//! `dump`: extract a volume to a raw sparse image.

use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

use serde::Serialize;
use zfs_read::dsl::{open_mos, walk, Dataset};
use zfs_read::pool::{select_uberblock, uberblock_candidates, Candidate, TxgSelect};
use zfs_read::zio::PoolReader;
use zfs_read::zvol::{extract, open_volume, OnError, Report};
use zvolrescue_io::{refuse_if_evidence, SparseFile};

use crate::list::{choose_pool, open_members};
use crate::timefmt::iso8601;
use crate::{evidence, exit, Format, Global, PoolSpec};

/// Options of the `dump` command.
pub struct Options {
    /// Dataset name.
    pub dataset: String,
    /// Output image path.
    pub output: PathBuf,
    /// Exact TXG; default is the newest that still has the dataset.
    pub txg: Option<u64>,
    /// Abort on the first unreadable block.
    pub strict: bool,
    /// Encryption key spec (phase 2).
    pub key: Option<String>,
    /// Resume (phase 2).
    pub resume: bool,
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
    pool: String,
    pool_guid: String,
    members: Vec<PathBuf>,
    dataset: String,
    dataset_guid: String,
    txg: u64,
    time: String,
    /// TXGs that were walked before the dataset was found (newest first).
    txgs_searched: Vec<u64>,
    output: PathBuf,
    volsize: u64,
    blocksize: u64,
    blocks_total: u64,
    blocks_read: u64,
    blocks_holes: u64,
    blocks_zeroed: u64,
    bytes_written: u64,
    strict: bool,
    aborted: bool,
    sha256: String,
    seconds: f64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    bad: Vec<BadOut>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

fn find_dataset<'c>(
    reader: &PoolReader<'_>,
    candidates: &'c [Candidate],
    sel: Option<u64>,
    pool_name: &str,
    name: &str,
    searched: &mut Vec<u64>,
) -> Result<(&'c Candidate, Dataset), u8> {
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
                if let Some(d) = tree.get(name) {
                    return Ok((c, d.clone()));
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

fn print_text(out: &DumpOut) {
    println!(
        "{}: {} bytes from {} at txg {} ({}) -> {}",
        out.dataset,
        out.volsize,
        out.pool,
        out.txg,
        out.time,
        out.output.display()
    );
    println!(
        "  blocks: {} total, {} read, {} holes, {} zeroed (unreadable); {} bytes written in {:.1}s",
        out.blocks_total,
        out.blocks_read,
        out.blocks_holes,
        out.blocks_zeroed,
        out.bytes_written,
        out.seconds
    );
    println!("  sha256: {}", out.sha256);
    for w in &out.warnings {
        println!("  warning: {w}");
    }
    for b in &out.bad {
        println!(
            "  unreadable: blkid {} offset {} len {}: {}",
            b.blkid, b.offset, b.len, b.reason
        );
    }
    if out.aborted {
        println!("  ABORTED at the first unreadable block (--strict); the image is incomplete");
    } else if !out.bad.is_empty() {
        println!(
            "  WARNING: {} unreadable block(s) were written as zeros; rerun with --strict to refuse partial output",
            out.bad.len()
        );
    }
}

/// Run `dump`.
pub fn run(g: &Global, spec: &PoolSpec, opts: &Options) -> u8 {
    if opts.key.is_some() {
        eprintln!("zvolrescue: --key (encrypted datasets) arrives in phase 2 (docs/SPEC.md §10)");
        return exit::NOT_IMPLEMENTED;
    }
    if opts.resume {
        eprintln!("zvolrescue: --resume arrives in phase 2 (docs/SPEC.md §10)");
        return exit::NOT_IMPLEMENTED;
    }
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
    let reader = PoolReader::new(&pool, members.devices());
    let mut searched = Vec::new();
    let (chosen, ds) = match find_dataset(
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
    let (obj, _) = match open_volume(&reader, &ds) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("zvolrescue: {}: {e}", opts.dataset);
            return exit::UNRECOVERABLE;
        }
    };
    let Some(volsize) = ds.volsize else {
        eprintln!(
            "zvolrescue: {}: volsize unknown ({})",
            opts.dataset,
            ds.warnings.join("; ")
        );
        return exit::UNRECOVERABLE;
    };
    let mut sink = match SparseFile::create(&opts.output) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zvolrescue: cannot create {}: {e}", opts.output.display());
            return exit::USAGE;
        }
    };
    let started = Instant::now();
    let quiet = g.quiet;
    let mut last_report = Instant::now();
    let progress = |done: u64, total: u64| {
        if !quiet && (last_report.elapsed().as_secs() >= 2 || done == total) {
            eprint!("\r  {done}/{total} blocks");
            let _ = std::io::stderr().flush();
            last_report = Instant::now();
        }
    };
    let on_error = if opts.strict {
        OnError::Abort
    } else {
        OnError::Zero
    };
    let report: Report = match extract(&obj, volsize, &mut sink, on_error, progress) {
        Ok(r) => r,
        Err(e) => {
            if !quiet {
                eprintln!();
            }
            eprintln!("zvolrescue: extraction failed: {e}");
            return exit::UNRECOVERABLE;
        }
    };
    if !quiet {
        eprintln!();
    }
    let out = DumpOut {
        pool: pool.name.clone(),
        pool_guid: format!("{:#018x}", pool.guid),
        members: members.paths.clone(),
        dataset: ds.name.clone(),
        dataset_guid: format!("{:#018x}", ds.guid),
        txg: chosen.ub.txg,
        time: iso8601(chosen.ub.timestamp),
        txgs_searched: searched,
        output: opts.output.clone(),
        volsize: report.volsize,
        blocksize: report.blocksize,
        blocks_total: report.blocks_total,
        blocks_read: report.blocks_read,
        blocks_holes: report.blocks_holes,
        blocks_zeroed: report.blocks_zeroed,
        bytes_written: report.bytes_written,
        strict: opts.strict,
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
        warnings: ds.warnings.clone(),
    };
    let json = serde_json::to_value(&out).expect("serialisable");
    match g.format {
        Format::Json => println!(
            "{}",
            serde_json::to_string_pretty(&json).expect("serialisable")
        ),
        Format::Text => print_text(&out),
    }
    if let Some(log) = &g.evidence_log {
        if let Err(e) = evidence::append(log, &json) {
            eprintln!(
                "zvolrescue: cannot write evidence log {}: {e}",
                log.display()
            );
            return exit::USAGE;
        }
    }
    if report.aborted {
        exit::PARTIAL
    } else if members.any_failed() {
        exit::EVIDENCE
    } else {
        0
    }
}
