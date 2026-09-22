//! `zvolcarve dump` — extract one candidate (C-07).
//!
//! The same pipeline as `zvolrescue dump`, because it is the same code:
//! the candidate's dnode is wrapped in the reader every other extraction
//! uses, and every block is verified by its own checksum before a byte
//! of it reaches the image. A candidate's score bought it a place in the
//! list and nothing else.

use std::path::PathBuf;
use std::time::Instant;

use zfs_ondisk::dmu::DnodePhys;
use zfs_ondisk::Endian;
use zfs_read::dmu::ObjectReader;
use zfs_read::hash::Extra;
use zfs_read::zio::PoolReader;
use zfs_read::zvol::{extract_from, OnError};
use zvol_common::evidence::FileRef;
use zvol_common::members::{choose_pool, open_members};
use zvol_common::{exit, resume, Format, Global, PoolSpec};
use zvolrescue_io::refuse_if_evidence;

use crate::model::{from_hex, load_index};

/// Options of a `dump` run.
pub struct Options {
    pub dir: PathBuf,
    pub candidate: String,
    pub output: PathBuf,
    pub strict: bool,
    pub size: Option<u64>,
    /// Legacy digests to take alongside SHA-256 (SPEC F-53).
    pub hash: Extra,
    /// Continue an interrupted extraction (C-07, SPEC F-32).
    pub resume: bool,
}

/// Run `dump`.
pub fn run(g: &Global, spec: &PoolSpec, opts: &Options) -> u8 {
    // From here a SIGINT ends the extraction at the next block with its
    // state written; before the first block it is the default action.
    let interrupt = zvol_common::interrupt_flag();
    let index = match load_index(&opts.dir) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("zvolcarve: {e}");
            return exit::EVIDENCE;
        }
    };
    let Some(c) = index.candidates.iter().find(|c| c.id == opts.candidate) else {
        eprintln!(
            "zvolcarve: no candidate {} in {} ({} there)",
            opts.candidate,
            opts.dir.display(),
            index.candidates.len()
        );
        return exit::USAGE;
    };
    let bytes = match from_hex(&c.dnode_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("zvolcarve: {}: dnode: {e}", opts.candidate);
            return exit::EVIDENCE;
        }
    };
    let dnode = match DnodePhys::parse(&bytes, Endian::Little) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("zvolcarve: {}: dnode: {e}", opts.candidate);
            return exit::EVIDENCE;
        }
    };

    let members = match open_members(spec) {
        Ok(m) => m,
        Err(code) => return zvol_common::end_early(g, "zvolcarve", spec, code),
    };
    if let Err(e) = refuse_if_evidence(&opts.output, &members.paths) {
        eprintln!("zvolcarve: {e}");
        return zvol_common::end_early(g, "zvolcarve", spec, exit::REFUSED);
    }
    let pool = match choose_pool(members.pools.clone(), spec.pool_guid.as_deref()) {
        Ok(p) => p,
        Err(code) => return zvol_common::end_early(g, "zvolcarve", spec, code),
    };
    let reader = PoolReader::new(&pool, members.devices()).with_base_offsets(&members.bases());
    let obj = ObjectReader::new(&reader, dnode, Endian::Little);

    // The dnode says how many blocks it has, not how large the volume
    // was created: the `zvol_prop` ZAP that knew is not reachable from a
    // carved dnode. Say which number is being used.
    // Where the size comes from, best first: what was asked for, then
    // what the volume's own contents say it was made for (C-12), then
    // what the dnode implies. The last is the weakest — a volume whose
    // tail was never written has fewer blocks than it had bytes.
    let from_contents = c.contents.iter().find_map(|f| f.size);
    let (size, why) = match (opts.size, from_contents) {
        (Some(s), _) => (s, "as asked".to_string()),
        (None, Some(s)) => (
            s,
            format!(
                "the {} inside it was made for this",
                c.contents
                    .iter()
                    .find(|f| f.size.is_some())
                    .map_or("filesystem", |f| f.kind.as_str())
            ),
        ),
        (None, None) => (c.implied_size, "implied by the dnode".to_string()),
    };
    if !g.quiet {
        eprintln!(
            "zvolcarve: {}: {} block(s) of {} bytes, {size} bytes ({why})",
            c.id,
            c.maxblkid + 1,
            c.volblocksize,
        );
    }
    // The same state file, the same resume, as `zvolrescue dump`
    // (C-07): a candidate has no dataset GUID or TXG to record, and
    // says so rather than inventing them.
    let state_path = resume::path(&opts.output);
    let expected_state = resume::State {
        version: 1,
        dataset: c.id.clone(),
        dataset_guid: "candidate".into(),
        txg: 0,
        volsize: size,
        blocksize: obj.dnode().datablksz(),
        blocks_done: 0,
    };
    let (start_block, digests, mut sink) = match resume::open(
        "zvolcarve",
        &c.id,
        &opts.output,
        &expected_state,
        opts.hash,
        opts.resume,
        g.quiet,
    ) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("zvolcarve: {e}");
            return exit::USAGE;
        }
    };
    let on_error = if opts.strict {
        OnError::Abort
    } else {
        OnError::Zero
    };
    let mut last_state = Instant::now();
    let state_file = state_path.clone();
    let progress = |done: u64, total: u64| {
        if last_state.elapsed().as_secs() >= 5 && done < total {
            resume::write(&state_file, &expected_state, done);
            last_state = Instant::now();
        }
    };
    let report = match extract_from(
        &obj,
        size,
        &mut sink,
        on_error,
        start_block,
        digests,
        Some(&interrupt),
        progress,
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("zvolcarve: {}: {e}", c.id);
            return exit::UNRECOVERABLE;
        }
    };
    if let Some(at) = report.interrupted_at {
        eprintln!(
            "zvolcarve: {}: interrupted at block {at} of {}; the image holds the blocks before it, --resume continues there (exit 6)",
            c.id, report.blocks_total
        );
    }
    if report.aborted || report.interrupted_at.is_some() {
        let done = report
            .interrupted_at
            .or_else(|| report.bad.first().map(|b| b.blkid))
            .unwrap_or(start_block);
        resume::write(&state_path, &expected_state, done);
    } else {
        resume::clear(&state_path);
    }

    let out = serde_json::json!({
        "candidate": c.id,
        "output": opts.output,
        "size": size,
        "blocksize": report.blocksize,
        "blocks_total": report.blocks_total,
        "blocks_read": report.blocks_read,
        "blocks_holes": report.blocks_holes,
        "blocks_zeroed": report.blocks_zeroed,
        "blocks_salvaged": report.blocks_salvaged,
        "bytes_written": report.bytes_written,
        "resumed_from_block": start_block,
        "aborted": report.aborted,
        "stopped_by_medium": report.stopped_by_medium,
        "interrupted_at": report.interrupted_at,
        "sha256": report.sha256,
        "sha1": report.sha1,
        "md5": report.md5,
    });
    match g.format {
        Format::Json => println!(
            "{}",
            serde_json::to_string_pretty(&out).expect("serialisable")
        ),
        Format::Text => {
            println!("{}: {} bytes -> {}", c.id, size, opts.output.display());
            println!(
                "  blocks: {} total, {} read, {} holes, {} zeroed (unreadable), {} salvaged (unreadable sectors zeroed)",
                report.blocks_total,
                report.blocks_read,
                report.blocks_holes,
                report.blocks_zeroed,
                report.blocks_salvaged
            );
            println!("  sha256: {}", report.sha256);
            if let Some(h) = &report.sha1 {
                println!("  sha1:   {h}");
            }
            if let Some(h) = &report.md5 {
                println!("  md5:    {h}");
            }
            if let Some(at) = report.interrupted_at {
                println!("  INTERRUPTED at block {at} (exit 6); the image is incomplete, --resume continues there");
            }
        }
    }
    // Either way the image is not the whole volume: say so with the
    // code, not only in the report.
    let code = exit::after_extraction(
        0,
        report.aborted,
        report.blocks_zeroed + report.blocks_salvaged,
    );
    let code = if report.interrupted_at.is_some() {
        code.max(exit::INTERRUPTED)
    } else {
        code
    };
    let written = vec![FileRef::known_with(
        &opts.output,
        &report.sha256,
        report.sha1.as_deref(),
        report.md5.as_deref(),
    )];
    // A device refused a read: every incident on stderr, and the stop —
    // when one stopped the run — as the exit code (SPEC F-33, N-10).
    let code = zvol_common::report_medium(&members.ledger).unwrap_or(code);
    g.log_evidence_with_incidents(
        "zvolcarve",
        &out,
        code,
        &members.paths,
        written,
        &members.ledger.incidents(),
    )
}
