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
use zfs_read::zvol::{extract_from, OnError, Report};
use zvol_common::evidence::FileRef;
use zvol_common::members::{choose_pool, open_members};
use zvol_common::{exit, resume, Format, Global, PoolSpec, WriteGuard};

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

/// How many candidates the index holds, and what they are called.
fn there(candidates: &[crate::model::Candidate]) -> String {
    match (candidates.first(), candidates.last()) {
        (Some(a), Some(b)) => format!("{} there, {} to {}", candidates.len(), a.id, b.id),
        _ => "none there".to_string(),
    }
}

/// The candidate a number names when it is not spelled as the index
/// spells it: `3` or `c3` for `c0003`. It was "no candidate 3", with
/// nothing to say what to type instead.
fn spelled_as(asked: &str, candidates: &[crate::model::Candidate]) -> Option<String> {
    let n: u64 = asked
        .strip_prefix(['c', 'C'])
        .unwrap_or(asked)
        .parse()
        .ok()?;
    let id = format!("c{n:04}");
    (id != asked && candidates.iter().any(|c| c.id == id)).then_some(id)
}

/// Run `dump`.
pub fn run(g: &Global, spec: &PoolSpec, opts: &Options) -> u8 {
    // From here a SIGINT ends the extraction at the next block with its
    // state written. One that comes while the members are still being
    // opened is acted on when the extraction begins, at its first block;
    // a second is the default action, for a run that never gets there.
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
            "zvolcarve: no candidate {} in {} ({}){}",
            opts.candidate,
            opts.dir.display(),
            there(&index.candidates),
            spelled_as(&opts.candidate, &index.candidates)
                .map(|id| format!("; did you mean {id}?"))
                .unwrap_or_default()
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
    // The image and its state go nowhere the run reads: the members,
    // the maps and hints, and the scan's own index this candidate came
    // from.
    let mut reads = spec.reads();
    reads.extend(members.paths.iter().cloned());
    // And the members the scan read, as the index names them: given
    // here by other names — copies, or links — they were not among the
    // reads, and `-o` could name one of them.
    reads.extend(index.members.iter().cloned());
    reads.extend(index.candidates.iter().map(|c| c.path.clone()));
    reads.push(opts.dir.join(crate::model::INDEX));
    reads.push(opts.dir.join(crate::model::STATE));
    let guard = WriteGuard::new(g, &reads);
    let [state, tmp] = resume::sidecars(&opts.output);
    for (what, path) in [
        ("-o", opts.output.clone()),
        ("to write", state),
        ("to write", tmp),
    ] {
        if let Err(code) = guard.refuse("zvolcarve", what, &path) {
            return zvol_common::end_early(g, "zvolcarve", spec, code);
        }
    }
    let pool = match choose_pool(members.pools.clone(), spec.pool_guid.as_deref()) {
        Ok(p) => p,
        Err(code) => return zvol_common::end_early(g, "zvolcarve", spec, code),
    };
    // The candidate's dnode points into the pool the scan read. Read
    // through another pool's members its block pointers lead to
    // whatever is at those offsets there: every block fails its
    // checksum, the image is zeros, and the run ended 4 as if the
    // volume were damaged.
    let guid = format!("{:#018x}", pool.guid);
    if index.pool_guid != "-" && index.pool_guid != guid {
        eprintln!(
            "zvolcarve: {} was made from pool {} ({}); these members are pool {} ({guid}): give the members that scan read",
            opts.dir.display(),
            index.pool,
            index.pool_guid,
            pool.name
        );
        return zvol_common::end_early(g, "zvolcarve", spec, exit::USAGE);
    }
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
            c.maxblkid.saturating_add(1),
            c.volblocksize,
        );
    }
    // The same state file, the same resume, as `zvolrescue dump`
    // (C-07): a candidate has no dataset GUID or TXG to record, and
    // says so rather than inventing them. What it has instead is its
    // dnode, which is the volume: an id is only a place in one scan's
    // list, and `c0001` of another scan — of another pool, or of this
    // one with another profile — has the same id and, often, the same
    // size; its state was taken up and the image went on with the other
    // volume's blocks.
    let expected_state = resume::State {
        version: 1,
        dataset: c.id.clone(),
        dataset_guid: format!(
            "candidate, dnode sha256 {}",
            zvol_common::evidence::sha256_hex(&bytes)
        ),
        txg: 0,
        volsize: size,
        blocksize: obj.dnode().datablksz(),
        blocks_done: 0,
        lost: resume::Lost::default(),
    };
    let (start_block, digests, mut sink, earlier) = match resume::open(
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
    let mut saver = resume::Saver::new(&opts.output, &expected_state, start_block);
    let progress = |done: u64, total: u64, so_far: &Report| {
        if last_state.elapsed().as_secs() >= 5 && done < total {
            let lost = earlier.and(so_far, done);
            if !saver.save(done, &lost) {
                // The image could not be flushed: nothing written to it
                // from here on can be counted. The run stops as a signal
                // stops it, and says why below.
                interrupt.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            last_state = Instant::now();
        }
    };
    let mut report = match extract_from(
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
    if let Some(e) = saver.unflushed() {
        report
            .output_failed
            .get_or_insert_with(|| format!("the image could not be flushed: {e}"));
    }
    let resume_at = saver.conclude(&report, &earlier, start_block);
    let resume_words = if report.output_failed.is_some() {
        saver.words("and --resume continues there once the output has room")
    } else if report.interrupted_at.is_some() || !report.aborted {
        saver.words("--resume continues there")
    } else {
        saver.words("--resume continues after a repair")
    };
    if let Some(why) = &report.output_failed {
        eprintln!("zvolcarve: {}: {why}; {resume_words} (exit 6)", c.id);
    } else if let Some(at) = report.interrupted_at {
        eprintln!(
            "zvolcarve: {}: interrupted at block {at} of {}; {resume_words} (exit 6)",
            c.id, report.blocks_total
        );
    }
    // What the run that was resumed lost is this image's too.
    earlier.into_report(&mut report);

    // The same shape as `zvolrescue dump`'s, `volumes` and all, so that
    // a carve's extraction reaches the report: without it `zvolreport`
    // saw none, and its zeroed blocks were listed nowhere (R-02, C-07).
    let bad: Vec<serde_json::Value> = report
        .bad
        .iter()
        .map(|b| {
            serde_json::json!({
                "blkid": b.blkid, "offset": b.offset, "len": b.len, "reason": b.reason,
            })
        })
        .collect();
    let mut volume = serde_json::json!({
        "dataset": c.id,
        "carved": true,
        // A carved dnode has no TXG of its own to be read at; the one it
        // was born at is the nearest thing.
        "txg": c.birth,
        "output": opts.output,
        "volsize": size,
        "blocksize": report.blocksize,
        "blocks_total": report.blocks_total,
        "blocks_read": report.blocks_read,
        "blocks_holes": report.blocks_holes,
        "blocks_zeroed": report.blocks_zeroed,
        "blocks_salvaged": report.blocks_salvaged,
        "bytes_written": report.bytes_written,
        "resumed_from_block": start_block,
        "strict": opts.strict,
        "aborted": report.aborted,
        "sha256": report.sha256,
    });
    for (key, value) in [
        ("stopped_by_medium", report.stopped_by_medium.clone()),
        ("sha1", report.sha1.clone()),
        ("md5", report.md5.clone()),
    ] {
        if let Some(v) = value {
            volume[key] = v.into();
        }
    }
    if let Some(at) = report.interrupted_at {
        volume["interrupted_at"] = at.into();
    }
    if let Some(why) = &report.output_failed {
        volume["output_failed"] = why.clone().into();
    }
    if let Some(at) = resume_at {
        volume["resume_at"] = at.into();
    }
    if !bad.is_empty() {
        volume["bad"] = bad.clone().into();
    }
    let out = serde_json::json!({
        "candidate": c.id,
        "pool": pool.name,
        "pool_guid": guid,
        "members": members.paths,
        "volumes": [volume],
        "bad": bad,
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
        "output_failed": report.output_failed,
        "resume_at": resume_at,
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
            if let Some(b) = report.bad.first() {
                println!(
                    "  {} unreadable range(s), the first at byte {} (block {}): {}",
                    report.bad.len(),
                    b.offset,
                    b.blkid,
                    b.reason
                );
            }
            if let Some(why) = &report.output_failed {
                println!(
                    "  OUTPUT FAILED (exit 6): {why}; the image is incomplete: {resume_words}"
                );
            } else if let Some(at) = report.interrupted_at {
                println!(
                    "  INTERRUPTED at block {at} (exit 6); the image is incomplete: {resume_words}"
                );
            } else if report.aborted {
                println!("  ABORTED (--strict, exit 4): the image is incomplete: {resume_words}");
            }
            if let Some(why) = &report.stopped_by_medium {
                println!("  STOPPED by the medium: {why}");
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
    let code = if report.interrupted_at.is_some() || report.output_failed.is_some() {
        code.max(exit::INTERRUPTED)
    } else {
        code
    };
    let written: Vec<FileRef> = if zvol_common::evidence::keeps_nothing(&opts.output) {
        Vec::new()
    } else if !report.finished {
        // Not finished: what the file holds is not what was hashed on
        // the way, and the record does not say it is.
        vec![FileRef::stat(&opts.output)]
    } else {
        vec![FileRef::known_with(
            &opts.output,
            &report.sha256,
            report.sha1.as_deref(),
            report.md5.as_deref(),
        )
        .image(report.image_bytes)]
    };
    // A device refused a read: every incident on stderr, and the stop —
    // when one stopped the run — as the exit code (SPEC F-33, N-10).
    let code = zvol_common::report_medium(&members.ledger).unwrap_or(code);
    g.log_evidence_with_incidents(
        "zvolcarve",
        &out,
        code,
        &members.inputs(),
        written,
        &members.ledger.incidents(),
    )
}
