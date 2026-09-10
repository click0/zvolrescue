//! `zvolcarve dump` — extract one candidate (C-07).
//!
//! The same pipeline as `zvolrescue dump`, because it is the same code:
//! the candidate's dnode is wrapped in the reader every other extraction
//! uses, and every block is verified by its own checksum before a byte
//! of it reaches the image. A candidate's score bought it a place in the
//! list and nothing else.

use std::path::PathBuf;

use zfs_ondisk::dmu::DnodePhys;
use zfs_ondisk::Endian;
use zfs_read::dmu::ObjectReader;
use zfs_read::zio::PoolReader;
use zfs_read::zvol::{extract, OnError};
use zvol_common::evidence::FileRef;
use zvol_common::members::{choose_pool, open_members};
use zvol_common::{exit, Format, Global, PoolSpec};
use zvolrescue_io::{refuse_if_evidence, SparseFile};

use crate::model::{from_hex, load_index};

/// Options of a `dump` run.
pub struct Options {
    pub dir: PathBuf,
    pub candidate: String,
    pub output: PathBuf,
    pub strict: bool,
    pub size: Option<u64>,
}

/// Run `dump`.
pub fn run(g: &Global, spec: &PoolSpec, opts: &Options) -> u8 {
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
        Err(code) => return code,
    };
    if let Err(e) = refuse_if_evidence(&opts.output, &members.paths) {
        eprintln!("zvolcarve: {e}");
        return exit::REFUSED;
    }
    let pool = match choose_pool(members.pools.clone(), spec.pool_guid.as_deref()) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let reader = PoolReader::new(&pool, members.devices()).with_base_offsets(&members.bases());
    let obj = ObjectReader::new(&reader, dnode, Endian::Little);

    // The dnode says how many blocks it has, not how large the volume
    // was created: the `zvol_prop` ZAP that knew is not reachable from a
    // carved dnode. Say which number is being used.
    let size = opts.size.unwrap_or(c.implied_size);
    if !g.quiet {
        eprintln!(
            "zvolcarve: {}: {} block(s) of {} bytes, {} bytes{}",
            c.id,
            c.maxblkid + 1,
            c.volblocksize,
            size,
            if opts.size.is_some() {
                " (as asked)"
            } else {
                " implied by the dnode"
            }
        );
    }
    let mut sink = match SparseFile::create(&opts.output) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zvolcarve: {}: {e}", opts.output.display());
            return exit::USAGE;
        }
    };
    let on_error = if opts.strict {
        OnError::Abort
    } else {
        OnError::Zero
    };
    let report = match extract(&obj, size, &mut sink, on_error, |_, _| {}) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("zvolcarve: {}: {e}", c.id);
            return exit::UNRECOVERABLE;
        }
    };

    let out = serde_json::json!({
        "candidate": c.id,
        "output": opts.output,
        "size": size,
        "blocksize": report.blocksize,
        "blocks_total": report.blocks_total,
        "blocks_read": report.blocks_read,
        "blocks_holes": report.blocks_holes,
        "blocks_zeroed": report.blocks_zeroed,
        "bytes_written": report.bytes_written,
        "aborted": report.aborted,
        "sha256": report.sha256,
    });
    match g.format {
        Format::Json => println!(
            "{}",
            serde_json::to_string_pretty(&out).expect("serialisable")
        ),
        Format::Text => {
            println!("{}: {} bytes -> {}", c.id, size, opts.output.display());
            println!(
                "  blocks: {} total, {} read, {} holes, {} zeroed (unreadable)",
                report.blocks_total, report.blocks_read, report.blocks_holes, report.blocks_zeroed
            );
            println!("  sha256: {}", report.sha256);
        }
    }
    // Either way the image is not the whole volume: say so with the
    // code, not only in the report.
    let code = if report.aborted || report.blocks_zeroed > 0 {
        exit::PARTIAL
    } else {
        0
    };
    let written = vec![FileRef::known(&opts.output, &report.sha256)];
    g.log_evidence("zvolcarve", &out, code, &members.paths, written)
}
