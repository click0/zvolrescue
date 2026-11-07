//! `zvolfiles objects` — one file per object (Z-08).
//!
//! The fallback for when the POSIX metadata is too damaged to walk: the
//! root directory ZAP unreadable, the master node gone, names that lead
//! nowhere. The objects themselves are still there, and their contents
//! are what someone came for; the names can be worked out afterwards
//! from what is inside them.

use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use serde::Serialize;
use sha2::{Digest, Sha256};
use zvol_common::evidence::FileRef;
use zvol_common::{exit, Format, Global, PoolSpec};

use crate::common::{with_dataset, AtArgs};
use crate::out::{OutError, OutTree};

#[derive(Debug, Serialize)]
struct ObjectOut {
    object: u64,
    #[serde(rename = "type")]
    kind: String,
    type_code: u8,
    blocksize: u64,
    maxblkid: u64,
    size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
    /// Blocks that could not be read and were written as zeros.
    errors: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// The error was a refusal (exit 5).
    #[serde(skip)]
    refused: bool,
}

#[derive(Debug, Serialize)]
struct ObjectsOut {
    dataset: String,
    txg: u64,
    output: std::path::PathBuf,
    objects: Vec<ObjectOut>,
    /// Objects whose contents were written.
    written: usize,
    /// Objects with at least one block written as zeros.
    incomplete: usize,
    /// What of the dataset's own metadata could not be read: the reason
    /// to be here rather than in `extract` (Z-08).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    damaged: Vec<String>,
    /// A signal ended the run (exit 6); objects after the last listed
    /// were not looked at.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    interrupted: bool,
}

/// Run `objects`.
pub fn run(
    g: &Global,
    spec: &PoolSpec,
    dataset: &str,
    at: &AtArgs,
    output: &Path,
    strict: bool,
) -> u8 {
    // A dataset that claims a great many objects takes long; a signal
    // ends the run at the next object, with the index of what was done.
    let interrupt = zvol_common::interrupt_flag();
    let result = with_dataset(spec, dataset, at, true, |fs, opened| {
        let tree = OutTree::open(g, spec, at, opened, output)?;
        let max = fs.objects.max_object();
        let mut objects = Vec::new();
        let mut obj = 0;
        while obj <= max {
            if interrupt.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            let Ok(d) = fs.objects.get(obj) else {
                obj += 1;
                continue;
            };
            // A large dnode owns the slots that follow it, and those hold
            // the rest of its bonus buffer rather than objects of their
            // own (Z-10). Stepping by one would dump whatever those
            // attribute bytes happen to parse as, as an object that was
            // never there.
            let next = obj + 1 + u64::from(d.extra_slots);
            if d.is_free() {
                obj = next;
                continue;
            }
            let mut record = ObjectOut {
                object: obj,
                kind: d.type_name(),
                type_code: d.object_type,
                blocksize: d.datablksz(),
                maxblkid: d.maxblkid,
                size: d.datablksz().saturating_mul(d.maxblkid.saturating_add(1)),
                sha256: None,
                errors: 0,
                error: None,
                refused: false,
            };
            match write_object(fs, &tree, obj, record.size, output, strict, &interrupt) {
                Ok((hash, errors)) => {
                    record.sha256 = Some(hash);
                    record.errors = errors;
                }
                Err(e) => {
                    record.refused = matches!(e, OutError::Refused(_));
                    record.error = Some(e.to_string());
                }
            }
            objects.push(record);
            obj = next;
        }
        let written = objects.iter().filter(|o| o.error.is_none()).count();
        let incomplete = objects.iter().filter(|o| o.errors > 0).count();
        Ok((
            ObjectsOut {
                dataset: dataset.to_string(),
                txg: opened.txg,
                output: output.to_path_buf(),
                objects,
                written,
                incomplete,
                damaged: fs.damaged.clone(),
                interrupted: interrupt.load(std::sync::atomic::Ordering::Relaxed),
            },
            opened.members.paths.clone(),
            opened.members.ledger.clone(),
            tree,
        ))
    });
    let (out, paths, ledger, tree) = match result {
        Ok(v) => v,
        // Nothing was produced — the members did not open, or the
        // dataset was not reached — but a device may have refused a
        // read on the way, and that ends the run the same way as one
        // refused later (SPEC F-33, N-10).
        Err(code) => return zvol_common::end_early(g, "zvolfiles", spec, code),
    };

    let json = serde_json::to_value(&out).expect("serialisable");
    let index = output.join("objects.json");
    let wrote = tree.create(&index).and_then(|mut f| {
        f.write_all((serde_json::to_string_pretty(&json).expect("serialisable") + "\n").as_bytes())
            .map_err(|e| OutError::Failed(format!("{}: {e}", index.display())))
    });
    if let Err(e) = wrote {
        eprintln!("zvolfiles: {}: {e}", index.display());
        return if matches!(e, OutError::Refused(_)) {
            exit::REFUSED
        } else {
            exit::USAGE
        };
    }
    match g.format {
        Format::Json => println!(
            "{}",
            serde_json::to_string_pretty(&json).expect("serialisable")
        ),
        Format::Text => {
            println!(
                "{} at txg {}: {} object(s), {} written -> {}",
                out.dataset,
                out.txg,
                out.objects.len(),
                out.written,
                out.output.display()
            );
            for o in &out.objects {
                println!(
                    "  {:>6} {:<28} {:>10} bytes{}",
                    o.object,
                    o.kind,
                    o.size,
                    o.error
                        .as_ref()
                        .map_or(String::new(), |e| format!("  ({e})"))
                );
            }
            println!("  index: {}", index.display());
        }
    }
    let refused = out.objects.iter().filter(|o| o.refused).count();
    if refused > 0 {
        eprintln!(
            "zvolfiles: {refused} object(s) refused: the path holds something this run reads (exit 5)"
        );
    }
    if out.interrupted {
        eprintln!("zvolfiles: interrupted; the index lists the objects written (exit 6)");
    }
    let code = if out.interrupted {
        exit::INTERRUPTED
    } else if refused > 0 {
        exit::REFUSED
    } else if out.incomplete > 0 || out.written < out.objects.len() {
        exit::PARTIAL
    } else {
        0
    };
    let written = FileRef::hashed(&index).map(|f| vec![f]).unwrap_or_default();
    // A device refused a read: every incident on stderr, and the stop —
    // when one stopped the run — as the exit code (SPEC F-33, N-10).
    let code = zvol_common::report_medium(&ledger).unwrap_or(code);
    g.log_evidence_with_incidents(
        "zvolfiles",
        &json,
        code,
        &paths,
        written,
        &ledger.incidents(),
    )
}

/// Write one object's blocks to `DIR/objects/NNNNN.bin`.
fn write_object(
    fs: &zfs_read::zpl::Filesystem<'_, '_>,
    tree: &OutTree,
    object: u64,
    size: u64,
    output: &Path,
    strict: bool,
    stop: &std::sync::atomic::AtomicBool,
) -> Result<(String, u64), OutError> {
    let fail = OutError::Failed;
    let obj = fs.object(object).map_err(|e| fail(e.to_string()))?;
    let bs = obj.dnode().datablksz().max(512);
    let path = output.join("objects").join(format!("{object:06}.bin"));
    let mut file = tree.create(&path)?;
    let mut hasher = Sha256::new();
    let mut errors = 0u64;
    let zeros = vec![0u8; bs as usize];
    for blkid in 0..size.div_ceil(bs) {
        if stop.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(fail(format!("interrupted at block {blkid}")));
        }
        let chunk = match obj.read_blkid(blkid) {
            Ok(b) => b,
            Err(e) => {
                if strict {
                    return Err(fail(format!("block {blkid}: {e}")));
                }
                errors += 1;
                zeros.clone()
            }
        };
        hasher.update(&chunk);
        // A hole, or a block of zeros, is left a hole.
        if chunk.iter().any(|&b| b != 0) {
            file.seek(SeekFrom::Start(blkid * bs))
                .and_then(|_| file.write_all(&chunk))
                .map_err(|e| fail(format!("{}: {e}", path.display())))?;
        }
    }
    file.set_len(size.div_ceil(bs) * bs)
        .map_err(|e| fail(format!("{}: {e}", path.display())))?;
    let hex = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok((hex, errors))
}
