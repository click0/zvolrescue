//! `zvolfiles objects` — one file per object (Z-08).
//!
//! The fallback for when the POSIX metadata is too damaged to walk: the
//! root directory ZAP unreadable, the master node gone, names that lead
//! nowhere. The objects themselves are still there, and their contents
//! are what someone came for; the names can be worked out afterwards
//! from what is inside them.

use std::io::Write;
use std::path::Path;

use serde::Serialize;
use sha2::{Digest, Sha256};
use zvol_common::evidence::FileRef;
use zvol_common::{exit, Format, Global, PoolSpec};
use zvolrescue_io::refuse_if_evidence;

use crate::common::{with_dataset, AtArgs};

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
    let result = with_dataset(spec, dataset, at, |fs, opened| {
        if let Err(e) = refuse_if_evidence(output, &opened.members.paths) {
            eprintln!("zvolfiles: {e}");
            return Err(exit::REFUSED);
        }
        std::fs::create_dir_all(output).map_err(|e| {
            eprintln!("zvolfiles: {}: {e}", output.display());
            exit::USAGE
        })?;
        let max = fs.objects.max_object();
        let mut objects = Vec::new();
        let mut obj = 0;
        while obj <= max {
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
            };
            match write_object(fs, obj, record.size, output, strict) {
                Ok((hash, errors)) => {
                    record.sha256 = Some(hash);
                    record.errors = errors;
                }
                Err(e) => record.error = Some(e),
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
            },
            opened.members.paths.clone(),
            opened.members.ledger.clone(),
        ))
    });
    let (out, paths, ledger) = match result {
        Ok(v) => v,
        // Nothing was produced — the members did not open, or the
        // dataset was not reached — but a device may have refused a
        // read on the way, and that ends the run the same way as one
        // refused later (SPEC F-33, N-10).
        Err(code) => return zvol_common::end_early(g, "zvolfiles", spec, code),
    };

    let json = serde_json::to_value(&out).expect("serialisable");
    let index = output.join("objects.json");
    if let Err(e) = std::fs::write(
        &index,
        serde_json::to_string_pretty(&json).expect("serialisable") + "\n",
    ) {
        eprintln!("zvolfiles: {}: {e}", index.display());
        return exit::USAGE;
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
    let code = if out.incomplete > 0 || out.written < out.objects.len() {
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
    object: u64,
    size: u64,
    output: &Path,
    strict: bool,
) -> Result<(String, u64), String> {
    let obj = fs.object(object).map_err(|e| e.to_string())?;
    let bs = obj.dnode().datablksz().max(512);
    let dir = output.join("objects");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let path = dir.join(format!("{object:06}.bin"));
    let mut file = std::fs::File::create(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut errors = 0u64;
    let zeros = vec![0u8; bs as usize];
    for blkid in 0..size.div_ceil(bs) {
        let chunk = match obj.read_blkid(blkid) {
            Ok(b) => b,
            Err(e) => {
                if strict {
                    return Err(format!("block {blkid}: {e}"));
                }
                errors += 1;
                zeros.clone()
            }
        };
        hasher.update(&chunk);
        file.write_all(&chunk)
            .map_err(|e| format!("{}: {e}", path.display()))?;
    }
    let hex = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok((hex, errors))
}
