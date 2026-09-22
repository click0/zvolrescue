//! The state an interrupted extraction leaves, and how a run takes it up
//! (SPEC F-32, COMPANIONS C-07).
//!
//! One file next to the output image, `OUT.img.resume.json`, says which
//! dataset the image is of, at which TXG, how big it is, and how many
//! blocks from the start are complete. A run that is asked to `--resume`
//! reads it back, refuses it if it describes something else, hashes the
//! prefix the image already holds, and goes on from the block the state
//! names. `zvolrescue dump` and `zvolcarve dump` share this so that the
//! file one writes is the file the other would write — there is one
//! extraction pipeline, not two that agree by luck.

use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zfs_read::hash::{Digests, Extra};
use zvolrescue_io::SparseFile;

/// Resume state written next to the output image.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    /// Format version of this file; 1.
    pub version: u32,
    /// The dataset — or the carve candidate — the image is of.
    pub dataset: String,
    /// Its GUID as `0x…`, or what the tool has instead of one.
    pub dataset_guid: String,
    /// The TXG it is read at; 0 where there is none (a carved candidate).
    pub txg: u64,
    /// Bytes the finished image will hold.
    pub volsize: u64,
    /// Data block size of the volume.
    pub blocksize: u64,
    /// Blocks `0..blocks_done` are complete in the output.
    pub blocks_done: u64,
}

impl State {
    /// What has to agree for a state to belong to an image: everything
    /// but the count.
    pub fn key(&self) -> State {
        State {
            blocks_done: 0,
            ..self.clone()
        }
    }
}

/// Where the state of `output` lives: `OUT.img.resume.json`.
pub fn path(output: &Path) -> PathBuf {
    let mut p = output.as_os_str().to_owned();
    p.push(".resume.json");
    PathBuf::from(p)
}

/// Record that blocks `0..blocks_done` are complete. Best effort: a
/// state that cannot be written costs a resume, not the run.
pub fn write(state_path: &Path, expected: &State, blocks_done: u64) {
    let s = State {
        blocks_done,
        ..expected.key()
    };
    if let Ok(json) = serde_json::to_vec(&s) {
        let _ = std::fs::write(state_path, json);
    }
}

/// The image is whole: nothing to resume.
pub fn clear(state_path: &Path) {
    let _ = std::fs::remove_file(state_path);
}

/// Open the output for writing, resuming when asked and when the state
/// on disk describes this very image.
///
/// Returns the block to start at, the digests fed with the prefix the
/// image already holds, and the sink. Without `resume`, or with a state
/// that describes something else, the image starts over from block 0 —
/// said on stderr, never silently. `Err` is the message for an output
/// that cannot be opened at all.
pub fn open(
    tool: &str,
    name: &str,
    output: &Path,
    expected: &State,
    extra: Extra,
    resume: bool,
    quiet: bool,
) -> Result<(u64, Digests, SparseFile), String> {
    let state_path = path(output);
    let mut start_block = 0u64;
    let mut digests = Digests::new(extra);
    let sink = if resume {
        let state: Option<State> = std::fs::read(&state_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok());
        match state {
            Some(s) if s.key() == expected.key() => {
                start_block = s.blocks_done;
                let prefix = start_block * expected.blocksize;
                match std::fs::File::open(output) {
                    Ok(mut f) => {
                        let mut left = prefix;
                        let mut buf = vec![0u8; 1 << 20];
                        while left > 0 {
                            let n = (left as usize).min(buf.len());
                            if f.read_exact(&mut buf[..n]).is_err() {
                                eprintln!(
                                    "{tool}: {}: shorter than the {prefix} bytes the resume state claims; starting over",
                                    output.display()
                                );
                                start_block = 0;
                                digests = Digests::new(extra);
                                break;
                            }
                            digests.update(&buf[..n]);
                            left -= n as u64;
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "{tool}: cannot read {} to resume: {e}; starting over",
                            output.display()
                        );
                        start_block = 0;
                    }
                }
                if !quiet {
                    eprintln!("  resuming {name} at block {start_block}");
                }
                if start_block > 0 {
                    SparseFile::open_existing(output)
                } else {
                    SparseFile::create(output)
                }
            }
            Some(_) => {
                eprintln!(
                    "{tool}: {} describes a different dataset/txg/size than {name}; starting over",
                    state_path.display()
                );
                SparseFile::create(output)
            }
            None => SparseFile::create(output),
        }
    } else {
        SparseFile::create(output)
    }
    .map_err(|e| format!("cannot open {}: {e}", output.display()))?;
    Ok((start_block, digests, sink))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zvolrescue_io::BlockSink;

    fn scratch(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("zvol-common-resume-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn expected() -> State {
        State {
            version: 1,
            dataset: "tank/vm/disk0".into(),
            dataset_guid: "0x00000000000000a3".into(),
            txg: 7,
            volsize: 4096 * 4,
            blocksize: 4096,
            blocks_done: 0,
        }
    }

    /// A state that names this image resumes it: the prefix is hashed
    /// back and the sink keeps it; one that names another starts over
    /// and says so; none at all starts over quietly.
    #[test]
    fn a_state_is_taken_up_only_when_it_describes_this_image() {
        let dir = scratch("takeup");
        let out = dir.join("out.img");
        let exp = expected();
        // Two blocks of a four-block image, then a state that says so.
        let prefix: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&out, &prefix).unwrap();
        write(&path(&out), &exp, 2);

        let (start, digests, mut sink) = open(
            "test",
            "tank/vm/disk0",
            &out,
            &exp,
            Extra::none(),
            true,
            true,
        )
        .unwrap();
        assert_eq!(start, 2);
        sink.write_at(8192, &[7u8; 8192]).unwrap();
        sink.finish(16384).unwrap();
        let mut whole = prefix.clone();
        whole.extend_from_slice(&[7u8; 8192]);
        assert_eq!(std::fs::read(&out).unwrap(), whole);
        let mut direct = Digests::new(Extra::none());
        direct.update(&prefix);
        assert_eq!(digests.finish().sha256, direct.finish().sha256);

        // The same state against another dataset: from the start, and
        // the file is truncated by the create.
        let other = State {
            dataset: "tank/vm/disk1".into(),
            ..exp.clone()
        };
        let (start, _, _) = open("test", "disk1", &out, &other, Extra::none(), true, true).unwrap();
        assert_eq!(start, 0);
        assert_eq!(std::fs::metadata(&out).unwrap().len(), 0);

        // Not asked to resume: from the start, whatever the state says.
        write(&path(&out), &exp, 2);
        let (start, _, _) = open(
            "test",
            "tank/vm/disk0",
            &out,
            &exp,
            Extra::none(),
            false,
            true,
        )
        .unwrap();
        assert_eq!(start, 0);

        // A state whose prefix the image no longer holds starts over
        // rather than hashing bytes that are not there.
        std::fs::write(&out, &prefix[..100]).unwrap();
        write(&path(&out), &exp, 2);
        let (start, _, _) = open(
            "test",
            "tank/vm/disk0",
            &out,
            &exp,
            Extra::none(),
            true,
            true,
        )
        .unwrap();
        assert_eq!(start, 0);

        clear(&path(&out));
        assert!(!path(&out).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
