//! What a report is (COMPANIONS R-02).
//!
//! Deliberately plain data: `build` fills it from evidence records,
//! `verify` reads it back, and the Markdown rendering walks it. Nothing
//! here reads a file or asks the clock — a report is a function of the
//! logs it was built from (R-03).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use zvol_common::evidence::PathText;

/// Report format this build writes.
///
/// Version 2 gives an extraction what version 1 had no place for: the
/// run it is of, as a place in `commands` (`command`), and of a carved
/// volume the name and the GUID of the dataset it was (`dataset_name`,
/// `dataset_guid`).
pub const REPORT_VERSION: u32 = 2;

/// The oldest report format `verify` checks.
///
/// `verify` builds a report again from its logs and compares all of it,
/// so a field a newer format adds would make every report of the older
/// one differ from what this build builds. A report is therefore built
/// again in the format it says it is of: what that format had, and
/// nothing a later one added.
pub const OLDEST_REPORT_VERSION: u32 = 1;

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// A path under `path`, with `path_hex` beside it when it is not text
/// ([`PathText`]).
mod path_text {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(p: &std::path::Path, s: S) -> Result<S::Ok, S::Error> {
        PathText::of(p).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<PathBuf, D::Error> {
        PathText::deserialize(d).map(|t| t.path())
    }
}

/// The same under `output`, with `output_hex`.
mod output_text {
    use super::*;
    use serde::{Deserializer, Serializer};

    #[derive(Serialize, Deserialize)]
    struct Output {
        output: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        output_hex: Option<String>,
    }

    pub fn serialize<S: Serializer>(p: &std::path::Path, s: S) -> Result<S::Ok, S::Error> {
        let t = PathText::of(p);
        Output {
            output: t.path,
            output_hex: t.path_hex,
        }
        .serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<PathBuf, D::Error> {
        Output::deserialize(d).map(|o| {
            PathText {
                path: o.output,
                path_hex: o.output_hex,
            }
            .path()
        })
    }
}

/// One evidence log the report was built from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRef {
    /// Where the log is. Written as an evidence record writes a path:
    /// one that is not text has its bytes beside it. Written plainly,
    /// a build run from a directory whose name is not text ended in a
    /// panic over a report it could not write.
    #[serde(flatten, with = "path_text")]
    pub path: PathBuf,
    /// Records read from it.
    pub records: usize,
    /// Hash of the log itself, so a report can be tied to the log.
    pub sha256: String,
    /// How many bytes of it the hash and the records are of. A log is
    /// appended to and never rewritten, so what a later run added is
    /// after them and is not this report's: hashed whole, any record
    /// appended since broke every report built before it. Absent (0)
    /// from reports built before it existed, whose hash is of the whole.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub bytes: u64,
    /// Lines of it that are not records and were left out, by number:
    /// a run killed while it wrote leaves part of a line behind. Absent
    /// when every line was read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub left_out: Vec<usize>,
}

/// A tool that appears in the logs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ToolRef {
    pub tool: String,
    pub version: String,
}

/// One file, as the logs recorded it. A path that is not text is
/// written with its bytes beside it, as the logs write it
/// ([`PathText`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(from = "RawFileRef", into = "RawFileRef")]
pub struct FileRef {
    pub path: PathBuf,
    /// `file` or `device`, as the run that read it recorded (F-68).
    /// Absent from evidence logs written before that was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<zvol_common::evidence::Kind>,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Legacy digests taken while the file was written, when `--hash`
    /// asked for them (SPEC F-53). Absent everywhere else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha1: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub md5: Option<String>,
}

/// [`FileRef`] as a report holds it.
#[derive(Serialize, Deserialize)]
struct RawFileRef {
    #[serde(flatten)]
    path: PathText,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kind: Option<zvol_common::evidence::Kind>,
    size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sha1: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    md5: Option<String>,
}

impl From<RawFileRef> for FileRef {
    fn from(r: RawFileRef) -> FileRef {
        FileRef {
            path: r.path.path(),
            kind: r.kind,
            size: r.size,
            sha256: r.sha256,
            sha1: r.sha1,
            md5: r.md5,
        }
    }
}

impl From<FileRef> for RawFileRef {
    fn from(f: FileRef) -> RawFileRef {
        RawFileRef {
            path: PathText::of(&f.path),
            kind: f.kind,
            size: f.size,
            sha256: f.sha256,
            sha1: f.sha1,
            md5: f.md5,
        }
    }
}

/// A piece of evidence and what was run against it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    #[serde(flatten)]
    pub file: FileRef,
    /// Tools that read it, in the order they first did.
    pub read_by: Vec<String>,
}

/// One command, as it ran.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Command {
    pub ts: u64,
    pub tool: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    pub argv: Vec<String>,
    pub status: u8,
}

/// What the `scan` records said about a pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pool {
    pub name: String,
    pub guid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Oldest and newest transaction group any member verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txg_window: Option<[u64; 2]>,
    pub readable: bool,
}

/// One dataset that was extracted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Extraction {
    pub dataset: String,
    pub txg: u64,
    #[serde(flatten, with = "output_text")]
    pub output: PathBuf,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Legacy digests of the same image (SPEC F-53).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha1: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub md5: Option<String>,
    /// Blocks that could not be read whole: written as zeros, or kept
    /// with their unreadable sectors zeroed. For a tree of files, the
    /// entries not read whole or not written.
    pub errors: u64,
    /// Blocks written that nothing verified: their pointers name no
    /// checksum (`checksum=off`). Read whole, so not among `errors`,
    /// and not read through a checksum like the rest.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub unverified: u64,
    /// Records the dataset's intent log held that the extraction did
    /// not apply: writes acknowledged as safe that are not in the
    /// output.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub unreplayed: u64,
    /// For a tree of files (`zvolfiles extract`): how many were written,
    /// each of them among the outputs with its hash; `output` is the
    /// manifest that lists them and `sha256` its hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files: Option<u64>,
    /// The extraction stopped early (`--strict` on an unreadable block).
    pub aborted: bool,
    /// A signal ended it before this block; `--resume` goes on from it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interrupted_at: Option<u64>,
    /// A device refused a read and the run stopped there (SPEC F-33).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stopped_by_medium: Option<String>,
    /// The output refused a block, or could not be finished: the image
    /// is not the volume the hash describes, whatever else went well.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_failed: Option<String>,
    /// Found by carving (`zvolcarve dump`): `txg` is the TXG its dnode
    /// was born at, which no uberblock need lead to any more.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub carved: bool,
    /// Of a carved volume, the dataset it was, where `zvolcarve roots`
    /// found a MOS header that names it: `dataset` is the candidate's
    /// place in the scan, which says nothing to a reader, and this is
    /// what the pool called the volume. Report format 2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_name: Option<String>,
    /// And that dataset's GUID, by which the candidate was matched to
    /// the name. Report format 2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_guid: Option<String>,
    /// The run this extraction is of: its place in `commands`, counted
    /// from 0. A volume dumped, interrupted and resumed is three rows
    /// that read alike, and which command — at what time, with what
    /// exit status — gave which was not in the report. Report format 2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<usize>,
    /// Kept, not extracted: a `dump -r --resume` found the image an
    /// earlier run had finished, whole and hashing as that run's
    /// manifest records, and left it. The run read nothing of the pool
    /// for it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub kept: bool,
    /// What the run could not look at: objects whose block of the
    /// object array did not read, newer transaction groups passed over
    /// because they did not read. What is there is whole, and is not
    /// all there was to extract.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unread: Vec<String>,
    /// A later run wrote over the output, and what this extraction
    /// wrote is no longer in the file: which run did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overwritten_by: Option<String>,
    /// Whether the output was finished to its length and flushed, where
    /// the record says. Not part of the report: it decides what is said
    /// of the hash of an output that failed.
    #[serde(skip)]
    pub finished: Option<bool>,
    /// The pool the run read, as its record names it: what R-06 holds
    /// the TXG against. Not part of the report — `verify` compares the
    /// extractions a report holds with those its logs give again, and a
    /// report built by an earlier version does not carry it.
    #[serde(skip)]
    pub pool_guid: Option<String>,
}

impl Extraction {
    /// Whether the run went to its end: not stopped by `--strict`, by a
    /// signal or by a device, and taken whole by its output.
    pub fn ran_to_its_end(&self) -> bool {
        !self.aborted
            && self.interrupted_at.is_none()
            && self.stopped_by_medium.is_none()
            && self.output_failed.is_none()
    }

    /// Whether the image is the whole volume as it could be read: the
    /// run went to its end, and left nothing it could not look at.
    pub fn complete(&self) -> bool {
        self.ran_to_its_end() && self.unread.is_empty()
    }
}

/// What came after an extraction that did not run to its end: runs of
/// the same image — the same volume, at the same TXG, into the same
/// file, which is what a `--resume` goes on with. A dump interrupted and
/// then resumed is two extractions, and only the first of them is not
/// the whole volume.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Later {
    /// A later run of the same image ran to its end: it was finished.
    pub finished: bool,
    /// A later run was of the same image at all: it was gone on with,
    /// whether or not to the end.
    pub gone_on_with: bool,
}

/// [`Later`] for each of `extractions`, in one pass from the last: asked
/// of each against all that follow, a report of a hundred thousand
/// interrupted extractions took half a minute to build and minutes to
/// render.
pub fn later_of_the_same(extractions: &[Extraction]) -> Vec<Later> {
    // Per image: whether one was met, and whether one that ran to its end.
    let mut met: std::collections::HashMap<(&str, u64, &std::path::Path), bool> =
        std::collections::HashMap::new();
    let mut out = vec![Later::default(); extractions.len()];
    for (i, e) in extractions.iter().enumerate().rev() {
        let key = (e.dataset.as_str(), e.txg, e.output.as_path());
        if !e.ran_to_its_end() {
            if let Some(&whole) = met.get(&key) {
                out[i] = Later {
                    finished: whole,
                    gone_on_with: true,
                };
            }
        }
        *met.entry(key).or_insert(false) |= e.ran_to_its_end();
    }
    out
}

#[cfg(test)]
impl Report {
    /// Whether the extraction at `i` was finished by one after it.
    pub fn finished_later(&self, i: usize) -> bool {
        later_of_the_same(&self.extractions)
            .get(i)
            .is_some_and(|l| l.finished)
    }
}

/// The whole report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub report_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub examiner: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    pub logs: Vec<LogRef>,
    pub tools: Vec<ToolRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    pub evidence: Vec<Evidence>,
    pub commands: Vec<Command>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pools: Vec<Pool>,
    /// Every file any of the runs wrote, with the hash it wrote it under.
    pub outputs: Vec<FileRef>,
    pub extractions: Vec<Extraction>,
    /// Anything the report noticed that a reader should not have to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}
