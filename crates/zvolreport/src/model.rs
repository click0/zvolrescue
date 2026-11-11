//! What a report is (COMPANIONS R-02).
//!
//! Deliberately plain data: `build` fills it from evidence records,
//! `verify` reads it back, and the Markdown rendering walks it. Nothing
//! here reads a file or asks the clock — a report is a function of the
//! logs it was built from (R-03).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Report format this build writes and understands.
pub const REPORT_VERSION: u32 = 1;

/// One evidence log the report was built from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRef {
    pub path: PathBuf,
    /// Records read from it.
    pub records: usize,
    /// Hash of the log itself, so a report can be tied to the log.
    pub sha256: String,
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

/// One file, as the logs recorded it.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// with their unreadable sectors zeroed.
    pub errors: u64,
    /// The extraction stopped early (`--strict` on an unreadable block).
    pub aborted: bool,
    /// A signal ended it before this block; `--resume` goes on from it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interrupted_at: Option<u64>,
    /// A device refused a read and the run stopped there (SPEC F-33).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stopped_by_medium: Option<String>,
    /// The pool the run read, as its record names it: what R-06 holds
    /// the TXG against. Not part of the report — `verify` compares the
    /// extractions a report holds with those its logs give again, and a
    /// report built by an earlier version does not carry it.
    #[serde(skip)]
    pub pool_guid: Option<String>,
}

impl Extraction {
    /// Whether the image is the whole volume as it could be read: not
    /// stopped by `--strict`, by a signal or by a device.
    pub fn complete(&self) -> bool {
        !self.aborted && self.interrupted_at.is_none() && self.stopped_by_medium.is_none()
    }

    /// Whether `later` finished what this one left: the same volume, at
    /// the same TXG, into the same file, and whole. A dump interrupted
    /// and then `--resume`d is two extractions, and only the first of
    /// them is not the whole volume.
    pub fn finished_by(&self, later: &Extraction) -> bool {
        !self.complete()
            && later.complete()
            && later.dataset == self.dataset
            && later.txg == self.txg
            && later.output == self.output
    }
}

impl Report {
    /// Whether the extraction at `i` was finished by one after it.
    pub fn finished_later(&self, i: usize) -> bool {
        self.extractions
            .get(i)
            .is_some_and(|e| self.extractions[i + 1..].iter().any(|l| e.finished_by(l)))
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
