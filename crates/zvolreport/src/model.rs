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
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
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
    /// Blocks that could not be read and were written as zeros.
    pub errors: u64,
    /// The extraction stopped early (`--strict` on an unreadable block).
    pub aborted: bool,
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
