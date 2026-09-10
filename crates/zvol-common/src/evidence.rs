//! Append-only JSON Lines evidence log (SPEC F-54).

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// One evidence-log record: which command ran, on what, with what result.
#[derive(Debug, Serialize)]
pub struct Record<'a> {
    /// Unix time the record was written.
    pub ts: u64,
    /// Tool name and version.
    pub tool: &'static str,
    /// Full command line as invoked.
    pub argv: Vec<String>,
    /// Command-specific payload (the same object printed with `-f json`).
    pub result: &'a serde_json::Value,
}

/// Append one record to `path`, creating the file if needed.
pub fn append(path: &Path, result: &serde_json::Value) -> io::Result<()> {
    let rec = Record {
        ts: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        tool: concat!("zvolrescue ", env!("CARGO_PKG_VERSION")),
        argv: std::env::args().collect(),
        result,
    };
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut f, &rec)?;
    f.write_all(b"\n")
}
