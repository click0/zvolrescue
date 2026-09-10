//! Append-only JSON Lines evidence log (SPEC F-54, COMPANIONS §1.3).
//!
//! One object per line, appended, never rewritten: which command ran, on
//! what, with what result, and how it ended. `zvolreport` reads these
//! back and checks that the files are still the files, so the record has
//! to carry enough to check — sizes and, where they are known, hashes.

use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Record format this build writes and understands.
pub const FORMAT_VERSION: u32 = 1;

/// A file a run read or wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRef {
    /// Path as the command named it.
    pub path: PathBuf,
    /// Size in bytes at the time of the run, or 0 if it could not be read.
    pub size: u64,
    /// Hex SHA-256, when it is known.
    ///
    /// Outputs always have one: a tool hashes what it writes. Inputs only
    /// when `--hash-inputs` was given, because hashing multi-terabyte
    /// evidence is slow and the choice is the operator's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

impl FileRef {
    /// Describe a file without reading its contents.
    pub fn stat(path: &Path) -> FileRef {
        FileRef {
            path: path.to_path_buf(),
            size: std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
            sha256: None,
        }
    }

    /// Describe a file whose hash the run already computed.
    pub fn known(path: &Path, sha256: &str) -> FileRef {
        FileRef {
            sha256: Some(sha256.to_string()),
            ..FileRef::stat(path)
        }
    }

    /// Describe a file and read it through to hash it.
    pub fn hashed(path: &Path) -> io::Result<FileRef> {
        Ok(FileRef {
            sha256: Some(sha256_of(path)?),
            ..FileRef::stat(path)
        })
    }
}

/// Hex SHA-256 of a file, read in 1 MiB chunks so a large image does not
/// have to fit in memory.
pub fn sha256_of(path: &Path) -> io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// One evidence-log record (format version 1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    /// Record format version. Anything but [`FORMAT_VERSION`] is refused
    /// by the reader rather than guessed at.
    pub v: u32,
    /// Unix time the record was written.
    pub ts: u64,
    /// Tool name, without the version.
    pub tool: String,
    /// Tool version.
    pub version: String,
    /// Host the tool ran on, when it can be told without asking the
    /// system to run anything (see [`host`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Full command line as invoked.
    pub argv: Vec<String>,
    /// Evidence the run read.
    pub inputs: Vec<FileRef>,
    /// Files the run wrote.
    pub outputs: Vec<FileRef>,
    /// The same document the run printed with `-f json`.
    pub result: serde_json::Value,
    /// Exit code the run is about to return.
    pub status: u8,
}

impl Record {
    /// A record for a run of `tool` that ended with `status`.
    pub fn new(tool: &str, result: &serde_json::Value, status: u8) -> Record {
        Record {
            v: FORMAT_VERSION,
            ts: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            tool: tool.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            host: host(),
            argv: std::env::args().collect(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            result: result.clone(),
            status,
        }
    }

    /// The evidence this run read. Hashed only when asked: `--hash-inputs`
    /// on a shelf of disk images costs hours.
    #[must_use]
    pub fn with_inputs(mut self, paths: &[PathBuf], hash: bool) -> Record {
        self.inputs = paths
            .iter()
            .map(|p| {
                if hash {
                    FileRef::hashed(p).unwrap_or_else(|_| FileRef::stat(p))
                } else {
                    FileRef::stat(p)
                }
            })
            .collect();
        self
    }

    /// Files this run wrote, each with the hash the run computed.
    #[must_use]
    pub fn with_outputs(mut self, files: Vec<FileRef>) -> Record {
        self.outputs = files;
        self
    }
}

/// The host name, without running anything.
///
/// A forensic record must not invent one, and §1.4 forbids spawning a
/// process, so this asks the places that already know: the environment a
/// shell exports, then the kernel's own file on Linux, then
/// `/etc/hostname`. When none of them answers, the field is left out.
pub fn host() -> Option<String> {
    for var in ["ZVOL_HOST", "HOSTNAME", "HOST"] {
        if let Ok(v) = std::env::var(var) {
            if !v.trim().is_empty() {
                return Some(v.trim().to_string());
            }
        }
    }
    for file in ["/proc/sys/kernel/hostname", "/etc/hostname"] {
        if let Ok(v) = std::fs::read_to_string(file) {
            if !v.trim().is_empty() {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// Append one record to `path`, creating the file if needed.
pub fn append(path: &Path, rec: &Record) -> io::Result<()> {
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut f, rec)?;
    f.write_all(b"\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_round_trips_through_its_own_format() {
        let result = serde_json::json!({"pool": "tank"});
        let rec = Record::new("zvolrescue", &result, 0)
            .with_outputs(vec![FileRef::known(Path::new("/tmp/disk0.img"), "ab")]);
        let line = serde_json::to_string(&rec).expect("serialisable");
        let back: Record = serde_json::from_str(&line).expect("readable");
        assert_eq!(back.v, FORMAT_VERSION);
        assert_eq!(back.tool, "zvolrescue");
        assert_eq!(back.status, 0);
        assert_eq!(back.result, result);
        assert_eq!(back.outputs[0].sha256.as_deref(), Some("ab"));
        // An input with no hash leaves the field out rather than writing
        // a null a reader would have to special-case.
        assert!(!line.contains("\"sha256\":null"));
    }

    #[test]
    fn the_hash_of_a_file_is_the_hash_of_its_bytes() {
        let dir = std::env::temp_dir().join("zvol-common-evidence-test");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let p = dir.join("empty");
        std::fs::write(&p, b"").expect("write");
        assert_eq!(
            sha256_of(&p).expect("hashed"),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let p = dir.join("abc");
        std::fs::write(&p, b"abc").expect("write");
        let f = FileRef::hashed(&p).expect("hashed");
        assert_eq!(f.size, 3);
        assert_eq!(
            f.sha256.as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
