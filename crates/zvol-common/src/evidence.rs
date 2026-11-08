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
use zvolrescue_io::medium::Incident;
// Re-exported so a tool that only depends on this crate can name the
// digests it is checking against (SPEC F-53).
pub use zfs_read::hash::{DigestSet, Digests, Extra};

/// Record format this build writes and understands.
pub const FORMAT_VERSION: u32 = 1;

/// A file a run read or wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRef {
    /// Path as the command named it.
    pub path: PathBuf,
    /// What the path is: a regular file, or a device (SPEC F-68).
    ///
    /// Not a detail of this tool, which reads either the same way, but
    /// of the recovery: a report that says the work was done against
    /// images says something a report that cannot tell does not.
    /// Absent from records written before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<Kind>,
    /// Size in bytes at the time of the run, or 0 if it could not be read.
    pub size: u64,
    /// Hex SHA-256, when it is known.
    ///
    /// Outputs always have one: a tool hashes what it writes. Inputs only
    /// when `--hash-inputs` was given, because hashing multi-terabyte
    /// evidence is slow and the choice is the operator's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Hex SHA-1 of the same file, when `--hash` asked for it while it
    /// was being written (SPEC F-53). Present only on outputs, and only
    /// when asked: nothing recomputes it later, because doing so costs
    /// another full read of the image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha1: Option<String>,
    /// Hex MD5 of the same file, on the same terms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub md5: Option<String>,
}

/// What a path turned out to be (SPEC F-68).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A regular file: an image, or an extracted volume.
    File,
    /// A block device — the evidence itself, not a copy of it.
    Device,
    /// Something else, or something that could not be stat'ed.
    Other,
}

impl Kind {
    /// What `path` is, without opening it.
    pub fn of(path: &Path) -> Kind {
        let Ok(meta) = std::fs::metadata(path) else {
            return Kind::Other;
        };
        if meta.is_file() {
            return Kind::File;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            // A raw disk is a block device everywhere this runs; on
            // FreeBSD it is a character device, and both are the
            // evidence rather than a copy of it.
            let ft = meta.file_type();
            if ft.is_block_device() || ft.is_char_device() {
                return Kind::Device;
            }
        }
        Kind::Other
    }

    /// Whether this is the evidence itself rather than a copy.
    pub fn is_device(self) -> bool {
        self == Kind::Device
    }
}

impl FileRef {
    /// Describe a file without reading its contents.
    pub fn stat(path: &Path) -> FileRef {
        FileRef {
            path: path.to_path_buf(),
            kind: Some(Kind::of(path)),
            size: std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
            sha256: None,
            sha1: None,
            md5: None,
        }
    }

    /// Describe a file whose hash the run already computed.
    pub fn known(path: &Path, sha256: &str) -> FileRef {
        FileRef {
            sha256: Some(sha256.to_string()),
            ..FileRef::stat(path)
        }
    }

    /// The same, with the legacy digests that were taken alongside it
    /// (SPEC F-53).
    pub fn known_with(path: &Path, sha256: &str, sha1: Option<&str>, md5: Option<&str>) -> FileRef {
        FileRef {
            sha1: sha1.map(str::to_string),
            md5: md5.map(str::to_string),
            ..FileRef::known(path, sha256)
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

/// Every digest `extra` names, plus SHA-256, of a file read through once
/// in 1 MiB chunks so a large image never has to fit in memory
/// (SPEC F-53).
pub fn digests_of(path: &Path, extra: Extra) -> io::Result<DigestSet> {
    let mut f = std::fs::File::open(path)?;
    let mut digests = Digests::new(extra);
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        digests.update(&buf[..n]);
    }
    Ok(digests.finish())
}

/// Hex SHA-256 of bytes already in memory.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Hex SHA-256 of a file, read through once.
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
    /// Reads a device refused during the run, each with whether it
    /// stopped the run (SPEC F-33, N-10). Absent when there were none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub incidents: Vec<serde_json::Value>,
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
            incidents: Vec::new(),
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

    /// The device reads the run had refused (SPEC F-33, N-10).
    #[must_use]
    pub fn with_incidents(mut self, incidents: &[Incident]) -> Record {
        self.incidents = crate::incidents_json(incidents);
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
///
/// The record goes out in one `write` of the whole line. Serialised
/// straight into the file it was some 800 writes of a few bytes each,
/// and two runs sharing one case log — two dumps started side by side —
/// interleaved them: half the lines of eight such runs were no longer
/// JSON, and `zvolreport build` refused the log. One write of a line to
/// a file opened for appending lands whole and after whatever is there.
///
/// A log whose last line was cut short — a run killed while it wrote —
/// gets a newline first, so that what is torn stays on a line of its
/// own: appended straight on, the next record was glued to the
/// fragment and lost with it. (A record another run is writing at that
/// very moment can look torn too; then the newline makes an empty line,
/// which a reader passes over.)
pub fn append(path: &Path, rec: &Record) -> io::Result<()> {
    use std::io::{Seek, SeekFrom};
    let mut line = serde_json::to_vec(rec)?;
    line.push(b'\n');
    let mut f = match OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(path)
    {
        Ok(f) => f,
        // A log this run may add to but not read: append without looking.
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            return OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?
                .write_all(&line);
        }
        Err(e) => return Err(e),
    };
    let len = f.metadata()?.len();
    if len > 0 {
        let mut last = [0u8; 1];
        f.seek(SeekFrom::Start(len - 1))?;
        if f.read_exact(&mut last).is_ok() && last[0] != b'\n' {
            line.insert(0, b'\n');
        }
    }
    f.write_all(&line)
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

    fn record(n: u64) -> Record {
        let result = serde_json::json!({"n": n, "pad": "x".repeat(2000)});
        Record::new("zvolrescue", &result, 0)
            .with_outputs(vec![FileRef::known(Path::new("/tmp/disk0.img"), "ab")])
    }

    /// Runs that share a log keep their records whole: serialised into
    /// the file a few bytes at a time, eight runs side by side left half
    /// the lines unreadable.
    #[test]
    fn records_from_runs_side_by_side_stay_whole() {
        let dir =
            std::env::temp_dir().join(format!("zvol-common-evidence-{}-side", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("case.jsonl");
        std::thread::scope(|s| {
            for t in 0..8u64 {
                let log = &log;
                s.spawn(move || {
                    for i in 0..25 {
                        append(log, &record(t * 100 + i)).unwrap();
                    }
                });
            }
        });
        let text = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 200);
        for line in lines {
            serde_json::from_str::<Record>(line).expect("a whole record");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A line cut short by a run that died stays a line of its own: the
    /// next record used to be glued onto it and lost with it.
    #[test]
    fn a_torn_last_line_does_not_take_the_next_record_with_it() {
        let dir =
            std::env::temp_dir().join(format!("zvol-common-evidence-{}-torn", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("case.jsonl");
        append(&log, &record(1)).unwrap();
        let mut torn = serde_json::to_vec(&record(2)).unwrap();
        torn.truncate(300);
        let mut f = OpenOptions::new().append(true).open(&log).unwrap();
        f.write_all(&torn).unwrap();
        drop(f);
        append(&log, &record(3)).unwrap();
        let text = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3, "{text}");
        assert!(serde_json::from_str::<Record>(lines[0]).is_ok());
        assert!(serde_json::from_str::<Record>(lines[1]).is_err());
        let last: Record = serde_json::from_str(lines[2]).expect("the next record is whole");
        assert_eq!(last.result["n"], 3);
        std::fs::remove_dir_all(&dir).ok();
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
