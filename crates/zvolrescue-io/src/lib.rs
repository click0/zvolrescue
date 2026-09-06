//! Read-only evidence access.
//!
//! [`BlockSource`] is the only way the rest of `zvolrescue` sees a device
//! or image. It has no write methods, and [`FileSource::open`] is the single
//! place in the workspace where an input path becomes a file descriptor —
//! always read-only (SPEC §8.3, invariant 1).
//!
//! The workspace forbids `unsafe_code`; this crate keeps the same setting for
//! now and will relax it to `deny` with per-block `// SAFETY:` comments only
//! if raw `libc` calls become necessary (e.g. `O_EXCL` on block devices).

use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

/// A read-only, random-access source of bytes: a device, a partition, an
/// image file, or an in-memory buffer in tests.
pub trait BlockSource {
    /// Total size in bytes.
    fn size(&self) -> u64;

    /// Fill `buf` from `offset`. Fails if the range is not fully readable.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()>;
}

/// A device or image file opened read-only.
#[derive(Debug)]
pub struct FileSource {
    path: PathBuf,
    file: File,
    size: u64,
}

impl FileSource {
    /// Open `path` read-only and determine its size.
    ///
    /// Block devices report a zero length from `metadata()`, so the size is
    /// taken from seeking to the end instead.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new().read(true).write(false).open(&path)?;
        let mut size = file.metadata()?.len();
        if size == 0 {
            size = (&file).seek(SeekFrom::End(0))?;
        }
        Ok(FileSource { path, file, size })
    }

    /// The path this source was opened from.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl BlockSource for FileSource {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.file.read_exact_at(buf, offset)
    }
}

/// An in-memory source for tests and fixtures.
#[derive(Debug, Clone)]
pub struct MemSource(Vec<u8>);

impl MemSource {
    /// Wrap a buffer.
    pub fn new(bytes: Vec<u8>) -> Self {
        MemSource(bytes)
    }

    /// Mutable access, for tests that damage a fixture after building it.
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl BlockSource for MemSource {
    fn size(&self) -> u64 {
        self.0.len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(offset).map_err(|_| io::ErrorKind::UnexpectedEof)?;
        let end = start
            .checked_add(buf.len())
            .filter(|&e| e <= self.0.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        buf.copy_from_slice(&self.0[start..end]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mem_source_bounds() {
        let m = MemSource::new((0..16).collect());
        let mut b = [0u8; 4];
        m.read_at(12, &mut b).unwrap();
        assert_eq!(b, [12, 13, 14, 15]);
        assert!(m.read_at(13, &mut b).is_err());
        assert!(m.read_at(u64::MAX, &mut b).is_err());
    }

    #[test]
    fn file_source_is_read_only() {
        let dir = std::env::temp_dir().join(format!("zvolrescue-io-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("img");
        std::fs::write(&p, [7u8; 4096]).unwrap();
        let f = FileSource::open(&p).unwrap();
        assert_eq!(f.size(), 4096);
        let mut b = [0u8; 8];
        f.read_at(4088, &mut b).unwrap();
        assert_eq!(b, [7u8; 8]);
        assert!(f.read_at(4090, &mut b).is_err());
        // The handle was opened without write access.
        assert!(f.file.write_at(&[0u8; 1], 0).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

// ---------------------------------------------------------------------------
// Output: sparse writing and the "never onto evidence" check
// ---------------------------------------------------------------------------

use std::io::Write;
use std::os::unix::fs::{FileTypeExt, MetadataExt};

/// Where extracted bytes go. Implementations must tolerate writes in any
/// order and leave unwritten ranges as zeros.
pub trait BlockSink {
    /// Write `buf` at `offset`. All-zero buffers may be skipped to keep the
    /// output sparse; the final length is fixed by [`BlockSink::finish`].
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()>;

    /// Set the final length and flush.
    fn finish(&mut self, len: u64) -> io::Result<()>;
}

/// A file written sparsely: zero-filled blocks are skipped, so holes in
/// the source stay holes on disk.
#[derive(Debug)]
pub struct SparseFile {
    file: File,
    written: u64,
}

impl SparseFile {
    /// Create or truncate `path`.
    pub fn create(path: impl AsRef<Path>) -> io::Result<SparseFile> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        Ok(SparseFile { file, written: 0 })
    }

    /// Open `path` for resuming: existing contents are kept.
    pub fn open_existing(path: impl AsRef<Path>) -> io::Result<SparseFile> {
        let file = OpenOptions::new().write(true).open(path)?;
        Ok(SparseFile { file, written: 0 })
    }

    /// Bytes actually written (holes excluded).
    pub fn bytes_written(&self) -> u64 {
        self.written
    }
}

impl BlockSink for SparseFile {
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()> {
        if buf.iter().all(|&b| b == 0) {
            return Ok(());
        }
        self.file.write_all_at(buf, offset)?;
        self.written += buf.len() as u64;
        Ok(())
    }

    fn finish(&mut self, len: u64) -> io::Result<()> {
        self.file.set_len(len)?;
        self.file.flush()?;
        self.file.sync_all()
    }
}

/// An in-memory sink for tests.
#[derive(Debug, Default)]
pub struct MemSink {
    /// Contents so far.
    pub data: Vec<u8>,
    /// Ranges written, in call order.
    pub writes: Vec<(u64, usize)>,
}

impl BlockSink for MemSink {
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()> {
        let end = offset as usize + buf.len();
        if self.data.len() < end {
            self.data.resize(end, 0);
        }
        self.data[offset as usize..end].copy_from_slice(buf);
        self.writes.push((offset, buf.len()));
        Ok(())
    }

    fn finish(&mut self, len: u64) -> io::Result<()> {
        self.data.resize(len as usize, 0);
        Ok(())
    }
}

/// Refuse an output path that is one of the inputs, or the device an
/// input lives on (SPEC §8.3, invariant 2). Compares `st_dev`/`st_ino` of
/// the canonicalised paths; a not-yet-existing output is checked through
/// its parent directory's device against block-device inputs.
pub fn refuse_if_evidence(output: &Path, inputs: &[PathBuf]) -> io::Result<()> {
    let out_meta = match std::fs::metadata(output) {
        Ok(m) => Some(m),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent_meta = std::fs::metadata(parent)?;
    for input in inputs {
        let Ok(in_meta) = std::fs::metadata(input) else {
            continue;
        };
        if let Some(o) = &out_meta {
            if o.dev() == in_meta.dev() && o.ino() == in_meta.ino() {
                return Err(io::Error::other(format!(
                    "output {} is the same file as input {}",
                    output.display(),
                    input.display()
                )));
            }
        }
        // Writing a file onto a filesystem that lives on an input block
        // device would overwrite evidence through the filesystem.
        let ft = in_meta.file_type();
        if ft.is_block_device() && parent_meta.dev() == in_meta.rdev() {
            return Err(io::Error::other(format!(
                "output directory {} is on input device {}",
                parent.display(),
                input.display()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod sink_tests {
    use super::*;

    #[test]
    fn sparse_file_skips_zero_blocks() {
        let dir = std::env::temp_dir().join(format!("zvolrescue-sink-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("out.img");
        let mut f = SparseFile::create(&p).unwrap();
        f.write_at(0, &[1u8; 4096]).unwrap();
        f.write_at(4096, &[0u8; 4096]).unwrap();
        f.write_at(8192, &[2u8; 4096]).unwrap();
        f.finish(1 << 20).unwrap();
        assert_eq!(f.bytes_written(), 8192);
        let data = std::fs::read(&p).unwrap();
        assert_eq!(data.len(), 1 << 20);
        assert_eq!(data[0], 1);
        assert_eq!(data[4096], 0);
        assert_eq!(data[8192], 2);
        assert_eq!(data[(1 << 20) - 1], 0);
        // Same-file refusal.
        assert!(refuse_if_evidence(&p, std::slice::from_ref(&p)).is_err());
        assert!(refuse_if_evidence(&p, &[dir.join("other")]).is_ok());
        assert!(refuse_if_evidence(&dir.join("new.img"), std::slice::from_ref(&p)).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn mem_sink() {
        let mut m = MemSink::default();
        m.write_at(10, &[7, 7]).unwrap();
        m.finish(16).unwrap();
        assert_eq!(m.data.len(), 16);
        assert_eq!(&m.data[10..12], &[7, 7]);
        assert_eq!(m.writes, vec![(10, 2)]);
    }
}
