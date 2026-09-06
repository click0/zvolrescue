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
