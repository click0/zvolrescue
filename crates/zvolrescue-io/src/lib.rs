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

pub mod trace;

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

    /// Fill `buf` from `offset`, reading around what the device refuses
    /// (SPEC F-33). A disk with a bad sector fails the whole request
    /// that touches it; this retries the request in pieces and then by
    /// sector, leaves each sector the device still refuses as zeros,
    /// and returns those ranges relative to `offset`, in order. A short
    /// device is still an error: bytes past its end are not unreadable
    /// sectors, they are not there. The default is a plain read: a
    /// source that cannot fail per sector has nothing to salvage.
    fn read_at_salvaging(&self, offset: u64, buf: &mut [u8]) -> io::Result<Vec<(u64, u64)>> {
        self.read_at(offset, buf).map(|()| Vec::new())
    }
}

/// The unit a salvage falls back to: the smallest sector any disk has,
/// so nothing readable is given up with what is not.
pub const SALVAGE_SECTOR: u64 = 512;
/// The first retry granularity: a physical 4 KiB sector, so a 512e
/// disk that fails a whole physical sector costs eight reads, not one
/// per logical sector of the request.
const SALVAGE_PIECE: u64 = 4096;

/// Read `buf` from `offset` with `read`, and when that fails for a
/// reason other than the end of the device, again in pieces aligned to
/// [`SALVAGE_PIECE`] and, within a piece that fails, by
/// [`SALVAGE_SECTOR`]. Sectors that still fail are zeroed and returned
/// as `(start, len)` relative to `offset`, adjacent ones merged.
///
/// Separate from any device so it can be tested against a read that
/// fails where it is told to; a real bad sector is not something a test
/// can make.
pub fn salvage(
    read: &mut dyn FnMut(u64, &mut [u8]) -> io::Result<()>,
    offset: u64,
    buf: &mut [u8],
) -> io::Result<Vec<(u64, u64)>> {
    salvage_retrying(read, offset, buf, 0)
}

/// [`salvage`], with each refused sector read again up to `retries`
/// more times before it is given up (SPEC F-33). A marginal sector on a
/// live disk reads on the third try and not on the first; an image
/// file never does, and pays nothing for the allowance.
pub fn salvage_retrying(
    read: &mut dyn FnMut(u64, &mut [u8]) -> io::Result<()>,
    offset: u64,
    buf: &mut [u8],
    retries: u32,
) -> io::Result<Vec<(u64, u64)>> {
    match read(offset, buf) {
        Ok(()) => return Ok(Vec::new()),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Err(e),
        Err(_) => {}
    }
    let len = buf.len() as u64;
    let mut bad: Vec<(u64, u64)> = Vec::new();
    let mut note = |start: u64, n: u64| match bad.last_mut() {
        Some((s, l)) if *s + *l == start => *l += n,
        _ => bad.push((start, n)),
    };
    // Pieces end on absolute multiples of the unit, so a piece is what a
    // physical sector is, not what the request happened to start at.
    let next_edge = |at: u64, unit: u64| ((offset + at) / unit + 1) * unit - offset;
    let mut at = 0;
    while at < len {
        let piece_end = next_edge(at, SALVAGE_PIECE).min(len);
        let piece = &mut buf[at as usize..piece_end as usize];
        match read(offset + at, piece) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Err(e),
            Err(_) => {
                let mut s = at;
                while s < piece_end {
                    let sector_end = next_edge(s, SALVAGE_SECTOR).min(piece_end);
                    let sector = &mut buf[s as usize..sector_end as usize];
                    let mut refused = false;
                    for _ in 0..=retries {
                        match read(offset + s, sector) {
                            Ok(()) => {
                                refused = false;
                                break;
                            }
                            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Err(e),
                            Err(_) => refused = true,
                        }
                    }
                    if refused {
                        sector.fill(0);
                        note(s, sector_end - s);
                    }
                    s = sector_end;
                }
            }
        }
        at = piece_end;
    }
    Ok(bad)
}

/// A GNU ddrescue mapfile (SPEC F-72): what an imager could and could
/// not read of the disk this image came from.
///
/// An image of a failing disk is almost always made with `ddrescue`,
/// and the mapfile beside it is the only record of which bytes the
/// disk actually gave. Where it could not read, `ddrescue` leaves
/// zeros — or, with `--fill`, whatever was asked for — and an image
/// read without its map presents those bytes as data. A block that
/// crosses them then fails its checksum for no reason a reader can
/// name, when the truth is that the disk never produced them. With the
/// map, those sectors are refused *before* the read, the way a disk
/// refuses a bad sector, and the block takes the F-33 path: what the
/// imager did read is kept, the rest is zeros with the reason.
///
/// The format is `ddrescue`'s own (`info ddrescue`, "Mapfile
/// structure"): comment lines, one status line `current_pos
/// current_status [current_pass]`, then one line per block `pos size
/// status`, positions and sizes in hex. Status `+` is finished; `?`
/// non-tried, `*` non-trimmed, `/` non-scraped and `-` bad-sector are
/// all "the disk did not give these bytes", and are treated alike.
pub mod ddrescue {
    use std::collections::BTreeMap;

    /// The map, reduced to what a reader needs.
    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct Map {
        /// Ranges the imager did not finish, merged and in order.
        unreadable: Vec<(u64, u64)>,
        /// Bytes per block status character, as the map has them.
        pub by_status: BTreeMap<char, u64>,
        /// One past the last byte the map describes.
        pub extent: u64,
    }

    impl Map {
        /// Parse the text of a mapfile.
        pub fn parse(text: &str) -> Result<Map, String> {
            let mut map = Map::default();
            let mut seen_status_line = false;
            let mut last_end = 0u64;
            for (n, raw) in text.lines().enumerate() {
                let line = raw.split('#').next().unwrap_or("").trim();
                if line.is_empty() {
                    continue;
                }
                let fields: Vec<&str> = line.split_whitespace().collect();
                if !seen_status_line {
                    // `current_pos current_status [current_pass]`
                    if fields.len() < 2 || fields.len() > 3 {
                        return Err(format!("line {}: not a status line: {raw:?}", n + 1));
                    }
                    seen_status_line = true;
                    continue;
                }
                if fields.len() != 3 {
                    return Err(format!("line {}: want `pos size status`: {raw:?}", n + 1));
                }
                let pos = hex(fields[0])
                    .ok_or_else(|| format!("line {}: bad position {:?}", n + 1, fields[0]))?;
                let size = hex(fields[1])
                    .ok_or_else(|| format!("line {}: bad size {:?}", n + 1, fields[1]))?;
                let status = fields[2]
                    .chars()
                    .next()
                    .ok_or_else(|| format!("line {}: no status", n + 1))?;
                if !matches!(status, '+' | '?' | '*' | '/' | '-') {
                    return Err(format!("line {}: unknown status {status:?}", n + 1));
                }
                if pos < last_end {
                    return Err(format!("line {}: blocks out of order at {pos:#x}", n + 1));
                }
                *map.by_status.entry(status).or_insert(0) += size;
                if status != '+' && size > 0 {
                    match map.unreadable.last_mut() {
                        Some((s, l)) if *s + *l == pos => *l += size,
                        _ => map.unreadable.push((pos, size)),
                    }
                }
                last_end = pos + size;
                map.extent = last_end;
            }
            if !seen_status_line {
                return Err("empty mapfile".into());
            }
            Ok(map)
        }

        /// Ranges the imager did not finish, merged and in order.
        pub fn unreadable(&self) -> &[(u64, u64)] {
            &self.unreadable
        }

        /// Bytes the imager did not finish, in total.
        pub fn unreadable_bytes(&self) -> u64 {
            self.unreadable.iter().map(|&(_, l)| l).sum()
        }

        /// Whether any byte of `[offset, offset + len)` is unfinished.
        pub fn touches(&self, offset: u64, len: u64) -> bool {
            let end = offset.saturating_add(len);
            self.unreadable
                .iter()
                .any(|&(s, l)| s < end && offset < s + l)
        }

        /// The unfinished parts of `[offset, offset + len)`, clipped to
        /// it and relative to `offset`.
        pub fn within(&self, offset: u64, len: u64) -> Vec<(u64, u64)> {
            let end = offset.saturating_add(len);
            self.unreadable
                .iter()
                .filter(|&&(s, l)| s < end && offset < s + l)
                .map(|&(s, l)| {
                    let a = s.max(offset);
                    let b = (s + l).min(end);
                    (a - offset, b - a)
                })
                .collect()
        }
    }

    fn hex(s: &str) -> Option<u64> {
        let t = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
        u64::from_str_radix(t, 16).ok()
    }
}

/// A device or image file opened read-only.
#[derive(Debug)]
pub struct FileSource {
    path: PathBuf,
    file: File,
    size: u64,
    /// Refused sectors are read again this many more times (SPEC F-33).
    retries: u32,
    /// What the imager could not read of this image (SPEC F-72).
    map: Option<ddrescue::Map>,
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
        Ok(FileSource {
            path,
            file,
            size,
            retries: 0,
            map: None,
        })
    }

    /// The path this source was opened from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read a refused sector again up to `n` more times before giving
    /// it up (SPEC F-33).
    pub fn with_retries(mut self, n: u32) -> Self {
        self.retries = n;
        self
    }

    /// Refuse, before reading, every sector the imager's map says the
    /// disk did not give (SPEC F-72).
    pub fn with_map(mut self, map: ddrescue::Map) -> Self {
        self.map = Some(map);
        self
    }

    /// The imager's map, when one was given.
    pub fn map(&self) -> Option<&ddrescue::Map> {
        self.map.as_ref()
    }

    /// The error a read that touches what the imager could not read
    /// fails with: an I/O error, as the disk's own would be, that says
    /// whose refusal it is.
    fn imager_refused() -> io::Error {
        io::Error::other("sector(s) the imager could not read (ddrescue map)")
    }
}

impl BlockSource for FileSource {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if let Some(m) = &self.map {
            if m.touches(offset, buf.len() as u64) {
                return Err(Self::imager_refused());
            }
        }
        self.file.read_exact_at(buf, offset)
    }

    fn read_at_salvaging(&self, offset: u64, buf: &mut [u8]) -> io::Result<Vec<(u64, u64)>> {
        // The imager's map first: what it could not read is not read
        // again here, it is zeroed and named. Then the disk's own
        // refusals, for what the map does not cover.
        let map = self.map.as_ref();
        let mut read = |o: u64, b: &mut [u8]| {
            if map.is_some_and(|m| m.touches(o, b.len() as u64)) {
                return Err(Self::imager_refused());
            }
            self.file.read_exact_at(b, o)
        };
        salvage_retrying(&mut read, offset, buf, self.retries)
    }
}

/// A source that refuses every read touching the ranges it was given,
/// as a disk with bad sectors does, and salvages around them the way a
/// [`FileSource`] would. For tests: a real bad sector is not something
/// a test can make, and this is the next best thing.
#[derive(Debug, Clone)]
pub struct FlakySource<S> {
    inner: S,
    bad: Vec<(u64, u64)>,
}

impl<S: BlockSource> FlakySource<S> {
    /// Wrap `inner`; reads touching any `(offset, len)` in `bad` fail
    /// with `EIO`.
    pub fn new(inner: S, bad: Vec<(u64, u64)>) -> Self {
        FlakySource { inner, bad }
    }
}

impl<S: BlockSource> BlockSource for FlakySource<S> {
    fn size(&self) -> u64 {
        self.inner.size()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let end = offset + buf.len() as u64;
        if self.bad.iter().any(|&(s, l)| s < end && offset < s + l) {
            return Err(io::Error::from_raw_os_error(5)); // EIO
        }
        self.inner.read_at(offset, buf)
    }

    fn read_at_salvaging(&self, offset: u64, buf: &mut [u8]) -> io::Result<Vec<(u64, u64)>> {
        salvage(&mut |o, b| self.read_at(o, b), offset, buf)
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

    /// A read that fails for one sector of a block gives the block back
    /// with that sector zeroed and named, and nothing else lost.
    #[test]
    fn salvage_keeps_every_sector_the_device_will_give() {
        let disk: Vec<u8> = (0..16384u32).map(|i| (i % 251) as u8).collect();
        let src = FlakySource::new(
            MemSource::new(disk.clone()),
            vec![(9000, 100), (10240, 1024)],
        );
        let mut buf = vec![0xffu8; 8192];
        assert!(
            src.read_at(4096, &mut buf).is_err(),
            "a plain read fails whole"
        );
        let bad = src.read_at_salvaging(4096, &mut buf).expect("salvaged");
        // 9000..9100 lies in the sector 8704..9216, i.e. 4608..5120 of the
        // request; 10240..11264 is two sectors, merged: 6144..7168.
        assert_eq!(bad, vec![(4608, 512), (6144, 1024)]);
        for (i, b) in buf.iter().enumerate() {
            let at = 4096 + i as u64;
            let zeroed = (4096 + 4608..4096 + 5120).contains(&at)
                || (4096 + 6144..4096 + 7168).contains(&at);
            assert_eq!(*b, if zeroed { 0 } else { disk[at as usize] }, "byte {at}");
        }
        // A read the device does not refuse costs one read and no ranges.
        let mut buf = vec![0u8; 4096];
        assert_eq!(
            src.read_at_salvaging(0, &mut buf).unwrap(),
            Vec::<(u64, u64)>::new()
        );
        assert_eq!(buf, disk[..4096]);
        // Past the end is not a bad sector.
        let mut buf = vec![0u8; 4096];
        assert_eq!(
            src.read_at_salvaging(16384 - 1024, &mut buf)
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    /// The retry reads in physical-sector pieces first, and only a piece
    /// that fails is read sector by sector.
    #[test]
    fn salvage_retries_by_piece_then_by_sector() {
        let mut reads: Vec<(u64, usize)> = Vec::new();
        let mut buf = vec![0u8; 8192];
        let bad = salvage(
            &mut |o, b| {
                reads.push((o, b.len()));
                // The sector 5120..5632 is bad: every read touching it fails.
                if o < 5632 && o + b.len() as u64 > 5120 {
                    Err(io::Error::from_raw_os_error(5))
                } else {
                    b.fill(1);
                    Ok(())
                }
            },
            0,
            &mut buf,
        )
        .unwrap();
        assert_eq!(bad, vec![(5120, 512)]);
        // The whole request, two 4 KiB pieces, and the failing piece's
        // eight sectors: 1 + 2 + 8 reads.
        assert_eq!(reads.len(), 11);
        assert_eq!(reads[0], (0, 8192));
        assert_eq!(reads[1], (0, 4096));
        assert_eq!(reads[2], (4096, 4096));
        assert!(reads[3..].iter().all(|&(_, n)| n == 512));
        assert_eq!(buf.iter().filter(|&&b| b == 0).count(), 512);
    }

    /// A sector that gives on the third try is read with two retries
    /// and lost with one.
    #[test]
    fn a_retry_allowance_is_spent_per_sector() {
        let attempt = |retries: u32| {
            let mut failures_left = 2;
            let mut buf = vec![0u8; 4096];
            salvage_retrying(
                &mut |o, b| {
                    if o < 1024 && o + b.len() as u64 > 512 && failures_left > 0 {
                        // Anything touching sector 512..1024 fails twice.
                        if b.len() == 512 {
                            failures_left -= 1;
                        }
                        return Err(io::Error::from_raw_os_error(5));
                    }
                    b.fill(7);
                    Ok(())
                },
                0,
                &mut buf,
                retries,
            )
            .unwrap()
        };
        assert_eq!(attempt(1), vec![(512, 512)]);
        assert_eq!(attempt(2), Vec::<(u64, u64)>::new());
    }

    /// The map `ddrescue` writes, in its own format: the unfinished
    /// blocks come out merged, the finished ones do not count, and the
    /// status line and comments are skipped.
    #[test]
    fn a_ddrescue_mapfile_says_what_the_disk_did_not_give() {
        let text = "\
# Mapfile. Created by GNU ddrescue version 1.27
# Command line: ddrescue -d -r3 /dev/sdb sdb.img sdb.map
# Start time:   2026-09-16 10:00:00
# Current time: 2026-09-16 11:30:00
# Finished
# current_pos  current_status  current_pass
0x00100000     +               3
#      pos        size  status
0x00000000  0x00100000  +
0x00100000  0x00000200  -
0x00100200  0x00000200  -
0x00100400  0x0000FC00  +
0x00110000  0x00001000  /
0x00111000  0x00001000  *
0x00112000  0x00001000  ?
0x00113000  0x000ED000  +
";
        let m = ddrescue::Map::parse(text).expect("a map");
        assert_eq!(m.unreadable(), &[(0x100000, 0x400), (0x110000, 0x3000)]);
        assert_eq!(m.unreadable_bytes(), 0x3400);
        assert_eq!(m.extent, 0x200000);
        assert_eq!(m.by_status[&'+'], 0x1FCC00);
        assert_eq!(m.by_status[&'-'], 0x400);
        assert!(m.touches(0x100300, 16));
        assert!(!m.touches(0x100400, 0x1000));
        assert_eq!(m.within(0x0FFE00, 0x400), vec![(0x200, 0x200)]);
        assert_eq!(m.within(0x10F000, 0x5000), vec![(0x1000, 0x3000)]);
        assert!(ddrescue::Map::parse("# only comments\n").is_err());
        assert!(ddrescue::Map::parse("0x0 + 1\n0x0 0x100 x\n").is_err());
        assert!(ddrescue::Map::parse("0x0 + 1\n0x100 0x100 +\n0x0 0x100 +\n").is_err());
    }

    /// With a map, the sectors the imager could not read are refused
    /// without touching the file, and a salvaging read zeroes exactly
    /// them.
    #[test]
    fn a_mapped_image_refuses_what_the_imager_could_not_read() {
        let dir = std::env::temp_dir().join(format!("zvolrescue-io-map-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("img");
        let data: Vec<u8> = (0..16384u32).map(|i| (i % 251) as u8 + 1).collect();
        std::fs::write(&p, &data).unwrap();
        let map = ddrescue::Map::parse("0x0 + 1\n0x0 0x1000 +\n0x1000 0x200 -\n0x1200 0x2e00 +\n")
            .unwrap();
        let f = FileSource::open(&p).unwrap().with_map(map);
        let mut buf = vec![0u8; 8192];
        let err = f.read_at(0, &mut buf).unwrap_err();
        assert!(err.to_string().contains("imager could not read"), "{err}");
        let bad = f.read_at_salvaging(0, &mut buf).unwrap();
        assert_eq!(bad, vec![(0x1000, 0x200)]);
        assert_eq!(&buf[..0x1000], &data[..0x1000]);
        assert!(buf[0x1000..0x1200].iter().all(|&b| b == 0));
        assert_eq!(&buf[0x1200..], &data[0x1200..8192]);
        // Outside the map's holes the file reads as itself.
        let mut tail = vec![0u8; 4096];
        f.read_at(8192, &mut tail).unwrap();
        assert_eq!(tail, data[8192..12288]);
        std::fs::remove_dir_all(&dir).unwrap();
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
