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

pub mod medium;
pub mod trace;

use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use medium::{Kind, Ledger};

/// A read-only, random-access source of bytes: a device, a partition, an
/// image file, or an in-memory buffer in tests.
pub trait BlockSource {
    /// Total size in bytes.
    fn size(&self) -> u64;

    /// Fill `buf` from `offset`. Fails if the range is not fully readable.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()>;

    /// What this source is: an image, or the medium itself (SPEC N-10).
    /// The default is an image, which is what every in-memory source is.
    fn kind(&self) -> Kind {
        Kind::Image
    }

    /// Fill `buf` from `offset`, keeping what can be kept of a request
    /// that is refused (SPEC F-33). On an image with its imager's map
    /// the map refuses ranges before they are read, so the request is
    /// read again in pieces and then by sector around them, each
    /// refused sector left as zeros and returned as a range relative to
    /// `offset`, in order. On a device nothing is read twice: this is
    /// one read, and its refusal is an incident (N-10). A short source
    /// is still an error: bytes past its end are not unreadable sectors,
    /// they are not there. The default is a plain read.
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
/// reason other than the end of the source, again in pieces aligned to
/// [`SALVAGE_PIECE`] and, within a piece that fails, by
/// [`SALVAGE_SECTOR`]. Sectors that still fail are zeroed and returned
/// as `(start, len)` relative to `offset`, adjacent ones merged.
///
/// For an image whose map refuses ranges (SPEC F-72): the refusals
/// come from the map, and no medium is asked anything twice. A device
/// never takes this path (N-10). Separate from any source so it can be
/// tested against a read that fails where it is told to.
pub fn salvage(
    read: &mut dyn FnMut(u64, &mut [u8]) -> io::Result<()>,
    offset: u64,
    buf: &mut [u8],
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
                    match read(offset + s, sector) {
                        Ok(()) => {}
                        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Err(e),
                        Err(_) => {
                            sector.fill(0);
                            note(s, sector_end - s);
                        }
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
    /// An image, or the medium itself (SPEC N-10).
    kind: Kind,
    /// Where a device's refusals are recorded and judged. Every source
    /// of a run shares one; a device opened without one gets its own,
    /// which stops at the first incident.
    ledger: Arc<Ledger>,
    /// What the imager could not read of this image (SPEC F-72).
    map: Option<ddrescue::Map>,
    /// The last few reads, kept so that a read inside one of them is
    /// answered from memory and no address is asked of a device twice
    /// (SPEC N-10): the labels are read whole first, and the partition
    /// table, the GEOM sector and the rest of a scan's probes lie
    /// inside them. Bounded: [`Self::WINDOWS`] entries of at most
    /// [`Self::WINDOW_MAX`] bytes each.
    windows: Mutex<std::collections::VecDeque<(u64, Arc<[u8]>)>>,
}

impl FileSource {
    /// How many recent reads are kept.
    const WINDOWS: usize = 8;
    /// The largest read kept: a label, and a little more.
    const WINDOW_MAX: usize = 512 << 10;
    /// Open `path` read-only and determine its size.
    ///
    /// Block devices report a zero length from `metadata()`, so the size is
    /// taken from seeking to the end instead.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new().read(true).write(false).open(&path)?;
        let meta = file.metadata()?;
        let ft = meta.file_type();
        let kind = if ft.is_block_device() || ft.is_char_device() {
            Kind::Device
        } else {
            Kind::Image
        };
        let mut size = meta.len();
        if size == 0 {
            size = (&file).seek(SeekFrom::End(0))?;
        }
        Ok(FileSource {
            path,
            file,
            size,
            kind,
            ledger: Arc::new(Ledger::stop_at_first()),
            map: None,
            windows: Mutex::new(std::collections::VecDeque::new()),
        })
    }

    /// Serve `buf` from a recent read that covers it, if one does.
    fn served_from_windows(&self, offset: u64, buf: &mut [u8]) -> bool {
        let windows = self.windows.lock().unwrap_or_else(|p| p.into_inner());
        let end = offset + buf.len() as u64;
        for (start, bytes) in windows.iter() {
            if *start <= offset && end <= *start + bytes.len() as u64 {
                let from = (offset - start) as usize;
                buf.copy_from_slice(&bytes[from..from + buf.len()]);
                return true;
            }
        }
        false
    }

    /// Remember a read, dropping the oldest past [`Self::WINDOWS`].
    fn remember(&self, offset: u64, buf: &[u8]) {
        if buf.len() > Self::WINDOW_MAX {
            return;
        }
        let mut windows = self.windows.lock().unwrap_or_else(|p| p.into_inner());
        if windows.len() >= Self::WINDOWS {
            windows.pop_front();
        }
        windows.push_back((offset, Arc::from(buf)));
    }

    /// The path this source was opened from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Record this source's refusals in `ledger`, the run's, whose
    /// policy decides whether one stops the run (SPEC N-10).
    pub fn with_ledger(mut self, ledger: Arc<Ledger>) -> Self {
        self.ledger = ledger;
        self
    }

    /// The ledger this source's refusals go to.
    pub fn ledger(&self) -> &Arc<Ledger> {
        &self.ledger
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

    /// One read of the file. On a device a refusal — anything but the
    /// end of the device — is an incident: recorded, judged, and
    /// returned as the error the reader acts on (SPEC N-10, F-33).
    fn read_once(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if self.served_from_windows(offset, buf) {
            return Ok(());
        }
        match self.file.read_exact_at(buf, offset) {
            Ok(()) => {
                self.remember(offset, buf);
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Err(e),
            Err(e) if self.kind == Kind::Device => {
                let incident = self.ledger.record(&self.path, offset, buf.len() as u64, &e);
                Err(medium::error_for(incident))
            }
            Err(e) => Err(e),
        }
    }
}

impl BlockSource for FileSource {
    fn size(&self) -> u64 {
        self.size
    }

    fn kind(&self) -> Kind {
        self.kind
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if let Some(m) = &self.map {
            if m.touches(offset, buf.len() as u64) {
                return Err(Self::imager_refused());
            }
        }
        self.read_once(offset, buf)
    }

    fn read_at_salvaging(&self, offset: u64, buf: &mut [u8]) -> io::Result<Vec<(u64, u64)>> {
        // A device is read once; its refusal is an incident, not a
        // range to read around (N-10). An image is read around what its
        // imager's map refuses: those bytes are zeroed and named, never
        // read.
        if self.kind == Kind::Device {
            return self.read_at(offset, buf).map(|()| Vec::new());
        }
        let map = self.map.as_ref();
        let mut read = |o: u64, b: &mut [u8]| {
            if map.is_some_and(|m| m.touches(o, b.len() as u64)) {
                return Err(Self::imager_refused());
            }
            self.file.read_exact_at(b, o)
        };
        salvage(&mut read, offset, buf)
    }
}

/// A source that refuses every read touching the ranges it was given,
/// as a disk with bad sectors does. As an image (the default) it
/// salvages around them the way a mapped [`FileSource`] would; as a
/// device ([`Self::as_device`]) each refusal is an incident in the
/// ledger and nothing is read twice, the way a real device is treated.
/// For tests: a real bad sector is not something a test can make, and
/// this is the next best thing. Every read is counted, so a test can
/// prove that an address was asked for once.
#[derive(Debug)]
pub struct FlakySource<S> {
    inner: S,
    bad: Vec<(u64, u64)>,
    device: Option<(PathBuf, Arc<Ledger>)>,
    reads: Mutex<Vec<(u64, u64)>>,
}

impl<S: BlockSource> FlakySource<S> {
    /// Wrap `inner`; reads touching any `(offset, len)` in `bad` fail
    /// with `EIO`.
    pub fn new(inner: S, bad: Vec<(u64, u64)>) -> Self {
        FlakySource {
            inner,
            bad,
            device: None,
            reads: Mutex::new(Vec::new()),
        }
    }

    /// Behave as a device named `path` whose refusals go to `ledger`.
    pub fn as_device(mut self, path: impl AsRef<Path>, ledger: Arc<Ledger>) -> Self {
        self.device = Some((path.as_ref().to_path_buf(), ledger));
        self
    }

    /// Every read asked of this source so far, as `(offset, len)`.
    pub fn reads(&self) -> Vec<(u64, u64)> {
        self.reads.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// How many reads touched `offset`.
    pub fn reads_touching(&self, offset: u64) -> usize {
        self.reads()
            .iter()
            .filter(|&&(o, l)| o <= offset && offset < o + l)
            .count()
    }
}

impl<S: BlockSource> BlockSource for FlakySource<S> {
    fn size(&self) -> u64 {
        self.inner.size()
    }

    fn kind(&self) -> Kind {
        if self.device.is_some() {
            Kind::Device
        } else {
            Kind::Image
        }
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.reads
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((offset, buf.len() as u64));
        let end = offset + buf.len() as u64;
        if self.bad.iter().any(|&(s, l)| s < end && offset < s + l) {
            let eio = io::Error::from_raw_os_error(5);
            return Err(match &self.device {
                Some((path, ledger)) => {
                    medium::error_for(ledger.record(path, offset, buf.len() as u64, &eio))
                }
                None => eio,
            });
        }
        self.inner.read_at(offset, buf)
    }

    fn read_at_salvaging(&self, offset: u64, buf: &mut [u8]) -> io::Result<Vec<(u64, u64)>> {
        if self.device.is_some() {
            return self.read_at(offset, buf).map(|()| Vec::new());
        }
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
    fn salvage_reads_by_piece_then_by_sector() {
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

    /// A device is asked once. Its refusal is an incident in the ledger
    /// that stops the run, the error carries it, and the salvaging read
    /// — the path a mapped image takes in pieces — is one read too.
    #[test]
    fn a_device_is_asked_once_and_its_refusal_is_an_incident() {
        let disk: Vec<u8> = (0..16384u32).map(|i| (i % 251) as u8).collect();
        let ledger = Arc::new(Ledger::stop_at_first());
        let dev = FlakySource::new(MemSource::new(disk), vec![(9000, 100)])
            .as_device("/dev/da9", ledger.clone());
        assert_eq!(dev.kind(), Kind::Device);
        let mut buf = vec![0u8; 8192];
        let e = dev.read_at_salvaging(4096, &mut buf).unwrap_err();
        let i = medium::incident_of(&e).expect("a medium incident");
        assert_eq!((i.offset, i.len, i.stopped), (4096, 8192, true));
        assert_eq!(i.path, Path::new("/dev/da9"));
        assert_eq!(
            dev.reads(),
            vec![(4096, 8192)],
            "one read, no pieces, no sectors"
        );
        assert_eq!(ledger.incidents().len(), 1);
        assert!(ledger.stopped().is_some());
        // A clean read is a clean read.
        assert!(dev.read_at_salvaging(0, &mut buf).unwrap().is_empty());
        assert_eq!(dev.reads().len(), 2);
    }

    /// With `--device-may-fail` the refusal is skipped — the incident is
    /// recorded and not a stop — and the device is still asked once.
    #[test]
    fn a_device_that_may_fail_is_still_asked_once() {
        let ledger = Arc::new(Ledger::may_fail());
        let dev = FlakySource::new(MemSource::new(vec![1u8; 8192]), vec![(512, 512)])
            .as_device("/dev/sdz", ledger.clone());
        let mut buf = vec![0u8; 4096];
        let e = dev.read_at_salvaging(0, &mut buf).unwrap_err();
        assert!(!medium::incident_of(&e).unwrap().stopped);
        assert_eq!(dev.reads().len(), 1);
        assert!(ledger.stopped().is_none());
    }

    /// A read inside a recent read is served from that read: after the
    /// first 256 KiB are read whole, the first sector, the second and a
    /// 32 KiB run at 1 KiB are all answered without asking the file, and
    /// answered right. Only a bounded number of recent reads are kept.
    #[test]
    fn a_read_inside_a_recent_read_asks_nothing_more() {
        let dir = std::env::temp_dir().join(format!("zvolrescue-io-win-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let img = dir.join("member.img");
        let data: Vec<u8> = (0..(1u32 << 20)).map(|i| (i % 253) as u8).collect();
        std::fs::write(&img, &data).unwrap();
        let f = FileSource::open(&img).unwrap();
        let mut label = vec![0u8; 256 << 10];
        f.read_at(0, &mut label).unwrap();
        assert_eq!(f.windows.lock().unwrap().len(), 1);
        for (at, len) in [(0u64, 512usize), (512, 512), (1024, 32768), (4096, 4096)] {
            let mut b = vec![0u8; len];
            assert!(
                f.served_from_windows(at, &mut b),
                "{at}+{len} lies inside the label read"
            );
            assert_eq!(&b[..], &data[at as usize..at as usize + len]);
            f.read_at(at, &mut b).unwrap();
            assert_eq!(&b[..], &data[at as usize..at as usize + len]);
        }
        assert_eq!(
            f.windows.lock().unwrap().len(),
            1,
            "served reads are not remembered again"
        );
        // A read that only partly overlaps the window is not served from
        // it — not the part that fits, not with the rest zeroed: it goes
        // to the file whole. Straddling the window's end, and starting
        // inside it but running past.
        for (at, len) in [
            ((256u64 << 10) - 512, 1024usize),
            (1, 256 << 10),
            (4096, 256 << 10),
        ] {
            let mut b = vec![0u8; len];
            assert!(
                !f.served_from_windows(at, &mut b),
                "{at}+{len} straddles the label read and must not be served from it"
            );
            f.read_at(at, &mut b).unwrap();
            assert_eq!(&b[..], &data[at as usize..at as usize + len]);
        }
        // Past the label: a fresh read, remembered; the queue is bounded.
        for i in 0..(FileSource::WINDOWS as u64 + 4) {
            let mut b = vec![0u8; 4096];
            f.read_at((512 << 10) + i * 4096, &mut b).unwrap();
        }
        assert_eq!(f.windows.lock().unwrap().len(), FileSource::WINDOWS);
        let mut b = vec![0u8; 4096];
        assert!(
            !f.served_from_windows(0, &mut b),
            "the label read was dropped for newer ones"
        );
        // Too large to keep.
        let mut big = vec![0u8; FileSource::WINDOW_MAX + 1];
        f.read_at(0, &mut big).unwrap();
        assert!(!f.served_from_windows(0, &mut b));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A regular file opened by path is an image, whatever it holds;
    /// a character device is a device.
    #[test]
    fn what_was_opened_is_known() {
        let dir = std::env::temp_dir().join(format!("zvolrescue-io-kind-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let img = dir.join("member.img");
        std::fs::write(&img, vec![0u8; 4096]).unwrap();
        let f = FileSource::open(&img).unwrap();
        assert_eq!(f.kind(), Kind::Image);
        let _ = std::fs::remove_dir_all(&dir);
        if let Ok(null) = FileSource::open("/dev/null") {
            assert_eq!(null.kind(), Kind::Device);
            // Reading past the end of a device is the end, not an incident.
            let mut b = [0u8; 16];
            assert!(null.read_at(0, &mut b).is_err());
            assert!(null.ledger().incidents().is_empty());
        }
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
