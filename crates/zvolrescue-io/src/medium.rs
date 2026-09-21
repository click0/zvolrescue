//! The medium policy (SPEC N-10, F-33): this tool reads healthy media.
//!
//! An input is an image — a regular file — or a device. Metadata is
//! parsed and volumes are extracted from images, clones, or devices
//! that read cleanly. The first read a device refuses is an *incident*:
//! it is recorded here, with everything an operator needs to act on
//! it, and by default it stops the run. Nothing is read twice — no
//! retry, no re-read in pieces, no sector-by-sector pass — because
//! those cost a failing disk what it has left and gain nothing a
//! user-space program can control. Physical recovery is a separate
//! trade: a disk with defects is imaged first, by a tool built for
//! that, and this tool works on the image and its map.
//!
//! `--device-may-fail` is the one way past the first incident, for the
//! operator who has weighed it and needs one small object off a disk
//! that cannot be imaged: each refused range is skipped once, and after
//! [`Ledger::MAY_FAIL_LIMIT`] incidents the run stops anyway.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// The smallest sector any disk has: the unit an LBA is given in.
pub const LBA_SECTOR: u64 = 512;

/// What an input is (SPEC F-68): the policy turns on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A regular file: an image or a clone. Reads fail only when the
    /// imager's map says so, or when the operator's own filesystem does.
    Image,
    /// A block or character device: the medium itself.
    Device,
}

/// One read a device refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incident {
    /// The device.
    pub path: PathBuf,
    /// Byte offset of the refused read on the device.
    pub offset: u64,
    /// Length of the refused read.
    pub len: u64,
    /// What the operating system said, e.g. `Input/output error (os error 5)`.
    pub error: String,
    /// When, as `YYYY-MM-DDTHH:MM:SSZ`.
    pub at: String,
    /// Whether this incident stopped the run: the first one does unless
    /// the operator said the device may fail, and the last allowed one
    /// does regardless.
    pub stopped: bool,
}

impl Incident {
    /// The LBA the refused read starts at, in 512-byte sectors.
    pub fn lba(&self) -> u64 {
        self.offset / LBA_SECTOR
    }

    /// How many 512-byte sectors the refused read covers.
    pub fn sectors(&self) -> u64 {
        self.len.div_ceil(LBA_SECTOR)
    }
}

impl fmt::Display for Incident {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} refused {} byte(s) at byte {} (LBA {}, {} sector(s) of {}): {} at {}",
            self.path.display(),
            self.len,
            self.offset,
            self.lba(),
            self.sectors(),
            LBA_SECTOR,
            self.error,
            self.at
        )
    }
}

/// The record of every incident of a run, and the policy that decides
/// whether the next one stops it. One ledger is shared by every member
/// a run opens.
#[derive(Debug)]
pub struct Ledger {
    may_fail: bool,
    incidents: Mutex<Vec<Incident>>,
}

impl Ledger {
    /// How many incidents `--device-may-fail` allows before the run
    /// stops anyway.
    pub const MAY_FAIL_LIMIT: usize = 8;

    /// The default: the first refused read stops the run.
    pub fn stop_at_first() -> Ledger {
        Ledger {
            may_fail: false,
            incidents: Mutex::new(Vec::new()),
        }
    }

    /// `--device-may-fail`: refused reads are skipped, once each, until
    /// [`Self::MAY_FAIL_LIMIT`] of them.
    pub fn may_fail() -> Ledger {
        Ledger {
            may_fail: true,
            incidents: Mutex::new(Vec::new()),
        }
    }

    /// Whether the operator allowed the device to fail.
    pub fn allows_failure(&self) -> bool {
        self.may_fail
    }

    /// Record a refused read and decide whether it stops the run.
    pub fn record(&self, path: &Path, offset: u64, len: u64, error: &io::Error) -> Incident {
        let mut all = self.incidents.lock().unwrap_or_else(|p| p.into_inner());
        let stopped = !self.may_fail || all.len() + 1 >= Self::MAY_FAIL_LIMIT;
        let incident = Incident {
            path: path.to_path_buf(),
            offset,
            len,
            error: error.to_string(),
            at: now_iso8601(),
            stopped,
        };
        all.push(incident.clone());
        incident
    }

    /// Every incident so far, in order.
    pub fn incidents(&self) -> Vec<Incident> {
        self.incidents
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// The incident that stopped the run, if one did.
    pub fn stopped(&self) -> Option<Incident> {
        self.incidents().into_iter().find(|i| i.stopped)
    }

    /// The incident that closed the device at `path` for the rest of
    /// the run, if one did: a refusal that stopped the run, on that
    /// path. A device that refused is not read again, whatever asks
    /// (SPEC N-10) — the io layer answers every later read of it with
    /// this incident, before touching it. Other devices and every image
    /// go on being read: the run is over, but the report still wants
    /// their labels. A skipped refusal (`--device-may-fail`) closes
    /// nothing; that flag exists so that the other addresses of the
    /// device are still read.
    pub fn stopped_on(&self, path: &Path) -> Option<Incident> {
        self.incidents
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .find(|i| i.stopped && i.path == path)
            .cloned()
    }
}

/// The error a refused device read fails with: carries the incident,
/// so that a reader can tell a medium's refusal from any other failure
/// and act on it without parsing text.
#[derive(Debug)]
pub struct MediumError(pub Incident);

impl fmt::Display for MediumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.stopped {
            write!(f, "medium refused a read, stopping: {}", self.0)
        } else {
            write!(f, "medium refused a read, skipped: {}", self.0)
        }
    }
}

impl std::error::Error for MediumError {}

/// Wrap an incident as the `io::Error` a read returns.
pub fn error_for(incident: Incident) -> io::Error {
    io::Error::other(MediumError(incident))
}

/// The incident behind an `io::Error`, when a medium's refusal is what
/// it is.
pub fn incident_of(e: &io::Error) -> Option<&Incident> {
    e.get_ref()
        .and_then(|inner| inner.downcast_ref::<MediumError>())
        .map(|m| &m.0)
}

/// Seconds since the Unix epoch as `YYYY-MM-DDTHH:MM:SSZ` (Howard
/// Hinnant's civil-from-days; no date crate).
pub fn iso8601(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let secs = unix % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3_600,
        (secs / 60) % 60,
        secs % 60
    )
}

fn now_iso8601() -> String {
    iso8601(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eio() -> io::Error {
        io::Error::from_raw_os_error(5)
    }

    #[test]
    fn the_first_incident_stops_the_run_by_default() {
        let l = Ledger::stop_at_first();
        assert!(l.stopped().is_none());
        let i = l.record(Path::new("/dev/da3"), 8192 + 512 * 3, 4096, &eio());
        assert!(i.stopped);
        assert_eq!(i.lba(), 19);
        assert_eq!(i.sectors(), 8);
        assert_eq!(l.stopped(), Some(i.clone()));
        assert_eq!(l.incidents().len(), 1);
        let s = i.to_string();
        assert!(
            s.contains("/dev/da3 refused 4096 byte(s) at byte 9728 (LBA 19, 8 sector(s) of 512)"),
            "{s}"
        );
        assert!(s.contains("os error 5"), "{s}");
    }

    #[test]
    fn may_fail_skips_until_the_limit_and_then_stops() {
        let l = Ledger::may_fail();
        for n in 1..Ledger::MAY_FAIL_LIMIT {
            let i = l.record(Path::new("/dev/sdb"), n as u64 * 4096, 4096, &eio());
            assert!(!i.stopped, "incident {n} must be skipped");
            assert!(l.stopped().is_none());
        }
        let last = l.record(Path::new("/dev/sdb"), 0, 512, &eio());
        assert!(last.stopped);
        assert_eq!(l.incidents().len(), Ledger::MAY_FAIL_LIMIT);
        assert_eq!(l.stopped().map(|i| i.offset), Some(0));
    }

    #[test]
    fn the_error_carries_its_incident() {
        let l = Ledger::stop_at_first();
        let i = l.record(Path::new("/dev/x"), 512, 512, &eio());
        let e = error_for(i.clone());
        assert_eq!(incident_of(&e), Some(&i));
        assert!(e
            .to_string()
            .starts_with("medium refused a read, stopping: /dev/x"));
        assert!(incident_of(&eio()).is_none());
        let skipped = error_for(Incident {
            stopped: false,
            ..i
        });
        assert!(skipped
            .to_string()
            .starts_with("medium refused a read, skipped:"));
    }

    #[test]
    fn timestamps_are_iso8601_utc() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(1_700_000_000), "2023-11-14T22:13:20Z");
    }
}
