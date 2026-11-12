//! Scratch directories for tests, gone when the test is.
//!
//! The tests write members, images and workspaces under the system's
//! temporary directory, one directory per test and per process, and
//! most of them left it there: a thousand of them after a day of runs,
//! 129 MiB a time for the timeline's, until the disk was full. A
//! [`Scratch`] is removed when it is dropped — when the test that made
//! it ends. A test that fails keeps it, and says where, for whoever
//! looks into the failure; the next run of that test removes it.
//!
//! A library module rather than a test-only one, as `zfs_read::fixture`
//! is: the tests of every program use it, and a test of one crate cannot
//! see another's `cfg(test)` code.

use std::path::{Path, PathBuf};

/// A directory that is removed when this is dropped, unless the thread
/// is panicking — a failed test keeps what it wrote.
#[derive(Debug)]
pub struct Scratch {
    path: PathBuf,
}

impl Scratch {
    /// A fresh, empty `PREFIX-PID-NAME` under the temporary directory.
    ///
    /// What an earlier run of the same test kept — `PREFIX-N-NAME` for
    /// any process `N` that is no longer running — is removed first;
    /// exactly that name, so that tests running beside this one in the
    /// same process keep theirs.
    pub fn new(prefix: &str, name: &str) -> Scratch {
        let tmp = std::env::temp_dir();
        if let Ok(entries) = std::fs::read_dir(&tmp) {
            for e in entries.flatten() {
                let n = e.file_name().to_string_lossy().into_owned();
                let pid = n
                    .strip_prefix(prefix)
                    .and_then(|r| r.strip_prefix('-'))
                    .and_then(|r| r.strip_suffix(name))
                    .and_then(|r| r.strip_suffix('-'));
                if pid.is_some_and(|p| {
                    !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && !running(p)
                }) {
                    let _ = std::fs::remove_dir_all(e.path());
                }
            }
        }
        let path = tmp.join(format!("{prefix}-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("scratch directory");
        Scratch { path }
    }

    /// Where it is.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Whether process `pid` is running, where `/proc` can say; elsewhere
/// only this process is known to be.
fn running(pid: &str) -> bool {
    if pid == std::process::id().to_string() {
        return true;
    }
    Path::new("/proc/self").exists() && Path::new("/proc").join(pid).exists()
}

impl std::ops::Deref for Scratch {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.path
    }
}

impl AsRef<Path> for Scratch {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("scratch kept for the failure: {}", self.path.display());
        } else {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Scratch;

    /// Gone when dropped; an earlier run's, of a process that is no
    /// longer running, is cleared; one of a longer name is not touched.
    #[test]
    fn a_scratch_directory_goes_with_its_test() {
        let path = {
            let s = Scratch::new("zvol-common-scratch", "drop");
            std::fs::write(s.join("f"), b"x").unwrap();
            s.path().to_path_buf()
        };
        assert!(!path.exists());

        let tmp = std::env::temp_dir();
        // No process has this id: it is past every pid_max.
        let stale = tmp.join("zvol-common-scratch-4294967295-left");
        let longer = tmp.join("zvol-common-scratch-4294967295-left-over");
        std::fs::create_dir_all(&stale).unwrap();
        std::fs::create_dir_all(&longer).unwrap();
        let s = Scratch::new("zvol-common-scratch", "left");
        assert!(!stale.exists());
        assert!(longer.exists());
        assert!(s.is_dir());
        std::fs::remove_dir_all(&longer).unwrap();
    }
}
