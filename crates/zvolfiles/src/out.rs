//! Writing into the output directory (SPEC §8.3, invariant 2).
//!
//! `extract` and `objects` write many files under one directory, and a
//! check made once for the directory says nothing about what is already
//! inside it. A member of the pool lying there under the name of a file
//! in the dataset was truncated to that file; a symbolic link left there
//! was written through to wherever it pointed, a member included.
//!
//! So nothing already in the tree is written through. Every path is made
//! from the output directory down, one component at a time. A symbolic
//! link in the way of a directory or a file is removed — which touches
//! only the link — and the entry is made in its place; a file in the way
//! of a file is removed and made again, the way `tar` extracts over one;
//! and every file is opened with `create_new`, which does not follow a
//! link. Before anything in the way is removed, and before anything new
//! is made, the path is put to the run's [`WriteGuard`]: an entry that is
//! one of the inputs, or a directory on a filesystem that lives on an
//! input device, is refused rather than replaced.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use zfs_read::crypt::KeyMaterial;
use zvol_common::{exit, Blocked, Global, PoolSpec, WriteGuard};

use crate::common::{AtArgs, Opened};

/// What went wrong with one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutError {
    /// Writing it would have reached what the run reads (exit 5).
    Refused(String),
    /// It could not be written.
    Failed(String),
}

impl std::fmt::Display for OutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutError::Refused(why) => write!(f, "refused: {why}"),
            OutError::Failed(why) => f.write_str(why),
        }
    }
}

impl From<Blocked> for OutError {
    fn from(b: Blocked) -> OutError {
        match b {
            Blocked::Refused(why) => OutError::Refused(why),
            // A name too long, a directory not to be entered: the entry
            // cannot be written, which is a failure of that entry — said
            // as a refusal it read "the path holds something this run
            // reads", and the run exited 5.
            Blocked::Unchecked(why) => OutError::Failed(why),
        }
    }
}

/// The output directory and the rules it is written by.
#[derive(Debug, Clone)]
pub struct OutTree {
    root: PathBuf,
    guard: WriteGuard,
}

impl OutTree {
    /// Check `root` against everything the run reads, and make it.
    pub fn open(
        g: &Global,
        spec: &PoolSpec,
        at: &AtArgs,
        opened: &Opened<'_>,
        root: &Path,
    ) -> Result<OutTree, u8> {
        let mut reads = spec.reads();
        reads.extend(opened.members.paths.iter().cloned());
        reads.extend(at.key.as_deref().and_then(KeyMaterial::spec_file));
        let guard = WriteGuard::new(g, &reads);
        guard.refuse("zvolfiles", "-o", root)?;
        std::fs::create_dir_all(root).map_err(|e| {
            eprintln!("zvolfiles: {}: {e}", root.display());
            exit::USAGE
        })?;
        Ok(OutTree {
            root: root.to_path_buf(),
            guard,
        })
    }

    /// The directory `dir`, which is `root` or under it, made down from
    /// `root`: a component that is a symbolic link is replaced by a
    /// directory, never followed; one that is a file is an error.
    pub fn dir(&self, dir: &Path) -> Result<(), OutError> {
        let rel = dir.strip_prefix(&self.root).map_err(|_| {
            OutError::Failed(format!("{}: not under the output directory", dir.display()))
        })?;
        let mut cur = self.root.clone();
        for c in rel.components() {
            cur.push(c);
            match std::fs::symlink_metadata(&cur) {
                Ok(m) if m.is_dir() => continue,
                Ok(m) if m.file_type().is_symlink() => {
                    self.guard.check_name(&cur).map_err(OutError::Refused)?;
                    remove(&cur)?
                }
                Ok(_) => {
                    return Err(OutError::Failed(format!(
                        "{}: a file is in the way of a directory",
                        cur.display()
                    )))
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(OutError::Failed(format!("{}: {e}", cur.display()))),
            }
            self.guard.check(&cur).map_err(OutError::from)?;
            match std::fs::create_dir(&cur) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists && cur.is_dir() => {}
                Err(e) => return Err(OutError::Failed(format!("{}: {e}", cur.display()))),
            }
        }
        Ok(())
    }

    /// A new, empty file at `path`, with its directories made as
    /// [`dir`](Self::dir) makes them and whatever was at `path` gone.
    pub fn create(&self, path: &Path) -> Result<File, OutError> {
        self.make_way(path)?;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| OutError::Failed(format!("{}: {e}", path.display())))
    }

    /// `to` as a second name for `from`, a file this run wrote. `Ok(Some)`
    /// says why the output's filesystem takes no further name for it —
    /// ext4 stops at 65 000 — and the caller writes a copy instead.
    pub fn hard_link(&self, from: &Path, to: &Path) -> Result<Option<String>, OutError> {
        self.make_way(to)?;
        match std::fs::hard_link(from, to) {
            Ok(()) => Ok(None),
            Err(e) if no_more_names(&e) => Ok(Some(e.to_string())),
            Err(e) => Err(OutError::Failed(format!("{}: {e}", to.display()))),
        }
    }

    /// Make the directories above `path`, and clear `path` itself.
    fn make_way(&self, path: &Path) -> Result<(), OutError> {
        if let Some(parent) = path.parent() {
            self.dir(parent)?;
        }
        match std::fs::symlink_metadata(path) {
            // A link in the way is replaced, not followed — unless the
            // link is itself how the run names an input or a log: a member
            // given as `-o/hello.txt`, a link to it, lost its name to the
            // extracted file, and the record then described that file.
            Ok(m) if m.file_type().is_symlink() => {
                self.guard.check_name(path).map_err(OutError::Refused)?;
                remove(path)?
            }
            Ok(m) if m.is_dir() => {
                return Err(OutError::Failed(format!(
                    "{}: a directory is in the way",
                    path.display()
                )))
            }
            _ => {}
        }
        // A file in the way is looked at before it is removed: removing a
        // member's only other name would lose it once this run ends.
        self.guard.check(path).map_err(OutError::from)?;
        match std::fs::remove_file(path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => {
                Err(OutError::Failed(format!("{}: {e}", path.display())))
            }
            _ => Ok(()),
        }
    }
}

/// The filesystem will not give the file another name: it has as many
/// as it takes, or it takes no hard links at all.
fn no_more_names(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::TooManyLinks | io::ErrorKind::Unsupported
    )
}

#[cfg(all(test, any(target_os = "linux", target_os = "freebsd")))]
#[test]
fn a_file_with_every_name_it_can_take_is_copied() {
    // EMLINK is 31 on both.
    assert!(no_more_names(&io::Error::from_raw_os_error(31)));
    assert!(!no_more_names(&io::Error::from_raw_os_error(28)));
}

/// Remove a link or a file; one already gone is not an error.
fn remove(path: &Path) -> Result<(), OutError> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => {
            Err(OutError::Failed(format!("{}: {e}", path.display())))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(root: &Path, reads: &[PathBuf]) -> OutTree {
        #[derive(clap::Parser)]
        struct Cli {
            #[command(flatten)]
            global: Global,
        }
        let g = <Cli as clap::Parser>::parse_from(["t"]).global;
        OutTree {
            root: root.to_path_buf(),
            guard: WriteGuard::new(&g, reads),
        }
    }

    fn scratch(name: &str) -> zvol_common::scratch::Scratch {
        zvol_common::scratch::Scratch::new("zvolfiles-out", name)
    }

    /// A link already in the tree — to a member, or to a directory
    /// outside it — is replaced, and what it pointed at is untouched.
    #[test]
    fn nothing_in_the_tree_is_written_through() {
        let dir = scratch("through");
        let member = dir.join("member1.img");
        std::fs::write(&member, b"evidence").unwrap();
        let outside = dir.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        std::os::unix::fs::symlink(&member, out.join("spilled.txt")).unwrap();
        std::os::unix::fs::symlink(&outside, out.join("sub")).unwrap();
        let t = tree(&out, std::slice::from_ref(&member));
        use std::io::Write;
        t.create(&out.join("spilled.txt"))
            .unwrap()
            .write_all(b"x")
            .unwrap();
        t.create(&out.join("sub/deep.txt"))
            .unwrap()
            .write_all(b"y")
            .unwrap();
        assert_eq!(std::fs::read(&member).unwrap(), b"evidence");
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
        assert!(!std::fs::symlink_metadata(out.join("sub"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read(out.join("sub/deep.txt")).unwrap(), b"y");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A link that is the very name the run reads a member by stays: it
    /// was removed first and asked about after, so the member lost the
    /// name the run had for it and the record described the extracted
    /// file instead. A link that only points at a member is replaced.
    #[test]
    fn a_link_that_names_an_input_is_kept() {
        let dir = scratch("names-input");
        let member = dir.join("member1.img");
        std::fs::write(&member, b"evidence").unwrap();
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let named = out.join("hello.txt");
        std::os::unix::fs::symlink(&member, &named).unwrap();
        let t = tree(&out, std::slice::from_ref(&named));
        assert!(matches!(t.create(&named), Err(OutError::Refused(_))));
        assert!(std::fs::symlink_metadata(&named)
            .unwrap()
            .file_type()
            .is_symlink());
        std::os::unix::fs::symlink(&member, out.join("other.txt")).unwrap();
        t.create(&out.join("other.txt")).unwrap();
        assert_eq!(std::fs::read(&member).unwrap(), b"evidence");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A member lying in the tree under a name the extraction makes is
    /// refused, not removed; another file there is replaced, and a
    /// second run over the same tree replaces its own files and links.
    #[test]
    fn a_member_in_the_tree_is_refused_and_anything_else_replaced() {
        let dir = scratch("member");
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let member = out.join("hello.txt");
        std::fs::write(&member, b"evidence").unwrap();
        let t = tree(&out, std::slice::from_ref(&member));
        assert!(matches!(t.create(&member), Err(OutError::Refused(_))));
        assert_eq!(std::fs::read(&member).unwrap(), b"evidence");
        std::fs::write(out.join("old.txt"), b"old").unwrap();
        t.create(&out.join("old.txt")).unwrap();
        assert_eq!(std::fs::read(out.join("old.txt")).unwrap(), b"");
        for _ in 0..2 {
            t.create(&out.join("a.txt")).unwrap();
            assert_eq!(
                t.hard_link(&out.join("a.txt"), &out.join("b.txt")).unwrap(),
                None
            );
        }
        assert!(matches!(t.create(&out), Err(OutError::Failed(_))));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
