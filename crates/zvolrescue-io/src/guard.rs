//! The check that keeps every write off the evidence (SPEC §8.3,
//! invariant 2).
//!
//! A write reaches the bytes of an input in more ways than "the same
//! path". The output can be the input under another name — a hard link,
//! a symbolic link, another device node for the same device. It can be a
//! device the input shares bytes with: a partition of an input disk, the
//! disk an input partition is on, a loop device over an input image, or
//! the disk under the filesystem an input image lives on. And it can be a
//! file on a filesystem that is itself on an input device, or the file a
//! loop device among the inputs reads.
//!
//! [`Evidence`] works the inputs out once — what each one is, and every
//! device and file its bytes are held by — and is then asked about each
//! file a run writes. What the kernel cannot say (no sysfs, a stack this
//! build does not trace) is no relation, never an error: the check guards
//! against a slip, and the plain same-file comparison always holds.

use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::disks;

/// What a run reads, reduced to what a write could reach.
#[derive(Debug, Clone, Default)]
pub struct Evidence {
    inputs: Vec<Input>,
}

/// One input that exists, and where its bytes are.
#[derive(Debug, Clone)]
struct Input {
    path: PathBuf,
    /// The input itself: `(st_dev, st_ino)` of the file or device node.
    node: (u64, u64),
    /// Files a loop device in the input's stack reads, by the same pair.
    backing: Vec<(u64, u64)>,
    /// Devices whose raw bytes hold the input: the input device itself,
    /// or the device under the filesystem an input file (or a loop's
    /// backing file) is on. A write to one of these, or to a device
    /// built on or under it, writes the input.
    raw: Vec<u64>,
    /// The input device, when the input is one: a file written on a
    /// filesystem that lives on it writes the input's bytes.
    device: Option<u64>,
}

impl Evidence {
    /// Work out the inputs. One that cannot be looked at is left out:
    /// what does not exist cannot be overwritten.
    pub fn new(inputs: &[PathBuf]) -> Evidence {
        let mut out = Vec::new();
        for path in inputs {
            let Ok(m) = std::fs::metadata(path) else {
                continue;
            };
            let mut input = Input {
                path: path.clone(),
                node: (m.dev(), m.ino()),
                backing: Vec::new(),
                raw: Vec::new(),
                device: None,
            };
            if disks::is_device(&m) {
                let dev = m.rdev();
                input.device = Some(dev);
                input.raw.push(dev);
                for d in disks::stack(dev) {
                    let Some(b) = disks::backing_file(d).and_then(|p| std::fs::metadata(p).ok())
                    else {
                        continue;
                    };
                    input.backing.push((b.dev(), b.ino()));
                    input.raw.push(b.dev());
                }
            } else {
                input.raw.push(m.dev());
            }
            out.push(input);
        }
        Evidence { inputs: out }
    }

    /// Refuse `output` when writing it would change an input's bytes.
    ///
    /// The output need not exist. A symbolic link is followed to where
    /// it points, a dangling one included, and a file still to be made is
    /// judged by the filesystem it would be made on: that of the nearest
    /// directory above it that exists. An output that exists — an image
    /// being resumed, the directory `-r` writes into, which may be a mount
    /// point — is judged by its own.
    pub fn check(&self, output: &Path) -> io::Result<()> {
        let target = final_target(output);
        let out_meta = match std::fs::metadata(&target) {
            Ok(m) => Some(m),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        let shown = output.display();
        if let Some(o) = &out_meta {
            let node = (o.dev(), o.ino());
            for i in &self.inputs {
                if i.node == node {
                    return Err(io::Error::other(format!(
                        "output {shown} is the same file as input {}",
                        i.path.display()
                    )));
                }
                if i.backing.contains(&node) {
                    return Err(io::Error::other(format!(
                        "output {shown} is the file loop device {} reads",
                        i.path.display()
                    )));
                }
            }
        }
        if let Some(o) = out_meta.as_ref().filter(|m| disks::is_device(m)) {
            let dev = o.rdev();
            for i in &self.inputs {
                if i.raw.iter().any(|&r| disks::overlap(dev, r)) {
                    return Err(io::Error::other(format!(
                        "output {shown} shares its bytes with input {} (the same device, a partition of it, the disk it is on, or the disk under its filesystem)",
                        i.path.display()
                    )));
                }
            }
            // A loop device writes the file it reads.
            for d in disks::stack(dev) {
                let Some(file) = disks::backing_file(d) else {
                    continue;
                };
                let Ok(b) = std::fs::metadata(&file) else {
                    continue;
                };
                for i in &self.inputs {
                    if i.node == (b.dev(), b.ino()) {
                        return Err(io::Error::other(format!(
                            "output {shown} is a loop device over input {}",
                            i.path.display()
                        )));
                    }
                    if i.device.is_some_and(|e| disks::overlap(b.dev(), e)) {
                        return Err(io::Error::other(format!(
                            "output {shown} is a loop device over {}, which is on input device {}",
                            file.display(),
                            i.path.display()
                        )));
                    }
                }
            }
            return Ok(());
        }
        // A file: on whichever filesystem it is, or would be, made on.
        let (landing, m) = match out_meta {
            Some(m) => (target, m),
            None => nearest_existing(&target)?,
        };
        for i in &self.inputs {
            if i.device.is_some_and(|e| disks::overlap(m.dev(), e)) {
                return Err(io::Error::other(format!(
                    "output directory {} is on input device {}",
                    landing.display(),
                    i.path.display()
                )));
            }
        }
        Ok(())
    }
}

/// Refuse an output path that is one of the inputs, or whose bytes an
/// input shares; [`Evidence::check`] for a single question.
///
/// A disk is a block device on Linux and a character device on FreeBSD,
/// which has no block devices; both are inputs to compare against.
pub fn refuse_if_evidence(output: &Path, inputs: &[PathBuf]) -> io::Result<()> {
    Evidence::new(inputs).check(output)
}

/// Where `path` ends up once every symbolic link at its end is followed,
/// a link to something that does not exist yet included. A relative
/// target is read from the link's own directory, as the kernel reads it.
fn final_target(path: &Path) -> PathBuf {
    let mut p = path.to_path_buf();
    // The kernel's own bound on a chain of links.
    for _ in 0..40 {
        let is_link = std::fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_symlink());
        if !is_link {
            break;
        }
        let Ok(to) = std::fs::read_link(&p) else {
            break;
        };
        p = match p.parent() {
            Some(dir) if to.is_relative() => dir.join(to),
            _ => to,
        };
    }
    p
}

/// The nearest directory above `path` that exists, and what it is, with
/// links along the way followed as the write would follow them.
fn nearest_existing(path: &Path) -> io::Result<(PathBuf, std::fs::Metadata)> {
    let mut p = path.to_path_buf();
    // A path has as many parents as it has components; the bound is for
    // links that keep pointing deeper.
    for _ in 0..4096 {
        let parent = match p.parent() {
            Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let parent = final_target(&parent);
        match std::fs::metadata(&parent) {
            Ok(m) => return Ok((parent, m)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => p = parent,
            Err(e) => return Err(e),
        }
    }
    let here = Path::new(".");
    Ok((here.to_path_buf(), std::fs::metadata(here)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("zvolrescue-guard-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Another name for an input is the input: a hard link, a link to
    /// it, and a link that still dangles but names it through a
    /// directory that is itself a link.
    #[test]
    fn every_name_of_an_input_is_the_input() {
        let dir = scratch("names");
        let member = dir.join("member0.img");
        std::fs::write(&member, [1u8; 4096]).unwrap();
        std::fs::hard_link(&member, dir.join("hard.img")).unwrap();
        std::os::unix::fs::symlink(&member, dir.join("soft.img")).unwrap();
        std::os::unix::fs::symlink("member0.img", dir.join("relative.img")).unwrap();
        let ev = Evidence::new(std::slice::from_ref(&member));
        for name in ["member0.img", "hard.img", "soft.img", "relative.img"] {
            let err = ev.check(&dir.join(name)).unwrap_err().to_string();
            assert!(err.contains("same file as input"), "{name}: {err}");
        }
        // A new file beside it is fine; so is one through a dangling link.
        assert!(ev.check(&dir.join("out.img")).is_ok());
        std::os::unix::fs::symlink(dir.join("not-yet.img"), dir.join("dangling")).unwrap();
        assert!(ev.check(&dir.join("dangling")).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A link that dangles is judged where it points, not where it is:
    /// a log named through one used to be judged by the link's own
    /// directory while the write went wherever the link led.
    #[test]
    fn a_dangling_link_is_judged_where_it_points() {
        let dir = scratch("dangling");
        std::fs::create_dir_all(dir.join("far/away")).unwrap();
        std::os::unix::fs::symlink(dir.join("far/away/new.log"), dir.join("near.log")).unwrap();
        assert_eq!(
            final_target(&dir.join("near.log")),
            dir.join("far/away/new.log")
        );
        let (landing, _) = nearest_existing(&final_target(&dir.join("near.log"))).unwrap();
        assert_eq!(landing, dir.join("far/away"));
        // Through a directory link that dangles too, to a directory that
        // is not there: judged by the nearest one that is.
        std::os::unix::fs::symlink(dir.join("far/gone"), dir.join("dirlink")).unwrap();
        let (landing, _) = nearest_existing(&dir.join("dirlink/sub/x.log")).unwrap();
        assert_eq!(landing, dir.join("far"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Outputs that are already there — an image being resumed, a
    /// directory `-r` writes into — are judged by themselves, and an
    /// output under directories that do not exist yet is not refused for
    /// its parent.
    #[test]
    fn plain_outputs_pass() {
        let dir = scratch("plain");
        let member = dir.join("member0.img");
        std::fs::write(&member, [1u8; 4096]).unwrap();
        let ev = Evidence::new(std::slice::from_ref(&member));
        assert!(ev.check(&dir).is_ok());
        assert!(ev.check(&dir.join("a/b/new.img")).is_ok());
        std::fs::write(dir.join("resumed.img"), [2u8; 4096]).unwrap();
        assert!(ev.check(&dir.join("resumed.img")).is_ok());
        // Inputs that are not there are no inputs.
        assert!(Evidence::new(&[dir.join("missing")])
            .check(&dir.join("missing"))
            .is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
