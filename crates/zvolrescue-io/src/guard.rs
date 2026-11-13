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
//! loop device among the inputs reads — or, when the evidence is kept on
//! a loop-mounted image, that image file, a second loop over it, or a
//! filesystem inside an image that lies on an input device.
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

/// Why an output was refused: it would write an input. Carried inside
/// the `io::Error` [`Evidence::check`] returns, so that a refusal can be
/// told from a check that could not be made at all.
#[derive(Debug)]
struct Refusal(String);

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refusal {}

fn refusal(why: String) -> io::Error {
    io::Error::other(Refusal(why))
}

/// Whether `e`, from [`Evidence::check`], says the output would write an
/// input — as opposed to the path not being one that can be looked at:
/// a file where a directory should be, a loop of links, a name too long,
/// a directory this user may not enter. Those are no refusal; the write
/// would fail on them anyway, and said as a refusal they read "the path
/// holds something this run reads", which was false.
pub fn is_refusal(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<Refusal>())
}

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
    /// The same bytes under another name the kernel knows of: the file
    /// in an overlay's layer that the input, read through the overlay,
    /// is.
    aliases: Vec<(u64, u64)>,
    /// The files an input device is made of: what a loop device in its
    /// stack reads, at any depth, by the same pair. Writing one, or
    /// writing into a filesystem inside one, writes the input.
    backing: Vec<(u64, u64)>,
    /// The image files that hold the filesystem an input file is on, when
    /// that filesystem is loop-mounted: the file itself and a loop device
    /// over it write the input; a file made inside the same filesystem
    /// does not, as one made beside an image on a disk does not.
    holders: Vec<(u64, u64)>,
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
                aliases: Vec::new(),
                backing: Vec::new(),
                holders: Vec::new(),
                raw: Vec::new(),
                device: None,
            };
            // Where the bytes are: the device itself, or the device
            // under the filesystem the file is on — and when either is a
            // loop device, the file it reads and the device that file is
            // on, as far down as loops go. An image kept on a filesystem
            // that is itself a loop-mounted image lives inside that image
            // file: writing the file, or another loop over it, rewrites
            // the evidence.
            let dev = if disks::is_device(&m) {
                input.device = Some(m.rdev());
                m.rdev()
            } else {
                m.dev()
            };
            // A filesystem with no device of its own — an overlay,
            // btrfs — is on the devices its mount names, and an overlay's
            // file is a file in one of its layers.
            let mut devs = vec![dev];
            if input.device.is_none() {
                let b = disks::beneath(dev, path);
                if let Some(f) = b.file.as_ref().and_then(|f| std::fs::metadata(f).ok()) {
                    input.aliases.push((f.dev(), f.ino()));
                }
                devs.extend(b.devs);
            }
            for dev in devs {
                input.raw.push(dev);
                for f in loop_files(dev) {
                    if input.device.is_some() {
                        input.backing.push(f.node);
                    } else {
                        input.holders.push(f.node);
                    }
                    input.raw.push(f.on);
                }
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
                    return Err(refusal(format!(
                        "output {shown} is the same file as input {}",
                        i.path.display()
                    )));
                }
                if i.aliases.contains(&node) {
                    return Err(refusal(format!(
                        "output {shown} is the file input {} is, in the layer of the overlay it is read through",
                        i.path.display()
                    )));
                }
                if i.backing.contains(&node) {
                    return Err(refusal(format!(
                        "output {shown} is the file loop device {} reads",
                        i.path.display()
                    )));
                }
                if i.holders.contains(&node) {
                    return Err(refusal(format!(
                        "output {shown} is the image holding the filesystem input {} is on",
                        i.path.display()
                    )));
                }
            }
        }
        if let Some(o) = out_meta.as_ref().filter(|m| disks::is_device(m)) {
            let dev = o.rdev();
            for i in &self.inputs {
                if i.raw.iter().any(|&r| disks::overlap(dev, r)) {
                    return Err(refusal(format!(
                        "output {shown} shares its bytes with input {} (the same device, a partition of it, the disk it is on, or the disk under its filesystem)",
                        i.path.display()
                    )));
                }
            }
            // A loop device writes the file it reads.
            return self.over_loops(&format!("output {shown} is a loop device"), dev, true);
        }
        // A file: on whichever filesystem it is, or would be, made on —
        // and when that filesystem is a loop-mounted image, inside the
        // image file.
        let (landing, m, to_be_made) = match out_meta {
            Some(m) => (target, m, false),
            None => {
                let (landing, m) = nearest_existing(&target)?;
                (landing, m, true)
            }
        };
        // The filesystem it lands on, and — when that has no device of
        // its own — the devices beneath it.
        let mut devs = vec![m.dev()];
        devs.extend(disks::beneath(m.dev(), &landing).devs);
        // The output named, and where it lands when it is still to be
        // made: the directory it lands in was called the output, an
        // `-o mnt/B.img` refused as "output directory mnt".
        let what = if to_be_made {
            format!("output {shown}, to be made in {},", landing.display())
        } else {
            let kind = if m.is_dir() { "directory" } else { "file" };
            format!("output {kind} {}", landing.display())
        };
        for dev in devs {
            for i in &self.inputs {
                if i.device.is_some_and(|e| disks::overlap(dev, e)) {
                    return Err(refusal(format!(
                        "{what} is on input device {}",
                        i.path.display()
                    )));
                }
            }
            self.over_loops(
                &format!("{what} is on a filesystem in a loop device"),
                dev,
                false,
            )?;
        }
        Ok(())
    }

    /// Refuse when a loop device in `dev`'s stack, at any depth, reads a
    /// file that is an input, that an input device is made of, or that
    /// lives on an input device — and, for a write to the device itself
    /// (`raw`), a file holding the filesystem an input is on. `what`
    /// begins the message.
    fn over_loops(&self, what: &str, dev: u64, raw: bool) -> io::Result<()> {
        for f in loop_files(dev) {
            let file = f.path.display();
            for i in &self.inputs {
                let input = i.path.display();
                if i.node == f.node {
                    return Err(refusal(format!("{what} over input {input}")));
                }
                if i.backing.contains(&f.node) || (raw && i.holders.contains(&f.node)) {
                    return Err(refusal(format!(
                        "{what} over {file}, which holds input {input}"
                    )));
                }
                if i.device.is_some_and(|e| disks::overlap(f.on, e)) {
                    return Err(refusal(format!(
                        "{what} over {file}, which is on input device {input}"
                    )));
                }
            }
        }
        Ok(())
    }
}

/// A file a loop device reads.
struct LoopFile {
    path: PathBuf,
    /// `(st_dev, st_ino)` of the file.
    node: (u64, u64),
    /// The device the file is on.
    on: u64,
}

/// The files whose bytes hold device `dev`: what a loop device in its
/// stack reads, then — when that file is on a loop-mounted filesystem —
/// what that loop reads, and so on down. A loop's file is kept apart from
/// the device stack on purpose: a loop over a file is no write to the raw
/// disk under it, and an image written beside the evidence on the same
/// disk touches nothing of it.
fn loop_files(dev: u64) -> Vec<LoopFile> {
    let mut out: Vec<LoopFile> = Vec::new();
    let mut todo = vec![dev];
    let mut seen = Vec::new();
    while let Some(d) = todo.pop() {
        // A stack of loops is a few deep; the bound is against a cycle.
        if seen.contains(&d) || seen.len() > 16 {
            continue;
        }
        seen.push(d);
        for x in disks::stack(d) {
            let Some(path) = disks::backing_file(x) else {
                continue;
            };
            let Ok(m) = std::fs::metadata(&path) else {
                continue;
            };
            let node = (m.dev(), m.ino());
            if out.iter().any(|f| f.node == node) {
                continue;
            }
            // A loop over a device — another loop, a partition — reads
            // that device, not the filesystem its node in /dev is on:
            // taken as a file, a loop over a loop over F was followed to
            // devtmpfs, and F was missed both ways (an output F truncated
            // its own input; an output to the outer loop overwrote F).
            let on = if disks::is_device(&m) {
                m.rdev()
            } else {
                m.dev()
            };
            todo.push(on);
            out.push(LoopFile { path, node, on });
        }
    }
    out
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
pub fn final_target(path: &Path) -> PathBuf {
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
