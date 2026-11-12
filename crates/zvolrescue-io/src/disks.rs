//! Which devices share bytes: the relation [`refuse_if_evidence`] needs
//! beyond "the same file".
//!
//! Writing to a partition changes the disk it is on, and writing to a
//! disk changes every partition on it; a logical volume or an md array
//! is made of the devices under it. Two device numbers *overlap* when one
//! of them is the other or is built on it, at any depth. Two partitions
//! of one disk do not: a rescue run on a laptop with one disk writes its
//! image to the root filesystem beside the damaged pool's partition, and
//! that touches no byte of the evidence.
//!
//! A loop device is made of the file it reads ([`backing_file`]).
//!
//! What the kernel says is read from where it says it — sysfs on Linux,
//! the device nodes under `/dev` on FreeBSD — and anything that cannot be
//! read is no relation rather than an error: the check this serves is a
//! guard against a slip, and the plain same-device comparison still holds.
//!
//! [`refuse_if_evidence`]: crate::refuse_if_evidence

/// Whether `meta` is a disk-like device: a block device, or on FreeBSD,
/// which has no block devices, a character device.
pub(crate) fn is_device(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt;
    let ft = meta.file_type();
    if cfg!(target_os = "linux") {
        ft.is_block_device()
    } else {
        ft.is_block_device() || ft.is_char_device()
    }
}

/// Whether a write to device `a` can change the bytes of device `b`, or
/// the other way round: the same device, or one built on the other.
pub(crate) fn overlap(a: u64, b: u64) -> bool {
    a == b || under(a).contains(&b) || under(b).contains(&a)
}

/// `dev` and every device it is built on, `dev` first.
pub(crate) fn stack(dev: u64) -> Vec<u64> {
    let mut out = vec![dev];
    out.extend(under(dev));
    out
}

/// The file a loop device reads, when `dev` is one: writing the device
/// writes the file, and the other way round. Linux says so in sysfs; a
/// file deleted since it was attached is no file to compare with.
/// FreeBSD's md(4) keeps its backing file behind an ioctl, and is not
/// traced.
#[cfg(target_os = "linux")]
pub(crate) fn backing_file(dev: u64) -> Option<std::path::PathBuf> {
    let (maj, min) = (linux_major(dev), linux_minor(dev));
    let s =
        std::fs::read_to_string(format!("/sys/dev/block/{maj}:{min}/loop/backing_file")).ok()?;
    let s = s.strip_suffix('\n').unwrap_or(&s);
    (!s.is_empty() && !s.ends_with(" (deleted)")).then(|| std::path::PathBuf::from(s))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn backing_file(_dev: u64) -> Option<std::path::PathBuf> {
    None
}

/// Every device `dev` is built on, nearest first: the disk of a
/// partition, the members of a logical volume or an array, and theirs.
fn under(dev: u64) -> Vec<u64> {
    let mut out = Vec::new();
    let mut todo = vec![dev];
    // A device stack is a handful deep; the bound is against a cycle.
    while let Some(d) = todo.pop() {
        if out.len() > 64 {
            break;
        }
        for p in parents(d) {
            if p != dev && !out.contains(&p) {
                out.push(p);
                todo.push(p);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn parents(dev: u64) -> Vec<u64> {
    let (maj, min) = (linux_major(dev), linux_minor(dev));
    // A link into the device tree. A partition's directory carries a
    // `partition` file and sits inside its disk's; a mapped or md device
    // names what it is made of under `slaves/`.
    let Ok(dir) = std::fs::canonicalize(format!("/sys/dev/block/{maj}:{min}")) else {
        return Vec::new();
    };
    let dev_of = |d: &std::path::Path| {
        std::fs::read_to_string(d.join("dev"))
            .ok()
            .and_then(|s| parse_maj_min(s.trim()))
            .map(|(a, b)| linux_makedev(a, b))
    };
    let mut out = Vec::new();
    if dir.join("partition").exists() {
        if let Some(disk) = dir.parent().and_then(dev_of) {
            out.push(disk);
        }
    }
    if let Ok(slaves) = std::fs::read_dir(dir.join("slaves")) {
        for s in slaves.flatten() {
            if let Some(d) = std::fs::canonicalize(s.path())
                .ok()
                .as_deref()
                .and_then(dev_of)
            {
                out.push(d);
            }
        }
    }
    out
}

#[cfg(target_os = "freebsd")]
fn parents(dev: u64) -> Vec<u64> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    // GEOM names a partition after its disk (ada0p3, da0s1a) and every
    // provider has a node in /dev. A label under /dev/gpt or /dev/diskid
    // is a provider of its own and is not traced to the disk under it.
    let nodes: Vec<(String, u64)> = std::fs::read_dir("/dev")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let m = std::fs::metadata(e.path()).ok()?;
            m.file_type()
                .is_char_device()
                .then(|| (e.file_name().to_string_lossy().into_owned(), m.rdev()))
        })
        .collect();
    let Some(name) = nodes
        .iter()
        .find(|(_, r)| *r == dev)
        .map(|(n, _)| n.clone())
    else {
        return Vec::new();
    };
    freebsd_parent_name(&name)
        .and_then(|up| nodes.iter().find(|(n, _)| *n == up).map(|(_, r)| vec![*r]))
        .unwrap_or_default()
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
fn parents(_dev: u64) -> Vec<u64> {
    Vec::new()
}

/// Where a filesystem with no device of its own keeps its bytes.
///
/// On Linux a filesystem that is not one block device — btrfs, an
/// overlay, a ZFS dataset, tmpfs — has a device number of major 0, which
/// names no device at all: the trace from an image to the disk under it
/// stopped there, and an output on that disk, or on the image file it
/// was loop-mounted from, was let through. What the kernel says of the
/// mount says where to go on: an overlay's file is a file in one of its
/// layers, and a filesystem whose source is a device node is on that
/// device. A ZFS dataset's source is a dataset name, and a tmpfs has no
/// bytes on a disk; neither goes further.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Beneath {
    /// Devices the filesystem's bytes are on.
    pub devs: Vec<u64>,
    /// For a file that exists in an overlay: the file in the layer that
    /// holds it, which is the same bytes under another name.
    pub file: Option<std::path::PathBuf>,
}

/// One line of `/proc/self/mountinfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct Mount {
    /// The directory of the filesystem mounted here (`/` unless a bind).
    pub root: std::path::PathBuf,
    /// Where it is mounted.
    pub point: std::path::PathBuf,
    pub fstype: String,
    pub source: String,
    /// The superblock's options: an overlay's layers are among them.
    pub options: String,
}

/// The mount of device `MAJ:MIN` in `mountinfo`'s text, the first one
/// when there are several (a bind mount is the same filesystem).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn mount_in(mountinfo: &str, major: u64, minor: u64) -> Option<Mount> {
    let want = format!("{major}:{minor}");
    mountinfo.lines().find_map(|l| {
        let (pre, post) = l.split_once(" - ")?;
        let f: Vec<&str> = pre.split(' ').collect();
        if *f.get(2)? != want {
            return None;
        }
        let mut p = post.splitn(3, ' ');
        Some(Mount {
            root: unescape(f.get(3)?).into(),
            point: unescape(f.get(4)?).into(),
            fstype: p.next()?.to_string(),
            source: unescape(p.next()?),
            options: p.next().unwrap_or("").to_string(),
        })
    })
}

/// The kernel writes a space, a tab, a newline and a backslash in a
/// mount's fields as three octal digits after a backslash.
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            out.push((b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0'));
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// An overlay's layers, the upper one first: where a file of it is.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn overlay_layers(options: &str) -> Vec<std::path::PathBuf> {
    let opt = |name: &str| {
        options
            .split(',')
            .find_map(|o| o.strip_prefix(name))
            .map(str::to_string)
    };
    let mut out: Vec<std::path::PathBuf> = opt("upperdir=").into_iter().map(Into::into).collect();
    if let Some(lower) = opt("lowerdir=") {
        out.extend(lower.split(':').filter(|l| !l.is_empty()).map(Into::into));
    }
    out
}

/// What is beneath `dev`, the filesystem `path` is (or would be made)
/// on; nothing when `dev` is a device of its own.
#[cfg(target_os = "linux")]
pub(crate) fn beneath(dev: u64, path: &std::path::Path) -> Beneath {
    beneath_at(dev, path, 0)
}

#[cfg(target_os = "linux")]
fn beneath_at(dev: u64, path: &std::path::Path, depth: usize) -> Beneath {
    use std::os::unix::fs::MetadataExt;
    let mut out = Beneath::default();
    // An overlay over an overlay is a few deep; the bound is a cycle's.
    if linux_major(dev) != 0 || depth > 4 {
        return out;
    }
    let Some(m) = std::fs::read_to_string("/proc/self/mountinfo")
        .ok()
        .and_then(|t| mount_in(&t, 0, linux_minor(dev)))
    else {
        return out;
    };
    if m.fstype == "overlay" {
        let layers = overlay_layers(&m.options);
        // The path inside the overlay, and so inside each layer.
        let inside = std::fs::canonicalize(path).ok().and_then(|c| {
            let rel = c.strip_prefix(&m.point).ok()?.to_path_buf();
            Some(m.root.strip_prefix("/").unwrap_or(&m.root).join(rel))
        });
        let found = inside.as_ref().and_then(|rel| {
            layers
                .iter()
                .map(|l| l.join(rel))
                .find(|f| std::fs::symlink_metadata(f).is_ok())
        });
        // A file that is there is in one layer; one still to be made goes
        // to the upper one.
        let on = found.clone().or_else(|| layers.first().cloned());
        if let Some(on_meta) = on.as_deref().and_then(|p| std::fs::metadata(p).ok()) {
            out.devs.push(on_meta.dev());
            let deeper = beneath_at(on_meta.dev(), on.as_deref().expect("checked"), depth + 1);
            out.devs.extend(deeper.devs);
        }
        out.file = found;
        return out;
    }
    if m.source.starts_with('/') {
        if let Ok(s) = std::fs::metadata(&m.source) {
            if is_device(&s) {
                out.devs.push(s.rdev());
            }
        }
    }
    out
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn beneath(_dev: u64, _path: &std::path::Path) -> Beneath {
    Beneath::default()
}

/// The major number of a Linux `dev_t` (glibc's encoding).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn linux_major(dev: u64) -> u64 {
    ((dev >> 32) & 0xffff_f000) | ((dev >> 8) & 0x0000_0fff)
}

/// The minor number of a Linux `dev_t`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn linux_minor(dev: u64) -> u64 {
    ((dev >> 12) & 0xffff_ff00) | (dev & 0x0000_00ff)
}

/// A Linux `dev_t` from its numbers.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn linux_makedev(major: u64, minor: u64) -> u64 {
    ((major & 0xffff_f000) << 32)
        | ((major & 0x0000_0fff) << 8)
        | ((minor & 0xffff_ff00) << 12)
        | (minor & 0x0000_00ff)
}

/// `MAJ:MIN`, as sysfs writes it.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn parse_maj_min(s: &str) -> Option<(u64, u64)> {
    let (a, b) = s.split_once(':')?;
    Some((a.parse().ok()?, b.parse().ok()?))
}

/// The GEOM provider a FreeBSD partition is cut from: `ada0p3` and
/// `ada0s1` are on `ada0`, `da0s1a` is on `da0s1`. A name with no such
/// suffix — a whole disk — has none.
#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
pub(crate) fn freebsd_parent_name(name: &str) -> Option<String> {
    // A BSD label partition: one letter a–h after a slice.
    if let Some(stem) = name.strip_suffix(|c: char| ('a'..='h').contains(&c)) {
        if numbered_suffix(stem, 's').is_some() {
            return Some(stem.to_string());
        }
    }
    // An MBR slice or a GPT partition, after the disk's unit number.
    numbered_suffix(name, 's')
        .or_else(|| numbered_suffix(name, 'p'))
        .map(str::to_string)
}

/// `name` without a trailing `<marker><digits>` that follows a digit.
#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
fn numbered_suffix(name: &str, marker: char) -> Option<&str> {
    let digits = name.len() - name.trim_end_matches(|c: char| c.is_ascii_digit()).len();
    if digits == 0 {
        return None;
    }
    let rest = name[..name.len() - digits].strip_suffix(marker)?;
    rest.ends_with(|c: char| c.is_ascii_digit()).then_some(rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_device_numbers_round_trip() {
        // sdb1 is 8:17; a dynamically numbered device can be far larger.
        assert_eq!(linux_makedev(8, 17), (8 << 8) | 17);
        for (maj, min) in [(8, 17), (259, 3), (253, 0), (4095, 1 << 20), (1 << 13, 255)] {
            let d = linux_makedev(maj, min);
            assert_eq!((linux_major(d), linux_minor(d)), (maj, min));
        }
        assert_eq!(parse_maj_min("8:17"), Some((8, 17)));
        assert_eq!(parse_maj_min("8"), None);
    }

    #[test]
    fn freebsd_partitions_name_their_disk() {
        assert_eq!(freebsd_parent_name("ada0p3").as_deref(), Some("ada0"));
        assert_eq!(freebsd_parent_name("nvd0p12").as_deref(), Some("nvd0"));
        assert_eq!(freebsd_parent_name("da0s1").as_deref(), Some("da0"));
        assert_eq!(freebsd_parent_name("da0s1a").as_deref(), Some("da0s1"));
        assert_eq!(freebsd_parent_name("mmcsd0s2").as_deref(), Some("mmcsd0"));
        // Whole disks, and names that only look like it.
        for whole in ["ada0", "da12", "nvd0", "das1", "md", "zvol"] {
            assert_eq!(freebsd_parent_name(whole), None, "{whole}");
        }
    }

    /// What the kernel writes of a mount is read back as it was meant:
    /// the device by its numbers, the fields unescaped, an overlay's
    /// layers upper first.
    #[test]
    fn a_mount_is_read_from_its_line() {
        let text = "\
22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw\n\
41 22 0:41 / /srv/ov rw,relatime - overlay overlay rw,lowerdir=/mnt/l1:/mnt/l2,upperdir=/mnt/up,workdir=/mnt/w\n\
42 22 0:43 /sub /data\\040two rw - btrfs /dev/loop3 rw,space_cache=v2\n";
        let ov = mount_in(text, 0, 41).expect("the overlay");
        assert_eq!(ov.fstype, "overlay");
        assert_eq!(ov.point, std::path::Path::new("/srv/ov"));
        assert_eq!(
            overlay_layers(&ov.options),
            ["/mnt/up", "/mnt/l1", "/mnt/l2"].map(std::path::PathBuf::from)
        );
        let bt = mount_in(text, 0, 43).expect("the btrfs");
        assert_eq!(bt.point, std::path::Path::new("/data two"));
        assert_eq!(bt.root, std::path::Path::new("/sub"));
        assert_eq!(bt.source, "/dev/loop3");
        assert_eq!(mount_in(text, 0, 44), None);
    }

    /// A device overlaps itself; without a device tree to read, two
    /// different numbers do not.
    #[test]
    fn a_device_overlaps_itself() {
        assert!(overlap(12345, 12345));
        assert!(!overlap(u64::MAX - 1, u64::MAX - 2));
    }
}
