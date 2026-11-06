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

    /// A device overlaps itself; without a device tree to read, two
    /// different numbers do not.
    #[test]
    fn a_device_overlaps_itself() {
        assert!(overlap(12345, 12345));
        assert!(!overlap(u64::MAX - 1, u64::MAX - 2));
    }
}
