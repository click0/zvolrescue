//! FreeBSD GEOM metadata in a provider's last sector (SPEC F-71).
//!
//! Every GEOM class that keeps state on the disk keeps it in the same
//! place: the last sector of the provider it was configured on. The
//! provider it then offers is one sector shorter, and that shorter
//! provider is what ZFS was given. Two things follow for a reader that
//! has the raw device or partition in hand.
//!
//! First, a name. `glabel label tank-d0 ada0p2` writes `tank-d0` here,
//! and the pool's labels then record the member as `/dev/label/tank-d0`.
//! When those labels are gone from this member, the name in this sector
//! is the one thing on the disk that still ties it to the leaf its
//! siblings describe. A GPT partition label (`gpart -l`) does the same
//! through `/dev/gpt/NAME`, and the partition's own GUID through
//! `/dev/gptid/…`; those live in the partition table and are read in
//! [`crate::part`].
//!
//! Second, a size. The rear pair of ZFS labels sits against the end of
//! the provider ZFS saw — its size rounded down to 256 KiB — and that
//! provider is one sector shorter than what a forensic image of the
//! partition holds. Whenever that sector carries the size across a
//! 256 KiB boundary, a search that trusts the image size looks in the
//! wrong place and reports two labels missing on a member that has all
//! four. `md_provsize`, where the metadata version carries it, says
//! exactly how long that provider was.
//!
//! Formats are from `sys/geom/{label,mirror,eli}/g_*.h`: a 16-byte
//! magic, a little-endian version, and per-class fields after that.
//! Only what a reader needs is decoded: the name and the provider size.
//! `geli` gets its magic recognised and nothing more, because a member
//! under it is ciphertext and the honest answer is to say so.

/// Bytes of one GEOM metadata record; every class fits one 512-byte
/// sector, whatever the provider's sector size.
pub const SECTOR: usize = 512;

/// What was found in the last sector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeomMeta {
    /// The GEOM class, lowercase as its device directory is named:
    /// `label`, `mirror`, `eli`, `stripe`, `concat`, `raid3`, `raid`,
    /// `journal`, `cache`, `virstor`, `shsec`.
    pub class: &'static str,
    /// The name the class gave the provider, where it has one — the
    /// tail of `/dev/label/…` or `/dev/mirror/…`.
    pub name: Option<String>,
    /// Size in bytes of the provider the class was configured on, where
    /// the metadata version records it. The provider offered above it,
    /// the one ZFS wrote to, is one sector shorter.
    pub provsize: Option<u64>,
    /// Metadata version, as written.
    pub version: u32,
}

impl GeomMeta {
    /// The device node FreeBSD would offer for this provider, when the
    /// class names its providers: `/dev/label/NAME`, `/dev/mirror/NAME`.
    pub fn device_name(&self) -> Option<String> {
        let name = self.name.as_deref()?;
        match self.class {
            "label" | "mirror" | "stripe" | "concat" | "raid3" | "raid" | "journal" | "cache"
            | "virstor" | "shsec" => Some(format!("/dev/{}/{name}", self.class)),
            _ => None,
        }
    }
}

/// Magic to class. The magic is NUL-padded to 16 bytes on disk.
const CLASSES: &[(&[u8], &str)] = &[
    (b"GEOM::LABEL", "label"),
    (b"GEOM::MIRROR", "mirror"),
    (b"GEOM::ELI", "eli"),
    (b"GEOM::STRIPE", "stripe"),
    (b"GEOM::CONCAT", "concat"),
    (b"GEOM::RAID3", "raid3"),
    (b"GEOM::RAID", "raid"),
    (b"GEOM::JOURNAL", "journal"),
    (b"GEOM::CACHE", "cache"),
    (b"GEOM::VIRSTOR", "virstor"),
    (b"GEOM::SHSEC", "shsec"),
];

/// Parse the last sector of a provider. `None` when no GEOM class
/// wrote there — which is what most disks look like.
pub fn parse(sector: &[u8]) -> Option<GeomMeta> {
    if sector.len() < 36 {
        return None;
    }
    // The magic is a C string in a 16-byte field. The kernel compares it
    // with `strcmp`, and so must this: `glabel label` fills the field
    // with `strlcpy` into a struct it never zeroed, so what follows the
    // NUL is whatever was on the stack — a real `glabel` record parsed
    // as nothing until this compared the string and not the field.
    // Exact, so `GEOM::RAID` does not claim a `GEOM::RAID3` record.
    let field = &sector[..16];
    let word = &field[..field.iter().position(|&b| b == 0)?];
    let class = CLASSES
        .iter()
        .find_map(|(m, class)| (*m == word).then_some(*class))?;
    let version = u32::from_le_bytes(sector[16..20].try_into().expect("4 bytes"));
    let name_at = |from: usize| -> Option<String> {
        let raw = sector.get(from..from + 16)?;
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        let s = std::str::from_utf8(&raw[..end]).ok()?;
        (!s.is_empty()).then(|| s.to_string())
    };
    let u64_at = |at: usize| -> Option<u64> {
        sector
            .get(at..at + 8)
            .map(|b| u64::from_le_bytes(b.try_into().expect("8 bytes")))
    };
    let (name, provsize) = match class {
        // g_label.h: magic, version, label[16], provsize (version >= 2).
        "label" => (name_at(20), (version >= 2).then(|| u64_at(36)).flatten()),
        // g_mirror.h: magic, version, name[16], mid, did, all(1), genid,
        // syncid, priority(1), slice, balance(1), mediasize, sectorsize,
        // sync_offset, mflags, dflags, provider[16], provsize (version
        // >= 3). The offsets are the packed ones the encoder writes.
        "mirror" => (name_at(20), (version >= 3).then(|| u64_at(111)).flatten()),
        // g_stripe.h / g_concat.h: magic, version, name[16], id, …
        "stripe" | "concat" | "raid3" | "journal" | "cache" | "virstor" | "shsec" => {
            (name_at(20), None)
        }
        // Encrypted: no name, and the size does not help read it.
        _ => (None, None),
    };
    Some(GeomMeta {
        class,
        name,
        provsize,
        version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sector(magic: &[u8], version: u32, name: &[u8]) -> Vec<u8> {
        let mut s = vec![0u8; SECTOR];
        s[..magic.len()].copy_from_slice(magic);
        s[16..20].copy_from_slice(&version.to_le_bytes());
        s[20..20 + name.len()].copy_from_slice(name);
        s
    }

    /// The record `glabel label -v tank-d0` writes, version 2, with
    /// the provider size after the name.
    #[test]
    fn a_glabel_record_gives_its_name_and_the_provider_size() {
        let mut s = sector(b"GEOM::LABEL", 2, b"tank-d0");
        s[36..44].copy_from_slice(&(64u64 << 20).to_le_bytes());
        let m = parse(&s).expect("a label");
        assert_eq!(m.class, "label");
        assert_eq!(m.name.as_deref(), Some("tank-d0"));
        assert_eq!(m.provsize, Some(64 << 20));
        assert_eq!(m.device_name().as_deref(), Some("/dev/label/tank-d0"));
    }

    /// Version 1 has no size field: what is at that offset is not one.
    #[test]
    fn a_version_1_label_has_a_name_and_no_size() {
        let mut s = sector(b"GEOM::LABEL", 1, b"old");
        s[36..44].copy_from_slice(&0xdead_beefu64.to_le_bytes());
        let m = parse(&s).expect("a label");
        assert_eq!((m.name.as_deref(), m.provsize), (Some("old"), None));
    }

    #[test]
    fn a_gmirror_record_names_the_mirror() {
        let mut s = sector(b"GEOM::MIRROR", 4, b"gm0");
        s[111..119].copy_from_slice(&(10u64 << 30).to_le_bytes());
        let m = parse(&s).expect("a mirror");
        assert_eq!(m.class, "mirror");
        assert_eq!(m.device_name().as_deref(), Some("/dev/mirror/gm0"));
        assert_eq!(m.provsize, Some(10 << 30));
    }

    /// `geli` is recognised and not read: there is no name to offer and
    /// nothing below it is plaintext.
    #[test]
    fn geli_is_named_and_nothing_else() {
        let m = parse(&sector(b"GEOM::ELI", 7, b"")).expect("eli");
        assert_eq!(m.device_name(), None);
        assert_eq!((m.class, m.name, m.provsize), ("eli", None, None));
    }

    /// A magic is a whole padded word: `GEOM::RAID` is not a prefix
    /// match for `GEOM::RAID3`, and a sector of zeros or of ZFS data is
    /// nothing.
    #[test]
    fn magics_match_whole_and_anything_else_is_nothing() {
        assert_eq!(
            parse(&sector(b"GEOM::RAID3", 1, b"r3")).unwrap().class,
            "raid3"
        );
        assert_eq!(
            parse(&sector(b"GEOM::RAID", 1, b"r")).unwrap().class,
            "raid"
        );
        assert_eq!(parse(&[0u8; SECTOR]), None);
        assert_eq!(parse(&sector(b"GEOM::LABELX", 2, b"x")), None);
        assert_eq!(parse(&sector(b"GEOM::LABELXXXXX", 2, b"x")), None);
        assert_eq!(parse(b"GEOM::LABEL"), None);
    }

    /// What `glabel label` really writes: the magic `strlcpy`'d into a
    /// field that was never zeroed, so the bytes after its NUL are
    /// stack garbage. The kernel reads it back with `strcmp`; so does
    /// this. Found on FreeBSD 15 in CI, not by reading the header.
    #[test]
    fn a_magic_followed_by_stack_garbage_is_still_the_magic() {
        let mut s = sector(b"GEOM::LABEL", 2, b"tank-d0");
        s[12..16].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        s[36..44].copy_from_slice(&(64u64 << 20).to_le_bytes());
        let m = parse(&s).expect("a label");
        assert_eq!((m.class, m.name.as_deref()), ("label", Some("tank-d0")));
    }
}
