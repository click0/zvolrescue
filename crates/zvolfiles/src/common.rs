//! Opening a filesystem dataset at a transaction group, once, for every
//! subcommand.

use clap::Args;
use zfs_read::crypt::{unwrap_keys, wrapping_key, DatasetKeys, KeyMaterial};
use zfs_read::dsl::{open_mos, walk};
use zfs_read::pool::uberblock_candidates;
use zfs_read::zio::PoolReader;
use zfs_read::zpl::{open_filesystem, open_objects, Filesystem};
use zvol_common::members::{choose_pool, open_members, Members};
use zvol_common::{exit, PoolSpec};

/// The bytes of a path as the operating system gave it.
///
/// On Unix an argument is bytes and reaches a name that is not UTF-8;
/// elsewhere it is text and the lossy form is all there is (Z-09).
#[cfg(unix)]
pub fn os_bytes(s: &std::ffi::OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    s.as_bytes().to_vec()
}

/// The bytes of a path as the operating system gave it.
#[cfg(not(unix))]
pub fn os_bytes(s: &std::ffi::OsStr) -> Vec<u8> {
    s.to_string_lossy().as_bytes().to_vec()
}

/// A file or object whose size runs this far past its last block with
/// data is said to on standard error: the rest is a hole, hashed as
/// zeros without a read, and a forged size or block count of a petabyte
/// hashes for days.
pub const TAIL_NOTE: u64 = 1 << 30;

/// Where an object's last block with data ends, in bytes of `bs`: from
/// its pointers where they say, and from `dn_maxblkid` where they do
/// not — never past it, since a read there is of nothing. The second
/// value says which: `false` when the pointers could not say, an
/// indirect block on the way unreadable, and the end is only what the
/// dnode claims.
pub fn data_end(obj: &zfs_read::dmu::ObjectReader<'_, '_>, bs: u64) -> (u64, bool) {
    let claimed = obj.dnode().maxblkid.saturating_add(1);
    let found = obj.data_blocks();
    (
        found.map_or(claimed, |n| n.min(claimed)).saturating_mul(bs),
        found.is_some(),
    )
}

/// Bytes of a file or object written as zeros because the block that
/// held them could not be read whole (Z-06, SPEC F-33): which block,
/// where in the file, how much, and why. A count alone said that
/// something was missing and not what.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Zeroed {
    pub block: u64,
    pub offset: u64,
    pub length: u64,
    pub reason: String,
}

/// Why an object whose dnode gives a block size of 0 has nothing that
/// can be read: no size ZFS writes, so where its blocks fall cannot be
/// known. It came out as a file of zeros, or an empty object, and no
/// error.
pub const NO_BLOCK_SIZE: &str =
    "the dnode's block size is 0, which ZFS never writes: it is damaged, and where the object's blocks fall cannot be known";

/// A device number, as stored and as the major and minor it packs.
///
/// How it packs them depends on the system that made the node: illumos
/// (and the Solaris the format came from) stores the expanded 64-bit
/// form, the major in the high 32 bits (`zfs_expldev`); Linux stores its
/// kernel's `dev_t`, a 12-bit major above a 20-bit minor. Read the first
/// way only, a Linux disk's `8,1` came out as `0,8388609`. A value with
/// anything in its high half can only be the first; one without is read
/// the Linux way, the system nearly every pool with device nodes in it
/// comes from, and `encoding` says which was taken — `raw` is there for
/// whoever knows better.
///
/// One shape for `list` and for the manifest: `list` gave `"8,1"`, the
/// manifest `{raw, major, minor}`, for the same device.
#[derive(Debug, serde::Serialize)]
pub struct Rdev {
    pub raw: u64,
    pub major: u64,
    pub minor: u64,
    /// `illumos` or `linux`: how `raw` was split.
    pub encoding: &'static str,
}

impl Rdev {
    /// The number of a character or block device; nothing for the rest.
    pub fn of(z: &zfs_ondisk::zpl::Znode) -> Option<Rdev> {
        use zfs_ondisk::zpl::FileType;
        matches!(z.file_type(), FileType::CharDevice | FileType::BlockDevice)
            .then(|| Rdev::split(z.rdev))
    }

    fn split(raw: u64) -> Rdev {
        if raw >> 32 != 0 {
            Rdev {
                raw,
                major: raw >> 32,
                minor: raw & 0xffff_ffff,
                encoding: "illumos",
            }
        } else {
            Rdev {
                raw,
                major: (raw >> 20) & 0xfff,
                minor: raw & 0xf_ffff,
                encoding: "linux",
            }
        }
    }
}

#[cfg(test)]
mod rdev_tests {
    use super::Rdev;

    /// `/dev/sda1` (8,1) and `/dev/null` (1,3) as each system stores
    /// them.
    #[test]
    fn a_device_number_is_split_as_its_system_packed_it() {
        for (raw, want) in [
            ((8u64 << 32) | 1, (8, 1, "illumos")),
            ((1u64 << 32) | 3, (1, 3, "illumos")),
            ((8u64 << 20) | 1, (8, 1, "linux")),
            ((1u64 << 20) | 3, (1, 3, "linux")),
        ] {
            let r = Rdev::split(raw);
            assert_eq!((r.major, r.minor, r.encoding), want, "{raw:#x}");
        }
    }
}

/// Resolve a `--path` to its object and to its path as the dataset
/// spells it (Z-09), or say why not.
///
/// A path that is not there at this transaction group is not damage:
/// a file removed since is still at an older one, and the message says
/// so rather than calling the dataset unreadable.
pub fn resolve_path(
    fs: &Filesystem<'_, '_>,
    asked: &std::ffi::OsStr,
    txg: u64,
) -> Result<(u64, Vec<u8>), u8> {
    resolve_path_or_why(fs, asked, txg).map_err(|why| {
        eprintln!("zvolfiles: {why}");
        exit::UNRECOVERABLE
    })
}

/// [`resolve_path`], with the reason returned rather than printed: for
/// a run that goes on with the paths that are there.
pub fn resolve_path_or_why(
    fs: &Filesystem<'_, '_>,
    asked: &std::ffi::OsStr,
    txg: u64,
) -> Result<(u64, Vec<u8>), String> {
    fs.resolve(&os_bytes(asked)).map_err(|e| {
        let e = match e {
            zfs_read::zio::ReadError::Io(m) => m,
            other => other.to_string(),
        };
        let shown = asked.to_string_lossy();
        // The reader's message starts with the path; the flag and the
        // txg say the rest.
        let why = e
            .strip_prefix(&format!("{shown}: "))
            .unwrap_or(&e)
            .to_string();
        format!(
            "--path {shown}: {why} at txg {txg}; a file removed since may still be at an older --txg"
        )
    })
}

/// Which transaction group to read, and the key if the dataset needs one.
#[derive(Debug, Args)]
pub struct AtArgs {
    /// Transaction group to read; the newest that verifies when absent.
    #[arg(long, value_name = "N")]
    pub txg: Option<u64>,
    /// Dataset encryption key: raw:FILE | hex:HEX | passphrase:FILE | prompt.
    #[arg(long, value_name = "KEYSPEC")]
    pub key: Option<String>,
}

/// What an opened dataset gives a subcommand.
pub struct Opened<'a> {
    /// Transaction group it was read at.
    pub txg: u64,
    /// Members, kept for the evidence record.
    pub members: &'a Members,
    /// The newer transaction groups passed over for this one, and why.
    pub passed_over: Vec<PassedOver>,
}

/// A transaction group newer than the one read, and why it was not.
///
/// When the newer ones did not read — their MOS, or the dataset in them —
/// what is read is the dataset as it was before, perhaps empty: a run
/// that fell back to the TXG the dataset was created at listed nothing,
/// "0 file(s)", exit 0, and its record named that TXG without a word
/// about the newer ones. Such a run now ends 4, and says which.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PassedOver {
    pub txg: u64,
    pub reason: String,
    /// It did not read, as against not holding the dataset.
    pub unread: bool,
}

impl PassedOver {
    /// Whether any of `passed` is a TXG that did not read.
    pub fn any_unread(passed: &[PassedOver]) -> bool {
        passed.iter().any(|p| p.unread)
    }
}

/// Open `name` at the requested transaction group and hand the
/// filesystem to `f`.
///
/// The callback exists because the filesystem borrows the reader, which
/// borrows the members: none of them outlives the pool they came from,
/// and threading that through three subcommands would be worse than one
/// closure.
///
/// `objects_only` opens the dataset for its objects alone, without the
/// POSIX metadata `list` and `extract` need (Z-08). A transaction group
/// at which the dataset does not open is said and passed over for an
/// older one, as `zvolrescue dump` passes over an object set reused
/// since; `--txg` asks for exactly one.
pub fn with_dataset<T>(
    spec: &PoolSpec,
    name: &str,
    at: &AtArgs,
    objects_only: bool,
    f: impl FnOnce(&Filesystem<'_, '_>, &Opened<'_>) -> Result<T, u8>,
) -> Result<T, u8> {
    let members = open_members(spec)?;
    let pool = choose_pool(members.pools.clone(), spec.pool_guid.as_deref())?;
    let reader = PoolReader::new(&pool, members.devices()).with_base_offsets(&members.bases());

    // Newest first; --txg picks one exactly.
    let candidates = uberblock_candidates(&members.scans, &pool);
    let wanted: Vec<_> = match at.txg {
        None => candidates,
        Some(n) => candidates.into_iter().filter(|c| c.ub.txg == n).collect(),
    };
    if wanted.is_empty() {
        match at.txg {
            Some(n) => eprintln!("zvolfiles: no verified uberblock at txg {n}"),
            None => eprintln!("zvolfiles: no verified uberblock on these members"),
        }
        return Err(exit::UNRECOVERABLE);
    }

    // Why each transaction group was passed over, said as it is: a MOS
    // that could not be read was left out of the reasons, and a run that
    // read none ended "no dataset" — as if the dataset had not been
    // there — and one that read an older one did so without a word.
    let mut passed: Vec<PassedOver> = Vec::new();
    let older = wanted.len();
    let mut pass = |txg: u64, why: String, unread: bool| {
        if passed.len() + 1 < older {
            eprintln!("zvolfiles: {why}; passed over for an older one");
        }
        passed.push(PassedOver {
            txg,
            reason: why,
            unread,
        });
    };
    for c in &wanted {
        let tree = match open_mos(&reader, &c.ub).and_then(|mos| walk(&mos, &pool.name)) {
            Ok(t) => t,
            Err(e) => {
                pass(
                    c.ub.txg,
                    format!("txg {}: the pool's metadata does not read: {e}", c.ub.txg),
                    true,
                );
                continue;
            }
        };
        let Some(ds) = tree.datasets.iter().find(|d| d.name == name) else {
            pass(
                c.ub.txg,
                format!("txg {}: no dataset {name}", c.ub.txg),
                false,
            );
            continue;
        };
        // A dataset of another kind is the wrong command, not damage: it
        // was tried at every txg as "I/O error: … is a volume", and the
        // run ended "in none of the 3 transaction group(s) read", exit 3.
        if let Some(kind) = ds.kind.filter(|k| *k != zfs_ondisk::dmu::ObjsetType::Zfs) {
            eprintln!(
                "zvolfiles: {name} is {}, not a filesystem{}",
                kind.described(),
                if kind == zfs_ondisk::dmu::ObjsetType::Zvol {
                    "; zvolrescue dump extracts a volume as an image"
                } else {
                    ""
                }
            );
            return Err(exit::USAGE);
        }
        // An encrypted dataset needs its key before any of its blocks
        // can be read; the metadata that says so needs none.
        if let Some(enc) = &ds.encryption {
            let keys = unlock(name, enc, at.key.as_deref())?;
            reader.set_keys(Some(keys));
        }
        let opened = if objects_only {
            open_objects(&reader, ds)
        } else {
            open_filesystem(&reader, ds)
        };
        let fs = match opened {
            Ok(fs) => fs,
            Err(e) => {
                pass(c.ub.txg, format!("{name} at txg {}: {e}", c.ub.txg), true);
                continue;
            }
        };
        for d in &fs.damaged {
            eprintln!("zvolfiles: {name} at txg {}: {d}", c.ub.txg);
        }
        let opened = Opened {
            txg: c.ub.txg,
            members: &members,
            passed_over: passed.clone(),
        };
        return f(&fs, &opened);
    }
    eprintln!(
        "zvolfiles: {name} is in none of the {} transaction group(s) read{}",
        wanted.len(),
        passed
            .last()
            .map(|e| format!(" ({})", e.reason))
            .unwrap_or_default()
    );
    Err(exit::UNRECOVERABLE)
}

/// Turn `--key` into the dataset's keys, or say what is missing.
fn unlock(
    name: &str,
    enc: &zfs_read::dsl::Encryption,
    spec: Option<&str>,
) -> Result<DatasetKeys, u8> {
    let Some(spec) = spec else {
        eprintln!(
            "zvolfiles: {name} is encrypted ({}, keyformat {}); supply --key raw:FILE | hex:HEX | passphrase:FILE | prompt",
            enc.suite_name(),
            enc.keyformat_name()
        );
        return Err(exit::USAGE);
    };
    let material = if spec == "prompt" {
        eprint!("{name} ({}) key: ", enc.keyformat_name());
        KeyMaterial::prompt(enc.keyformat)
    } else {
        KeyMaterial::from_spec(spec)
    };
    material
        .and_then(|m| wrapping_key(&m, enc))
        .and_then(|w| unwrap_keys(enc, &w))
        .map_err(|e| {
            eprintln!("zvolfiles: {name}: {e}");
            exit::USAGE
        })
}
