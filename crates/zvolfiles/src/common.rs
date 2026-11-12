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
/// not — never past it, since a read there is of nothing.
pub fn data_end(obj: &zfs_read::dmu::ObjectReader<'_, '_>, bs: u64) -> u64 {
    let claimed = obj.dnode().maxblkid.saturating_add(1);
    obj.data_blocks()
        .map_or(claimed, |n| n.min(claimed))
        .saturating_mul(bs)
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
        eprintln!(
            "zvolfiles: --path {shown}: {why} at txg {txg}; a file removed since may still be at an older --txg"
        );
        exit::UNRECOVERABLE
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

    let mut last = None;
    for c in &wanted {
        let Ok(mos) = open_mos(&reader, &c.ub) else {
            continue;
        };
        let Ok(tree) = walk(&mos, &pool.name) else {
            continue;
        };
        let Some(ds) = tree.datasets.iter().find(|d| d.name == name) else {
            last = Some(format!("txg {}: no dataset {name}", c.ub.txg));
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
                eprintln!("zvolfiles: {name} at txg {}: {e}", c.ub.txg);
                last = Some(format!("txg {}: {e}", c.ub.txg));
                continue;
            }
        };
        for d in &fs.damaged {
            eprintln!("zvolfiles: {name} at txg {}: {d}", c.ub.txg);
        }
        let opened = Opened {
            txg: c.ub.txg,
            members: &members,
        };
        return f(&fs, &opened);
    }
    eprintln!(
        "zvolfiles: {name} is in none of the {} transaction group(s) read{}",
        wanted.len(),
        last.map(|e| format!(" ({e})")).unwrap_or_default()
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
