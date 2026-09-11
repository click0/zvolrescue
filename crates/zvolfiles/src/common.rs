//! Opening a filesystem dataset at a transaction group, once, for every
//! subcommand.

use clap::Args;
use zfs_read::crypt::{unwrap_keys, wrapping_key, DatasetKeys, KeyMaterial};
use zfs_read::dsl::{open_mos, walk};
use zfs_read::pool::uberblock_candidates;
use zfs_read::zio::PoolReader;
use zfs_read::zpl::{open_filesystem, Filesystem};
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
pub fn with_dataset<T>(
    spec: &PoolSpec,
    name: &str,
    at: &AtArgs,
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
        // An encrypted dataset needs its key before any of its blocks
        // can be read; the metadata that says so needs none.
        if let Some(enc) = &ds.encryption {
            let keys = unlock(name, enc, at.key.as_deref())?;
            reader.set_keys(Some(keys));
        }
        let fs = match open_filesystem(&reader, ds) {
            Ok(fs) => fs,
            Err(e) => {
                eprintln!("zvolfiles: {name} at txg {}: {e}", c.ub.txg);
                return Err(exit::UNRECOVERABLE);
            }
        };
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
