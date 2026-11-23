//! `dump`: extract a volume — or every volume under a dataset with `-r` —
//! to raw sparse images.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;
use zvol_common::{errln, outln};

use serde::{Deserialize, Serialize};
use zfs_read::crypt::{unwrap_keys, wrapping_key, DatasetKeys, KeyMaterial};
use zfs_read::dsl::{open_mos, walk, Dataset, DatasetTree, Encryption};
use zfs_read::hash::{Digests, Extra};
use zfs_read::pool::{select_uberblock, uberblock_candidates, Candidate, TxgSelect};
use zfs_read::zio::{PoolReader, ReadError};
use zfs_read::zvol::{extract_from, open_volume, volume_facts, OnError, Report};

use zvol_common::members::{choose_pool, open_members};
use zvol_common::timefmt::iso8601;
use zvol_common::{evidence, exit, resume, Format, Global, PoolSpec, WriteGuard};

/// Options of the `dump` command.
pub struct Options {
    /// Dataset name (a volume, or with `recursive` the root of a tree).
    pub dataset: String,
    /// Output image path, or a directory with `recursive`.
    pub output: PathBuf,
    /// Exact TXG; default is the newest that still names the dataset
    /// and can read its object set.
    pub txg: Option<u64>,
    /// Abort on the first unreadable block.
    pub strict: bool,
    /// Encryption key spec (phase 3).
    pub key: Option<String>,
    /// Continue an interrupted extraction.
    pub resume: bool,
    /// Extract every volume under `dataset`.
    pub recursive: bool,
    /// Legacy digests to take alongside SHA-256 (SPEC F-53).
    pub hash: Extra,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BadOut {
    blkid: u64,
    offset: u64,
    len: u64,
    reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DumpOut {
    dataset: String,
    dataset_guid: String,
    txg: u64,
    time: String,
    output: PathBuf,
    volsize: u64,
    blocksize: u64,
    blocks_total: u64,
    blocks_read: u64,
    /// Those of `blocks_read` that nothing verified: their pointers
    /// name no checksum (`checksum=off`).
    blocks_unverified: u64,
    blocks_holes: u64,
    blocks_zeroed: u64,
    /// Blocks written with only their unreadable sectors zeroed (SPEC
    /// F-33); each zeroed range is in `bad`.
    blocks_salvaged: u64,
    bytes_written: u64,
    resumed_from_block: u64,
    strict: bool,
    aborted: bool,
    /// The device refusal that stopped the extraction, when one did
    /// (SPEC F-33, N-10): the incident, as the ledger recorded it.
    #[serde(skip_serializing_if = "Option::is_none")]
    stopped_by_medium: Option<String>,
    /// The block the run was about to read when a SIGINT stopped it
    /// (exit 6): the image holds every block before it, and `--resume`
    /// starts here.
    #[serde(skip_serializing_if = "Option::is_none")]
    interrupted_at: Option<u64>,
    /// The output refused the image — a write, or finishing it — and the
    /// run stopped there (exit 6): what it said.
    #[serde(skip_serializing_if = "Option::is_none")]
    output_failed: Option<String>,
    /// For an output that failed: whether it was still finished and
    /// flushed, so that the hash is the file's — the blocks before the
    /// one it refused — or was not, and the hash is of nothing known to
    /// be on it. What a report says of the hash goes by this.
    #[serde(skip_serializing_if = "Option::is_none")]
    output_finished: Option<bool>,
    /// Where a `--resume` starts, for an image that stopped short: the
    /// block the state on disk names.
    #[serde(skip_serializing_if = "Option::is_none")]
    resume_at: Option<u64>,
    /// What the volume's intent log holds that was not applied: writes
    /// acknowledged as safe that are not in the image, which is the
    /// volume as `txg` left it. Said, and not an exit status: nothing
    /// that was read for failed to read.
    #[serde(skip_serializing_if = "Option::is_none")]
    intent_log: Option<serde_json::Value>,
    /// The sentence that says so.
    #[serde(skip)]
    intent_log_says: Option<String>,
    /// What the run says of the image and of a resume of it.
    #[serde(skip)]
    resume_words: String,
    /// The image was finished and flushed: its hash is the file's.
    #[serde(skip)]
    finished: bool,
    sha256: String,
    /// SHA-1 and MD5, when `--hash` asked for them (SPEC F-53).
    #[serde(skip_serializing_if = "Option::is_none")]
    sha1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    md5: Option<String>,
    /// How long the image is: what a device holds of it.
    #[serde(skip)]
    image_bytes: u64,
    seconds: f64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    bad: Vec<BadOut>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
    /// Encryption suite the volume was decrypted with.
    #[serde(skip_serializing_if = "Option::is_none")]
    encryption: Option<String>,
    /// A `-r --resume` found the image whole, as the run it resumes
    /// finished it, and its SHA-256 still the one that run's manifest
    /// records: it was kept, not extracted again.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    kept: bool,
}

/// What a `-r` run's manifest says, as far as a `--resume` of it reads.
#[derive(Debug, Deserialize)]
struct EarlierRun {
    pool_guid: String,
    #[serde(default)]
    volumes: Vec<DumpOut>,
    #[serde(default)]
    finished_before: Vec<DumpOut>,
}

/// What a `-r --resume` does with a volume the run it resumes finished.
enum Earlier {
    /// The image is the one that run finished: keep it.
    Kept(Box<DumpOut>),
    /// Nothing to keep: extract it.
    Extract,
    /// A signal came while the image was being read back.
    Interrupted,
}

/// The volumes of the `-r` run a `--resume` takes up that it finished
/// whole, from the manifest it left in `dir`. A run that stopped at its
/// third volume left the first two whole and their states cleared, and
/// the resume extracted them again from block 0 — hours, for nothing.
///
/// Whole means every block read: an image with blocks written as zeros
/// is extracted again, as it always was — what did not read then may
/// read now, with the member that was missing given.
fn earlier_run(dir: &Path, pool_guid: &str) -> Vec<DumpOut> {
    let manifest = dir.join("manifest.json");
    let Ok(bytes) = std::fs::read(&manifest) else {
        return Vec::new();
    };
    match serde_json::from_slice::<EarlierRun>(&bytes) {
        Ok(run) if run.pool_guid == pool_guid || run.pool_guid == zvol_common::NO_POOL_GUID => run
            .volumes
            .into_iter()
            .chain(run.finished_before)
            .filter(|v| {
                !v.aborted
                    && v.interrupted_at.is_none()
                    && v.output_failed.is_none()
                    && v.stopped_by_medium.is_none()
                    // Each of them none: added up, a count of
                    // 2^64 - 1 zeroed and one salvaged came to 0, and
                    // the image was whole.
                    && v.blocks_zeroed == 0
                    && v.blocks_salvaged == 0
                    && v.bad.is_empty()
            })
            .collect(),
        Ok(run) => {
            errln!(
                "zvolrescue: {} is of pool {}, not {pool_guid}; every volume is extracted",
                manifest.display(),
                run.pool_guid
            );
            Vec::new()
        }
        Err(e) => {
            errln!(
                "zvolrescue: {} is not a manifest this reads ({e}); every volume is extracted",
                manifest.display()
            );
            Vec::new()
        }
    }
}

/// Whether the image a volume goes to is the one the run being resumed
/// finished: that run's manifest names it whole, at this TXG and for
/// this dataset, nothing left for a resume state to take up, and the
/// file hashes to what the manifest records.
///
/// The record of a kept image is this run's. The manifest's entry was
/// copied whole — its dataset name, its time, its counts — checked for
/// nothing but the GUID, the TXG, the path, the length and the hash,
/// and so printed and written to the evidence log as what this run
/// found: an entry edited to name another dataset, at another time,
/// was this run's record of the volume. What the run has in hand it
/// says itself — the name, the time of the TXG, the intent log — and
/// what only reading the volume again would give, its block counts, is
/// taken from the manifest where it is the volume's.
#[allow(clippy::too_many_arguments)]
fn keep_earlier(
    reader: &PoolReader<'_>,
    earlier: &[DumpOut],
    ds: &Dataset,
    txg: u64,
    newest: bool,
    time: &str,
    output: &Path,
    extra: Extra,
) -> Earlier {
    let guid = format!("{:#018x}", ds.guid);
    let Some(was) = earlier
        .iter()
        .find(|v| v.dataset_guid == guid && v.txg == txg && v.output == output)
    else {
        return Earlier::Extract;
    };
    if resume::path(output).exists() {
        return Earlier::Extract;
    }
    let Ok(mut file) = std::fs::File::open(output) else {
        return Earlier::Extract;
    };
    let interrupt = zvol_common::interrupt_flag();
    let mut digests = Digests::new(extra);
    let mut buf = vec![0u8; 1 << 20];
    let mut len = 0u64;
    loop {
        if interrupt.load(std::sync::atomic::Ordering::Relaxed) {
            return Earlier::Interrupted;
        }
        match std::io::Read::read(&mut file, &mut buf) {
            Ok(0) => break,
            Ok(n) => {
                digests.update(&buf[..n]);
                len += n as u64;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Earlier::Extract,
        }
    }
    let sums = digests.finish();
    if len != was.volsize || sums.sha256 != was.sha256 {
        errln!(
            "zvolrescue: {}: not the image the run being resumed finished ({}); extracting it again",
            output.display(),
            if len != was.volsize {
                format!("{len} bytes, not {}", was.volsize)
            } else {
                "its sha256 differs from the manifest's".to_string()
            }
        );
        return Earlier::Extract;
    }
    let its_own = ds.volsize.is_none_or(|size| size == was.volsize)
        && ds.volblocksize.is_none_or(|b| b == was.blocksize)
        && was.blocksize != 0
        // The blocks counted are those up to the last one written;
        // past it the volume is one hole.
        && was.blocks_total <= was.volsize.div_ceil(was.blocksize)
        && was
            .blocks_read
            .checked_add(was.blocks_holes)
            .is_some_and(|n| n <= was.blocks_total)
        && was.blocks_unverified <= was.blocks_read
        && was.bytes_written <= was.volsize;
    if !its_own {
        errln!(
            "zvolrescue: {}: what the manifest of the run being resumed says of it is not this volume's (its sizes or its block counts); extracting it again",
            output.display()
        );
        return Earlier::Extract;
    }
    let log = zfs_read::zil::intent_log(reader, ds, txg);
    let mut v = was.clone();
    v.dataset = ds.name.clone();
    v.time = time.to_string();
    v.encryption = ds.encryption.as_ref().map(Encryption::suite_name);
    v.intent_log = zvol_common::intent_log_json(log.as_ref());
    v.intent_log_says = log
        .as_ref()
        .filter(|l| l.unreplayed > 0)
        .map(|l| l.says(&ds.name, txg, newest));
    v.warnings = ds
        .warnings
        .iter()
        .filter(|w| !(reader.has_keys() && w.contains("encrypted block: no key")))
        .cloned()
        .collect();
    v.seconds = 0.0;
    v.kept = true;
    v.finished = true;
    v.image_bytes = len;
    v.resumed_from_block = 0;
    v.resume_at = None;
    if extra.sha1 {
        v.sha1 = sums.sha1;
    }
    if extra.md5 {
        v.md5 = sums.md5;
    }
    Earlier::Kept(Box::new(v))
}

/// The volumes the run being resumed finished that this one stopped
/// before it came to: those whose image is among the ones still `left`
/// to do. One this run came to — kept, written again, or failed — is on
/// its own record, or on none.
fn unreached(earlier: &[DumpOut], left: &[PathBuf]) -> Vec<DumpOut> {
    earlier
        .iter()
        .filter(|v| left.contains(&v.output))
        .cloned()
        .collect()
}

/// A TXG that was passed over for an older one. At the `dataset` stage
/// it names the dataset but does not read it — its object set, or for a
/// volume the dnodes beneath it: a destroyed dataset's blocks are free
/// to reuse from the next txg on, and the ring may still name it at one
/// where they are gone while an older one's read. At the `pool` stage
/// the pool itself does not read there: the object set the uberblock
/// points at matches no block, which is what a sync leaves behind when
/// its uberblocks reached the members and its MOS did not — or a ring
/// slot forged outright. At the `tree` stage the pool reads and the
/// dataset tree does not, where the dataset would be: its directory, or
/// the list it would be in. Whether the dataset is there is not known,
/// which was taken for "not there" and passed over without a word.
#[derive(Debug, Serialize)]
struct UnreadableAt {
    txg: u64,
    stage: Stage,
    error: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Stage {
    Pool,
    Tree,
    Dataset,
}

/// What the search for the dataset went through, for the record.
#[derive(Debug, Default)]
struct Searched {
    /// TXGs walked, newest first.
    txgs: Vec<u64>,
    /// Those among them that name the dataset but cannot read it.
    unreadable: Vec<UnreadableAt>,
}

#[derive(Debug, Serialize)]
struct RunOut {
    pool: String,
    pool_guid: String,
    members: Vec<PathBuf>,
    /// TXGs that were walked before the dataset was found (newest first).
    txgs_searched: Vec<u64>,
    /// TXGs among them that name the dataset but cannot read it (newest
    /// first), passed over for an older one.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    unreadable_at: Vec<UnreadableAt>,
    recursive: bool,
    volumes: Vec<DumpOut>,
    /// Datasets under the tree that were skipped (not volumes) or failed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    skipped: Vec<String>,
    /// Volumes the run a `-r --resume` took up had finished, which this
    /// one stopped before it reached: as that run recorded them, for
    /// the next `--resume` to check and keep.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    finished_before: Vec<DumpOut>,
    /// Peak resident set of the run, in KiB (SPEC N-03), where the
    /// platform reports it. Like `seconds`, it varies from run to run
    /// and is not part of what a reproducible run must repeat (N-05).
    #[serde(skip_serializing_if = "Option::is_none")]
    peak_rss_kib: Option<u64>,
}

/// Whether the dataset is still on disk as far as `dump_one` opens it
/// before the first data block: its object set block and, for a volume,
/// the dnodes beneath it (the data object, and the properties that give
/// its size). Read and verified, or verified ciphertext waiting for a
/// key — either way the dataset can be opened once the run gets that
/// far. Checking the object set block alone is not enough: the blocks
/// a destroy frees are reused in no particular order, and the dnode
/// block can be gone while the object set block above it still reads.
fn dataset_reads(reader: &PoolReader<'_>, ds: &Dataset) -> Result<(), ReadError> {
    match reader.read_block(&ds.phys.bp, false) {
        Ok(_) | Err(ReadError::Encrypted) => {}
        Err(e) => return Err(e),
    }
    if ds.kind != Some(zfs_ondisk::dmu::ObjsetType::Zvol) {
        return Ok(());
    }
    match open_volume(reader, ds) {
        Ok(_) | Err(ReadError::Encrypted) => {}
        Err(e) => return Err(e),
    }
    if ds.volsize.is_none() && ds.encryption.is_none() {
        return Err(ReadError::Io(format!(
            "volume size unknown ({})",
            ds.warnings.join("; ")
        )));
    }
    Ok(())
}

/// The newest verified TXG that names `name` and at which it still
/// reads — or the one `sel` asks for, if it does. A TXG that names the
/// dataset but has lost its object set or its volume's dnodes is passed
/// over, said on stderr and recorded in `unreadable`, and an older one
/// is tried: after a `zfs destroy` the pool goes on writing, and the
/// freed blocks are among the first to be reused while older uberblocks
/// still lead to them whole.
fn find_dataset<'c>(
    reader: &PoolReader<'_>,
    candidates: &'c [Candidate],
    sel: Option<u64>,
    pool_name: &str,
    name: &str,
    quiet: bool,
    searched: &mut Searched,
) -> Result<(&'c Candidate, DatasetTree), u8> {
    let pick: Vec<&Candidate> = match sel {
        Some(txg) => match select_uberblock(candidates, TxgSelect::Exact(txg)) {
            Some(c) => vec![c],
            None => {
                errln!(
                    "zvolrescue: no verified uberblock for txg {txg}; available: {}",
                    candidates
                        .iter()
                        .map(|c| c.ub.txg.to_string())
                        .collect::<Vec<_>>()
                        .join(" ")
                );
                return Err(exit::UNRECOVERABLE);
            }
        },
        None => candidates.iter().collect(),
    };
    let mut last_err = None;
    for c in pick {
        searched.txgs.push(c.ub.txg);
        match open_mos(reader, &c.ub).and_then(|mos| walk(&mos, pool_name)) {
            Ok(tree) => {
                let Some(ds) = tree.get(name) else {
                    if let Some(why) = tree.unread_why(name) {
                        if !quiet {
                            errln!(
                                "zvolrescue: {name}: txg {}: the dataset tree does not read there ({why}); trying an older TXG",
                                c.ub.txg
                            );
                        }
                        searched.unreadable.push(UnreadableAt {
                            txg: c.ub.txg,
                            stage: Stage::Tree,
                            error: why,
                        });
                    }
                    continue;
                };
                match dataset_reads(reader, ds) {
                    Ok(()) => return Ok((c, tree)),
                    Err(e) => {
                        // A device that refused a read has stopped the
                        // run (N-10): no older TXG is tried on it.
                        let stopped = matches!(e, ReadError::Medium { .. });
                        if !quiet {
                            errln!(
                                "zvolrescue: {name}: txg {}: unreadable ({e}){}",
                                c.ub.txg,
                                if stopped { "" } else { "; trying an older TXG" }
                            );
                        }
                        searched.unreadable.push(UnreadableAt {
                            txg: c.ub.txg,
                            stage: Stage::Dataset,
                            error: e.to_string(),
                        });
                        if stopped {
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                // The pool itself does not read at this TXG. Said and
                // recorded like a dataset that does not, and passed
                // over the same way: the ring's newest slot is not
                // the pool's newest state when nothing is behind it.
                let stopped = matches!(e, ReadError::Medium { .. });
                if !quiet {
                    errln!(
                        "zvolrescue: txg {}: unreadable ({e}){}",
                        c.ub.txg,
                        if stopped { "" } else { "; trying an older TXG" }
                    );
                }
                searched.unreadable.push(UnreadableAt {
                    txg: c.ub.txg,
                    stage: Stage::Pool,
                    error: e.to_string(),
                });
                last_err = Some(format!("txg {}: {e}", c.ub.txg));
                if stopped {
                    break;
                }
            }
        }
    }
    if let Some(u) = searched
        .unreadable
        .iter()
        .find(|u| u.stage == Stage::Dataset)
    {
        errln!(
            "zvolrescue: dataset {name:?} is named at txg {} but does not read there ({}); readable at none of {} verified TXG(s)",
            u.txg,
            u.error,
            searched.txgs.len()
        );
        return Err(exit::UNRECOVERABLE);
    }
    if let Some(u) = searched.unreadable.iter().find(|u| u.stage == Stage::Tree) {
        errln!(
            "zvolrescue: dataset {name:?} is at none of the {} verified TXG(s) that read where it would be; at txg {} the dataset tree does not ({})",
            searched.txgs.len(),
            u.txg,
            u.error
        );
        return Err(exit::UNRECOVERABLE);
    }
    let pool_unreadable = searched.unreadable.len();
    if pool_unreadable > 1 && pool_unreadable == searched.txgs.len() {
        let u = &searched.unreadable[0];
        errln!(
            "zvolrescue: cannot read the pool at any of {pool_unreadable} verified TXG(s) (newest: txg {}: {})",
            u.txg, u.error
        );
        return Err(exit::UNRECOVERABLE);
    }
    match last_err {
        Some(e) if searched.txgs.len() == 1 => {
            errln!("zvolrescue: cannot read the pool at {e}")
        }
        _ => errln!(
            "zvolrescue: dataset {name:?} not found at any of {} verified TXG(s){}",
            searched.txgs.len(),
            last_err
                .map(|e| format!(" (last error: {e})"))
                .unwrap_or_default()
        ),
    }
    Err(exit::UNRECOVERABLE)
}

/// Turn `--key` into the dataset keys of `enc`, or explain what is
/// missing. No key, an unparsable spec, the wrong format and a wrong key
/// are all exit `USAGE`: the pool is fine, the input is not.
fn unlock(ds: &Dataset, enc: &Encryption, spec: Option<&str>) -> Result<DatasetKeys, u8> {
    let Some(spec) = spec else {
        errln!(
            "zvolrescue: {} is encrypted ({}, keyformat {}{}); supply --key raw:FILE | hex:HEX | passphrase:FILE | prompt",
            ds.name,
            enc.suite_name(),
            enc.keyformat_name(),
            enc.keylocation
                .as_ref()
                .map_or(String::new(), |l| format!(", keylocation {l}"))
        );
        return Err(exit::USAGE);
    };
    let material = if spec == "prompt" {
        eprint!(
            "{} ({}) key: ",
            zvol_common::text::shown(&ds.name),
            enc.keyformat_name()
        );
        KeyMaterial::prompt(enc.keyformat)
    } else {
        KeyMaterial::from_spec(spec)
    };
    material
        .and_then(|m| wrapping_key(&m, enc))
        .and_then(|w| unwrap_keys(enc, &w))
        .map_err(|e| {
            errln!("zvolrescue: {}: {e}", ds.name);
            exit::USAGE
        })
}

/// Extract one volume to `output`. `Err(code)` is a hard failure; a
/// completed-with-errors extraction is an `Ok` report with `aborted` set.
#[allow(clippy::too_many_arguments)]
fn dump_one(
    g: &Global,
    reader: &PoolReader<'_>,
    ds: &Dataset,
    txg: u64,
    newest: bool,
    time: &str,
    output: &Path,
    strict: bool,
    resume: bool,
    hash: Extra,
) -> Result<DumpOut, u8> {
    let (obj, _) = match open_volume(reader, ds) {
        Ok(x) => x,
        Err(e) => {
            errln!("zvolrescue: {}: {e}", ds.name);
            return Err(exit::UNRECOVERABLE);
        }
    };
    // list could not read the size of an encrypted volume; with the
    // keys installed it is readable now.
    let volsize = match ds.volsize {
        Some(v) => v,
        None if reader.has_keys() => match volume_facts(reader, ds) {
            Ok((v, _)) => v,
            Err(e) => {
                errln!("zvolrescue: {}: volume size: {e}", ds.name);
                return Err(exit::UNRECOVERABLE);
            }
        },
        None => {
            errln!(
                "zvolrescue: {}: volsize unknown ({})",
                ds.name,
                ds.warnings.join("; ")
            );
            return Err(exit::UNRECOVERABLE);
        }
    };
    let blocksize = obj.dnode().datablksz();
    let expected_state = resume::State {
        version: 1,
        dataset: ds.name.clone(),
        dataset_guid: format!("{:#018x}", ds.guid),
        txg,
        volsize,
        blocksize,
        blocks_done: 0,
        lost: resume::Lost::default(),
        prefix_sha256: None,
    };
    // Where to start, the hash of what is already there, and what that
    // lost.
    let (start_block, hasher, mut sink, earlier) = resume::open(
        "zvolrescue",
        &ds.name,
        output,
        &expected_state,
        hash,
        resume,
        g.quiet,
    )
    .map_err(|e| {
        errln!("zvolrescue: {e}");
        exit::USAGE
    })?;

    // Counted before the image is written, said after it: nothing of
    // the intent log is applied.
    let log = zfs_read::zil::intent_log(reader, ds, txg);
    let started = Instant::now();
    let quiet = g.quiet;
    let mut last_report = Instant::now();
    let mut last_state = Instant::now();
    let mut saver = resume::Saver::new(output, &expected_state, start_block);
    let interrupt = zvol_common::interrupt_flag();
    let progress = |done: u64, total: u64, so_far: &Report, digests: &Digests| {
        if !quiet && (last_report.elapsed().as_secs() >= 2 || done == total) {
            eprint!(
                "\r  {} {done}/{total} blocks",
                zvol_common::text::shown(&ds.name)
            );
            let _ = std::io::stderr().flush();
            last_report = Instant::now();
        }
        if last_state.elapsed().as_secs() >= 5 && done < total {
            let lost = earlier.and(so_far, done);
            // The digests have taken exactly the blocks done: what a
            // resume has to read back from the image to go on.
            let prefix = digests.clone().finish().sha256;
            if !saver.save(done, &lost, &prefix) {
                // The image could not be flushed: nothing written to it
                // from here on can be counted. The run stops as a signal
                // stops it, and says why below.
                interrupt.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            last_state = Instant::now();
        }
    };
    let on_error = if strict {
        OnError::Abort
    } else {
        OnError::Zero
    };
    let mut report: Report = match extract_from(
        &obj,
        volsize,
        &mut sink,
        on_error,
        start_block,
        hasher,
        Some(&interrupt),
        progress,
    ) {
        Ok(r) => r,
        Err(e) => {
            if !quiet {
                errln!();
            }
            errln!("zvolrescue: {}: extraction failed: {e}", ds.name);
            return Err(exit::UNRECOVERABLE);
        }
    };
    if !quiet {
        errln!();
    }
    if let Some(e) = saver.unflushed() {
        report
            .output_failed
            .get_or_insert_with(|| format!("the image could not be flushed: {e}"));
    }
    // A state so --resume can continue past the fix — at the block the
    // abort stopped at, the last range listed — or, after an interrupt or
    // an output that refused, from the block that was next; none for a
    // whole image. What the run says of it is what the state on disk
    // bears out.
    let resume_at = saver.conclude(&report, &earlier, start_block);
    let resume_words = if report.output_failed.is_some() {
        saver.words("and --resume continues there once the output has room")
    } else if report.interrupted_at.is_some() || !report.aborted {
        saver.words("--resume continues there")
    } else {
        saver.words("--resume continues after a repair")
    };
    if let Some(why) = &report.output_failed {
        errln!("zvolrescue: {}: {why}; {resume_words} (exit 6)", ds.name);
    } else if let Some(at) = report.interrupted_at {
        errln!(
            "zvolrescue: {}: interrupted at block {at} of {}; {resume_words} (exit 6)",
            ds.name,
            report.blocks_total
        );
    }
    // What the run that was resumed lost is this image's too.
    earlier.into_report(&mut report);
    Ok(DumpOut {
        dataset: ds.name.clone(),
        dataset_guid: format!("{:#018x}", ds.guid),
        txg,
        time: time.to_string(),
        output: output.to_path_buf(),
        volsize: report.volsize,
        blocksize: report.blocksize,
        blocks_total: report.blocks_total,
        blocks_read: report.blocks_read,
        blocks_unverified: report.blocks_unverified,
        blocks_holes: report.blocks_holes,
        blocks_zeroed: report.blocks_zeroed,
        blocks_salvaged: report.blocks_salvaged,
        bytes_written: report.bytes_written,
        resumed_from_block: start_block,
        strict,
        aborted: report.aborted,
        stopped_by_medium: report.stopped_by_medium.clone(),
        interrupted_at: report.interrupted_at,
        output_failed: report.output_failed.clone(),
        output_finished: report.output_failed.as_ref().map(|_| report.finished),
        resume_at,
        intent_log: zvol_common::intent_log_json(log.as_ref()),
        intent_log_says: log
            .as_ref()
            .filter(|l| l.unreplayed > 0)
            .map(|l| l.says(&ds.name, txg, newest)),
        resume_words,
        finished: report.finished,
        sha256: report.sha256.clone(),
        sha1: report.sha1.clone(),
        md5: report.md5.clone(),
        image_bytes: report.image_bytes,
        seconds: started.elapsed().as_secs_f64(),
        bad: report
            .bad
            .iter()
            .map(|b| BadOut {
                blkid: b.blkid,
                offset: b.offset,
                len: b.len,
                reason: b.reason.clone(),
            })
            .collect(),
        warnings: ds
            .warnings
            .iter()
            .filter(|w| !(reader.has_keys() && w.contains("encrypted block: no key")))
            .cloned()
            .collect(),
        encryption: ds.encryption.as_ref().map(Encryption::suite_name),
        kept: false,
    })
}

fn print_text(out: &RunOut) {
    for v in &out.volumes {
        outln!(
            "{}: {} bytes from {} at txg {} ({}) -> {}{}",
            v.dataset,
            v.volsize,
            out.pool,
            v.txg,
            v.time,
            v.output.display(),
            if v.kept {
                " (kept: whole as the run being resumed left it, sha256 as its manifest records)"
                    .to_string()
            } else if v.resumed_from_block > 0 {
                format!(" (resumed at block {})", v.resumed_from_block)
            } else {
                String::new()
            }
        );
        // A device gets every byte of the image, holes as zeros: the
        // bytes of data alone read as all that went to it.
        let written = if std::fs::metadata(&v.output).is_ok_and(|m| !m.is_file()) {
            format!(
                "{} bytes of data, {} on the device with the holes as zeros,",
                v.bytes_written, v.image_bytes
            )
        } else {
            format!("{} bytes written", v.bytes_written)
        };
        outln!(
            "  blocks: {} total, {} read, {} holes, {} zeroed (unreadable), {} salvaged (unreadable sectors zeroed); {written} in {:.1}s",
            v.blocks_total, v.blocks_read, v.blocks_holes, v.blocks_zeroed, v.blocks_salvaged, v.seconds
        );
        if v.blocks_unverified > 0 {
            outln!(
                "  UNVERIFIED: {} of the {} block(s) read carry no checksum (checksum=off): written as the members gave them, and checked by nothing",
                v.blocks_unverified, v.blocks_read
            );
        }
        if let Some(says) = &v.intent_log_says {
            outln!("  INTENT LOG NOT APPLIED: {says}");
        }
        outln!("  sha256: {}", v.sha256);
        if let Some(h) = &v.sha1 {
            outln!("  sha1:   {h}");
        }
        if let Some(h) = &v.md5 {
            outln!("  md5:    {h}");
        }
        if let Some(e) = &v.encryption {
            outln!("  decrypted: {e}");
        }
        for w in &v.warnings {
            outln!("  warning: {w}");
        }
        for b in &v.bad {
            outln!(
                "  unreadable: blkid {} offset {} len {}: {}",
                b.blkid,
                b.offset,
                b.len,
                b.reason
            );
        }
        if let Some(why) = &v.output_failed {
            outln!(
                "  OUTPUT FAILED (exit 6): {why}; the image is incomplete: {}",
                v.resume_words
            );
        } else if v.stopped_by_medium.is_some() {
            outln!("  STOPPED: a device refused a read (exit 7); the image is incomplete. Image the disk with a map, then --map and --resume continue on the image (SPEC F-33, N-10)");
        } else if let Some(at) = v.interrupted_at {
            outln!(
                "  INTERRUPTED at block {at} (exit 6); the image is incomplete: {}",
                v.resume_words
            );
        } else if v.aborted {
            outln!(
                "  ABORTED at the first unreadable block (--strict); the image is incomplete: {}",
                v.resume_words
            );
        } else if !v.bad.is_empty() {
            outln!(
                "  WARNING: {} unreadable range(s) were written as zeros (exit 4); rerun with --strict to refuse partial output",
                v.bad.len()
            );
        }
    }
    for s in &out.skipped {
        outln!("skipped: {s}");
    }
    if !out.finished_before.is_empty() {
        outln!(
            "{} volume(s) the run being resumed finished were not reached; --resume checks and keeps them",
            out.finished_before.len()
        );
    }
    if out.recursive {
        let kept = out.volumes.iter().filter(|v| v.kept).count();
        if kept > 0 {
            outln!(
                "{} volume(s) written, {kept} kept from the run being resumed; manifest in the output directory",
                out.volumes.len() - kept
            );
        } else {
            outln!(
                "{} volume(s) written; manifest in the output directory",
                out.volumes.len()
            );
        }
    }
}

/// The end of every run, early or not: the medium incidents on stderr
/// and the stop, when one stopped the run, as the exit code (SPEC F-33,
/// N-10); then the evidence record, with them. A run that failed before
/// it wrote a byte ends here too — a device that refused a read while
/// the MOS was being opened is the same incident as one that refused a
/// data block, and the operator is told the same way.
fn finish(
    g: &Global,
    members: &zvol_common::members::Members,
    json: &serde_json::Value,
    code: u8,
    written: Vec<evidence::FileRef>,
) -> u8 {
    let code = if code == 0 && members.any_failed() {
        exit::EVIDENCE
    } else {
        code
    };
    zvol_common::end_run(
        g,
        "zvolrescue",
        json,
        code,
        &members.inputs(),
        written,
        &members.ledger,
    )
}

/// The file each volume of a `-r` run goes to: its name with `/` as `_`
/// and `.img` after it. So with every character that is not seen as
/// itself — a control character, a bidirectional override: a dataset
/// named with an escape sequence gave a file named with one, which
/// cleared the screen of whoever listed the directory.
///
/// Two names can come out the same — `tank/vm/web_1` and `tank/vm_web/1`
/// are both `tank_vm_web_1.img` — and the second extraction used to
/// truncate the first one's image. Every name of such a group gets its
/// dataset GUID as well, which keeps the plain names everyone else has
/// and makes the same pool give the same files whatever order its
/// datasets are walked in; a name that still repeats after that (a
/// dataset named like another's GUID-suffixed file) gets a counter.
fn image_file_names(datasets: &[(&str, u64)]) -> Vec<String> {
    let plain = |c: char| {
        if c == '/' || c.is_control() || zvol_common::text::unseen(c) {
            '_'
        } else {
            c
        }
    };
    let flat: Vec<String> = datasets
        .iter()
        .map(|(n, _)| n.chars().map(plain).collect())
        .collect();
    let mut used = std::collections::BTreeSet::new();
    datasets
        .iter()
        .zip(&flat)
        .map(|((_, guid), f)| {
            let base = if flat.iter().filter(|g| *g == f).count() > 1 {
                format!("{f}.{guid:016x}")
            } else {
                f.clone()
            };
            let mut name = format!("{base}.img");
            let mut n = 2;
            while !used.insert(name.clone()) {
                name = format!("{base}.{n}.img");
                n += 1;
            }
            name
        })
        .collect()
}

/// Run `dump`.
pub fn run(g: &Global, spec: &PoolSpec, opts: &Options) -> u8 {
    // From here a SIGINT sets the flag the extraction looks at between
    // blocks: one that comes while the members are still being opened is
    // acted on at the first block, and a second is the default action,
    // for a run that never gets there.
    let _ = zvol_common::interrupt_flag();
    let members = match open_members(spec) {
        Ok(m) => m,
        Err(code) => return zvol_common::end_early(g, "zvolrescue", spec, code),
    };
    // Everything the run reads, for every file it writes.
    let mut reads = spec.reads();
    reads.extend(members.paths.iter().cloned());
    reads.extend(opts.key.as_deref().and_then(KeyMaterial::spec_file));
    let guard = WriteGuard::new(g, &reads);
    if let Err(code) = guard.refuse("zvolrescue", "-o", &opts.output) {
        return zvol_common::end_early(g, "zvolrescue", spec, code);
    }
    let pool = match choose_pool(members.pools.clone(), spec.pool_guid.as_deref()) {
        Ok(p) => p,
        Err(code) => return zvol_common::end_early(g, "zvolrescue", spec, code),
    };
    let candidates = uberblock_candidates(&members.scans, &pool);
    if candidates.is_empty() {
        errln!("zvolrescue: no verified uberblocks on the scanned members");
        return zvol_common::end_early(g, "zvolrescue", spec, exit::UNRECOVERABLE);
    }
    let reader = PoolReader::new(&pool, members.devices()).with_base_offsets(&members.bases());
    let mut searched = Searched::default();
    let (chosen, tree) = match find_dataset(
        &reader,
        &candidates,
        opts.txg,
        &pool.name,
        &opts.dataset,
        g.quiet,
        &mut searched,
    ) {
        Ok(x) => x,
        Err(code) => {
            // Nothing was written, but the run still ends the way every
            // run ends: a device may have refused a read on the way to
            // the dataset, and that is reported the same way as one
            // refused on the way to a data block.
            let out = RunOut {
                pool: pool.name.clone(),
                pool_guid: format!("{:#018x}", pool.guid),
                members: members.paths.clone(),
                txgs_searched: searched.txgs,
                unreadable_at: searched.unreadable,
                recursive: opts.recursive,
                volumes: Vec::new(),
                skipped: Vec::new(),
                finished_before: Vec::new(),
                peak_rss_kib: zvol_common::peak_rss_kib(),
            };
            let json = serde_json::to_value(&out).expect("serialisable");
            if g.format == Format::Json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json).expect("serialisable")
                );
            }
            return finish(g, &members, &json, code, Vec::new());
        }
    };
    let txg = chosen.ub.txg;
    // Whether this is the pool's present: only there is a dataset's
    // intent log what an import would replay.
    let newest = candidates.first().is_some_and(|c| c.ub.txg == txg);
    let time = iso8601(chosen.ub.timestamp);

    // Which datasets, and where each one goes.
    let targets: Vec<(&Dataset, PathBuf)> = if opts.recursive {
        // Nothing to extract is not a success: "0 volume(s) written",
        // exit 0, while the volumes were destroyed at this txg and an
        // older one still has them — which `list --diff` names.
        // `POOL/VOL@SNAP` is that snapshot of every volume under
        // `POOL/VOL` which has one, as `zfs snapshot -r` makes them: it
        // was "no volume under …", exit 3, while a plain `dump` of the
        // same name read it.
        let (root, snap) = match opts.dataset.split_once('@') {
            Some((r, s)) => (r, Some(s)),
            None => (opts.dataset.as_str(), None),
        };
        let prefix = format!("{root}/");
        let under = |d: &Dataset| match snap {
            None => !d.snapshot && (d.name == root || d.name.starts_with(&prefix)),
            Some(snap) => {
                d.snapshot
                    && d.name.split_once('@').is_some_and(|(head, s)| {
                        s == snap && (head == root || head.starts_with(&prefix))
                    })
            }
        };
        let any = tree
            .datasets
            .iter()
            .any(|d| under(d) && d.kind == Some(zfs_ondisk::dmu::ObjsetType::Zvol));
        if !any {
            errln!(
                "zvolrescue: no volume under {} at txg {txg}; `zvolrescue list --diff OLDER_TXG` names the volumes destroyed since, and --txg reads one where they are (exit 3)",
                opts.dataset
            );
            return zvol_common::end_early(g, "zvolrescue", spec, exit::UNRECOVERABLE);
        }
        if let Err(e) = std::fs::create_dir_all(&opts.output) {
            errln!(
                "zvolrescue: cannot create directory {}: {e}",
                opts.output.display()
            );
            return zvol_common::end_early(g, "zvolrescue", spec, exit::USAGE);
        }
        let chosen: Vec<&Dataset> = tree.datasets.iter().filter(|d| under(d)).collect();
        // Names only for what will be written: a filesystem flattening
        // to a volume's name gave the volume a GUID suffix for a clash
        // with nothing.
        let volumes: Vec<&Dataset> = chosen
            .iter()
            .copied()
            .filter(|d| d.kind == Some(zfs_ondisk::dmu::ObjsetType::Zvol))
            .collect();
        let names = image_file_names(
            &volumes
                .iter()
                .map(|d| (d.name.as_str(), d.guid))
                .collect::<Vec<_>>(),
        );
        let mut named = volumes.into_iter().zip(names);
        chosen
            .into_iter()
            .map(|d| {
                if d.kind == Some(zfs_ondisk::dmu::ObjsetType::Zvol) {
                    let (v, name) = named.next().expect("one name per volume");
                    (v, opts.output.join(name))
                } else {
                    // Skipped below as not a volume; never written.
                    (d, opts.output.clone())
                }
            })
            .collect()
    } else {
        vec![(
            tree.get(&opts.dataset).expect("found above"),
            opts.output.clone(),
        )]
    };
    // Every file this run will write, before the first is: the images
    // `-r` names inside the directory — one called like a member beside
    // them was written over — their resume states and the manifest.
    let mut writes: Vec<PathBuf> = Vec::new();
    for (ds, output) in &targets {
        if opts.recursive && ds.kind != Some(zfs_ondisk::dmu::ObjsetType::Zvol) {
            continue;
        }
        if opts.recursive {
            writes.push(output.clone());
        }
        writes.extend(resume::sidecars(output));
    }
    if opts.recursive {
        let manifest = opts.output.join("manifest.json");
        writes.push(resume::tmp_path(&manifest));
        writes.push(manifest);
    }
    // What `-r` writes inside its directory is named by the run, not by
    // the operator: a link already lying there under one of those names
    // is replaced, not followed, as `zvolfiles extract` replaces one. A
    // link to some file outside the tree got the image, and then the
    // manifest, written into it. One that is how the run names an input
    // or a log stays, and the run is refused.
    //
    // Before the guard looks: it followed the link, and one to a member
    // refused the run (exit 5) over a file it would never have touched.
    //
    // Every name is judged before any link goes: a run refused over the
    // third name had already removed the links at the first two, and a
    // refused run is to have changed nothing.
    let is_link = |w: &Path| std::fs::symlink_metadata(w).is_ok_and(|m| m.file_type().is_symlink());
    let links: Vec<&PathBuf> = if opts.recursive {
        writes.iter().filter(|w| is_link(w)).collect()
    } else {
        Vec::new()
    };
    for w in &links {
        if let Err(why) = guard.check_name(w) {
            errln!("zvolrescue: refusing to write {}: {why}", w.display());
            return zvol_common::end_early(g, "zvolrescue", spec, exit::REFUSED);
        }
    }
    for w in writes.iter().filter(|w| !links.contains(w)) {
        if let Err(code) = guard.refuse("zvolrescue", "to write", w) {
            return zvol_common::end_early(g, "zvolrescue", spec, code);
        }
    }
    for w in &links {
        if let Err(e) = std::fs::remove_file(w) {
            errln!("zvolrescue: {}: {e}", w.display());
            return zvol_common::end_early(g, "zvolrescue", spec, exit::USAGE);
        }
        if let Err(code) = guard.refuse("zvolrescue", "to write", w) {
            return zvol_common::end_early(g, "zvolrescue", spec, code);
        }
    }

    let mut out = RunOut {
        pool: pool.name.clone(),
        pool_guid: format!("{:#018x}", pool.guid),
        members: members.paths.clone(),
        txgs_searched: searched.txgs,
        unreadable_at: searched.unreadable,
        recursive: opts.recursive,
        volumes: Vec::new(),
        skipped: Vec::new(),
        finished_before: Vec::new(),
        peak_rss_kib: None,
    };
    let mut code = 0u8;
    let mut key_cache: std::collections::BTreeMap<u64, DatasetKeys> = Default::default();
    // What the run a `-r --resume` takes up finished, read before this
    // run writes a manifest of its own over that one's.
    let mut earlier = if opts.recursive && opts.resume {
        earlier_run(&opts.output, &out.pool_guid)
    } else {
        Vec::new()
    };
    let manifest = opts.output.join("manifest.json");
    // The images this run has yet to come to, in order.
    let mut left: Vec<PathBuf> = if opts.recursive {
        targets
            .iter()
            .filter(|(ds, _)| ds.kind == Some(zfs_ondisk::dmu::ObjsetType::Zvol))
            .map(|(_, output)| output.clone())
            .collect()
    } else {
        Vec::new()
    };
    // An image that run named another way — `-o out` then, `-o ./out`
    // now — is the same image: by the name this run gives it from here
    // on, or it was "not that run's" and extracted again without a word.
    for v in &mut earlier {
        if let Some(now) = left
            .iter()
            .find(|o| **o != v.output && zvol_common::same_file(o, &v.output))
        {
            v.output = now.clone();
        }
    }
    let earlier = earlier;
    // The manifest is written as each volume ends, not only at the end:
    // a run killed outright still leaves what it finished on record for
    // a `--resume` to keep. Whole or not at all, as a state is: cut
    // short by the kill, it was "not a manifest this reads", and every
    // image went again.
    let note = |out: &mut RunOut, left: &[PathBuf]| {
        if !opts.recursive {
            return;
        }
        out.finished_before = unreached(&earlier, left);
        let json = serde_json::to_string_pretty(&*out).expect("serialisable");
        let _ = resume::replace(&manifest, json.as_bytes());
    };
    for (ds, output) in targets {
        if opts.recursive && ds.kind != Some(zfs_ondisk::dmu::ObjsetType::Zvol) {
            out.skipped.push(format!("{}: not a volume", ds.name));
            continue;
        }
        left.retain(|l| *l != output);
        if !earlier.is_empty() {
            match keep_earlier(
                &reader, &earlier, ds, txg, newest, &time, &output, opts.hash,
            ) {
                Earlier::Kept(v) => {
                    if !g.quiet {
                        errln!(
                            "  keeping {}: {} is whole, as the run being resumed left it",
                            ds.name,
                            output.display()
                        );
                    }
                    out.volumes.push(*v);
                    note(&mut out, &left);
                    continue;
                }
                Earlier::Interrupted => {
                    errln!(
                        "zvolrescue: {}: interrupted while checking {}; --resume checks it again (exit 6)",
                        ds.name,
                        output.display()
                    );
                    // Not come to: it stays on the record as that run
                    // left it, for the next resume to check.
                    left.insert(0, output);
                    code = code.max(exit::INTERRUPTED);
                    break;
                }
                Earlier::Extract => {}
            }
        }
        reader.set_keys(None);
        if let Some(enc) = &ds.encryption {
            let keys = match key_cache.get(&enc.crypto_key_obj) {
                Some(k) => k.clone(),
                None => match unlock(ds, enc, opts.key.as_deref()) {
                    Ok(k) => {
                        key_cache.insert(enc.crypto_key_obj, k.clone());
                        k
                    }
                    Err(c) => {
                        if opts.recursive {
                            out.skipped
                                .push(format!("{}: encrypted, not unlocked (exit {c})", ds.name));
                            code = code.max(c);
                            continue;
                        }
                        return zvol_common::end_early(g, "zvolrescue", spec, c);
                    }
                },
            };
            if !g.quiet && g.format == Format::Text {
                outln!(
                    "  {}: unlocked ({}, key guid {:#x})",
                    ds.name,
                    enc.suite_name(),
                    keys.key_guid
                );
            }
            reader.set_keys(Some(keys));
        }
        // A filesystem is the wrong command, not an unreadable pool: it
        // was "I/O error: … is a filesystem, not a volume", exit 3. Asked
        // after the key, so that a key given for an encrypted dataset is
        // still checked, whatever the dataset turns out to be.
        if let Some(kind) = ds.kind.filter(|k| *k != zfs_ondisk::dmu::ObjsetType::Zvol) {
            errln!(
                "zvolrescue: {} is {}, not a volume{}",
                ds.name,
                kind.described(),
                if kind == zfs_ondisk::dmu::ObjsetType::Zfs {
                    "; its files come out with zvolfiles extract, its objects with zvolfiles objects"
                } else {
                    ""
                }
            );
            return zvol_common::end_early(g, "zvolrescue", spec, exit::USAGE);
        }
        match dump_one(
            g,
            &reader,
            ds,
            txg,
            newest,
            &time,
            &output,
            opts.strict,
            opts.resume,
            opts.hash,
        ) {
            Ok(v) => {
                // An image with blocks written as zeros is not the
                // volume, and a script that reads only the status must
                // not be told it is. The run says so in the warning, in
                // the JSON and in the evidence record; now it says so
                // in the one place a `dump || fail` can see.
                code = exit::after_extraction(code, v.aborted, v.blocks_zeroed + v.blocks_salvaged);
                // What the intent log holds is said and recorded, and
                // is not this status: the image is whole as its
                // transaction group left it, and 4 is for what could
                // not be read. On a pool that went down under load
                // nearly every volume has such a log, and 4 for it told
                // an image with nothing lost from one with blocks
                // written as zeros no more.
                // An interrupt ends the run, not just the volume: the
                // operator asked for it to stop, and a bulk run that went
                // on to the next volume would not have stopped.
                // An output that refused ends it too: the next volume
                // would go to the same place.
                let interrupted = v.interrupted_at.is_some() || v.output_failed.is_some();
                out.volumes.push(v);
                note(&mut out, &left);
                if interrupted {
                    code = code.max(exit::INTERRUPTED);
                    break;
                }
            }
            Err(c) => {
                if opts.recursive {
                    out.skipped.push(format!("{}: failed (exit {c})", ds.name));
                    code = code.max(c);
                } else {
                    // One target, and it failed: the run is over, but
                    // it ends below like any other, where a device's
                    // refusal becomes exit 7 and an incident on record.
                    code = code.max(c);
                    break;
                }
            }
        }
    }
    out.peak_rss_kib = zvol_common::peak_rss_kib();
    out.finished_before = unreached(&earlier, &left);
    let json = serde_json::to_value(&out).expect("serialisable");
    if opts.recursive {
        if let Err(e) = resume::replace(
            &manifest,
            serde_json::to_string_pretty(&json)
                .expect("serialisable")
                .as_bytes(),
        ) {
            errln!("zvolrescue: cannot write {}: {e}", manifest.display());
            code = code.max(exit::USAGE);
        }
    }
    match g.format {
        Format::Json => println!(
            "{}",
            serde_json::to_string_pretty(&json).expect("serialisable")
        ),
        Format::Text => print_text(&out),
    }
    // Every image this run wrote, with the hash `dump` already computed
    // over it — there is no reason to read a 32 GiB image back to hash
    // what was just hashed on the way out. The manifest of a bulk run is
    // small enough to hash here.
    // An image sent to a device is the device's first so many bytes,
    // and one sent to /dev/null is kept nowhere: its hash is in the
    // result, and there is no output to check it against.
    let mut written: Vec<evidence::FileRef> = out
        .volumes
        .iter()
        .filter(|v| !evidence::keeps_nothing(&v.output))
        .map(|v| {
            if v.finished {
                evidence::FileRef::known_with(
                    &v.output,
                    &v.sha256,
                    v.sha1.as_deref(),
                    v.md5.as_deref(),
                )
                .image(v.image_bytes)
            } else {
                // Not finished: what the file holds is not what was
                // hashed on the way, and the record does not say it is.
                evidence::FileRef::stat(&v.output)
            }
        })
        .collect();
    if opts.recursive {
        if let Ok(f) = evidence::FileRef::hashed(&manifest) {
            written.push(f);
        }
    }
    finish(g, &members, &json, code, written)
}

#[cfg(test)]
mod tests {
    use super::image_file_names;

    #[test]
    fn every_volume_of_a_recursive_dump_gets_a_file_of_its_own() {
        // The names everyone has stay what they were.
        assert_eq!(
            image_file_names(&[("tank/vm/a", 1), ("tank/vm/b", 2)]),
            ["tank_vm_a.img", "tank_vm_b.img"]
        );
        // Two that flatten alike both carry their GUID, whichever comes first.
        let one = image_file_names(&[("tank/vm/web_1", 0xa), ("tank/vm_web/1", 0xb)]);
        let other = image_file_names(&[("tank/vm_web/1", 0xb), ("tank/vm/web_1", 0xa)]);
        assert_eq!(
            one,
            [
                "tank_vm_web_1.000000000000000a.img",
                "tank_vm_web_1.000000000000000b.img"
            ]
        );
        assert_eq!(other, [one[1].clone(), one[0].clone()]);
        // A name built to look like another's suffixed file still gets its own.
        let odd = image_file_names(&[("t/a_b", 1), ("t_a/b", 2), ("t/a_b.0000000000000001", 3)]);
        let unique: std::collections::BTreeSet<_> = odd.iter().collect();
        assert_eq!(unique.len(), 3, "{odd:?}");
    }

    /// What is not seen as itself is no part of a file's name: a volume
    /// named with an escape sequence gave a file named with one. Two
    /// names that differ only there are told apart as two that differ
    /// only in a `/` are.
    #[test]
    fn a_file_is_not_named_with_what_is_not_seen() {
        assert_eq!(
            image_file_names(&[("np/x\u{1b}[2Jy", 1), ("np/a\nb\u{202e}c", 2)]),
            ["np_x_[2Jy.img", "np_a_b_c.img"]
        );
        assert_eq!(
            image_file_names(&[("t/a\u{1b}b", 0xa), ("t/a\u{7}b", 0xb)]),
            ["t_a_b.000000000000000a.img", "t_a_b.000000000000000b.img"]
        );
    }
}
