//! Reading every surviving TXG and printing what changed between them.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;

use serde::Serialize;
use zfs_ondisk::dmu::ObjsetType;
use zfs_read::dsl::{open_mos, walk, Dataset, Pending};
use zfs_read::pool::{uberblock_candidates, Candidate};
use zfs_read::zio::PoolReader;
use zvol_common::members::{choose_pool, open_members};
use zvol_common::timefmt::iso8601;
use zvol_common::{evidence, exit, shell_quote, Format, Global, PoolSpec, WriteGuard};

use crate::events::{sort, Event, Kind};

/// Options of a run.
pub struct Options {
    /// Oldest TXG to read.
    pub from: Option<u64>,
    /// Newest TXG to read.
    pub to: Option<u64>,
    /// Restrict the report to one object.
    pub dataset: Option<String>,
    /// Report the space held by pending frees and deadlists.
    pub pending: bool,
    /// Write the report here instead of stdout.
    pub output: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct EventOut {
    txg: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    time: Option<String>,
    event: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    object: Option<String>,
    #[serde(skip_serializing_if = "is_zero")]
    guid: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    details: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_seen_txg: Option<u64>,
    /// For a destroyed object: the command that gets it back.
    #[serde(skip_serializing_if = "Option::is_none")]
    recover_with: Option<String>,
}

fn is_zero(s: &String) -> bool {
    s == "0x0000000000000000"
}

#[derive(Debug, Serialize)]
struct TimelineOut {
    pool: String,
    pool_guid: String,
    members: Vec<PathBuf>,
    /// Every TXG whose uberblock verified, oldest first.
    txgs: Vec<u64>,
    /// TXGs that were read but whose MOS could not be walked.
    unreadable_txgs: Vec<u64>,
    /// TXGs whose MOS was walked but where part of the dataset tree
    /// could not be read: their datasets are partly carried over from
    /// the TXG before.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    partial_txgs: Vec<u64>,
    /// The object `--dataset` asked about.
    #[serde(skip_serializing_if = "Option::is_none")]
    dataset: Option<String>,
    events: Vec<EventOut>,
    /// Property changes left out: they are reported at `-v` (T-09).
    #[serde(skip_serializing_if = "is_none_left_out")]
    properties_not_shown: usize,
    /// `-q`: the text says nothing it need not.
    #[serde(skip)]
    quiet: bool,
}

fn is_none_left_out(n: &usize) -> bool {
    *n == 0
}

/// The command that recovers a destroyed object (T-05): `zvolrescue
/// dump` for a volume, `zvolfiles extract` for a filesystem, nothing for
/// anything else — a command printed for an object it cannot recover
/// only fails when it is run.
///
/// It repeats this run's own pool specification — the members as they
/// were named, and any `--hints`, `--search-order`, `--assume-member`,
/// `--map` or `--ignore-unknown-features` that made them readable —
/// because a command that reached the pool by a different route would
/// not reach the same dataset; and an encrypted one asks for its key.
fn recover_with(
    spec: &PoolSpec,
    object: &str,
    txg: u64,
    kind: Option<ObjsetType>,
    encrypted: bool,
) -> Option<String> {
    let flat = object.replace('/', "_");
    let (mut parts, output) = match kind? {
        ObjsetType::Zvol => (
            vec!["zvolrescue".to_string(), "dump".into(), shell_quote(object)],
            format!("{flat}.img"),
        ),
        ObjsetType::Zfs => (
            vec![
                "zvolfiles".to_string(),
                "extract".into(),
                shell_quote(object),
            ],
            flat,
        ),
        _ => return None,
    };
    parts.extend(spec.as_arguments());
    parts.push(format!("--txg {txg}"));
    if encrypted {
        parts.push("--key prompt".into());
    }
    parts.push(format!("-o {}", shell_quote(&output)));
    Some(parts.join(" "))
}

fn print_text(out: &TimelineOut, w: &mut dyn Write) -> std::io::Result<()> {
    // `txgs` is every TXG whose uberblock verified; the readable ones are
    // those whose MOS could also be walked.
    writeln!(
        w,
        "pool {:?} guid {}: {} transaction group(s) still readable{}",
        out.pool,
        out.pool_guid,
        out.txgs.len() - out.unreadable_txgs.len(),
        match (out.unreadable_txgs.len(), out.partial_txgs.len()) {
            (0, 0) => String::new(),
            (u, 0) => format!(", {u} unreadable"),
            (0, p) => format!(", {p} of them read in part"),
            (u, p) => format!(", {u} unreadable, {p} read in part"),
        }
    )?;
    if let Some(d) = out
        .dataset
        .as_ref()
        .filter(|_| out.events.iter().all(|e| e.object.is_none()))
    {
        writeln!(w, "nothing in them about {d}")?;
        if out.events.is_empty() {
            return Ok(());
        }
    } else if out.events.is_empty() {
        match out.properties_not_shown {
            0 => writeln!(w, "no change between them")?,
            n => writeln!(
                w,
                "no change between them but {n} change(s) of a property; -v shows them"
            )?,
        }
        return Ok(());
    }
    // What was destroyed says when it was last there: the TXG to read it
    // back at, which the JSON had and the text did not (T-05).
    let details = |e: &EventOut| match e.last_seen_txg {
        Some(t) if e.details.is_empty() => format!("last seen at txg {t}"),
        Some(t) => format!("{}; last seen at txg {t}", e.details),
        None => e.details.clone(),
    };
    writeln!(
        w,
        "{:<12} {:<22} {:<18} {:<28} DETAILS",
        "TXG", "TIME", "EVENT", "OBJECT"
    )?;
    for e in &out.events {
        writeln!(
            w,
            "{:<12} {:<22} {:<18} {:<28} {}",
            e.txg,
            e.time.as_deref().unwrap_or("—"),
            e.event,
            e.object.as_deref().unwrap_or("—"),
            details(e)
        )?;
        if let Some(cmd) = &e.recover_with {
            writeln!(w, "{:<12} {:<22} {:<18} -> {cmd}", "", "", "")?;
        }
    }
    if out.properties_not_shown > 0 && !out.quiet {
        writeln!(
            w,
            "{} change(s) of a property not shown; -v shows them",
            out.properties_not_shown
        )?;
    }
    Ok(())
}

/// The events about one object, `--dataset` (T-08): a name it had at
/// any TXG read, or its GUID.
///
/// By GUID once the name is known: a dataset renamed and then destroyed
/// lost both events to a filter on the name asked for, which it no
/// longer had. What is about the pool and not any object — what is
/// pending, a TXG that could not be walked — stays: `--pending` asked
/// for it, and the manual's own example showed none of it; and a gap in
/// the history is a gap in this object's.
fn about(events: Vec<Event>, want: &str) -> Vec<Event> {
    let mut guids: BTreeSet<u64> = events
        .iter()
        .filter(|e| e.object.as_deref() == Some(want))
        .map(|e| e.guid)
        .collect();
    // In hex as this tool prints it, or in decimal as `zfs get guid`
    // does: given that way, it matched nothing (exit 3). A name is never
    // all digits — a pool's begins with a letter, and the rest are
    // under it — so a number is a GUID.
    if let Some(g) = want
        .strip_prefix("0x")
        .and_then(|h| u64::from_str_radix(h, 16).ok())
        .or_else(|| want.parse::<u64>().ok())
    {
        guids.insert(g);
    }
    events
        .into_iter()
        .filter(|e| {
            matches!(e.kind, Kind::Pending | Kind::Unreadable)
                || e.object.as_deref() == Some(want)
                || (e.guid != 0 && guids.contains(&e.guid))
        })
        .collect()
}

/// Datasets at one TXG, or why its MOS cannot be walked.
///
/// `pending` is read from the same walk when it was asked for: opening
/// the MOS twice to answer two questions about the same transaction
/// group would double the reads for nothing.
fn datasets_at(
    reader: &PoolReader<'_>,
    c: &Candidate,
    pool_name: &str,
    want_pending: bool,
) -> Result<(zfs_read::dsl::DatasetTree, Option<Pending>), String> {
    let mos = open_mos(reader, &c.ub).map_err(|e| format!("the MOS: {e}"))?;
    let tree = walk(&mos, pool_name).map_err(|e| format!("the dataset tree: {e}"))?;
    let p = want_pending.then(|| zfs_read::dsl::pending(&mos, &tree.datasets));
    Ok((tree, p))
}

/// The history as it is read, one transaction group at a time, oldest
/// first: what [`run`] reads, and what the tests give it by hand.
#[derive(Default)]
struct History {
    events: Vec<Event>,
    unreadable: Vec<u64>,
    partial: Vec<u64>,
    // What each dataset was, the last time it was seen: a destroyed one
    // is recovered by the tool for its type, with a key if it had one.
    what: std::collections::BTreeMap<u64, (Option<ObjsetType>, bool)>,
    previous: Option<(u64, Vec<Dataset>)>,
    // The last TXG each dataset was read at, not carried to. Its
    // destruction is dated from there: dated from a TXG where it was
    // only carried over, "last seen at txg T" and the command to recover
    // it at T named a TXG it does not read at.
    read_at: std::collections::BTreeMap<u64, u64>,
}

impl History {
    /// Take in what was read at `txg`, or why nothing was.
    fn step(
        &mut self,
        txg: u64,
        timestamp: u64,
        read: Result<(zfs_read::dsl::DatasetTree, Option<Pending>), String>,
    ) {
        let (mut tree, pending) = match read {
            Ok(x) => x,
            Err(why) => {
                self.unreadable.push(txg);
                self.events.push(Event {
                    txg,
                    time: Some(timestamp),
                    kind: Kind::Unreadable,
                    object: None,
                    guid: 0,
                    details: format!(
                        "the MOS at this transaction group could not be walked: {why}"
                    ),
                    last_seen_txg: None,
                });
                return;
            }
        };
        let mut now = std::mem::take(&mut tree.datasets);
        for d in &now {
            self.read_at.insert(d.guid, txg);
        }
        // A part of the tree that could not be read here is not a part
        // that is gone. What was there at the last transaction group is
        // taken to be there still, and said: missing, it was "destroyed"
        // here and "created" again at the next one, the same GUID, on a
        // pool whose DSL directory simply did not read at this one.
        let carried: Vec<Dataset> = match &self.previous {
            Some((_, before)) if !tree.unread.is_empty() => before
                .iter()
                .filter(|d| tree.unread_at(&d.name) && !now.iter().any(|n| n.guid == d.guid))
                .cloned()
                .collect(),
            _ => Vec::new(),
        };
        if !tree.unread.is_empty() {
            self.partial.push(txg);
            let more = tree.errors.len().saturating_sub(3);
            self.events.push(Event {
                txg,
                time: Some(timestamp),
                kind: Kind::Unreadable,
                object: None,
                guid: 0,
                details: format!(
                    "part of the dataset tree could not be read at this transaction group ({}{}); {} dataset(s) and snapshot(s) there before are taken as unchanged",
                    tree.errors.iter().take(3).cloned().collect::<Vec<_>>().join("; "),
                    if more > 0 {
                        format!("; and {more} more")
                    } else {
                        String::new()
                    },
                    carried.len()
                ),
                last_seen_txg: None,
            });
        }
        now.extend(carried);
        if let Some(p) = pending {
            self.events.push(Event {
                txg,
                time: Some(timestamp),
                kind: Kind::Pending,
                object: None,
                guid: 0,
                details: format!(
                    "{} byte(s) not yet freed: {} in the pool's free list ({} block pointer(s)), {} in {} deadlist(s){}{}{}",
                    p.total(),
                    p.free_bpobj_bytes,
                    p.free_bpobj_blkptrs,
                    p.deadlist_bytes,
                    p.deadlists,
                    if p.unreadable > 0 {
                        format!(", {} unreadable", p.unreadable)
                    } else {
                        String::new()
                    },
                    // The deadlists' own objects come to the same total
                    // when this reader has them right; saying so is how
                    // anyone can tell the number is not invented. At any
                    // TXG but the newest some of those objects may have
                    // been reused since, and a header that could not be
                    // checked is said to be that, not contradicted.
                    if p.inconsistent > 0 {
                        format!(
                            "; {} deadlist(s) disagree with their own objects ({} byte(s) there)",
                            p.inconsistent, p.bpobj_bytes
                        )
                    } else if p.unverified > 0 {
                        format!(
                            "; {} deadlist(s) unverified, their objects unreadable at this TXG; the other(s)' own objects agree ({})",
                            p.unverified, p.bpobj_bytes
                        )
                    } else {
                        format!("; the deadlists' own objects agree ({})", p.bpobj_bytes)
                    },
                    // What the part of the tree that did not read holds
                    // back is not in these numbers: they are a floor.
                    if tree.unread.is_empty() {
                        String::new()
                    } else {
                        "; at least: part of the dataset tree could not be read, and the deadlists of what lies there are not counted".to_string()
                    }
                ),
                last_seen_txg: None,
            });
        }
        match &self.previous {
            None => {
                // The oldest readable TXG is the baseline: everything in
                // it was created at or before it, which the creation TXG
                // of each dataset already says.
                for d in &now {
                    // The dataset records when it was made, which can be
                    // older than anything still readable. Say so, rather
                    // than dating it to the transaction group it happened
                    // to be found in.
                    let mut details = crate::events::describe(d);
                    if d.creation_txg < txg {
                        if !details.is_empty() {
                            details.push_str(", ");
                        }
                        details
                            .push_str(&format!("already there at the oldest readable txg {}", txg));
                    }
                    self.events.push(Event {
                        txg: d.creation_txg.min(txg),
                        time: (d.creation_time != 0).then_some(d.creation_time),
                        kind: crate::events::appeared_as(d),
                        object: Some(d.name.clone()),
                        guid: d.guid,
                        details,
                        last_seen_txg: None,
                    });
                }
            }
            Some((prev_txg, before)) => {
                let mut diffed = crate::events::diff(before, &now, txg, Some(timestamp));
                for e in &mut diffed {
                    if matches!(e.kind, Kind::Destroyed | Kind::SnapshotDestroyed) {
                        e.last_seen_txg =
                            Some(self.read_at.get(&e.guid).copied().unwrap_or(*prev_txg));
                    }
                    // Not seen at the TXG before, but there by its own
                    // record: that read missed it — the part of the tree
                    // it lies in did not read, at the oldest TXG, where
                    // there is nothing to carry over from, or at one
                    // the dataset was made in between. Dated by when it
                    // was made, and said, as the oldest TXG's are; it
                    // was "created" here, with snapshots older than it.
                    if matches!(e.kind, Kind::Created | Kind::Snapshot | Kind::Clone) {
                        if let Some(d) = now
                            .iter()
                            .find(|d| d.guid == e.guid)
                            .filter(|d| d.creation_txg <= *prev_txg)
                        {
                            e.txg = d.creation_txg;
                            e.time = (d.creation_time != 0).then_some(d.creation_time);
                            if !e.details.is_empty() {
                                e.details.push_str(", ");
                            }
                            e.details.push_str(&format!(
                                "already there at txg {prev_txg}, where it was not read; first read at txg {}",
                                txg
                            ));
                        }
                    }
                }
                self.events.extend(diffed);
            }
        }
        for d in &now {
            self.what.insert(d.guid, (d.kind, d.encryption.is_some()));
        }
        self.previous = Some((txg, now));
    }
}

/// Run the tool.
pub fn run(g: &Global, spec: &PoolSpec, opts: &Options) -> u8 {
    let members = match open_members(spec) {
        Ok(x) => x,
        Err(code) => return zvol_common::end_early(g, "zvoltimeline", spec, code),
    };
    // The report is written where it is told to be, and nowhere the run
    // reads: `-o` naming a member replaced it with the report.
    if let Some(path) = &opts.output {
        let mut reads = spec.reads();
        reads.extend(members.paths.iter().cloned());
        if let Err(code) = WriteGuard::new(g, &reads).refuse("zvoltimeline", "-o", path) {
            return zvol_common::end_early(g, "zvoltimeline", spec, code);
        }
    }
    let pool = match choose_pool(members.pools.clone(), spec.pool_guid.as_deref()) {
        Ok(p) => p,
        Err(code) => return zvol_common::end_early(g, "zvoltimeline", spec, code),
    };
    // uberblock_candidates gives the newest first; history reads forward.
    let mut candidates = uberblock_candidates(&members.scans, &pool);
    candidates.reverse();
    candidates.retain(|c| {
        opts.from.is_none_or(|f| c.ub.txg >= f) && opts.to.is_none_or(|t| c.ub.txg <= t)
    });
    if candidates.is_empty() {
        eprintln!("zvoltimeline: no verified uberblock in that range");
        return zvol_common::end_early(g, "zvoltimeline", spec, exit::UNRECOVERABLE);
    }
    let reader = PoolReader::new(&pool, members.devices()).with_base_offsets(&members.bases());

    let mut history = History::default();
    // Only two dataset lists are ever held at once (T-11).
    for c in &candidates {
        let read = datasets_at(&reader, c, &pool.name, opts.pending);
        history.step(c.ub.txg, c.ub.timestamp, read);
    }
    let History {
        mut events,
        unreadable,
        partial,
        what,
        ..
    } = history;

    // Hosts that had the pool imported, from the labels (T-06).
    for (hostid, hostname) in &pool.hosts {
        events.push(Event {
            txg: pool.txg.unwrap_or(0),
            time: None,
            kind: Kind::Host,
            object: None,
            guid: 0,
            details: format!(
                "hostid {} {:?}",
                hostid.map_or("?".to_string(), |h| format!("{h:#010x}")),
                hostname.as_deref().unwrap_or("?")
            ),
            last_seen_txg: None,
        });
    }

    // Nothing about the object asked for, when one was asked for.
    let mut none_about: Option<String> = None;
    if let Some(want) = &opts.dataset {
        events = about(events, want);
        if !events.iter().any(|e| e.object.is_some()) {
            none_about = Some(want.clone());
        }
    }
    // Property changes are reported at `-v` (T-09): they were printed
    // whatever was asked, and `-v` did nothing.
    let before = events.len();
    if g.verbose == 0 {
        events.retain(|e| e.kind != Kind::Property);
    }
    let properties_not_shown = before - events.len();
    sort(&mut events);

    let out = TimelineOut {
        pool: pool.name.clone(),
        pool_guid: format!("{:#018x}", pool.guid),
        members: members.paths.clone(),
        txgs: candidates.iter().map(|c| c.ub.txg).collect(),
        unreadable_txgs: unreadable,
        partial_txgs: partial,
        dataset: opts.dataset.clone(),
        events: events
            .iter()
            .map(|e| EventOut {
                txg: e.txg,
                time: e.time.map(iso8601),
                event: e.kind.as_str(),
                object: e.object.clone(),
                guid: format!("{:#018x}", e.guid),
                details: e.details.clone(),
                last_seen_txg: e.last_seen_txg,
                // A snapshot is read back by the same commands as the
                // dataset it was of, at the TXG it was last seen at (T-05).
                recover_with: match (e.kind, &e.object, e.last_seen_txg) {
                    (Kind::Destroyed | Kind::SnapshotDestroyed, Some(o), Some(t)) => {
                        let (kind, encrypted) = what.get(&e.guid).copied().unwrap_or((None, false));
                        recover_with(spec, o, t, kind, encrypted)
                    }
                    _ => None,
                },
            })
            .collect(),
        properties_not_shown,
        quiet: g.quiet,
    };

    let json = serde_json::to_value(&out).expect("serialisable");
    let mut sink: Box<dyn Write> = match &opts.output {
        Some(path) => match std::fs::File::create(path) {
            Ok(f) => Box::new(f),
            Err(e) => {
                eprintln!("zvoltimeline: {}: {e}", path.display());
                return zvol_common::end_run(
                    g,
                    "zvoltimeline",
                    &json,
                    exit::USAGE,
                    &members.inputs(),
                    Vec::new(),
                    &members.ledger,
                );
            }
        },
        None => Box::new(std::io::stdout()),
    };
    let written = match g.format {
        Format::Json => writeln!(
            sink,
            "{}",
            serde_json::to_string_pretty(&json).expect("serialisable")
        ),
        Format::Text => print_text(&out, &mut sink),
    };
    if let Err(e) = written {
        // The reader left — `| head`, or `less` quit part way down. The
        // run did nothing wrong and there is nothing left to say to a
        // pipe nobody is reading, so it ends the way a `println!` into a
        // closed pipe now does: quietly, with 0.
        if zvol_common::is_broken_pipe(&e) {
            return 0;
        }
        eprintln!("zvoltimeline: writing the report: {e}");
        return zvol_common::end_run(
            g,
            "zvoltimeline",
            &json,
            exit::USAGE,
            &members.inputs(),
            Vec::new(),
            &members.ledger,
        );
    }
    // Exit 3 when no transaction group could be walked: a history of
    // nothing but "unreadable" is not one, though every uberblock
    // verified. Exit 2 when a member given could not be opened, as
    // `list` says it: the history is of the members that were.
    let unreadable: BTreeSet<u64> = out.unreadable_txgs.iter().copied().collect();
    // And exit 3 when `--dataset` named nothing that was there: "no
    // change between them", exit 0, said that it had been there all
    // along and stayed as it was.
    if let Some(want) = &none_about {
        eprintln!(
            "zvoltimeline: --dataset {want}: no dataset or snapshot of that name or GUID in transaction groups {}–{}",
            out.txgs.first().copied().unwrap_or(0),
            out.txgs.last().copied().unwrap_or(0)
        );
    }
    let code = if out.txgs.iter().all(|t| unreadable.contains(t)) || none_about.is_some() {
        exit::UNRECOVERABLE
    } else if members.any_failed() {
        exit::EVIDENCE
    } else {
        0
    };
    // The report is the only thing this tool writes; record it with the
    // hash of what actually landed on disk — a file, read back; a pipe
    // or a terminal is not read back, and the report is in the record.
    let written = match &opts.output {
        Some(path) => evidence::FileRef::hashed(path)
            .map(|f| vec![f])
            .unwrap_or_default(),
        None => Vec::new(),
    };
    // A device refused a read: every incident on stderr, and the stop —
    // when one stopped the run — as the exit code (SPEC F-33, N-10).
    let code = zvol_common::report_medium(&members.ledger).unwrap_or(code);
    g.log_evidence_with_incidents(
        "zvoltimeline",
        &json,
        code,
        &members.inputs(),
        written,
        &members.ledger.incidents(),
    )
}

#[cfg(test)]
mod history_tests {
    use super::*;
    use crate::events::tests::ds;
    use zfs_read::dsl::{DatasetTree, Unread};

    fn made(name: &str, guid: u64, txg: u64) -> Dataset {
        Dataset {
            creation_txg: txg,
            ..ds(name, guid, name.contains('@'))
        }
    }

    fn tree(datasets: Vec<Dataset>, unread: &[&str]) -> DatasetTree {
        DatasetTree {
            pool_name: "tank".into(),
            datasets,
            errors: unread.iter().map(|u| format!("{u}: unreadable")).collect(),
            unread: unread
                .iter()
                .map(|u| (u.to_string(), Unread::All))
                .collect(),
        }
    }

    fn line(h: &History, kind: Kind, object: &str) -> Event {
        h.events
            .iter()
            .find(|e| e.kind == kind && e.object.as_deref() == Some(object))
            .unwrap_or_else(|| panic!("no {kind:?} of {object}: {:#?}", h.events))
            .clone()
    }

    /// The oldest TXG read in part: what lies where it did not read is
    /// there when the next one reads it, made long before. It was
    /// "created" at the next TXG, and its snapshots with it; it is dated
    /// by when it was made, and said.
    #[test]
    fn what_the_oldest_txg_did_not_read_was_not_created_after_it() {
        let mut h = History::default();
        let tank = made("tank", 1, 1);
        let temp = made("tank/temp", 2, 40);
        let snap = made("tank/temp@s", 3, 45);
        h.step(
            100,
            1000,
            Ok((tree(vec![tank.clone()], &["tank/temp"]), None)),
        );
        h.step(
            101,
            1001,
            Ok((tree(vec![tank.clone(), temp, snap], &[]), None)),
        );
        // One made between the two is created at the second, as before.
        h.step(
            102,
            1002,
            Ok((tree(vec![tank, made("tank/new", 4, 102)], &[]), None)),
        );
        let e = line(&h, Kind::Created, "tank/temp");
        assert_eq!(e.txg, 40);
        assert!(
            e.details
                .contains("already there at txg 100, where it was not read"),
            "{e:?}"
        );
        assert_eq!(line(&h, Kind::Snapshot, "tank/temp@s").txg, 45);
        let new = line(&h, Kind::Created, "tank/new");
        assert_eq!((new.txg, new.details.as_str()), (102, ""));
        assert_eq!(h.partial, [100]);
    }

    /// Carried over a TXG that did not read its part of the tree, a
    /// dataset destroyed after it was last seen at the TXG before: its
    /// recovery at the carried one would not read it.
    #[test]
    fn a_dataset_carried_over_is_not_seen_where_it_was_carried() {
        let mut h = History::default();
        let tank = made("tank", 1, 1);
        let temp = made("tank/temp", 2, 40);
        h.step(642, 1, Ok((tree(vec![tank.clone(), temp], &[]), None)));
        h.step(643, 2, Ok((tree(vec![tank.clone()], &["tank/temp"]), None)));
        h.step(644, 3, Ok((tree(vec![tank], &[]), None)));
        let e = line(&h, Kind::Destroyed, "tank/temp");
        assert_eq!((e.txg, e.last_seen_txg), (644, Some(642)));
        assert_eq!(h.partial, [643]);
    }

    /// A TXG that cannot be walked says why; one read in part says its
    /// pending space is a floor.
    #[test]
    fn what_could_not_be_read_is_said() {
        let mut h = History::default();
        h.step(10, 1, Err("the MOS: every copy failed its checksum".into()));
        h.step(
            11,
            2,
            Ok((
                tree(vec![made("tank", 1, 1)], &["tank/x"]),
                Some(Pending::default()),
            )),
        );
        assert_eq!(h.unreadable, [10]);
        let walked = h.events.iter().find(|e| e.txg == 10).expect("an event");
        assert!(
            walked
                .details
                .ends_with(": the MOS: every copy failed its checksum"),
            "{walked:?}"
        );
        let pending = h
            .events
            .iter()
            .find(|e| e.kind == Kind::Pending)
            .expect("pending");
        assert!(
            pending
                .details
                .contains("; at least: part of the dataset tree"),
            "{pending:?}"
        );
    }
}

#[cfg(test)]
mod about_tests {
    use super::*;

    fn event(txg: u64, kind: Kind, object: Option<&str>, guid: u64) -> Event {
        Event {
            txg,
            time: None,
            kind,
            object: object.map(str::to_string),
            guid,
            details: String::new(),
            last_seen_txg: None,
        }
    }

    /// T-08: a name at any TXG. A dataset made as `a`, renamed `b` and
    /// destroyed as `b` is all one history; its snapshot and another
    /// dataset are objects of their own, and what is pending stays.
    #[test]
    fn a_name_is_followed_through_its_renames_by_guid() {
        let events = vec![
            event(10, Kind::Created, Some("tank/a"), 7),
            event(11, Kind::Snapshot, Some("tank/a@s1"), 8),
            event(20, Kind::Renamed, Some("tank/b"), 7),
            event(20, Kind::Renamed, Some("tank/b@s1"), 8),
            event(25, Kind::Pending, None, 0),
            event(30, Kind::Destroyed, Some("tank/b"), 7),
            event(30, Kind::Created, Some("tank/other"), 9),
            event(31, Kind::Host, None, 0),
        ];
        let kept = |want| {
            about(events.clone(), want)
                .iter()
                .map(|e| e.txg)
                .collect::<Vec<_>>()
        };
        assert_eq!(kept("tank/a"), [10, 20, 25, 30]);
        assert_eq!(kept("tank/b"), [10, 20, 25, 30]);
        assert_eq!(kept("tank/a@s1"), [11, 20, 25]);
        assert_eq!(kept("0x0000000000000009"), [25, 30]);
        assert!(about(events.clone(), "tank/none")
            .iter()
            .all(|e| e.object.is_none()));
    }
}

#[cfg(test)]
mod recover_tests {
    use super::*;

    fn spec(args: &[&str]) -> PoolSpec {
        #[derive(clap::Parser)]
        struct Cli {
            #[command(flatten)]
            pool: PoolSpec,
        }
        let mut argv = vec!["t"];
        argv.extend(args);
        <Cli as clap::Parser>::parse_from(argv).pool
    }

    /// A volume is recovered by `zvolrescue dump`, a filesystem by
    /// `zvolfiles extract`, anything else by nothing; the command keeps
    /// the maps and the leave to read unknown features that made the
    /// pool readable, and asks for the key of an encrypted dataset.
    #[test]
    fn the_command_fits_the_object() {
        let s = spec(&[
            "m0.img",
            "--map",
            "m0.img=m0.map",
            "--ignore-unknown-features",
        ]);
        let vol = recover_with(&s, "tank/vm/disk0", 7, Some(ObjsetType::Zvol), false).unwrap();
        assert!(
            vol.starts_with("zvolrescue dump tank/vm/disk0 m0.img"),
            "{vol}"
        );
        assert!(
            vol.contains("--map m0.img=m0.map --ignore-unknown-features --txg 7"),
            "{vol}"
        );
        assert!(vol.ends_with("-o tank_vm_disk0.img"), "{vol}");
        let fs = recover_with(&s, "tank/home", 7, Some(ObjsetType::Zfs), true).unwrap();
        assert!(fs.starts_with("zvolfiles extract tank/home"), "{fs}");
        assert!(fs.contains("--key prompt -o tank_home"), "{fs}");
        assert_eq!(
            recover_with(&s, "ztest/ds_0", 7, Some(ObjsetType::Other), false),
            None
        );
        assert_eq!(recover_with(&s, "gone", 7, None, false), None);
    }
}
