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
    /// The object `--dataset` asked about.
    #[serde(skip_serializing_if = "Option::is_none")]
    dataset: Option<String>,
    events: Vec<EventOut>,
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
        if out.unreadable_txgs.is_empty() {
            String::new()
        } else {
            format!(", {} unreadable", out.unreadable_txgs.len())
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
        writeln!(w, "no change between them")?;
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
    if let Some(g) = want
        .strip_prefix("0x")
        .and_then(|h| u64::from_str_radix(h, 16).ok())
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

/// Datasets at one TXG, or `None` when its MOS cannot be walked.
///
/// `pending` is read from the same walk when it was asked for: opening
/// the MOS twice to answer two questions about the same transaction
/// group would double the reads for nothing.
fn datasets_at(
    reader: &PoolReader<'_>,
    c: &Candidate,
    pool_name: &str,
    want_pending: bool,
) -> Option<(zfs_read::dsl::DatasetTree, Option<Pending>)> {
    let mos = open_mos(reader, &c.ub).ok()?;
    let tree = walk(&mos, pool_name).ok()?;
    let p = want_pending.then(|| zfs_read::dsl::pending(&mos, &tree.datasets));
    Some((tree, p))
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

    let mut events: Vec<Event> = Vec::new();
    let mut unreadable = Vec::new();
    // What each dataset was, the last time it was seen: a destroyed one
    // is recovered by the tool for its type, with a key if it had one.
    let mut what: std::collections::BTreeMap<u64, (Option<ObjsetType>, bool)> =
        std::collections::BTreeMap::new();
    let mut previous: Option<(u64, Vec<Dataset>)> = None;
    // Only two dataset lists are ever held at once (T-11).
    for c in &candidates {
        let Some((mut tree, pending)) = datasets_at(&reader, c, &pool.name, opts.pending) else {
            unreadable.push(c.ub.txg);
            events.push(Event {
                txg: c.ub.txg,
                time: Some(c.ub.timestamp),
                kind: Kind::Unreadable,
                object: None,
                guid: 0,
                details: "the MOS at this transaction group could not be walked".into(),
                last_seen_txg: None,
            });
            continue;
        };
        let mut now = std::mem::take(&mut tree.datasets);
        // A part of the tree that could not be read here is not a part
        // that is gone. What was there at the last transaction group is
        // taken to be there still, and said: missing, it was "destroyed"
        // here and "created" again at the next one, the same GUID, on a
        // pool whose DSL directory simply did not read at this one.
        let carried: Vec<Dataset> = match &previous {
            Some((_, before)) if !tree.unread.is_empty() => before
                .iter()
                .filter(|d| tree.unread_at(&d.name) && !now.iter().any(|n| n.guid == d.guid))
                .cloned()
                .collect(),
            _ => Vec::new(),
        };
        if !tree.unread.is_empty() {
            let more = tree.errors.len().saturating_sub(3);
            events.push(Event {
                txg: c.ub.txg,
                time: Some(c.ub.timestamp),
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
            events.push(Event {
                txg: c.ub.txg,
                time: Some(c.ub.timestamp),
                kind: Kind::Pending,
                object: None,
                guid: 0,
                details: format!(
                    "{} byte(s) not yet freed: {} in the pool's free list ({} block pointer(s)), {} in {} deadlist(s){}{}",
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
                    }
                ),
                last_seen_txg: None,
            });
        }
        match &previous {
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
                    if d.creation_txg < c.ub.txg {
                        if !details.is_empty() {
                            details.push_str(", ");
                        }
                        details.push_str(&format!(
                            "already there at the oldest readable txg {}",
                            c.ub.txg
                        ));
                    }
                    events.push(Event {
                        txg: d.creation_txg.min(c.ub.txg),
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
                let mut diffed = crate::events::diff(before, &now, c.ub.txg, Some(c.ub.timestamp));
                for e in &mut diffed {
                    if matches!(e.kind, Kind::Destroyed | Kind::SnapshotDestroyed) {
                        e.last_seen_txg = Some(*prev_txg);
                    }
                }
                events.extend(diffed);
            }
        }
        for d in &now {
            what.insert(d.guid, (d.kind, d.encryption.is_some()));
        }
        previous = Some((c.ub.txg, now));
    }

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
    sort(&mut events);

    let out = TimelineOut {
        pool: pool.name.clone(),
        pool_guid: format!("{:#018x}", pool.guid),
        members: members.paths.clone(),
        txgs: candidates.iter().map(|c| c.ub.txg).collect(),
        unreadable_txgs: unreadable,
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
    // hash of what actually landed on disk.
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
