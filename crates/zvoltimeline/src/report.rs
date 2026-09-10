//! Reading every surviving TXG and printing what changed between them.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;

use serde::Serialize;
use zfs_read::dsl::{open_mos, walk, Dataset, Pending};
use zfs_read::pool::{uberblock_candidates, Candidate};
use zfs_read::zio::PoolReader;
use zvol_common::members::{choose_pool, open_members};
use zvol_common::timefmt::iso8601;
use zvol_common::{evidence, exit, shell_quote, Format, Global, PoolSpec};

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
    events: Vec<EventOut>,
}

/// The `zvolrescue dump` command that recovers a destroyed object (T-05).
///
/// It repeats this run's own pool specification — the members as they
/// were named, and any `--hints`, `--search-order` or `--assume-member`
/// that made them readable — because a command that reached the pool by
/// a different route would not reach the same dataset.
fn recover_with(spec: &PoolSpec, object: &str, txg: u64) -> String {
    let mut parts = vec![
        "zvolrescue".to_string(),
        "dump".to_string(),
        shell_quote(object),
    ];
    parts.extend(spec.as_arguments());
    parts.push(format!("--txg {txg}"));
    parts.push(format!(
        "-o {}",
        shell_quote(&format!("{}.img", object.replace('/', "_")))
    ));
    parts.join(" ")
}

fn print_text(out: &TimelineOut, w: &mut dyn Write) -> std::io::Result<()> {
    writeln!(
        w,
        "pool {:?} guid {}: {} transaction group(s) still readable{}",
        out.pool,
        out.pool_guid,
        out.txgs.len(),
        if out.unreadable_txgs.is_empty() {
            String::new()
        } else {
            format!(", {} unreadable", out.unreadable_txgs.len())
        }
    )?;
    if out.events.is_empty() {
        writeln!(w, "no change between them")?;
        return Ok(());
    }
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
            e.details
        )?;
        if let Some(cmd) = &e.recover_with {
            writeln!(w, "{:<12} {:<22} {:<18} -> {cmd}", "", "", "")?;
        }
    }
    Ok(())
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
) -> Option<(Vec<Dataset>, Option<Pending>)> {
    let mos = open_mos(reader, &c.ub).ok()?;
    let tree = walk(&mos, pool_name).ok()?;
    let p = want_pending.then(|| zfs_read::dsl::pending(&mos, &tree.datasets));
    Some((tree.datasets, p))
}

/// Run the tool.
pub fn run(g: &Global, spec: &PoolSpec, opts: &Options) -> u8 {
    let members = match open_members(spec) {
        Ok(x) => x,
        Err(code) => return code,
    };
    let pool = match choose_pool(members.pools.clone(), spec.pool_guid.as_deref()) {
        Ok(p) => p,
        Err(code) => return code,
    };
    // uberblock_candidates gives the newest first; history reads forward.
    let mut candidates = uberblock_candidates(&members.scans, &pool);
    candidates.reverse();
    candidates.retain(|c| {
        opts.from.is_none_or(|f| c.ub.txg >= f) && opts.to.is_none_or(|t| c.ub.txg <= t)
    });
    if candidates.is_empty() {
        eprintln!("zvoltimeline: no verified uberblock in that range");
        return exit::UNRECOVERABLE;
    }
    let reader = PoolReader::new(&pool, members.devices()).with_base_offsets(&members.bases());

    let mut events: Vec<Event> = Vec::new();
    let mut unreadable = Vec::new();
    let mut previous: Option<(u64, Vec<Dataset>)> = None;
    // Only two dataset lists are ever held at once (T-11).
    for c in &candidates {
        let Some((now, pending)) = datasets_at(&reader, c, &pool.name, opts.pending) else {
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
        if let Some(p) = pending {
            events.push(Event {
                txg: c.ub.txg,
                time: Some(c.ub.timestamp),
                kind: Kind::Pending,
                object: None,
                guid: 0,
                details: format!(
                    "{} byte(s) not yet freed: {} in the pool's free list ({} block pointer(s)), {} in {} deadlist(s){}",
                    p.total(),
                    p.free_bpobj_bytes,
                    p.free_bpobj_blkptrs,
                    p.deadlist_bytes,
                    p.deadlists,
                    if p.unreadable > 0 {
                        format!(", {} unreadable", p.unreadable)
                    } else {
                        String::new()
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

    if let Some(want) = &opts.dataset {
        let guid = want
            .strip_prefix("0x")
            .and_then(|h| u64::from_str_radix(h, 16).ok());
        events.retain(|e| {
            e.object.as_deref() == Some(want.as_str()) || guid.is_some_and(|g| e.guid == g)
        });
    }
    sort(&mut events);

    let out = TimelineOut {
        pool: pool.name.clone(),
        pool_guid: format!("{:#018x}", pool.guid),
        members: members.paths.clone(),
        txgs: candidates.iter().map(|c| c.ub.txg).collect(),
        unreadable_txgs: unreadable,
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
                recover_with: match (e.kind, &e.object, e.last_seen_txg) {
                    (Kind::Destroyed, Some(o), Some(t)) => Some(recover_with(spec, o, t)),
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
                return exit::USAGE;
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
        eprintln!("zvoltimeline: writing the report: {e}");
        return exit::USAGE;
    }
    let txgs: BTreeSet<u64> = out.txgs.iter().copied().collect();
    let code = if txgs.is_empty() {
        exit::UNRECOVERABLE
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
    g.log_evidence("zvoltimeline", &json, code, &members.paths, written)
}
