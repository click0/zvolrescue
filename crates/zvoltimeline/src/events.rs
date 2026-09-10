//! Turning consecutive TXG snapshots of a pool into events (T-03).
//!
//! Two dataset lists, read at two transaction groups, differ in ways that
//! have names: an object present in the later one and not the earlier was
//! created; one present in the earlier and not the later was destroyed;
//! the same GUID under a new name was renamed. Nothing here reads a
//! device — it is pure comparison, so it can be tested on its own and can
//! never be the reason a run fails.

use std::collections::BTreeMap;

use zfs_read::dsl::Dataset;

/// What happened to one object between two transaction groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// A dataset or volume that was not there before.
    Created,
    /// A snapshot that was not there before.
    Snapshot,
    /// A dataset created from a snapshot of another (`origin` is set).
    Clone,
    /// The same GUID under a different name.
    Renamed,
    /// A dataset or volume that is no longer there.
    Destroyed,
    /// A snapshot that is no longer there.
    SnapshotDestroyed,
    /// A property the tool reports changed (`volsize`, compression …).
    Property,
    /// The pool's own facts: a host that had it imported.
    Host,
    /// The MOS at this TXG could not be read.
    Unreadable,
}

impl Kind {
    /// Lowercase name, as printed and as written to JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Created => "created",
            Kind::Snapshot => "snapshot",
            Kind::Clone => "clone",
            Kind::Renamed => "renamed",
            Kind::Destroyed => "destroyed",
            Kind::SnapshotDestroyed => "snapshot-destroyed",
            Kind::Property => "property",
            Kind::Host => "host",
            Kind::Unreadable => "unreadable",
        }
    }
}

/// One line of the history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// Transaction group the change was first visible at.
    pub txg: u64,
    /// Unix time of that TXG's uberblock, when there is one.
    pub time: Option<u64>,
    /// What happened.
    pub kind: Kind,
    /// The object it happened to, if any.
    pub object: Option<String>,
    /// `ds_guid` of that object, for ordering and for `--dataset`.
    pub guid: u64,
    /// Free-text detail: the volume's size, the old name, the reason.
    pub details: String,
    /// For a destroyed object: the last TXG that still had it.
    pub last_seen_txg: Option<u64>,
}

/// Sort key: TXG, then kind, then GUID — deterministic, as T-10 requires.
pub fn sort(events: &mut [Event]) {
    events.sort_by_key(|e| (e.txg, e.kind, e.guid, e.object.clone()));
}

/// A dataset as the diff sees it: what it is called and what about it is
/// worth reporting a change to.
fn describe(d: &Dataset) -> String {
    let mut parts = Vec::new();
    if let Some(v) = d.volsize {
        parts.push(format!("volsize {v}"));
    }
    if let Some(b) = d.volblocksize {
        parts.push(format!("volblocksize {b}"));
    }
    if let Some(e) = &d.encryption {
        parts.push(format!("encryption {}", e.suite_name()));
    }
    parts.join(" ")
}

/// Compare the datasets at `before` with those at `after`.
///
/// `txg` is the transaction group of the later snapshot: the point at
/// which the change became visible.
pub fn diff(before: &[Dataset], after: &[Dataset], txg: u64, time: Option<u64>) -> Vec<Event> {
    let by_guid = |list: &[Dataset]| -> BTreeMap<u64, Dataset> {
        list.iter().map(|d| (d.guid, d.clone())).collect()
    };
    let old = by_guid(before);
    let new = by_guid(after);
    let mut events = Vec::new();

    for (guid, d) in &new {
        match old.get(guid) {
            None => {
                let kind = if d.snapshot {
                    Kind::Snapshot
                } else if d.origin_obj != 0 {
                    Kind::Clone
                } else {
                    Kind::Created
                };
                events.push(Event {
                    txg,
                    time,
                    kind,
                    object: Some(d.name.clone()),
                    guid: *guid,
                    details: describe(d),
                    last_seen_txg: None,
                });
            }
            Some(was) => {
                if was.name != d.name {
                    events.push(Event {
                        txg,
                        time,
                        kind: Kind::Renamed,
                        object: Some(d.name.clone()),
                        guid: *guid,
                        details: format!("was {}", was.name),
                        last_seen_txg: None,
                    });
                }
                let (a, b) = (describe(was), describe(d));
                if a != b {
                    events.push(Event {
                        txg,
                        time,
                        kind: Kind::Property,
                        object: Some(d.name.clone()),
                        guid: *guid,
                        details: format!("{a} -> {b}"),
                        last_seen_txg: None,
                    });
                }
            }
        }
    }
    for (guid, d) in &old {
        if new.contains_key(guid) {
            continue;
        }
        events.push(Event {
            txg,
            time,
            kind: if d.snapshot {
                Kind::SnapshotDestroyed
            } else {
                Kind::Destroyed
            },
            object: Some(d.name.clone()),
            guid: *guid,
            details: describe(d),
            last_seen_txg: None,
        });
    }
    sort(&mut events);
    events
}
