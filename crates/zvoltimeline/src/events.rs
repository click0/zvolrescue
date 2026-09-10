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
    /// Space ZFS has finished with but has not freed yet.
    Pending,
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
            Kind::Pending => "pending",
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
pub fn describe(d: &Dataset) -> String {
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

/// What a dataset was when it first appeared: created, cloned, or a
/// snapshot. The same question is asked of the oldest transaction group
/// read, where there is nothing to compare against.
pub fn appeared_as(d: &Dataset) -> Kind {
    if d.snapshot {
        Kind::Snapshot
    } else if d.clone {
        Kind::Clone
    } else {
        Kind::Created
    }
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
                events.push(Event {
                    txg,
                    time,
                    kind: appeared_as(d),
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

#[cfg(test)]
mod tests {
    use super::*;
    use zfs_ondisk::dsl::{DslDatasetPhys, DSL_DATASET_MIN_LEN};
    use zfs_ondisk::Endian;

    /// A dataset with nothing on it but a name and an identity: the diff
    /// looks at the GUID, the name and the few properties it reports, and
    /// a zeroed `dsl_dataset_phys_t` is what an empty one parses to.
    fn ds(name: &str, guid: u64, snapshot: bool) -> Dataset {
        Dataset {
            name: name.to_string(),
            object: 0,
            dir_object: 0,
            guid,
            kind: None,
            snapshot,
            creation_txg: 0,
            creation_time: 0,
            referenced_bytes: 0,
            prev_snap_obj: 0,
            origin_obj: 0,
            clone: false,
            props_zapobj: 0,
            volsize: None,
            volblocksize: None,
            encryption: None,
            phys: DslDatasetPhys::parse(&[0u8; DSL_DATASET_MIN_LEN], Endian::Little)
                .expect("a zeroed bonus buffer parses"),
            warnings: Vec::new(),
        }
    }

    fn kinds(events: &[Event]) -> Vec<(&'static str, Option<&str>)> {
        events
            .iter()
            .map(|e| (e.kind.as_str(), e.object.as_deref()))
            .collect()
    }

    #[test]
    fn an_object_only_in_the_later_txg_was_created() {
        let before = vec![ds("tank", 1, false)];
        let after = vec![ds("tank", 1, false), ds("tank/vm", 2, false)];
        assert_eq!(
            kinds(&diff(&before, &after, 100, None)),
            [("created", Some("tank/vm"))]
        );
    }

    #[test]
    fn an_object_only_in_the_earlier_txg_was_destroyed() {
        let before = vec![ds("tank", 1, false), ds("tank/vm", 2, false)];
        let after = vec![ds("tank", 1, false)];
        assert_eq!(
            kinds(&diff(&before, &after, 100, None)),
            [("destroyed", Some("tank/vm"))]
        );
    }

    /// A snapshot is distinguished from a dataset, in both directions:
    /// "the snapshot is gone" and "the volume is gone" are not the same
    /// news for whoever is reading the report.
    #[test]
    fn snapshots_are_their_own_kind() {
        let head = ds("tank/vm", 2, false);
        let snap = ds("tank/vm@monday", 3, true);
        let created = diff(
            std::slice::from_ref(&head),
            &[head.clone(), snap.clone()],
            100,
            None,
        );
        assert_eq!(kinds(&created), [("snapshot", Some("tank/vm@monday"))]);
        let destroyed = diff(
            &[head.clone(), snap],
            std::slice::from_ref(&head),
            101,
            None,
        );
        assert_eq!(
            kinds(&destroyed),
            [("snapshot-destroyed", Some("tank/vm@monday"))]
        );
    }

    /// The GUID is what an object is; the name is what it is called. A
    /// rename must not read as a destroy followed by a create, because
    /// that would send someone hunting for data that never left.
    #[test]
    fn the_same_guid_under_a_new_name_is_a_rename() {
        let before = vec![ds("tank/vm/disk0", 7, false)];
        let after = vec![ds("tank/vm/disk1", 7, false)];
        let events = diff(&before, &after, 100, None);
        assert_eq!(kinds(&events), [("renamed", Some("tank/vm/disk1"))]);
        assert_eq!(events[0].details, "was tank/vm/disk0");
    }

    /// The other way round: a new GUID under an old name is a different
    /// object, and both halves have to be reported.
    #[test]
    fn a_reused_name_with_a_new_guid_is_a_destroy_and_a_create() {
        let before = vec![ds("tank/vm/disk0", 7, false)];
        let after = vec![ds("tank/vm/disk0", 8, false)];
        assert_eq!(
            kinds(&diff(&before, &after, 100, None)),
            [
                ("created", Some("tank/vm/disk0")),
                ("destroyed", Some("tank/vm/disk0"))
            ]
        );
    }

    #[test]
    fn a_dataset_with_an_origin_is_a_clone() {
        let mut clone = ds("tank/vm/copy", 9, false);
        clone.clone = true;
        assert_eq!(
            kinds(&diff(&[], &[clone], 100, None)),
            [("clone", Some("tank/vm/copy"))]
        );
    }

    #[test]
    fn a_changed_volsize_is_a_property_event() {
        let mut before = ds("tank/vm/disk0", 7, false);
        before.volsize = Some(32 << 30);
        let mut after = before.clone();
        after.volsize = Some(64 << 30);
        let events = diff(&[before], &[after], 100, None);
        assert_eq!(kinds(&events), [("property", Some("tank/vm/disk0"))]);
        assert_eq!(
            events[0].details,
            format!("volsize {} -> volsize {}", 32u64 << 30, 64u64 << 30)
        );
    }

    /// T-10: the same two dataset lists always produce the same order,
    /// whatever order the walker happened to return them in.
    #[test]
    fn the_order_of_events_does_not_depend_on_the_walk() {
        let a = ds("tank/a", 5, false);
        let b = ds("tank/b", 3, false);
        let c = ds("tank/c", 4, false);
        let one = diff(&[], &[a.clone(), b.clone(), c.clone()], 100, None);
        let other = diff(&[], &[c, a, b], 100, None);
        assert_eq!(one, other);
    }

    #[test]
    fn nothing_changed_is_no_events() {
        let list = vec![ds("tank", 1, false), ds("tank/vm", 2, false)];
        assert!(diff(&list, &list, 100, None).is_empty());
    }
}
