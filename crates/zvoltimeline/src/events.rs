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
    /// A clone promoted over its origin (`zfs promote`): it is no
    /// longer a clone, the origin's snapshots up to the one it was made
    /// from are now its own, and the dataset they were taken of is now
    /// its clone.
    Promoted,
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
    /// A TXG of a line of history an import with rewind left behind:
    /// written before a lower one already read. Not read.
    Abandoned,
}

impl Kind {
    /// Lowercase name, as printed and as written to JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Created => "created",
            Kind::Snapshot => "snapshot",
            Kind::Clone => "clone",
            Kind::Promoted => "promoted",
            Kind::Renamed => "renamed",
            Kind::Destroyed => "destroyed",
            Kind::SnapshotDestroyed => "snapshot-destroyed",
            Kind::Property => "property",
            Kind::Host => "host",
            Kind::Pending => "pending",
            Kind::Unreadable => "unreadable",
            Kind::Abandoned => "abandoned",
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
    describe_known(d, &[])
}

/// [`describe`], leaving out the facts named in `unknown`.
fn describe_known(d: &Dataset, unknown: &[&str]) -> String {
    let mut parts = Vec::new();
    let known = |f: &str| !unknown.contains(&f);
    if let Some(v) = d.volsize.filter(|_| known("volsize")) {
        parts.push(format!("volsize {v}"));
    }
    if let Some(b) = d.volblocksize.filter(|_| known("volblocksize")) {
        parts.push(format!("volblocksize {b}"));
    }
    if let Some(e) = d.encryption.as_ref().filter(|_| known("encryption")) {
        parts.push(format!("encryption {}", e.suite_name()));
    }
    parts.join(" ")
}

/// The snapshot a clone was made from, among `all`.
fn origin_of<'a>(d: &Dataset, all: &'a [Dataset]) -> Option<&'a Dataset> {
    if !d.clone || d.origin_obj == 0 {
        return None;
    }
    all.iter().find(|s| s.snapshot && s.object == d.origin_obj)
}

/// The dataset a snapshot was taken of, by name.
fn head(snapshot: &str) -> &str {
    snapshot.split_once('@').map_or(snapshot, |(h, _)| h)
}

/// A head dataset that holds a snapshot older than itself, which another
/// dataset is a clone of, got it by a promotion: it was made a clone,
/// and was promoted over that other one since. A snapshot older than
/// its dataset alone is not taken for one — nothing in a pool OpenZFS
/// wrote has it otherwise, but a damaged or hand-made one can.
pub fn promoted_since(d: &Dataset, all: &[Dataset]) -> bool {
    !d.snapshot
        && !d.clone
        && d.creation_txg != 0
        && all.iter().any(|s| {
            s.snapshot
                && s.creation_txg != 0
                && s.creation_txg < d.creation_txg
                && head(&s.name) == d.name
                && all
                    .iter()
                    .any(|c| !c.snapshot && c.clone && c.origin_obj == s.object)
        })
}

/// A clone older than the snapshot it is a clone of was not made from
/// it: it became a clone when the dataset holding that snapshot was
/// promoted over it.
fn demoted<'a>(d: &Dataset, all: &'a [Dataset]) -> Option<&'a Dataset> {
    origin_of(d, all)
        .filter(|o| o.creation_txg != 0 && d.creation_txg != 0 && o.creation_txg > d.creation_txg)
}

/// What a dataset was when it first appeared: created, cloned, or a
/// snapshot. The same question is asked of the oldest transaction group
/// read, where there is nothing to compare against. `all` is every
/// dataset read with it: a promotion read nowhere still shows in them,
/// and a dataset promoted since it was cloned was "created", the one it
/// was promoted over a "clone" made before what it is a clone of.
pub fn appeared_as(d: &Dataset, all: &[Dataset]) -> Kind {
    if d.snapshot {
        Kind::Snapshot
    } else if promoted_since(d, all) || (d.clone && demoted(d, all).is_none()) {
        Kind::Clone
    } else {
        Kind::Created
    }
}

/// What to add to the details of a dataset that appears already
/// touched by a promotion read nowhere: the one promoted over it.
pub fn appeared_details(d: &Dataset, all: &[Dataset]) -> Option<String> {
    if let Some(o) = demoted(d, all) {
        return Some(format!(
            "a clone of {} since {} was promoted over it",
            o.name,
            head(&o.name)
        ));
    }
    promoted_since(d, all).then(|| "made a clone, and promoted since".to_string())
}

/// `a`, then `b` after a comma when there is one.
pub fn joined(a: String, b: Option<String>) -> String {
    match b {
        Some(b) if a.is_empty() => b,
        Some(b) => format!("{a}, {b}"),
        None => a,
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
    // Clones that are clones no longer: promoted at this TXG.
    let promoted: Vec<&Dataset> = new
        .iter()
        .filter(|(g, d)| !d.snapshot && !d.clone && old.get(g).is_some_and(|o| o.clone))
        .map(|(_, d)| d)
        .collect();

    for (guid, d) in &new {
        match old.get(guid) {
            None => {
                events.push(Event {
                    txg,
                    time,
                    kind: appeared_as(d, after),
                    object: Some(d.name.clone()),
                    guid: *guid,
                    details: joined(describe(d), appeared_details(d, after)),
                    last_seen_txg: None,
                });
            }
            Some(was) => {
                if was.name != d.name {
                    // A promotion moves the snapshots of the origin, up
                    // to the one the clone was made from, to the clone:
                    // renamed, and said why.
                    let moved = d.snapshot
                        && head(&was.name) != head(&d.name)
                        && promoted.iter().any(|p| p.name == head(&d.name));
                    events.push(Event {
                        txg,
                        time,
                        kind: Kind::Renamed,
                        object: Some(d.name.clone()),
                        guid: *guid,
                        details: if moved {
                            format!(
                                "was {}, moved by the promotion of {}",
                                was.name,
                                head(&d.name)
                            )
                        } else {
                            format!("was {}", was.name)
                        },
                        last_seen_txg: None,
                    });
                }
                if was.clone && !d.clone && !d.snapshot {
                    // The datasets it was promoted over: those that were
                    // not clones and are now.
                    let over: Vec<&str> = new
                        .iter()
                        .filter(|(g, n)| n.clone && old.get(g).is_some_and(|o| !o.clone))
                        .map(|(_, n)| n.name.as_str())
                        .collect();
                    let from = origin_of(was, before)
                        .map(|o| format!("was a clone of {}", o.name))
                        .unwrap_or_else(|| "was a clone".to_string());
                    events.push(Event {
                        txg,
                        time,
                        kind: Kind::Promoted,
                        object: Some(d.name.clone()),
                        guid: *guid,
                        details: if over.is_empty() {
                            from
                        } else {
                            format!("{from}; now the origin of {}", over.join(", "))
                        },
                        last_seen_txg: None,
                    });
                }
                // Only what was read at both: a fact one of them could not
                // read is not one that changed. Unreadable encryption or
                // volume metadata at one TXG was a `property` event at it
                // and another at the next, neither of them true.
                let unknown: Vec<&str> = was.unknown.iter().chain(&d.unknown).copied().collect();
                let (a, b) = (describe_known(was, &unknown), describe_known(d, &unknown));
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
pub(crate) mod tests {
    use super::*;
    use zfs_ondisk::dsl::{DslDatasetPhys, DSL_DATASET_MIN_LEN};
    use zfs_ondisk::Endian;

    /// A dataset with nothing on it but a name and an identity: the diff
    /// looks at the GUID, the name and the few properties it reports, and
    /// a zeroed `dsl_dataset_phys_t` is what an empty one parses to.
    pub(crate) fn ds(name: &str, guid: u64, snapshot: bool) -> Dataset {
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
            unknown: Vec::new(),
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

    /// `zfs promote`: the clone is no longer one, the origin's snapshot
    /// moves to it, and the origin becomes its clone. It was only
    /// "renamed tank/vmc@before was tank/vm@before" (T-03).
    #[test]
    fn a_promotion_is_its_own_event() {
        let mut vm = ds("tank/vm", 1, false);
        vm.creation_txg = 5;
        let mut snap = ds("tank/vm@before", 2, true);
        snap.creation_txg = 9;
        snap.object = 70;
        let mut vmc = ds("tank/vmc", 3, false);
        vmc.creation_txg = 16;
        vmc.clone = true;
        vmc.origin_obj = 70;
        let before = vec![vm.clone(), snap.clone(), vmc.clone()];

        let mut vm2 = vm.clone();
        vm2.clone = true;
        vm2.origin_obj = 70;
        let mut snap2 = snap.clone();
        snap2.name = "tank/vmc@before".into();
        let mut vmc2 = vmc.clone();
        vmc2.clone = false;
        vmc2.origin_obj = 0;
        let after = vec![vm2, snap2, vmc2];

        let events = diff(&before, &after, 27, None);
        assert_eq!(
            kinds(&events),
            [
                ("promoted", Some("tank/vmc")),
                ("renamed", Some("tank/vmc@before"))
            ]
        );
        assert_eq!(
            events[0].details,
            "was a clone of tank/vm@before; now the origin of tank/vm"
        );
        assert_eq!(
            events[1].details,
            "was tank/vm@before, moved by the promotion of tank/vmc"
        );

        // Read only from after it: the old origin is no clone made before
        // what it is a clone of, and the promoted one no plain creation.
        assert_eq!(appeared_as(&after[0], &after), Kind::Created);
        assert_eq!(
            appeared_details(&after[0], &after).as_deref(),
            Some("a clone of tank/vmc@before since tank/vmc was promoted over it")
        );
        assert_eq!(appeared_as(&after[2], &after), Kind::Clone);
        assert!(promoted_since(&after[2], &after));
        // A clone made after its origin snapshot is just a clone.
        assert_eq!(appeared_as(&before[2], &before), Kind::Clone);
        assert!(!promoted_since(&before[0], &before));
        // A snapshot older than its dataset that nothing is a clone of
        // says no promotion.
        let alone = vec![after[1].clone(), after[2].clone()];
        assert!(!promoted_since(&alone[1], &alone));
        assert_eq!(appeared_as(&alone[1], &alone), Kind::Created);
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

    /// A fact one transaction group could not read is not one that
    /// changed: unreadable volume metadata at one TXG was a `property`
    /// event there, `volsize 8192 -> `, and another at the next.
    #[test]
    fn a_fact_not_read_is_no_change() {
        let mut was = ds("tank/vm/disk0", 7, false);
        was.volsize = Some(8192);
        was.volblocksize = Some(4096);
        let mut blind = was.clone();
        blind.volsize = None;
        blind.unknown = vec!["volsize"];
        assert!(diff(&[was.clone()], &[blind.clone()], 100, None).is_empty());
        assert!(diff(&[blind.clone()], &[was.clone()], 101, None).is_empty());
        // What it could read still counts.
        blind.volblocksize = Some(8192);
        let events = diff(&[was], &[blind], 100, None);
        assert_eq!(kinds(&events), [("property", Some("tank/vm/disk0"))]);
        assert_eq!(events[0].details, "volblocksize 4096 -> volblocksize 8192");
    }

    #[test]
    fn nothing_changed_is_no_events() {
        let list = vec![ds("tank", 1, false), ds("tank/vm", 2, false)];
        assert!(diff(&list, &list, 100, None).is_empty());
    }
}
