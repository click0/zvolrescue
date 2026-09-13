//! Read-incompatible feature flags, and whether this build honours them
//! (SPEC F-70).
//!
//! A pool's label lists under `features_for_read` the read-incompatible
//! features that are *active* — not merely enabled, but in use, so that
//! whatever imports the pool knows what it must understand to read it.
//! On real pools the list is short: a `ztest` pool carries three, and a
//! dRAID one four.
//!
//! That makes the label the authority and this module the confession. A
//! feature named there and not here is one this build has no account of,
//! and the honest response is to say so rather than to read the pool as
//! though the feature were not there. `raidz_expansion` is the case that
//! matters most: it reflows the whole layout, and a reader that ignores
//! it returns the wrong bytes without a single checksum complaining,
//! because the checksums it checks are of the wrong blocks.
//!
//! A name misspelled in the list below costs a refusal on a pool this
//! build could have read — recoverable, and the operator is told how.
//! A name wrongly *added* would cost a silent wrong answer, which is why
//! nothing is listed here that is not either exercised by the
//! cross-check against `zdb` or implemented by a named module of this
//! workspace.

/// What this build can say about one feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Support {
    /// Implemented: blocks on a pool using it are read correctly.
    Yes,
    /// Known, and known *not* to be implemented. The text says what it
    /// would take and what goes wrong without it.
    No(&'static str),
    /// Never heard of. Which is not the same as harmless.
    Unknown,
}

/// Features this build reads correctly, with the evidence for saying so.
const KNOWN: &[(&str, &str)] = &[
    // Carried by every pool the cross-check builds, and those pools are
    // compared dataset for dataset and block for block against `zdb`.
    ("com.delphix:hole_birth", "cross-checked against zdb"),
    ("com.delphix:embedded_data", "cross-checked against zdb"),
    ("com.klarasystems:vdev_zaps_v2", "cross-checked against zdb"),
    (
        "org.openzfs:draid",
        "cross-checked against zdb on draid1 and draid2",
    ),
    // Mechanisms implemented in this workspace and exercised in CI.
    ("org.illumos:lz4_compress", "compress.rs"),
    ("org.openzfs:zstd_compress", "compress.rs"),
    ("org.illumos:sha512", "checksum.rs"),
    ("org.illumos:skein", "skein.rs"),
    ("org.illumos:edonr", "checksum.rs"),
    ("org.openzfs:blake3", "checksum.rs"),
    (
        "com.delphix:extensible_dataset",
        "zpl.rs: system-attribute layouts",
    ),
    (
        "org.open-zfs:large_blocks",
        "blkptr.rs: lsize beyond 128 KiB",
    ),
    ("org.zfsonlinux:large_dnode", "dmu.rs: dn_extra_slots"),
    ("com.datto:encryption", "crypt.rs"),
];

/// Features this build knows it cannot honour, and what happens without
/// them. Naming them earns a better answer than "unknown": the operator
/// is told which part of the pool is out of reach and why.
const NOT_IMPLEMENTED: &[(&str, &str)] = &[
    (
        "com.delphix:device_removal",
        "a top-level vdev was removed and its blocks live elsewhere; the \
         indirect mapping that would translate their addresses is not read \
         (SPEC F-69), so those blocks are refused by name",
    ),
    (
        "com.delphix:obsolete_counts",
        "bookkeeping for a removed vdev; see com.delphix:device_removal \
         (SPEC F-69)",
    ),
    (
        "org.openzfs:raidz_expansion",
        "the raidz group was widened and its rows reflowed, so a block's \
         columns are no longer where the original geometry puts them. \
         Reading it with that geometry returns the wrong bytes and the \
         checksums do not object, because they are the checksums of other \
         blocks",
    ),
];

/// What this build can say about `name`.
pub fn support(name: &str) -> Support {
    if KNOWN.iter().any(|(n, _)| *n == name) {
        return Support::Yes;
    }
    match NOT_IMPLEMENTED.iter().find(|(n, _)| *n == name) {
        Some((_, why)) => Support::No(why),
        None => Support::Unknown,
    }
}

/// Every active feature this build cannot account for, in the order the
/// label gave them, paired with what it can say about each.
pub fn unaccounted(active: &[String]) -> Vec<(&str, Support)> {
    active
        .iter()
        .map(|n| (n.as_str(), support(n)))
        .filter(|(_, s)| *s != Support::Yes)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The features a real pool carries are all accounted for, or the
    /// tool would refuse every pool the cross-check reads correctly.
    #[test]
    fn the_features_of_the_pools_ci_reads_are_known() {
        // Exactly what `zdb -l` prints for the cross-check's pools.
        let ztest = [
            "com.delphix:hole_birth".to_string(),
            "com.delphix:embedded_data".to_string(),
            "com.klarasystems:vdev_zaps_v2".to_string(),
        ];
        assert!(unaccounted(&ztest).is_empty(), "{:?}", unaccounted(&ztest));
        let draid = [ztest.to_vec(), vec!["org.openzfs:draid".to_string()]].concat();
        assert!(unaccounted(&draid).is_empty(), "{:?}", unaccounted(&draid));
    }

    /// And the one that would be read wrongly in silence is named, not
    /// merely unknown.
    #[test]
    fn a_reflowed_raidz_is_named_and_not_merely_unknown() {
        let active = ["org.openzfs:raidz_expansion".to_string()];
        let out = unaccounted(&active);
        assert_eq!(out.len(), 1);
        match out[0].1 {
            Support::No(why) => assert!(why.contains("reflow"), "{why}"),
            other => panic!("{other:?}"),
        }
        // Something from after this build's time is Unknown, which is a
        // different message and the same refusal.
        let future = ["org.example:something_new_2031".to_string()];
        assert_eq!(unaccounted(&future)[0].1, Support::Unknown);
    }
}
