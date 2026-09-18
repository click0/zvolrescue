//! A packed nvlist from anywhere — a label's `vdev_phys`, the MOS
//! config object — and the label configuration read out of it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use zfs_ondisk::{label, nvlist};

fuzz_target!(|data: &[u8]| {
    if let Ok(nv) = nvlist::parse_packed(data) {
        let cfg = label::LabelConfig::from_nvlist(&nv);
        let _ = cfg.ashift();
        if let Some(tree) = nv.list("vdev_tree") {
            let node = label::VdevNode::from_nvlist(tree);
            let _ = node.leaves();
            let _ = node.display_name();
        }
    }
});
