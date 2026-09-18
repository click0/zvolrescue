//! An uberblock slot, a `vdev_phys`, and the zero-point search's reading
//! of a slot.
#![no_main]

use libfuzzer_sys::fuzz_target;
use zfs_ondisk::{label, uberblock, zeropoint};

fuzz_target!(|data: &[u8]| {
    if let Ok(ub) = uberblock::Uberblock::parse(data) {
        let _ = ub.rootbp_birth();
    }
    let phys = label::parse_vdev_phys(data, 0);
    if let Ok(nv) = &phys.config {
        let _ = label::LabelConfig::from_nvlist(nv).ashift();
    }
    let _ = zeropoint::plausible_shifts(data);
    let _ = zeropoint::confirm_slot(data, 0, None);
});
