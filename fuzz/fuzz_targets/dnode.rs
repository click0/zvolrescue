//! A dnode and an objset header, in both byte orders, and the carver's
//! judgement of the dnode.
#![no_main]

use libfuzzer_sys::fuzz_target;
use zfs_ondisk::{carve, dmu, Endian};

fuzz_target!(|data: &[u8]| {
    let _ = carve::plausible_head(data);
    for endian in [Endian::Little, Endian::Big] {
        if let Ok(d) = dmu::DnodePhys::parse(data, endian) {
            let _ = carve::plausible_dnode(&d);
            let _ = carve::Profile::implied_size(&d);
            let _ = carve::Profile::birth(&d);
        }
        let _ = dmu::ObjsetPhys::parse(data, endian);
    }
});
