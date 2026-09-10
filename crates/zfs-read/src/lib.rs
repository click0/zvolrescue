//! Pool walking on top of [`zvolrescue_io::BlockSource`].
//!
//! Planned modules (see `docs/SPEC.md` §8.2): `vdev`, `zio`, `dmu`, `dsl`,
//! `zvol`, `zpl`, `carve`. Phase 0 provides label scanning of single
//! members ([`vdev`]) and assembly of the scanned members into pools
//! ([`pool`]); [`zio`] reads and verifies blocks through them; [`dmu`]
//! walks object block trees and dnode arrays; [`zap`] reads whole ZAP
//! objects; [`dsl`] walks the MOS into a dataset tree; [`zvol`] extracts a
//! volume's data object. [`zeropoint`] recovers a member's vdev base from
//! surviving uberblocks when its labels are gone. [`fixture`] builds
//! synthetic members for tests.

pub mod bind;
pub mod crypt;
pub mod dmu;
pub mod dsl;
pub mod fixture;
pub mod hints;
pub mod pool;
pub mod vdev;
pub mod zap;
pub mod zeropoint;
pub mod zio;
pub mod zvol;
