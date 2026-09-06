//! Pool walking on top of [`zvolrescue_io::BlockSource`].
//!
//! Planned modules (see `docs/SPEC.md` §8.2): `vdev`, `zio`, `dmu`, `dsl`,
//! `zvol`, `zpl`, `carve`. Phase 0 provides label scanning of single
//! members ([`vdev`]) and assembly of the scanned members into pools
//! ([`pool`]); [`zio`] reads and verifies blocks through them. [`fixture`]
//! builds synthetic members for tests.

pub mod fixture;
pub mod pool;
pub mod vdev;
pub mod zio;
