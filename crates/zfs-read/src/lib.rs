//! Pool walking on top of [`zvolrescue_io::BlockSource`].
//!
//! Planned modules (see `docs/SPEC.md` §8.2): `vdev`, `zio`, `dmu`, `dsl`,
//! `zvol`, `zpl`, `carve`. Phase 0 only establishes the crate; the first
//! real content (label reading through a `BlockSource`) lands with
//! `zvolrescue scan`.

pub mod vdev;
