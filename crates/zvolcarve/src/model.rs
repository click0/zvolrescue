//! The carve workspace: what a scan leaves behind for `list` and `dump`.
//!
//! `DIR` is the only thing `scan` writes. It holds the candidate index,
//! the rejection counters that make an empty index readable, the profile
//! that produced it, and the state a `--resume` picks up from.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Index format this build writes and understands.
pub const INDEX_VERSION: u32 = 1;

/// The candidate index, `candidates.json`.
pub const INDEX: &str = "candidates.json";
/// The resume state, `state.json`.
pub const STATE: &str = "state.json";

/// The search profile as it was applied, copied into the index and into
/// the evidence record: a candidate list means nothing without the
/// filter that produced it (C-16).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileOut {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnode_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volblocksize: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub levels: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txg: Option<[u64; 2]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<[u64; 2]>,
    /// Profile fields were hard filters rather than hints.
    pub strict: bool,
}

/// What walking a candidate's tree found.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AssessmentOut {
    pub blocks_total: u64,
    pub blocks_verified: u64,
    pub blocks_holes: u64,
    pub blocks_failed: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub birth: Option<[u64; 2]>,
    /// Only a sample of the tree was walked.
    pub sampled: bool,
    /// Share of blocks that verified or are honest holes.
    pub agreement: f64,
}

/// One candidate volume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candidate {
    /// Short identifier, as `list` prints it and `dump` takes it.
    pub id: String,
    /// Member it was found on.
    pub device: usize,
    pub path: PathBuf,
    /// Offset of the dnode, or of the compressed block holding it.
    pub offset: u64,
    /// Slot inside that block, for a compressed hit.
    pub slot: u64,
    /// `plaintext` or `lz4`.
    pub found: String,
    pub dnode_type: String,
    pub dnode_type_code: u8,
    /// Data block size: `volblocksize` for a volume.
    pub volblocksize: u64,
    /// Tree depth.
    pub levels: u8,
    pub maxblkid: u64,
    /// Size the dnode implies: one more block than the largest block id.
    pub implied_size: u64,
    /// Newest birth transaction group among the dnode's own pointers.
    pub birth: u64,
    /// Rank in 0.0..=1.0. Not a probability, and never a licence: every
    /// block an extraction reads is still verified by its checksum.
    pub score: f64,
    /// Profile fields this candidate failed, when the profile was soft.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profile_misses: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assessment: Option<AssessmentOut>,
    /// The dataset whose objset still points at this object, when one of
    /// them survived the scan (C-11). Not a name — the DSL directory
    /// chain that holds names lives in the MOS, which is exactly what a
    /// carve cannot reach — but a GUID that `zvoltimeline` can match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_guid: Option<String>,
    /// Creation transaction group of that dataset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_creation_txg: Option<u64>,
    /// The dnode's own bytes, hex, so `list` and `dump` need not scan
    /// again. What they say is still only a claim: the extraction reads
    /// through the pool and checks every block against its checksum.
    pub dnode_hex: String,
}

/// The candidate index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Index {
    pub index_version: u32,
    pub pool: String,
    pub pool_guid: String,
    pub members: Vec<PathBuf>,
    pub profile: ProfileOut,
    /// Rejections by reason, most first.
    pub rejected: Vec<Rejection>,
    /// Rejections that came from the profile rather than from the bytes:
    /// what tells "the filter is too tight" from "there is nothing here".
    pub rejected_by_profile: u64,
    pub bytes_read: u64,
    pub slots_examined: u64,
    /// Dataset dnodes the scan met, which is what can name a candidate.
    #[serde(default)]
    pub datasets_met: usize,
    /// What the disk actually holds, when `--sample` asked (C-19).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub histograms: Option<Histograms>,
    pub candidates: Vec<Candidate>,
}

/// What a sample of the hits looks like, so a profile can be picked from
/// the disk rather than from memory (C-19).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Histograms {
    /// Hits the histograms were built from.
    pub sampled: usize,
    /// Object types, most common first.
    pub dnode_type: Vec<Bucket>,
    /// Data block sizes.
    pub volblocksize: Vec<Bucket>,
    /// Tree depths.
    pub levels: Vec<Bucket>,
    /// Birth transaction groups, in ranges of a thousand.
    pub txg: Vec<Bucket>,
}

/// One bar of a histogram.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bucket {
    /// What the bar is: a type name, a size, a depth, a TXG range.
    pub value: String,
    /// How many hits fell in it.
    pub count: u64,
}

/// One reason, and how much it accounted for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rejection {
    pub reason: String,
    pub count: u64,
    /// The reason came from the search profile.
    pub profile: bool,
}

/// Where a scan got to, per member (C-08).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct State {
    pub index_version: u32,
    /// Offset reached on each member.
    pub reached: Vec<u64>,
    /// The scan finished the range it was given.
    pub complete: bool,
}

/// Read the index of a workspace.
pub fn load_index(dir: &Path) -> Result<Index, String> {
    let path = dir.join(INDEX);
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let index: Index = serde_json::from_str(&text)
        .map_err(|e| format!("{}: not a carve index: {e}", path.display()))?;
    if index.index_version != INDEX_VERSION {
        return Err(format!(
            "{}: index version {}; this build reads version {INDEX_VERSION}",
            path.display(),
            index.index_version
        ));
    }
    Ok(index)
}

/// Hex, as the index stores a dnode.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Back from hex, refusing anything that is not a whole number of bytes.
pub fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd number of hex digits".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}
