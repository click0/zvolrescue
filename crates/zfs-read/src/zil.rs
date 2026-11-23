//! A dataset's intent log: what it holds that the transaction group
//! read does not.
//!
//! A write an application was told is on disk — `fsync`, `O_SYNC`, a
//! volume's flush — is in the pool before its transaction group syncs:
//! as a record in the dataset's intent log, a chain of blocks its
//! object set header points at. After a crash an import replays the
//! records of the groups that never synced. This reader replays
//! nothing: what it reads at a transaction group is the dataset as that
//! group left it. Which is right, and has to be said — an image of a
//! crashed pool's volume lacks the writes its guest was last told were
//! safe, and nothing in a run that ended 0 said so.
//!
//! So the chain is walked and counted: how many records an import would
//! replay, of which kinds, on which objects, from which transaction
//! groups. They are not applied.
//!
//! The chain is read as OpenZFS reads it (`zil_parse`): each block is
//! verified by the checksum it carries inside itself, seeded with the
//! checksum of the pointer that led to it, and names the next; the
//! chain ends at the first block that does not verify, which is how a
//! log ends — the block after the last one written was allocated and
//! never filled.

use std::collections::{BTreeMap, BTreeSet};

use zfs_ondisk::blkptr::{self, BlkPtr};
use zfs_ondisk::checksum::fletcher4;
use zfs_ondisk::dmu::ObjsetPhys;
use zfs_ondisk::Endian;
use zvolrescue_io::trace;

use crate::dsl::Dataset;
use crate::zio::PoolReader;

/// `zio_eck_t`'s magic, as the block's own byte order has it.
const ZEC_MAGIC: u64 = 0x0210_da7a_b10c_7a11;
/// `ZIO_CHECKSUM_ZILOG2`: the chain header leads the block.
const CHECKSUM_ZILOG2: u8 = 9;
/// `sizeof (zil_chain_t)`: pad, next pointer, bytes used, embedded checksum.
const CHAIN_SIZE: usize = 8 + blkptr::SIZE + 8 + 40;
const NEXT_AT: usize = 8;
const NUSED_AT: usize = 8 + blkptr::SIZE;
const MAGIC_AT: usize = NUSED_AT + 8;
const CKSUM_AT: usize = MAGIC_AT + 8;
/// `ZIL_MIN_BLKSZ`: what a block's used bytes are rounded to for its checksum.
const MIN_BLOCK: usize = 4096;
/// `sizeof (lr_t)`: type, length, transaction group, sequence.
const RECORD_HEADER: usize = 32;
/// `TX_CI`: the record's names are to be matched without regard to case.
const TX_CI: u64 = 1 << 63;
const TX_WRITE: u64 = 9;
const TX_TRUNCATE: u64 = 10;
/// Blocks of one chain that are walked: a log is a few seconds of
/// writes, and a chain that loops is cut here.
const MAX_BLOCKS: u64 = 1 << 16;
/// Objects named one by one; past them only their number is kept.
pub const OBJECTS_LISTED: usize = 64;

/// What a dataset's intent log holds, counted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IntentLog {
    /// `zh_claim_txg`: the group an import claimed the log in; 0 for a
    /// log no import has seen since it was written.
    pub claim_txg: u64,
    /// `zh_replay_seq`: the last record already replayed.
    pub replay_seq: u64,
    /// Blocks of the chain that verified.
    pub blocks: u64,
    /// Records in them.
    pub records: u64,
    /// Those an import would replay: of a transaction group newer than
    /// the one read (or, for a claimed log, not older than its claim)
    /// and past `replay_seq`. They are not in what was read.
    pub unreplayed: u64,
    /// The unreplayed ones by kind (`TX_WRITE`, …).
    pub by_type: BTreeMap<String, u64>,
    /// Objects the unreplayed writes and truncates name, the first
    /// [`OBJECTS_LISTED`] of them.
    pub objects: Vec<u64>,
    /// How many objects they name in all.
    pub object_count: u64,
    /// Bytes the unreplayed `TX_WRITE` records write.
    pub write_bytes: u64,
    /// The oldest and newest transaction group among the unreplayed.
    pub txgs: Option<(u64, u64)>,
    /// Why the walk stopped short of the chain's end, when it did: what
    /// is counted is then a lower bound.
    pub cut_short: Option<String>,
}

/// The name OpenZFS gives a record type (`zil_rec_info`).
fn type_name(txtype: u64) -> String {
    const NAMES: [&str; 24] = [
        "TX_CREATE",
        "TX_MKDIR",
        "TX_MKXATTR",
        "TX_SYMLINK",
        "TX_REMOVE",
        "TX_RMDIR",
        "TX_LINK",
        "TX_RENAME",
        "TX_WRITE",
        "TX_TRUNCATE",
        "TX_SETATTR",
        "TX_ACL_V0",
        "TX_ACL",
        "TX_CREATE_ACL",
        "TX_CREATE_ATTR",
        "TX_CREATE_ACL_ATTR",
        "TX_MKDIR_ACL",
        "TX_MKDIR_ATTR",
        "TX_MKDIR_ACL_ATTR",
        "TX_WRITE2",
        "TX_SETSAXATTR",
        "TX_RENAME_EXCHANGE",
        "TX_RENAME_WHITEOUT",
        "TX_CLONE_RANGE",
    ];
    match usize::try_from(txtype) {
        Ok(n) if (1..=NAMES.len()).contains(&n) => NAMES[n - 1].to_string(),
        _ => format!("TX_{txtype}"),
    }
}

/// One record's header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Record {
    txtype: u64,
    txg: u64,
    seq: u64,
    /// `lr_foid` and `lr_length` of a write or a truncate.
    object: Option<u64>,
    length: u64,
}

/// One log block, verified: its records and the pointer to the next.
struct LogBlock {
    records: Vec<Record>,
    next: BlkPtr,
    /// A record's length did not fit what the block says it uses.
    malformed: bool,
}

/// Verify `raw` as the log block `bp` points at and take it apart, or
/// `None` when it is not that block — which is how a chain ends.
fn parse_block(raw: &[u8], bp: &BlkPtr) -> Option<LogBlock> {
    if raw.len() < CHAIN_SIZE {
        return None;
    }
    let magic = Endian::Little.u64_at(raw, MAGIC_AT)?;
    let endian = if magic == ZEC_MAGIC {
        Endian::Little
    } else if magic.swap_bytes() == ZEC_MAGIC {
        Endian::Big
    } else {
        return None;
    };
    let nused = usize::try_from(endian.u64_at(raw, NUSED_AT)?).ok()?;
    if nused < CHAIN_SIZE {
        return None;
    }
    let covered = nused.checked_next_multiple_of(MIN_BLOCK)?;
    if covered > raw.len() {
        return None;
    }
    // The checksum is over the block with the pointer's own checksum in
    // the place the block's is kept.
    let stored: Vec<u64> = (0..4)
        .filter_map(|i| endian.u64_at(raw, CKSUM_AT + i * 8))
        .collect();
    let mut work = raw[..covered].to_vec();
    for (i, word) in bp.cksum.iter().enumerate() {
        let bytes = match endian {
            Endian::Little => word.to_le_bytes(),
            Endian::Big => word.to_be_bytes(),
        };
        work[CKSUM_AT + i * 8..CKSUM_AT + i * 8 + 8].copy_from_slice(&bytes);
    }
    if fletcher4(&work, endian)[..] != stored[..] {
        return None;
    }
    let next = BlkPtr::parse(&raw[NEXT_AT..NEXT_AT + blkptr::SIZE], endian).ok()?;
    // The next block is this chain's when its pointer carries this
    // one's checksum with the sequence one further (`zil_read_log_block`).
    let mut expected = bp.cksum;
    expected[3] = expected[3].wrapping_add(1);
    if next.cksum != expected {
        return None;
    }
    let mut records = Vec::new();
    let mut at = CHAIN_SIZE;
    let mut malformed = false;
    while at + RECORD_HEADER <= nused {
        let word = |i: usize| endian.u64_at(raw, at + i * 8).unwrap_or(0);
        let reclen = usize::try_from(word(1)).unwrap_or(usize::MAX);
        if reclen < RECORD_HEADER || reclen % 8 != 0 || reclen > nused - at {
            malformed = true;
            break;
        }
        let txtype = word(0) & !TX_CI;
        let touches = matches!(txtype, TX_WRITE | TX_TRUNCATE) && reclen >= RECORD_HEADER + 24;
        records.push(Record {
            txtype,
            txg: word(2),
            seq: word(3),
            object: touches.then(|| word(4)),
            length: if touches { word(6) } else { 0 },
        });
        at += reclen;
    }
    Some(LogBlock {
        records,
        next,
        malformed,
    })
}

/// Count what the intent log of `ds` holds, the dataset having been
/// read at transaction group `read_txg`. `None` when the dataset has no
/// log, or its object set does not read — which the caller's own read
/// of it says.
pub fn intent_log(reader: &PoolReader<'_>, ds: &Dataset, read_txg: u64) -> Option<IntentLog> {
    if ds.phys.bp.is_hole() {
        return None;
    }
    let block = reader.read_block(&ds.phys.bp, false).ok()?;
    let os = ObjsetPhys::parse(&block.data, ds.phys.bp.endian).ok()?;
    if os.zil_log.is_hole() {
        return None;
    }
    Some(walk_chain(
        reader,
        &ds.name,
        os.zil_log,
        os.zil_claim_txg,
        os.zil_replay_seq,
        read_txg,
    ))
}

/// Walk the chain that starts at `first` and count it.
fn walk_chain(
    reader: &PoolReader<'_>,
    name: &str,
    first: BlkPtr,
    claim_txg: u64,
    replay_seq: u64,
    read_txg: u64,
) -> IntentLog {
    let mut log = IntentLog {
        claim_txg,
        replay_seq,
        ..IntentLog::default()
    };
    let mut objects: BTreeSet<u64> = BTreeSet::new();
    let mut bp = first;
    loop {
        if bp.is_hole() {
            break;
        }
        if log.blocks >= MAX_BLOCKS {
            log.cut_short = Some(format!("the chain is longer than {MAX_BLOCKS} blocks"));
            break;
        }
        if bp.checksum_code != CHECKSUM_ZILOG2 {
            // The first block decides: a log of the format before
            // slim blocks (pool version 26) is not taken apart here.
            if log.blocks == 0 {
                log.cut_short = Some(format!(
                    "a log block with checksum {} is not one this reads",
                    bp.checksum_code
                ));
            }
            break;
        }
        if bp.dva.iter().any(|d| d.gang) {
            log.cut_short =
                Some("a log block written in pieces (a gang block) is not followed".into());
            break;
        }
        // Each copy as the member has it, unverified by the reader:
        // the block verifies itself.
        let size = bp.psize as usize;
        let parsed = bp
            .dva
            .iter()
            .filter(|d| d.asize != 0)
            .flat_map(|d| reader.raw_copies(d, size))
            .find_map(|raw| parse_block(&raw, &bp));
        let Some(parsed) = parsed else {
            trace!(
                "zil",
                "{name}: the chain ends after {} block(s)",
                log.blocks
            );
            break;
        };
        log.blocks += 1;
        for r in &parsed.records {
            log.records += 1;
            // What an import replays (`zil_replay_log_record`): past
            // what was replayed, and of a group that had not synced —
            // newer than the one read, or for a log an import has
            // claimed, not older than the claim.
            let unsynced = if log.claim_txg != 0 {
                r.txg >= log.claim_txg
            } else {
                r.txg > read_txg
            };
            if r.seq <= log.replay_seq || !unsynced {
                continue;
            }
            log.unreplayed += 1;
            *log.by_type.entry(type_name(r.txtype)).or_insert(0) += 1;
            log.txgs = Some(match log.txgs {
                None => (r.txg, r.txg),
                Some((lo, hi)) => (lo.min(r.txg), hi.max(r.txg)),
            });
            if let Some(o) = r.object {
                objects.insert(o);
            }
            if r.txtype == TX_WRITE {
                log.write_bytes = log.write_bytes.saturating_add(r.length);
            }
        }
        if parsed.malformed {
            log.cut_short = Some(format!(
                "a record in block {} of the chain is not one a log holds",
                log.blocks
            ));
            break;
        }
        bp = parsed.next;
    }
    log.object_count = objects.len() as u64;
    log.objects = objects.into_iter().take(OBJECTS_LISTED).collect();
    trace!(
        "zil",
        "{name}: {} block(s), {} record(s), {} an import would replay (claim txg {}, replay seq {}, read at txg {read_txg})",
        log.blocks,
        log.records,
        log.unreplayed,
        log.claim_txg,
        log.replay_seq
    );
    log
}

impl IntentLog {
    /// One sentence for a person: what was left out, and that it was.
    ///
    /// `newest` is whether `read_txg` is the pool's newest transaction
    /// group. Only there is the log what an import would replay; read at
    /// an older one, its records are of the groups that followed, which
    /// the reader chose to go before.
    pub fn says(&self, name: &str, read_txg: u64, newest: bool) -> String {
        let kinds: Vec<String> = self
            .by_type
            .iter()
            .map(|(k, n)| format!("{n} {k}"))
            .collect();
        let objects = match self.object_count {
            0 => String::new(),
            n if n as usize <= self.objects.len() => format!(
                " on object(s) {}",
                self.objects
                    .iter()
                    .map(u64::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            n => format!(" on {n} objects"),
        };
        let txgs = match self.txgs {
            Some((lo, hi)) if lo == hi => format!("txg {lo}"),
            Some((lo, hi)) => format!("txg {lo}–{hi}"),
            None => "a later txg".to_string(),
        };
        // Which records they are: a log an import has claimed keeps
        // them across the groups that sync until the dataset is opened.
        let which = if self.claim_txg != 0 {
            format!(
                "of {txgs}, claimed by an import at txg {} and not replayed since",
                self.claim_txg
            )
        } else {
            format!("of {txgs}, newer than the txg {read_txg} that was read")
        };
        let fate = match (newest, self.claim_txg != 0) {
            (true, false) => "an import replays such records, and they are".to_string(),
            (true, true) => {
                "OpenZFS replays them when the dataset is next opened, and they are".to_string()
            }
            (false, _) => format!(
                "they are of what came after txg {read_txg}, which is not the pool's newest, and are"
            ),
        };
        format!(
            "{name}: the intent log holds {} record(s) {which} ({}{objects}{}); {fate} NOT applied here: what is read is the dataset as txg {read_txg} left it, without those writes{}",
            self.unreplayed,
            kinds.join(", "),
            if self.write_bytes > 0 {
                format!(", {} byte(s) written", self.write_bytes)
            } else {
                String::new()
            },
            match &self.cut_short {
                Some(why) => format!(" (at least: {why})"),
                None => String::new(),
            }
        )
    }
}

/// Builders for fixtures.
pub mod encode {
    use super::*;
    use zfs_ondisk::blkptr::encode::Builder;

    /// `TX_WRITE`, for [`record`].
    pub const WRITE: u64 = TX_WRITE;
    /// `TX_TRUNCATE`.
    pub const TRUNCATE: u64 = TX_TRUNCATE;
    /// The bit a record of a case-insensitive name carries.
    pub const CI: u64 = TX_CI;

    /// The pointer to the log block at DVA offset `offset`, the `seq`-th
    /// of its chain: the checksum words of a log pointer are the chain's
    /// own identity and the block's place in it.
    pub fn pointer(offset: u64, seq: u64) -> [u8; blkptr::SIZE] {
        Builder::new()
            .dva(0, 0, offset, MIN_BLOCK as u64, false)
            .sizes(MIN_BLOCK as u64, MIN_BLOCK as u64)
            .props(2, CHECKSUM_ZILOG2, 9, 0)
            .births(0, 11, 1)
            .cksum([0x1111, 0x2222, 77, seq])
            .bytes(Endian::Little)
    }

    /// One record: its header, then `body`.
    pub fn record(txtype: u64, txg: u64, seq: u64, body: &[u64]) -> Vec<u8> {
        let reclen = (RECORD_HEADER + body.len() * 8) as u64;
        [txtype, reclen, txg, seq]
            .iter()
            .chain(body)
            .flat_map(|w| w.to_le_bytes())
            .collect()
    }

    /// A log block as OpenZFS writes it: the chain header, the records,
    /// and the checksum of it all with the pointer's in its place.
    pub fn block(
        bp: &[u8; blkptr::SIZE],
        next: &[u8; blkptr::SIZE],
        records: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut raw = vec![0u8; MIN_BLOCK];
        raw[NEXT_AT..NEXT_AT + blkptr::SIZE].copy_from_slice(next);
        let mut at = CHAIN_SIZE;
        for r in records {
            raw[at..at + r.len()].copy_from_slice(r);
            at += r.len();
        }
        raw[NUSED_AT..NUSED_AT + 8].copy_from_slice(&(at as u64).to_le_bytes());
        raw[MAGIC_AT..MAGIC_AT + 8].copy_from_slice(&ZEC_MAGIC.to_le_bytes());
        // The pointer's checksum words stand where the block's own
        // will: bytes 96..128 of a pointer.
        raw[CKSUM_AT..CKSUM_AT + 32].copy_from_slice(&bp[96..128]);
        let sum = fletcher4(&raw, Endian::Little);
        for (i, w) in sum.iter().enumerate() {
            raw[CKSUM_AT + i * 8..CKSUM_AT + i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pointer(seq: u64) -> BlkPtr {
        BlkPtr::parse(&encode::pointer(0x10000 * (seq + 1), seq), Endian::Little).unwrap()
    }

    fn record(txtype: u64, txg: u64, seq: u64, body: &[u64]) -> Vec<u8> {
        encode::record(txtype, txg, seq, body)
    }

    fn block(bp: &BlkPtr, next: &BlkPtr, records: &[Vec<u8>]) -> Vec<u8> {
        encode::block(bp.raw(), next.raw(), records)
    }

    /// A log block verifies by the checksum inside it, seeded with its
    /// pointer's, and gives its records and the next pointer; the same
    /// bytes under another pointer, or with a bit turned, are not a
    /// block of the chain — which is where a chain ends.
    #[test]
    fn a_log_block_is_taken_apart_and_a_block_that_is_not_one_ends_the_chain() {
        let (bp, next) = (pointer(1), pointer(2));
        let write = record(TX_WRITE, 11, 1, &[8, 4096, 4096, 0]);
        let create = record(1 | TX_CI, 11, 2, &[3, 4, 5]);
        let raw = block(&bp, &next, &[write, create]);
        let parsed = parse_block(&raw, &bp).expect("the block of this pointer");
        assert!(!parsed.malformed);
        assert_eq!(parsed.next.cksum, next.cksum);
        assert_eq!(
            parsed.records,
            vec![
                Record {
                    txtype: TX_WRITE,
                    txg: 11,
                    seq: 1,
                    object: Some(8),
                    length: 4096
                },
                Record {
                    txtype: 1,
                    txg: 11,
                    seq: 2,
                    object: None,
                    length: 0
                },
            ]
        );
        assert!(parse_block(&raw, &pointer(5)).is_none(), "another pointer");
        let mut turned = raw.clone();
        turned[CHAIN_SIZE + 40] ^= 1;
        assert!(parse_block(&turned, &bp).is_none(), "a bit turned");
        // The block after the last one written: allocated, never filled.
        assert!(parse_block(&vec![0u8; 4096], &next).is_none());
        // A next pointer that is not this chain's next.
        let stray = block(&bp, &pointer(7), &[]);
        assert!(parse_block(&stray, &bp).is_none());
    }

    /// A chain of two blocks and the block after them never filled, on
    /// a mirror: every record is counted, and those an import would
    /// replay are the ones of a transaction group newer than the one
    /// read and past what was replayed — or, for a log an import has
    /// claimed, not older than its claim.
    #[test]
    fn a_chain_is_walked_to_its_end_and_what_an_import_would_replay_is_counted() {
        use crate::fixture::{write_at_dva, Pool};
        use crate::pool::assemble;
        use crate::vdev::scan_device;
        use zvolrescue_io::{BlockSource, MemSource};

        let pool = Pool::mirror("tank", 0x77, 12).txgs(&[(10, 1)]);
        let (first, second, third) = (pointer(1), pointer(2), pointer(3));
        let one = block(
            &first,
            &second,
            &[
                record(TX_WRITE, 10, 1, &[8, 0, 512, 0]),
                record(TX_WRITE, 11, 2, &[8, 4096, 4096, 0]),
                record(TX_TRUNCATE, 12, 3, &[9, 0, 100]),
            ],
        );
        let two = block(&second, &third, &[record(1, 12, 4, &[3, 4, 5])]);
        let mut images: Vec<Vec<u8>> = (0..2).map(|i| pool.member_image(i, 8 << 20)).collect();
        // The first block on both sides, the second on one: a copy is enough.
        write_at_dva(&mut images[0], first.dva[0].offset, &one);
        write_at_dva(&mut images[1], first.dva[0].offset, &one);
        write_at_dva(&mut images[1], second.dva[0].offset, &two);
        let sources: Vec<MemSource> = images.into_iter().map(MemSource::new).collect();
        let scans: Vec<_> = sources.iter().map(|s| scan_device(s).ok()).collect();
        let assembly = assemble(&scans).into_iter().next().expect("one pool");
        let devs: Vec<Option<&dyn BlockSource>> = sources
            .iter()
            .map(|s| Some(s as &dyn BlockSource))
            .collect();
        let reader = PoolReader::new(&assembly, devs);

        let log = walk_chain(&reader, "tank/v", first.clone(), 0, 0, 10);
        assert_eq!((log.blocks, log.records, log.unreplayed), (2, 4, 3));
        assert_eq!(
            log.by_type,
            [("TX_CREATE", 1), ("TX_TRUNCATE", 1), ("TX_WRITE", 1)]
                .into_iter()
                .map(|(k, n)| (k.to_string(), n))
                .collect()
        );
        assert_eq!((log.objects.clone(), log.object_count), (vec![8, 9], 2));
        assert_eq!(log.write_bytes, 4096);
        assert_eq!(log.txgs, Some((11, 12)));
        assert_eq!(log.cut_short, None);

        // Read at the group the records are of: they are in it.
        assert_eq!(
            walk_chain(&reader, "tank/v", first.clone(), 0, 0, 12).unreplayed,
            0
        );
        // Replayed up to the second record.
        assert_eq!(
            walk_chain(&reader, "tank/v", first.clone(), 0, 2, 10).unreplayed,
            2
        );
        // Claimed by an import at txg 12: what is older had synced.
        let claimed = walk_chain(&reader, "tank/v", first.clone(), 12, 0, 40);
        assert_eq!((claimed.unreplayed, claimed.txgs), (2, Some((12, 12))));
        // A chain that begins nowhere: no block, nothing to replay.
        let none = walk_chain(&reader, "tank/v", third, 0, 0, 10);
        assert_eq!((none.blocks, none.unreplayed), (0, 0));
    }

    #[test]
    fn the_kinds_have_the_names_zdb_gives_them() {
        assert_eq!(type_name(TX_WRITE), "TX_WRITE");
        assert_eq!(type_name(TX_TRUNCATE), "TX_TRUNCATE");
        assert_eq!(type_name(1), "TX_CREATE");
        assert_eq!(type_name(23), "TX_RENAME_WHITEOUT");
        assert_eq!(type_name(24), "TX_CLONE_RANGE");
        assert_eq!(type_name(0), "TX_0");
        assert_eq!(type_name(99), "TX_99");
    }

    /// What is said of a log names the count, the kinds, the objects
    /// and the transaction group read — and that nothing was applied.
    #[test]
    fn what_was_left_out_is_said_in_one_sentence() {
        let log = IntentLog {
            unreplayed: 2,
            by_type: [("TX_WRITE".to_string(), 2)].into_iter().collect(),
            objects: vec![8],
            object_count: 1,
            write_bytes: 4196,
            txgs: Some((11, 11)),
            ..IntentLog::default()
        };
        let s = log.says("zl/fs", 10, true);
        assert!(
            s.contains("2 record(s) of txg 11, newer than the txg 10"),
            "{s}"
        );
        assert!(
            s.contains("2 TX_WRITE on object(s) 8, 4196 byte(s) written"),
            "{s}"
        );
        assert!(
            s.contains("an import replays such records, and they are NOT applied here")
                && s.contains("as txg 10 left it"),
            "{s}"
        );
        // Read at a group that is not the pool's newest: no import
        // replays the log that group had, and none is said to.
        let s = log.says("zl/fs", 10, false);
        assert!(
            s.contains("they are of what came after txg 10, which is not the pool's newest, and are NOT applied here")
                && !s.contains("import"),
            "{s}"
        );
        // A log an import has claimed holds its records across the
        // groups that sync after: they are not "newer than" the one read.
        let claimed = IntentLog {
            claim_txg: 12,
            txgs: Some((12, 12)),
            ..log.clone()
        };
        let s = claimed.says("zl/fs", 40, true);
        assert!(
            s.contains("of txg 12, claimed by an import at txg 12 and not replayed since")
                && s.contains("OpenZFS replays them when the dataset is next opened")
                && !s.contains("newer than"),
            "{s}"
        );
    }
}
