# Companion tools — Technical Specification

**Status:** Draft v0.1 · **Date:** 2026-09-06 · **Parent:** [SPEC.md](SPEC.md) §3.0, §7.1

**Ukrainian version:** [COMPANIONS.uk.md](COMPANIONS.uk.md)

The main binary `zvolrescue` does one job (SPEC §3.0). Everything marked ◇
in SPEC §5 is done by one of four companion binaries specified here. All
of them live in this repository and workspace (decision D-3 in SPEC §13):
one version number, one release tarball, one CI, one FreeBSD port that
installs all binaries.

Each companion tool is as atomic as the main one: one job, one static
binary, no configuration, no daemon, read-only on evidence, pure runs.
They never call each other; they exchange data only through files the
user names on the command line.

---

## 1. Common contract

Everything in this section is implemented once in the `zvol-common`
library crate and inherited by all five binaries.

### 1.1 Arguments

| Convention | Meaning |
|---|---|
| `POOLSPEC` | as in SPEC §7: devices, `--image FILE` (repeatable), `--pool-guid GUID`. A required `DATASET` always precedes it, because the member list is variable-length. |
| `-f, --format text\|json` | text for humans (default), one JSON document on stdout for machines |
| `-v` / `-q` | verbosity up / down, repeatable |
| `--evidence-log FILE` | append one JSON Lines record per run (§1.3) |
| `--no-color` | no ANSI colour; also implied when stdout is not a terminal |
| `--txg N` / `--before TS` | TXG selection, same semantics as `zvolrescue list` |
| `--key KEYSPEC` | dataset encryption key, same forms as `zvolrescue dump` |
| `-o PATH` | output file or directory; refused with exit 5 if it resolves onto evidence |

### 1.2 Exit codes

Identical to SPEC §7: `0` ok, `1` usage, `2` evidence unreadable, `3` pool
unrecoverable at TXG, `4` completed with errors, `5` refused (would write
to evidence). Tools that scan for a long time add `6` = interrupted with a
resumable state file written.

### 1.3 Evidence log record (format version 1)

One JSON object per line, appended, never rewritten:

```json
{"v":1,"ts":1757100010,"tool":"zvolcarve","version":"0.3.0","host":"rescue1",
 "argv":["zvolcarve","scan","--image","disk0.img","-o","/case42/carve"],
 "inputs":[{"path":"disk0.img","size":68719476736,"sha256":"…"}],
 "outputs":[{"path":"/case42/carve/cand-0007.img","size":10737418240,"sha256":"…"}],
 "result":{…tool-specific, identical to the -f json document…},
 "status":0}
```

* `inputs[].sha256` is present only when `--hash-inputs` was given (hashing
  multi-TB evidence is slow; the user chooses).
* `outputs[].sha256` is always present: every tool hashes what it writes.
* `zvolreport` consumes these records; nothing else reads them.

### 1.4 Read-only invariants

SPEC §8.3 applies unchanged: the only path from an input name to a file
descriptor is `zvolrescue-io`, which opens `O_RDONLY`; no
`std::process::Command`, no network; `#![forbid(unsafe_code)]` outside
`zvolrescue-io`.

---

## 2. `zvoltimeline` — what happened to this pool, and when

### 2.1 Job

Turn the TXGs that still exist on disk into a human-readable history of
the pool: which datasets, zvols and snapshots existed at each TXG, when
they appeared, were renamed or disappeared, which hosts imported the pool,
and — for anything destroyed — the last TXG that still had it, as a
ready-to-run `zvolrescue dump` command.

Answers UC-3 and the first question of UC-1 ("when did it disappear?").

### 2.2 CLI

```
zvoltimeline POOLSPEC [--from TXG] [--to TXG] [--dataset NAME|GUID]
                      [--pending] [--hash-inputs] [-f text|json] [-o FILE]
```

Text output is one line per event, oldest first:

```
TXG       TIME                  EVENT      OBJECT                     DETAILS
4816201   2025-09-05T19:17:40Z  created    pool/vm/disk0              zvol 32G lz4 sha256
4816229   2025-09-05T19:20:05Z  snapshot   pool/vm/disk0@before-upgrade
4816230   2025-09-05T19:20:10Z  host       —                          hostid 0x1a2b3c4d "vmhost2"
4816231   2025-09-05T19:20:15Z  destroyed  pool/vm/disk0              last seen txg 4816230 → zvolrescue dump … --txg 4816230
4816232   —                     unreadable —                          MOS blocks overwritten
```

### 2.3 Requirements

| ID | Pri | Requirement |
|---|---|---|
| T-01 | M | Enumerate every TXG that has a valid uberblock in any label of any member (SPEC F-04), plus the checkpoint TXG if present. |
| T-02 | M | For each TXG, list datasets with GUID, type, name, creation TXG (reusing `zfs-read` dsl; SPEC F-11/F-12). |
| T-03 | M | Diff consecutive TXGs into events: `created`, `destroyed`, `renamed` (same GUID, new name), `snapshot`, `snapshot-destroyed`, `clone`, `promoted`. |
| T-04 | M | A TXG whose MOS can no longer be read (blocks reused) is reported as `unreadable`, with the first failing block, and never aborts the run. |
| T-05 | M | For every `destroyed` event, print the last TXG that still referenced the object and the exact `zvolrescue dump` command line. |
| T-06 | S | `host` events from label nvlists: `hostid`, `hostname`, label TXG — detects imports on another machine. |
| T-07 | S | `--pending` (SPEC F-15): per TXG, size of the free bpobj / deadlists that still hold blocks of destroyed datasets, so the user can judge whether data is still physically present. |
| T-08 | S | `--dataset` filters events to one object (by name at any TXG, or GUID). |
| T-09 | S | Property changes (`compression`, `volsize`, `encryption` …) as `property` events at `-v`. |
| T-10 | M | Deterministic output ordering: TXG, then event kind, then object GUID. |
| T-11 | S | Memory bound: only two TXG snapshots of the dataset list are held at a time. |

### 2.4 Acceptance

Fixture pool with a scripted history (create, snapshot, rename, destroy at
recorded TXGs, imported on two hostids): the event list equals the script,
and the `dump` command printed for the destroyed zvol recovers it
bit-exact.

*Status: T-01…T-06, T-08, T-10 and T-11 are implemented and run in CI on
the mirror fixture (three transaction groups, the volume destroyed at the
newest): the event list is the scripted one, and the `dump` command the
tool prints recovers the volume with the SHA-256 the end-to-end step
already pins. `--pending` (T-07), property events (T-09) and
`--hash-inputs` are not implemented yet. A `ztest` pool exercises the
same code on real on-disk bytes, including transaction groups whose MOS
can no longer be walked, but scripts no history of its own.*

---

## 3. `zvolcarve` — find zvols that no uberblock points to any more

### 3.1 Job

When the uberblock ring has already rolled past the last TXG that
referenced a dataset, `zvolrescue list` cannot see it. `zvolcarve` scans
raw vdev space for surviving ZFS metadata — dnodes of type `DMU_OT_ZVOL`
and the indirect-block trees under them — rebuilds candidate zvols,
scores them, and extracts the ones the user picks with exactly the same
semantics as `zvolrescue dump` (same library code, same output format,
same evidence record).

### 3.2 CLI

```
zvolcarve scan    POOLSPEC -o DIR [--range VDEV:START-END]
                                  [--volblocksize BYTES] [--levels N]
                                  [--txg FROM..TO] [--size MIN..MAX]
                                  [--dnode-type TYPE...] [--profile FILE]
                                  [--like DATASET] [--strict-profile]
                                  [--resume] [--hash-inputs] [-f text|json]
zvolcarve list    DIR                      show candidates found by a previous scan
zvolcarve dump    DIR CANDIDATE -o OUT.img [--strict] [--key KEYSPEC] [--resume]
```

`DIR` is the carve workspace: a candidate index (`candidates.json`), the
raw hit log, and the resumable scan state. It is the only thing `scan`
writes.

### 3.3 Requirements

| ID | Pri | Requirement |
|---|---|---|
| C-01 | M | Scan every member (or `--range`) at `ashift` granularity, streaming, bounded memory; progress on stderr. |
| C-02 | M | Recognise dnode blocks by structural validation: `dn_type` in the known set, `dn_indblkshift` 9–17, `dn_nlevels` 1–7, `dn_nblkptr` 1–3, known checksum/compression codes, DVAs inside the vdev; every field range from OpenZFS `dnode.h`. |
| C-03 | M | Recognise indirect blocks: arrays of block pointers whose DVAs lie inside member vdevs and whose birth TXGs are mutually consistent. |
| C-04 | M | From each `DMU_OT_ZVOL` dnode, walk its tree, verify checksums, and build a candidate: estimated `volsize`, birth-TXG range, share of blocks that verified, share of blocks already overwritten by newer data. |
| C-05 | M | Score candidates (checksum agreement, contiguity, birth consistency, overwrite share) and sort by score; explain the score in `-v`. |
| C-06 | S | Detect overwritten blocks by checking each DVA against the space map of the newest importable TXG when available. |
| C-07 | M | `dump` is byte-for-byte the `zvolrescue dump` pipeline (sparse output, `--strict`, resume, evidence record); unreadable blocks become zeros and are logged. |
| C-08 | M | `scan --resume` continues from the state file; interruption exits 6. |
| C-09 | S | Mirror members are scanned once (identical copies), RAIDZ/dRAID members are scanned with parity reconstruction (phase 3+). |
| C-10 | S | Compressed metadata: try lz4/zstd/gzip/lzjb on candidate blocks whose plaintext validation fails. |
| C-11 | S | Also record `DMU_OT_OBJSET`/dataset dnodes found, so a candidate can be named when its DSL metadata survived. |
| C-12 | C | Signature carving inside candidate data (UFS/ext4/NTFS superblocks, SPEC F-43) to bound `volsize` when metadata is gone. |

#### The search profile

A pool that has lived through a hundred thousand transaction groups holds
far more recognisable metadata than belongs to the object being looked
for: dnodes of every dataset that ever existed, indirect blocks of every
generation of every tree. Structural validation (C-02) only says "this is
a dnode"; it does not say "this could be the 300 GB volume that was lost".
The operator usually knows the second thing — the volume's block size, how
deep its tree had to be, roughly when it was written, roughly how big it
was — and that knowledge is what turns a scan of millions of hits into a
handful of candidates.

The profile is a **filter, never an assumption**: it decides what is worth
following, and nothing that is extracted is trusted because it matched a
profile. Every block handed to `dump` is still verified by its own
checksum, exactly as in the main binary.

| ID | Pri | Requirement |
|---|---|---|
| C-13 | M | A **search profile** narrows what counts as a candidate *at recognition time*, before any tree is walked or scored: `--volblocksize` (data block size), `--levels` (`dn_nlevels`, i.e. tree depth L0…Ln), `--txg FROM..TO` (birth-TXG window), `--size MIN..MAX` (estimated `volsize`), `--dnode-type` (default `zvol`). Applying it during recognition rather than after is the point: a search for one 300 GB volume must not pay to walk the trees of everything else in the pool. |
| C-14 | M | Every profile field is optional and independent; an absent field filters nothing. A profile that matches nothing must be visibly a *rejection*, not an absence: the run reports how many hits each field rejected, so "0 candidates, 4.2 M dnodes rejected by volblocksize" is distinguishable from "there is nothing on this disk". |
| C-15 | M | Rejection counters per reason — dnode type, `indblkshift`, `nlevels`, `nblkptr`, DVA outside any member, birth TXG outside the window, size outside the range, checksum/compression code unknown — on stderr as progress and in the JSON result, so the operator can see which single field is too tight and loosen exactly that one. |
| C-16 | S | `--profile FILE`: the same fields as a JSON document, so a case can be re-run, reviewed and shared; the profile as applied is copied verbatim into the evidence record (§1.3), because a candidate list means nothing without the filter that produced it. |
| C-17 | S | `--like DATASET`: read `volblocksize`, `nlevels` and `volsize` from a dataset that *still* exists in the pool and use them as the profile. In most incidents the lost volume was created like its neighbours, and a surviving sibling is a better source for these numbers than the operator's memory. |
| C-18 | S | Profile fields are *hints* by default: a hit that fails a soft field is still recorded, with the failing field named, and ranked below the ones that matched, so a wrong guess costs ranking rather than the whole recovery. `--strict-profile` turns them into hard filters for the cases where the operator is certain and the scan would otherwise be too slow. |
| C-19 | C | Auto-profile: with no profile given, `scan --sample N` reads the first N hits and reports the histograms of `volblocksize`, `nlevels` and birth TXG it saw, so the operator can pick a profile from what is actually on the disk instead of guessing. |

### 3.4 Acceptance

Fixture: create a zvol with known content, destroy it, write enough
unrelated data to rotate all 128 uberblocks past it without reusing its
blocks. `zvolrescue list` no longer shows it; `zvolcarve scan` finds one
candidate scoring ≥ 0.95; `zvolcarve dump` produces an image whose SHA-256
equals the original.

For the profile: the same fixture with three more zvols of other block
sizes and sizes present in the pool. A scan with no profile finds all
four candidates; a scan with the destroyed volume's `--volblocksize` and
`--size` finds it and reports the other three as rejected, naming the
field that rejected each; a profile that matches none of them reports
zero candidates *and* a non-zero rejection count for the field at fault.
The extracted image is bit-identical in every case, because the profile
never touches what `dump` verifies.

---

## 4. `zvolreport` — one document that a third party can check

### 4.1 Job

Consolidate the evidence logs written by the other tools into a single
report with a verifiable hash chain: what evidence was examined, by which
tool versions, with which commands, what was extracted, and whether every
file still matches its recorded hash.

### 4.2 CLI

```
zvolreport build   LOG... -o report.json [--md report.md] [--case ID] [--examiner NAME]
                          [--note TEXT]...
zvolreport verify  report.json [--evidence-root DIR] [--outputs-root DIR]
```

### 4.3 Requirements

| ID | Pri | Requirement |
|---|---|---|
| R-01 | M | Parse evidence records of format version 1 (§1.3) from any number of logs; reject unknown versions with a clear message. |
| R-02 | M | Report sections: case metadata; evidence list (path, size, hash if known); tool versions; every command in chronological order with status; pool summary and TXG window (from `scan` records); extractions (dataset, TXG, output, size, hash, error count); warnings. |
| R-03 | M | `build` is pure: the same logs and flags produce the same `report.json` byte for byte (timestamps only from the records). |
| R-04 | M | `verify` recomputes SHA-256 of every output listed and of every input that has a recorded hash; prints a per-file PASS/FAIL table; exit 4 on any FAIL. |
| R-05 | S | Markdown rendering (`--md`) suitable for attaching to a ticket or a forensic case file. |
| R-06 | S | Detect gaps: extractions whose TXG is outside the recorded TXG window, outputs never hashed, records from mismatched tool versions. |
| R-07 | C | Sign `report.json` with an ed25519 key (`--sign KEYFILE`) and verify the signature. |

### 4.4 Acceptance

Run UC-1 end-to-end with `--evidence-log`; `zvolreport build` lists every
command and hash; modifying one byte of the extracted image makes
`zvolreport verify` fail with exit 4 naming that file.

---

## 5. `zvolfiles` — files out of filesystem datasets

### 5.1 Job

The main binary treats a filesystem dataset as an object dump at most.
`zvolfiles` understands the ZFS POSIX layer: directories, files, symlinks,
extended attributes, ownership and timestamps — and extracts a directory
tree, or a raw object dump when the ZPL metadata is too damaged.

### 5.2 CLI

```
zvolfiles list     DATASET POOLSPEC [--txg N] [--key KEYSPEC] [PATH] [-R]
zvolfiles extract  DATASET POOLSPEC [--txg N] [--key KEYSPEC] [PATH...] -o DIR
                                    [--strict] [--preserve owner,times,xattr]
zvolfiles objects  DATASET POOLSPEC [--txg N] [--key KEYSPEC] -o DIR
```

### 5.3 Requirements

| ID | Pri | Requirement |
|---|---|---|
| Z-01 | M | Read the ZPL master node, root directory, and both micro-ZAP and fat-ZAP directories. |
| Z-02 | M | Decode system attributes (SA layout) for size, mode, uid/gid, times, link count; fall back to legacy `znode_phys` bonus. |
| Z-03 | M | Regular files including sparse regions; symlinks (SA-embedded and object-based). |
| Z-04 | S | Extended attributes: directory-based (`xattr=on`) and SA-based (`xattr=sa`). |
| Z-05 | M | Manifest `manifest.json` in the output directory: every extracted path with size, mode, owner, times, SHA-256, and the error count for that file. |
| Z-06 | M | Unreadable blocks become zeros with the range logged (SPEC F-33); `--strict` aborts instead. |
| Z-07 | S | Hard links restored as hard links inside the output directory when both paths were extracted. |
| Z-08 | S | `objects` (SPEC F-29): one file per object plus `objects.json` with dnode metadata — the fallback when Z-01 fails. |
| Z-09 | S | `casesensitivity`, `normalization` and `utf8only` dataset properties honoured when matching `PATH`. |
| Z-10 | C | Large dnodes, project quotas and other feature-flag extensions to the SA layout. |

### 5.4 Acceptance

Fixture filesystem dataset with a nested tree, sparse files, symlinks,
xattrs and hard links, destroyed after a snapshot of its hashes:
`zvolfiles extract` at the last good TXG reproduces the tree with matching
hashes and metadata; `objects` produces the same file contents when the
root directory ZAP is deliberately zeroed.

---

## 6. Delivery

Companion tools follow the phases of SPEC §10; none ships before the main
binary's phase 1 is accepted, because they all depend on `zfs-read`'s
dsl/zvol layers.

| Phase | Tool | Scope |
|---|---|---|
| 3 | `zvoltimeline` | T-01…T-05, T-10 |
| 3 | `zvolcarve` | single/mirror scan, C-01…C-05, C-07, C-08 |
| 3 | `zvolreport` | R-01…R-04 |
| 4 | `zvolfiles` | Z-01…Z-03, Z-05, Z-06 |
| later | all | remaining S/C rows; `zvolcarve` on RAIDZ/dRAID |

Each tool is a workspace member `crates/<tool>/` with its own
`README.md`, man page (`<tool>.1`) and integration tests under
`tests/<tool>/`. The release tarball and the FreeBSD port install all
binaries and man pages together.
