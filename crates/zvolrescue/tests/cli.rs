//! The command line, end to end, on fixture members written to disk:
//! what `scan`, `list` and `dump` print and exit with is the contract a
//! script relies on, and until now only CI steps held it.

use std::path::Path;
use std::process::Command;

use zfs_ondisk::blkptr::LABEL_START_SIZE;
use zfs_ondisk::checksum::seal_label;
use zfs_ondisk::label::{label_offsets, LABEL_SIZE, UBERBLOCK_RING_OFFSET, UBERBLOCK_RING_SIZE};
use zfs_read::fixture::{
    build_sample_mos, checkpointed_members, configured_two_top_members, destroyed_zvol_members,
    lose_children_list, objset_reused_members, removed_since_members, removed_vdev_members,
    roots_json, two_top_mirror_members, two_top_raidz_members, zero_uberblock_rings, zpl_members,
    zvol_pattern, Alloc, Pool, SAMPLE_ZVOL_BLOCK0_OFFSET,
};
use zfs_read::hash::{Digests, Extra};
use zvol_common::scratch::Scratch;

const SIZE: u64 = 64 * LABEL_SIZE;

/// A directory for one test, removed when the test ends.
fn scratch(name: &str) -> Scratch {
    Scratch::new("zvolrescue-cli", name)
}

/// A two-way mirror with the sample MOS at one txg, the volume present.
fn plain_members() -> Vec<Vec<u8>> {
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
    let mut members = vec![vec![0u8; SIZE as usize], vec![0u8; SIZE as usize]];
    let mut a = Alloc::new(0x20_0000);
    build_sample_mos(&mut pool, &mut members, &mut a);
    for (i, m) in members.iter_mut().enumerate() {
        pool.write_labels(i, m);
    }
    members
}

/// [`plain_members`] with the volume deduplicated (SPEC F-28): the
/// dedup bit on its data pointers, sha256 checksums, `dedup=sha256,verify`
/// among its properties. The bytes are the same.
fn dedup_members() -> Vec<Vec<u8>> {
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
    let mut members = vec![vec![0u8; SIZE as usize], vec![0u8; SIZE as usize]];
    let mut a = Alloc::new(0x20_0000);
    a.dedup = true;
    build_sample_mos(&mut pool, &mut members, &mut a);
    for (i, m) in members.iter_mut().enumerate() {
        pool.write_labels(i, m);
    }
    members
}

fn write_members(dir: &Path, members: &[Vec<u8>]) -> Vec<String> {
    members
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let p = dir.join(format!("member{i}.img"));
            std::fs::write(&p, m).expect("write member");
            p.to_string_lossy().into_owned()
        })
        .collect()
}

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_zvolrescue"))
        .args(args)
        .output()
        .expect("run zvolrescue");
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn json(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout).unwrap_or_else(|e| panic!("not JSON ({e}): {stdout}"))
}

/// A member whose name is not UTF-8 cannot be named in the JSON or in
/// the evidence record; it is refused up front (exit 1) rather than
/// panicking when the run serialises its result — for `dump`, after the
/// image was written and before its hash or record.
#[cfg(unix)]
#[test]
fn a_member_named_in_bytes_that_are_not_text_is_refused() {
    use std::os::unix::ffi::OsStrExt;
    let dir = scratch("not-utf8");
    let paths = write_members(&dir, &plain_members());
    let odd = dir.join(std::ffi::OsStr::from_bytes(b"m\xff.img"));
    std::fs::rename(&paths[0], &odd).unwrap();
    for args in [vec!["list"], vec!["-f", "json", "scan"]] {
        let out = Command::new(env!("CARGO_BIN_EXE_zvolrescue"))
            .args(&args)
            .arg(&odd)
            .arg(&paths[1])
            .output()
            .expect("run");
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {err}");
        assert!(err.contains("not valid UTF-8"), "{err}");
        assert!(!err.contains("panicked"), "{err}");
    }
}

/// A layout no pool could have is refused when the hints are read (exit
/// 1), with what is wrong with it: raidz parity of 4 over 4 members, or
/// an ashift of 63, reached a division by zero or a shift out of the
/// word in the reader.
#[test]
fn hints_with_an_impossible_geometry_are_refused() {
    let dir = scratch("bad-geometry");
    let paths = write_members(&dir, &plain_members());
    for (kind, nparity, ashift, want) in [
        ("raidz", 2, 12, "nparity 2 over 2"),
        ("raidz", 4, 12, "nparity 4 over 2"),
        ("draid", 9, 12, "nparity 9"),
        // A dRAID no numbers make: refused with them, exit 1, where it
        // was "not supported yet" at every read, exit 3.
        (
            "draid",
            1,
            12,
            "no dRAID of 2 member(s) has draid_ndata absent",
        ),
        ("mirror", 0, 63, "ashift 63"),
        ("mirror", 0, 0, "ashift 0"),
    ] {
        let hints = dir.join("layout.hints");
        std::fs::write(
            &hints,
            serde_json::json!({"name": "tank", "ashift": ashift,
                "tops": [{"kind": kind, "nparity": nparity, "members": [&paths[0], &paths[1]]}]})
            .to_string(),
        )
        .unwrap();
        let (code, _, err) = run(&[
            "-q",
            "list",
            &paths[0],
            &paths[1],
            "--hints",
            &hints.to_string_lossy(),
        ]);
        assert_eq!(code, 1, "{kind} {nparity} {ashift}: {err}");
        assert!(err.contains(want), "{want}: {err}");
    }
    // A layout that names nothing readable: an unknown kind, a vdev with
    // no member or with every member null, a base past the member's end.
    // Each was taken as written and failed later with exit 3 and "no
    // verified uberblock matches the requested TXG; available: ".
    let m0 = serde_json::Value::from(paths[0].clone());
    for (tops, want) in [
        (
            serde_json::json!([{"kind": "weird", "members": [&paths[0], &paths[1]]}]),
            "is no vdev this reads",
        ),
        (
            serde_json::json!([{"kind": "mirror", "members": []}]),
            "has no members",
        ),
        (
            serde_json::json!([{"kind": "mirror", "members": [null, null]}]),
            "every member is null",
        ),
        (
            serde_json::json!([{"kind": "disk", "members": [{"path": m0, "base": 1u64 << 40}]}]),
            "is not inside",
        ),
    ] {
        let hints = dir.join("layout.hints");
        std::fs::write(
            &hints,
            serde_json::json!({"ashift": 12, "tops": tops}).to_string(),
        )
        .unwrap();
        let (code, _, err) = run(&[
            "-q",
            "list",
            &paths[0],
            &paths[1],
            "--hints",
            &hints.to_string_lossy(),
        ]);
        assert_eq!(code, 1, "{want}: {err}");
        assert!(err.contains(want), "{want}: {err}");
    }
}

/// A layout without the pool's name takes it from a label that has it:
/// the datasets were all `?/…`, and `dump tank/vm/disk0` found none.
#[test]
fn hints_without_a_name_take_the_pools() {
    let dir = scratch("hints-no-name");
    let paths = write_members(&dir, &plain_members());
    let hints = dir.join("layout.hints");
    std::fs::write(
        &hints,
        serde_json::json!({"ashift": 12,
            "tops": [{"kind": "mirror", "members": [&paths[0], &paths[1]]}]})
        .to_string(),
    )
    .unwrap();
    let (code, out, err) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &paths[0],
        &paths[1],
        "--hints",
        &hints.to_string_lossy(),
        "-o",
        &dir.join("vol.img").to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(json(&out)["volumes"][0]["dataset"], "tank/vm/disk0");
    // And the GUID from the pool's own configuration: it was 0 in the
    // header, the JSON and the record.
    assert_eq!(json(&out)["pool_guid"], "0x0000000000004242", "{out}");
}

/// With no label left and no name in the hints, the pool is named by
/// its own configuration in the MOS: its datasets were, and the pool
/// stayed "?" in the header, the JSON and the record.
#[test]
fn a_pool_no_label_names_is_named_by_its_mos() {
    let dir = scratch("hints-mos-name");
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
    let mut members = removed_vdev_members(&mut pool, SIZE);
    for m in &mut members {
        wipe_configs(m);
    }
    let paths = write_members(&dir, &members);
    let hints = dir.join("layout.hints");
    std::fs::write(
        &hints,
        serde_json::json!({"ashift": 12,
            "tops": [{"kind": "mirror", "members": [&paths[0], &paths[1]]}]})
        .to_string(),
    )
    .unwrap();
    let (code, out, err) = run(&[
        "-q",
        "-f",
        "json",
        "list",
        &paths[0],
        &paths[1],
        "--hints",
        &hints.to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(json(&out)["pool"], "tank", "{out}");
}

/// A member given twice — by its path and by a link to it — is read
/// once, and said; and a member given two maps is refused, where the
/// second was passed over for the first without a word.
#[test]
fn a_member_twice_is_read_once_and_given_one_map() {
    let dir = scratch("member-twice");
    let paths = write_members(&dir, &plain_members());
    let link = dir.join("again.img");
    std::os::unix::fs::symlink(&paths[0], &link).unwrap();
    let (code, out, err) = run(&[
        "-q",
        "-f",
        "json",
        "scan",
        &paths[0],
        &link.to_string_lossy(),
        &paths[1],
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(
        err.contains("again.img is ") && err.contains("again; read once"),
        "{err}"
    );
    assert_eq!(json(&out)["devices"].as_array().unwrap().len(), 2, "{out}");

    let (a, b) = (dir.join("a.map"), dir.join("b.map"));
    std::fs::write(&a, "0x0 +\n0x0 0x100000 +\n").unwrap();
    std::fs::write(&b, "0x0 +\n0x0 0x100000 -\n").unwrap();
    let (code, _, err) = run(&[
        "-q",
        "scan",
        &paths[0],
        &paths[1],
        "--map",
        &format!("{}={}", paths[0], a.display()),
        "--map",
        &format!("{}={}", paths[0], b.display()),
    ]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("has a map already"), "{err}");

    // A map given for the second spelling goes with the member read:
    // it was "read once", then "not among the members given", exit 1.
    for cmd in ["scan", "list"] {
        let (code, _, err) = run(&[
            "-q",
            cmd,
            &paths[0],
            &link.to_string_lossy(),
            &paths[1],
            "--map",
            &format!("{}={}", link.display(), a.display()),
        ]);
        assert_eq!(code, 0, "{cmd}: {err}");
        assert!(!err.contains("not among"), "{cmd}: {err}");
    }
}

/// A map shorter than its image says nothing of the rest, which is not
/// trusted as read: 1 MiB of map for a whole member said "0 bytes never
/// read", and every byte past it was taken as the imager's.
#[test]
fn what_a_map_does_not_describe_is_not_trusted() {
    let dir = scratch("short-map");
    let paths = write_members(&dir, &plain_members());
    let map = dir.join("m0.map");
    std::fs::write(&map, "0x0 +\n0x0 0x100000 +\n").unwrap();
    let (_, _, err) = run(&[
        "-q",
        "list",
        &paths[0],
        "--map",
        &format!("{}={}", paths[0], map.display()),
    ]);
    let rest = SIZE - 0x10_0000;
    assert!(
        err.contains(&format!(
            "the imager's map says nothing of {rest} byte(s), between its lines or past its end"
        )),
        "{err}"
    );
}

/// A map that describes more than its image holds is counted as far as
/// the image goes, and said not to fit: its ranges past the end were
/// "never read" of an image that has none of them — 268 MB of a 16 MB
/// one — and an image cut short of bytes its own map calls read went
/// without a word. The record has the bytes past the end.
#[test]
fn a_map_longer_than_its_image_is_said_not_to_fit() {
    let dir = scratch("long-map");
    let paths = write_members(&dir, &plain_members());
    let map = dir.join("m0.map");
    std::fs::write(
        &map,
        format!("0x0 +\n0x0 {SIZE:#x} +\n{SIZE:#x} 0x10000000 -\n"),
    )
    .unwrap();
    let mapped = format!("{}={}", paths[0], map.display());
    let (code, out, err) = run(&["-q", "list", &paths[0], &paths[1], "--map", &mapped]);
    assert_eq!(code, 0, "{out}\n{err}");
    assert!(
        err.contains("the imager's map says every byte was read")
            && !err.contains("never read")
            && err.contains(&format!(
                "the imager's map: it describes {} byte(s) and the image holds {SIZE}: 268435456 byte(s) of the map are past the image's end — the map of a larger disk, or an image cut short",
                SIZE + 0x1000_0000
            )),
        "{err}"
    );

    // The same member cut to half, under the map of the whole of it.
    let cut = dir.join("cut.img");
    std::fs::write(
        &cut,
        &std::fs::read(&paths[0]).unwrap()[..SIZE as usize / 2],
    )
    .unwrap();
    std::fs::write(&map, format!("0x0 +\n0x0 {SIZE:#x} +\n")).unwrap();
    let cut = cut.to_string_lossy().into_owned();
    let mapped = format!("{cut}={}", map.display());
    let (_, out, err) = run(&["scan", &cut, "--map", &mapped]);
    assert!(
        out.contains(&format!(
            "{} of them marked as read, which this image does not hold",
            SIZE / 2
        )),
        "{out}\n{err}"
    );
    let (_, out, _) = run(&["-f", "json", "scan", &cut, "--map", &mapped]);
    let v = json(&out);
    let m = &v["devices"][0]["map"];
    assert_eq!(m["beyond_image"], SIZE / 2, "{v}");
    assert_eq!(m["beyond_image_read"], SIZE / 2, "{v}");
    assert_eq!(m["by_status"]["+"], SIZE / 2, "{v}");
    // A map of the image's own size says nothing of the kind.
    let (_, out, _) = run(&[
        "-f",
        "json",
        "scan",
        &paths[1],
        "--map",
        &format!("{}={}", paths[1], map.display()),
    ]);
    assert!(
        json(&out)["devices"][0]["map"]
            .get("beyond_image")
            .is_none(),
        "{out}"
    );
}

/// A run read through `--hints` says so on its record: the hints file is
/// one of its inputs, and the layout read through — every vdev with its
/// members by name, in the order read — is there (SPEC F-65), as no
/// argument can say which order `--search-order` settled on.
#[test]
fn the_layout_a_run_read_through_is_on_its_record() {
    let dir = scratch("hints-record");
    let paths = write_members(&dir, &plain_members());
    let hints = dir.join("layout.hints");
    std::fs::write(
        &hints,
        serde_json::json!({"name": "tank", "ashift": 12,
            "tops": [{"kind": "mirror", "members": [&paths[0], &paths[1]]}]})
        .to_string(),
    )
    .unwrap();
    let hints = hints.to_string_lossy().into_owned();
    let log = dir.join("case.jsonl");
    let (code, _, err) = run(&[
        "-q",
        "--evidence-log",
        &log.to_string_lossy(),
        "list",
        &paths[0],
        &paths[1],
        "--hints",
        &hints,
    ]);
    assert_eq!(code, 0, "{err}");
    let text = std::fs::read_to_string(&log).unwrap();
    let rec: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
    let inputs: Vec<&str> = rec["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["path"].as_str().unwrap())
        .collect();
    assert!(inputs.contains(&hints.as_str()), "{inputs:?}");
    let layout = &rec["layout"];
    assert_eq!(layout["hints"], hints.as_str(), "{rec}");
    assert_eq!(layout["search_order"], false);
    assert_eq!(layout["tops"][0]["kind"], "mirror");
    assert_eq!(
        layout["tops"][0]["members"],
        serde_json::json!([&paths[0], &paths[1]])
    );

    // A run that ends before it reads anything still names the hints
    // among what it was given to read.
    let missing = dir.join("absent.img").to_string_lossy().into_owned();
    let (code, _, _) = run(&[
        "-q",
        "--evidence-log",
        &log.to_string_lossy(),
        "list",
        &missing,
        "--hints",
        &hints,
    ]);
    assert_ne!(code, 0);
    let text = std::fs::read_to_string(&log).unwrap();
    let rec: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
    let inputs: Vec<&str> = rec["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["path"].as_str().unwrap())
        .collect();
    assert!(inputs.contains(&hints.as_str()), "{rec}");

    // Read through the labels, a run has no layout to record.
    let (code, _, err) = run(&[
        "-q",
        "--evidence-log",
        &log.to_string_lossy(),
        "list",
        &paths[0],
        &paths[1],
    ]);
    assert_eq!(code, 0, "{err}");
    let text = std::fs::read_to_string(&log).unwrap();
    let rec: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
    assert!(rec.get("layout").is_none(), "{rec}");
}

/// `--search-order` settles on a member order no argument names: the
/// record keeps the one the run read through, and that order, written
/// back as hints without the search, reads the pool again. The order
/// the hints gave does not.
#[test]
fn the_order_a_search_settled_on_is_on_the_record() {
    let dir = scratch("search-order-record");
    let mut pool = Pool::raidz("tank", 0x1000, 12, 4, 2).txgs(&[(100, 1), (200, 2)]);
    let (members, _, _) = destroyed_zvol_members(&mut pool, SIZE);
    let paths = write_members(&dir, &members);
    let hints_for = |order: &serde_json::Value| {
        let h = dir.join("layout.hints");
        std::fs::write(
            &h,
            serde_json::json!({"name": "tank", "ashift": 12,
                "tops": [{"kind": "raidz", "nparity": 2, "members": order}]})
            .to_string(),
        )
        .unwrap();
        h.to_string_lossy().into_owned()
    };
    let given = serde_json::json!([&paths[3], &paths[1], &paths[0], &paths[2]]);
    let hints = hints_for(&given);
    let log = dir.join("case.jsonl").to_string_lossy().into_owned();
    let list = |hints: &str, extra: &[&str]| {
        let mut args = vec!["-q", "-f", "json", "--evidence-log", &log, "list", "-r"];
        args.extend(paths.iter().map(String::as_str));
        args.extend(["--hints", hints]);
        args.extend_from_slice(extra);
        run(&args)
    };
    let (code, searched, err) = list(&hints, &["--search-order"]);
    assert_eq!(code, 0, "{err}");
    let text = std::fs::read_to_string(&log).unwrap();
    let rec: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
    let layout = &rec["layout"];
    assert_eq!(layout["search_order"], true, "{rec}");
    let found = layout["tops"][0]["members"].clone();
    assert_eq!(found.as_array().map(Vec::len), Some(4), "{layout}");
    assert_ne!(found, given, "the order the hints gave read nothing");
    assert_eq!(layout["tops"][0]["nparity"], 2);

    // The recorded order alone reads what the search read.
    let (code, again, err) = list(&hints_for(&found), &[]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(json(&again)["datasets"], json(&searched)["datasets"]);
    let (code, _, _) = list(&hints_for(&given), &[]);
    assert_ne!(code, 0, "the order as given reads the pool");
}

/// A member that begins 100 MiB into its image, past where a search for
/// its start looks, is read from where the hints say it begins: its
/// labels and uberblocks too, not only its blocks. The labels were read
/// where the search had left it, none found, and the pool had no
/// transaction group to be read at (exit 3).
#[cfg(unix)]
#[test]
fn a_member_the_hints_place_is_read_from_there() {
    use std::os::unix::fs::FileExt;
    let dir = scratch("hints-far");
    let members = plain_members();
    let far = dir.join("far.img");
    let at = 100u64 << 20;
    let f = std::fs::File::create(&far).unwrap();
    f.write_all_at(&members[0], at).unwrap();
    drop(f);
    let far = far.to_string_lossy().into_owned();
    let hints = dir.join("far.hints");
    std::fs::write(
        &hints,
        serde_json::json!({"ashift": 12, "name": "tank",
            "tops": [{"kind": "mirror", "members": [{"path": &far, "base": at}, null]}]})
        .to_string(),
    )
    .unwrap();
    let (code, out, err) = run(&[
        "-q",
        "-f",
        "json",
        "list",
        &far,
        "--hints",
        &hints.to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{err}");
    let listed = json(&out);
    let names: Vec<&str> = listed["datasets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"tank/vm/disk0"), "{names:?}");
}

/// A pipe given as a member is refused at once: opening one to read waits
/// for a writer, and the run waited for ever, deaf to the first signal.
#[cfg(unix)]
#[test]
fn a_pipe_is_no_member() {
    let dir = scratch("fifo-member");
    let fifo = dir.join("member.fifo");
    assert!(Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    let mut child = Command::new(env!("CARGO_BIN_EXE_zvolrescue"))
        .args(["-q", "list", fifo.to_str().unwrap()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("run zvolrescue");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if std::time::Instant::now() > deadline {
            child.kill().ok();
            panic!("still waiting on the pipe after 30 seconds");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let mut err = String::new();
    std::io::Read::read_to_string(child.stderr.as_mut().unwrap(), &mut err).ok();
    assert_eq!(status.code(), Some(2), "{err}");
    assert!(
        err.contains("a pipe or a socket, not a device or an image"),
        "{err}"
    );
}

/// An image is written at offsets with its holes left out, which a pipe
/// cannot take: `-o /dev/stdout` into a pipe is a usage error up front,
/// where it failed on the first seek as exit 3, "unrecoverable". Where
/// `/dev/stdout` is a device of its own (FreeBSD, macOS) rather than a
/// link to the pipe, the pipe is found behind it all the same.
#[cfg(unix)]
#[test]
fn an_image_is_not_written_into_a_pipe() {
    let dir = scratch("pipe");
    let paths = write_members(&dir, &plain_members());
    let (code, _, err) = run(&[
        "-q",
        "dump",
        "tank/vm/disk0",
        &paths[0],
        &paths[1],
        "-o",
        "/dev/stdout",
    ]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("a pipe cannot take an image"), "{err}");
}

/// A layout of one plain disk can be described by hand: `"kind":
/// "disk"` is the leaf itself, as a label describes a single-disk top.
/// It was wrapped in a "disk" node of its own, a vdev type the reader
/// did not know (exit 3), and a disk of two members was taken.
#[test]
fn a_hand_written_layout_of_one_disk_reads() {
    let dir = scratch("hints-disk");
    let paths = write_members(&dir, &plain_members());
    let hints = dir.join("disk.hints");
    for (members, want) in [(vec![&paths[0]], 0), (vec![&paths[0], &paths[1]], 1)] {
        std::fs::write(
            &hints,
            serde_json::json!({"name": "tank", "ashift": 12,
                "tops": [{"kind": "disk", "members": members}]})
            .to_string(),
        )
        .unwrap();
        let mut args = vec!["-q", "-f", "json", "list", "--hints"];
        let h = hints.to_string_lossy().into_owned();
        args.push(&h);
        args.extend(members.iter().map(|m| m.as_str()));
        let (code, out, err) = run(&args);
        assert_eq!(code, want, "{err}");
        if want == 0 {
            let names: Vec<String> = json(&out)["datasets"]
                .as_array()
                .unwrap()
                .iter()
                .map(|d| d["name"].as_str().unwrap().to_string())
                .collect();
            assert!(names.contains(&"tank/vm/disk0".to_string()), "{names:?}");
        }
    }
}

/// `dump` writes nothing over anything the run reads: not an image of
/// `-r` named like a member beside it (one called `tank_vm_disk0.img`
/// was truncated to the volume), not a mapfile or a key file given as
/// `-o`, and not the evidence log, which does not exist until the run
/// ends and then was appended to the image.
#[test]
fn dump_never_writes_over_what_it_reads() {
    let dir = scratch("dump-over-inputs");
    let paths = write_members(&dir, &plain_members());
    let named = dir.join("tank_vm_disk0.img");
    std::fs::rename(&paths[0], &named).unwrap();
    let named = named.to_string_lossy().into_owned();
    let before = std::fs::read(&named).unwrap();
    let d = dir.to_string_lossy().into_owned();
    let (code, _, err) = run(&["-q", "dump", "-r", "tank", &named, &paths[1], "-o", &d]);
    assert_eq!(code, 5, "{err}");
    assert!(err.contains("same file as input"), "{err}");
    assert_eq!(
        std::fs::read(&named).unwrap(),
        before,
        "-r wrote the member"
    );

    let map = dir.join("m0.map").to_string_lossy().into_owned();
    std::fs::write(&map, "0x0 +\n").unwrap();
    let key = dir.join("raw.key").to_string_lossy().into_owned();
    std::fs::write(&key, [7u8; 32]).unwrap();
    for (extra, out) in [
        (
            vec!["--map".to_string(), format!("{named}={map}")],
            map.clone(),
        ),
        (vec!["--key".to_string(), format!("raw:{key}")], key.clone()),
    ] {
        let mut args = vec!["-q", "dump", "tank/vm/disk0", &named, &paths[1], "-o", &out];
        args.extend(extra.iter().map(String::as_str));
        let (code, _, err) = run(&args);
        assert_eq!(code, 5, "{out}: {err}");
    }
    assert_eq!(std::fs::read_to_string(&map).unwrap(), "0x0 +\n");
    assert_eq!(std::fs::read(&key).unwrap(), [7u8; 32]);
    // A log given as the image itself is said to be the image: it was
    // "output out.img is the same file as input out.img".
    let (code, _, err) = run(&[
        "--evidence-log",
        &map,
        "-q",
        "dump",
        "tank/vm/disk0",
        &named,
        &paths[1],
        "-o",
        &map,
    ]);
    assert_eq!(code, 5, "{err}");
    assert!(
        err.contains(&format!("it is {map}, which this run reads or writes")),
        "{err}"
    );
    assert!(!err.contains("as input"), "{err}");

    // The name the resume state is written under before its rename is
    // a file the run writes: a link there to the mapfile is refused.
    let img = dir.join("tmp.img").to_string_lossy().into_owned();
    let tmp = format!("{img}.resume.json.tmp");
    std::fs::hard_link(&map, &tmp).unwrap();
    let mapped = format!("{named}={map}");
    let (code, _, err) = run(&[
        "-q",
        "dump",
        "tank/vm/disk0",
        &named,
        &paths[1],
        "--map",
        &mapped,
        "-o",
        &img,
    ]);
    assert_eq!(code, 5, "{err}");
    assert!(err.contains(".resume.json.tmp"), "{err}");
    assert_eq!(std::fs::read_to_string(&map).unwrap(), "0x0 +\n");
    std::fs::remove_file(&tmp).unwrap();

    let both = dir.join("both.img").to_string_lossy().into_owned();
    let (code, _, err) = run(&[
        "--evidence-log",
        &both,
        "-q",
        "dump",
        "tank/vm/disk0",
        &named,
        &paths[1],
        "-o",
        &both,
    ]);
    assert_eq!(code, 5, "{err}");
    assert!(err.contains("refusing --evidence-log"), "{err}");
    // Refused before either is made: the log of the refused run was
    // left in the file asked for the image.
    assert!(!dir.join("both.img").exists(), "the log was made");
}

/// Neither log may be written over a member: `--debug-log` truncated
/// it before the run began, `--evidence-log` appended JSON to it and
/// exited 0. Both are refused now, with the member untouched, and a log
/// beside the members is still fine.
#[test]
fn a_log_is_never_written_over_a_member() {
    let dir = scratch("log-over-member");
    let paths = write_members(&dir, &plain_members());
    let before = std::fs::read(&paths[0]).unwrap();
    for flag in ["--debug-log", "--evidence-log"] {
        let (code, _, err) = run(&[flag, &paths[0], "-q", "scan", &paths[0], &paths[1]]);
        assert_eq!(code, 5, "{flag}: {err}");
        assert!(err.contains(&format!("refusing {flag}")), "{flag}: {err}");
        assert_eq!(
            std::fs::read(&paths[0]).unwrap(),
            before,
            "{flag} wrote the member"
        );
    }
    let both = dir.join("both.log").to_string_lossy().into_owned();
    let (code, _, err) = run(&[
        "--debug-log",
        &both,
        "--evidence-log",
        &both,
        "-q",
        "scan",
        &paths[0],
    ]);
    assert_eq!(code, 5, "{err}");
    // A mapfile named as `--map=MEMBER=MAPFILE`, in one word, is still a
    // file the run reads.
    let map = dir.join("m0.map").to_string_lossy().into_owned();
    std::fs::write(&map, "0x0 +\n").unwrap();
    let (code, _, err) = run(&[
        "--debug-log",
        &map,
        "-q",
        "scan",
        &paths[0],
        &format!("--map={}={map}", paths[0]),
    ]);
    assert_eq!(code, 5, "{err}");
    assert_eq!(std::fs::read_to_string(&map).unwrap(), "0x0 +\n");
    let log = dir.join("case.jsonl").to_string_lossy().into_owned();
    let (code, _, err) = run(&["--evidence-log", &log, "-q", "scan", &paths[0], &paths[1]]);
    assert_eq!(code, 0, "{err}");
    assert!(std::fs::metadata(&log).unwrap().len() > 0);
    // The resume state is read by `--resume` and named by no word of the
    // command line: a debug log there was created over it, and only then
    // did the run refuse.
    let img = dir.join("o.img").to_string_lossy().into_owned();
    let state = format!("{img}.resume.json");
    std::fs::write(&state, "{\"version\":1}").unwrap();
    let (code, _, err) = run(&[
        "--debug-log",
        &state,
        "-q",
        "dump",
        "tank/vm/disk0",
        &paths[0],
        &paths[1],
        "-o",
        &img,
        "--resume",
    ]);
    assert_eq!(code, 5, "{err}");
    assert_eq!(std::fs::read_to_string(&state).unwrap(), "{\"version\":1}");
}

/// `--emit-label` writes a label and its geometry for a *copy* of a
/// member; neither may land on a member or on the layout it was made
/// from. The geometry is `FILE.json`, whatever FILE is called: with the
/// extension replaced, it went over a `*.json` beside the label.
#[test]
fn emit_label_is_never_written_over_the_evidence() {
    let dir = scratch("emit-label");
    let paths = write_members(&dir, &plain_members());
    // Not `*.json`, so that what refuses it is the evidence check.
    let hints = dir.join("layout.hints");
    std::fs::write(
        &hints,
        serde_json::json!({"name": "tank", "ashift": 12,
            "tops": [{"kind": "mirror", "members": [&paths[0], &paths[1]]}]})
        .to_string(),
    )
    .unwrap();
    let hints = hints.to_string_lossy().into_owned();
    let map = dir.join("m0.map").to_string_lossy().into_owned();
    std::fs::write(&map, "0x0 +\n").unwrap();
    let before = std::fs::read(&paths[0]).unwrap();
    for target in [paths[0].clone(), hints.clone(), map.clone()] {
        let (code, _, err) = run(&[
            "-q",
            "scan",
            &paths[0],
            &paths[1],
            "--hints",
            &hints,
            "--map",
            &format!("{}={map}", paths[0]),
            "--emit-label",
            &target,
        ]);
        assert_eq!(code, 5, "{target}: {err}");
        assert!(err.contains("refusing --emit-label"), "{err}");
    }
    assert_eq!(std::fs::read(&paths[0]).unwrap(), before);
    assert_eq!(std::fs::read_to_string(&map).unwrap(), "0x0 +\n");
    let json_name = dir.join("label.json").to_string_lossy().into_owned();
    let (code, _, err) = run(&[
        "-q",
        "scan",
        &paths[0],
        &paths[1],
        "--hints",
        &hints,
        "--emit-label",
        &json_name,
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(dir.join("label.json.json").exists());
    std::fs::write(dir.join("L0.json"), "not the label's").unwrap();
    let label = dir.join("L0.bin").to_string_lossy().into_owned();
    let (code, _, err) = run(&[
        "-q",
        "scan",
        &paths[0],
        &paths[1],
        "--hints",
        &hints,
        "--emit-label",
        &label,
    ]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        std::fs::metadata(dir.join("L0.bin")).unwrap().len(),
        128 << 10
    );
    assert!(dir.join("L0.bin.json").exists());
    assert_eq!(
        std::fs::read_to_string(dir.join("L0.json")).unwrap(),
        "not the label's"
    );
}

/// A label emitted for a member the hints place 1 MiB into its image is
/// sealed for the vdev — the bytes from that base on — and not for the
/// whole image: sealed for the image, a rear label verified at neither
/// end.
#[test]
fn an_emitted_label_is_sealed_for_the_vdev_the_hints_place() {
    let dir = scratch("emit-label-base");
    let base = 1u64 << 20;
    let paths: Vec<String> = plain_members()
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let p = dir.join(format!("disk{i}.img"));
            let mut img = vec![0u8; base as usize];
            img.extend_from_slice(m);
            std::fs::write(&p, img).unwrap();
            p.to_string_lossy().into_owned()
        })
        .collect();
    let hints = dir.join("layout.hints");
    std::fs::write(
        &hints,
        serde_json::json!({"name": "tank", "ashift": 12, "tops": [{"kind": "mirror", "members": [
            {"path": &paths[0], "base": base}, {"path": &paths[1], "base": base}]}]})
        .to_string(),
    )
    .unwrap();
    let label = dir.join("L2.bin").to_string_lossy().into_owned();
    let (code, _, err) = run(&[
        "-q",
        "scan",
        &paths[0],
        &paths[1],
        "--hints",
        &hints.to_string_lossy(),
        "--emit-label",
        &label,
        "--emit-label-index",
        "2",
    ]);
    assert_eq!(code, 0, "{err}");
    let geometry: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("L2.bin.json")).unwrap()).unwrap();
    assert_eq!(geometry["sealed_for_vdev_size"], SIZE, "{geometry}");
}

/// The labels `--emit-label` makes for a pool of two vdevs are of two
/// vdevs. Each said it was of vdev #0: placed on copies, the pool the
/// layout had read whole was "top-level vdev #1: no scanned member
/// describes it — MISSING", the members of the second mirror were set
/// aside as superseded, and the volume did not read.
#[test]
fn emitted_labels_of_a_pool_of_two_vdevs_read_as_that_pool() {
    let dir = scratch("emit-label-tops");
    let want = reference_sha(&dir);
    let (_, mut members) = two_top_mirror_members("tank", 0x7070, 12, [2, 3], &[(100, 1)], SIZE);
    members.iter_mut().for_each(|m| wipe_configs(m));
    let paths = write_members(&dir, &members);
    let all: Vec<&str> = paths.iter().map(String::as_str).collect();
    let hints = dir.join("layout.hints");
    std::fs::write(
        &hints,
        serde_json::json!({"name": "tank", "ashift": 12, "tops": [
            {"kind": "mirror", "members": [&paths[0], &paths[1]]},
            {"kind": "mirror", "members": [&paths[2], &paths[3], &paths[4]]}]})
        .to_string(),
    )
    .unwrap();
    let hints = hints.to_string_lossy().into_owned();

    let mut copies = Vec::new();
    for (i, (top, leaf)) in [(0, 0), (0, 1), (1, 0), (1, 1), (1, 2)]
        .into_iter()
        .enumerate()
    {
        let label = dir
            .join(format!("L-{i}.bin"))
            .to_string_lossy()
            .into_owned();
        let mut args = vec!["-q", "scan"];
        args.extend(&all);
        let which = format!("{top}:{leaf}");
        args.extend([
            "--hints",
            &hints,
            "--emit-label",
            &label,
            "--emit-for",
            &which,
        ]);
        let (code, _, err) = run(&args);
        assert_eq!(code, 0, "{which}: {err}");
        let mut img = members[i].clone();
        let front = std::fs::read(&label).unwrap();
        img[..front.len()].copy_from_slice(&front);
        let copy = dir.join(format!("relabel{i}.img"));
        std::fs::write(&copy, img).unwrap();
        copies.push(copy.to_string_lossy().into_owned());
    }
    let copies: Vec<&str> = copies.iter().map(String::as_str).collect();

    let mut args = vec!["-q", "-f", "json", "scan"];
    args.extend(&copies);
    let (code, out, _) = run(&args);
    assert_eq!(code, 0, "{out}");
    let pool = &json(&out)["pools"][0];
    assert_eq!(pool["readable"], true, "{pool}");
    assert_eq!(pool["missing_tops"], serde_json::json!([]), "{pool}");
    let tops = pool["tops"].as_array().unwrap();
    assert_eq!(
        tops.iter()
            .map(|t| (
                t["id"].as_u64().unwrap(),
                t["members"].as_array().unwrap().len()
            ))
            .collect::<Vec<_>>(),
        vec![(0, 2), (1, 3)],
        "{pool}"
    );
    assert_eq!(pool["stale"], serde_json::json!([]), "{pool}");

    let image = dir.join("from-labels.img").to_string_lossy().into_owned();
    let mut args = vec!["-q", "-f", "json", "dump", "tank/vm/disk0"];
    args.extend(&copies);
    args.extend(["-o", &image]);
    let (code, out, err) = run(&args);
    assert_eq!(code, 0, "{out}{err}");
    assert_eq!(json(&out)["volumes"][0]["sha256"], want);
}

/// A pool whose top-level vdevs differ in `ashift` — raidz of 512-byte
/// disks, grown with one of 4Kn — is described with each vdev's own.
/// The hints had one `ashift` for the pool: with the labels gone no
/// value read it, the blocks of one vdev or the other failing their
/// checksums, and an `ashift` written inside a vdev was ignored without
/// a word. The scan's own template carries it, so the scan of a healthy
/// pool, kept, describes that pool.
#[test]
fn hints_give_each_top_level_vdev_its_own_ashift() {
    let dir = scratch("hints-ashift");
    let want = reference_sha(&dir);
    let mut members = two_top_raidz_members("tank", 0x7171, [9, 12], &[(100, 1)], SIZE);
    let labelled = write_members(&dir, &members);

    // With its labels the pool reads, and the scan says each vdev's.
    let mut args = vec!["-q", "-f", "json", "scan"];
    args.extend(labelled.iter().map(String::as_str));
    let (code, out, _) = run(&args);
    assert_eq!(code, 0, "{out}");
    let tops = json(&out)["pools"][0]["tops"].clone();
    assert_eq!(tops[0]["tree"]["ashift"], 9, "{tops}");
    assert_eq!(tops[1]["tree"]["ashift"], 12, "{tops}");

    members.iter_mut().for_each(|m| wipe_configs(m));
    let bare = scratch("hints-ashift-bare");
    let paths = write_members(&bare, &members);
    let all: Vec<&str> = paths.iter().map(String::as_str).collect();
    let dump = |hints: serde_json::Value, name: &str| {
        let file = bare.join(format!("{name}.hints"));
        std::fs::write(&file, hints.to_string()).unwrap();
        let image = bare
            .join(format!("{name}.img"))
            .to_string_lossy()
            .into_owned();
        let file = file.to_string_lossy().into_owned();
        let mut args = vec!["-q", "-f", "json", "dump", "tank/vm/disk0"];
        args.extend(&all);
        args.extend(["--hints", &file, "-o", &image]);
        run(&args)
    };
    let tops = |first: serde_json::Value, second: serde_json::Value| {
        let mut tops = vec![
            serde_json::json!({"kind": "raidz", "nparity": 1, "members": &paths[..3]}),
            serde_json::json!({"kind": "raidz", "nparity": 1, "members": &paths[3..]}),
        ];
        for (t, own) in tops.iter_mut().zip([first, second]) {
            if !own.is_null() {
                t["ashift"] = own;
            }
        }
        tops
    };
    let none = serde_json::Value::Null;

    // One value for the pool reads the vdev that has it, and the blocks
    // of the other fail their checksums.
    for ashift in [9, 12] {
        let (code, out, err) = dump(
            serde_json::json!({"name": "tank", "ashift": ashift, "tops": tops(none.clone(), none.clone())}),
            &format!("one-{ashift}"),
        );
        assert_ne!(code, 0, "ashift {ashift} for both: {out}{err}");
    }
    // The pool's and one vdev's own; each vdev's own and none for the
    // pool; the scan's template as it was printed.
    let scanned: Vec<serde_json::Value> = tops_from_scan(&out, &labelled, &paths);
    for (name, hints) in [
        (
            "own-one",
            serde_json::json!({"name": "tank", "ashift": 9, "tops": tops(none.clone(), 12.into())}),
        ),
        (
            "own-each",
            serde_json::json!({"name": "tank", "tops": tops(9.into(), 12.into())}),
        ),
        (
            "scanned",
            serde_json::json!({"name": "tank", "ashift": 9, "tops": scanned}),
        ),
    ] {
        let (code, out, err) = dump(hints, name);
        assert_eq!(code, 0, "{name}: {out}{err}");
        assert_eq!(json(&out)["volumes"][0]["sha256"], want, "{name}");
    }

    // No ashift for a vdev and none for the pool is refused, and so is
    // one written where nothing reads it, or one no vdev has.
    let mut nested = tops(none.clone(), none.clone());
    nested[1] = serde_json::json!({"kind": "mirror", "children": [
        {"kind": "raidz", "nparity": 1, "ashift": 12, "members": &paths[3..]}]});
    for (name, hints, said) in [
        (
            "absent",
            serde_json::json!({"name": "tank", "tops": tops(none.clone(), 12.into())}),
            "ashift is required",
        ),
        (
            "nested",
            serde_json::json!({"name": "tank", "ashift": 9, "tops": nested}),
            "tops[1].children[0].ashift",
        ),
        (
            "wild",
            serde_json::json!({"name": "tank", "ashift": 9, "tops": tops(none.clone(), 40.into())}),
            "tops[1].ashift 40",
        ),
    ] {
        let (code, _, err) = dump(hints, name);
        assert_eq!(code, 1, "{name}: {err}");
        assert!(err.contains(said), "{name}: {err}");
    }
}

/// The label `--emit-label` writes is the pool's own, where the pool
/// says what it is. Made from the layout alone it named a pool
/// "recovered", GUID 0, in the run that had just shown the pool's own
/// name and GUID from its MOS; and given those, it was still a label
/// OpenZFS takes none of: no `features_for_read`, and vdev GUIDs made
/// up here. The pool's configuration is in its MOS, and a label is
/// that configuration seen from one member: with every label wiped,
/// emitted for every member and position and placed, the copies are
/// the disks as they were, byte for byte.
#[test]
fn an_emitted_label_is_the_one_the_pool_wrote() {
    let dir = scratch("emit-label-own");
    let (_, originals) = configured_two_top_members("tank", 0x7070, 12, [2, 3], &[(100, 1)], SIZE);
    let mut wiped = originals.clone();
    wiped.iter_mut().for_each(|m| wipe_configs(m));
    let paths = write_members(&dir, &wiped);
    let all: Vec<&str> = paths.iter().map(String::as_str).collect();
    // Neither the pool's name nor its GUID: the pool has both.
    let hints = dir.join("layout.hints");
    std::fs::write(
        &hints,
        serde_json::json!({"ashift": 12, "tops": [
            {"kind": "mirror", "members": [&paths[0], &paths[1]]},
            {"kind": "mirror", "members": [&paths[2], &paths[3], &paths[4]]}]})
        .to_string(),
    )
    .unwrap();
    let hints = hints.to_string_lossy().into_owned();
    let label = dir.join("L.bin").to_string_lossy().into_owned();
    let emit = |hints: &str, which: &str, index: usize| {
        let mut args = vec!["scan"];
        args.extend(&all);
        let index = index.to_string();
        args.extend(["--hints", hints, "--emit-label", &label]);
        args.extend(["--emit-for", which, "--emit-label-index", &index]);
        let (code, _, err) = run(&args);
        assert_eq!(code, 0, "{which} L{index}: {err}");
        let geometry: serde_json::Value =
            serde_json::from_slice(&std::fs::read(format!("{label}.json")).unwrap()).unwrap();
        (std::fs::read(&label).unwrap(), geometry, err)
    };

    let size = SIZE as usize;
    let l = LABEL_SIZE as usize;
    let at = [0, l, size - 2 * l, size - l];
    for (i, which) in ["0:0", "0:1", "1:0", "1:1", "1:2"].into_iter().enumerate() {
        let mut copy = wiped[i].clone();
        for (index, offset) in at.into_iter().enumerate() {
            let (front, geometry, err) = emit(&hints, which, index);
            assert_eq!(geometry["config"], "pool", "{geometry}");
            assert_eq!(geometry["pool"], "tank", "{geometry}");
            assert_eq!(geometry["pool_guid"], "0x0000000000007070", "{geometry}");
            assert!(geometry["note"]
                .as_str()
                .unwrap()
                .contains("rests on the order in the layout alone"));
            assert!(
                err.contains("the pool's own configuration, from its MOS"),
                "{err}"
            );
            copy[offset..offset + front.len()].copy_from_slice(&front);
        }
        assert!(copy == originals[i], "member {i} is not the disk it was");
    }

    // The pool as the run names it, when the hints name it otherwise.
    let renamed = dir.join("renamed.hints");
    std::fs::write(
        &renamed,
        serde_json::json!({"name": "rescued", "ashift": 12, "tops": [
            {"kind": "mirror", "members": [&paths[0], &paths[1]]},
            {"kind": "mirror", "members": [&paths[2], &paths[3], &paths[4]]}]})
        .to_string(),
    )
    .unwrap();
    let (_, geometry, _) = emit(&renamed.to_string_lossy(), "1:0", 0);
    assert_eq!(geometry["pool"], "rescued", "{geometry}");
    assert_eq!(geometry["config"], "pool", "{geometry}");

    // A layout that is not the shape the pool has cannot be labelled
    // from the pool: the label is a template, said to be one and why.
    let flat = dir.join("flat.hints");
    std::fs::write(
        &flat,
        serde_json::json!({"ashift": 12, "tops": [
            {"kind": "mirror", "members": [&paths[0], &paths[1]]},
            {"kind": "mirror", "members": [&paths[2], &paths[3]]}]})
        .to_string(),
    )
    .unwrap();
    let (_, geometry, err) = emit(&flat.to_string_lossy(), "1:0", 0);
    assert_eq!(geometry["config"], "template", "{geometry}");
    assert_eq!(geometry["pool"], "tank", "{geometry}");
    let why = "top-level vdev #1 has 3 member(s) in the pool's configuration and 2 in the layout";
    assert!(
        geometry["note"].as_str().unwrap().contains(why),
        "{geometry}"
    );
    assert!(err.contains("a template with made-up vdev GUIDs"), "{err}");
    assert!(err.contains(why), "{err}");
    assert!(geometry.get("features_for_read").is_none(), "{geometry}");
}

/// A hints file is read strictly. A key nothing reads was passed over
/// without a word — `nparty` for `nparity` read a raidz2 as the raidz1
/// a raidz is by default — and is refused, in the layout, in a vdev
/// and in a member, `comment` standing for a note in any of them. A
/// GUID that is not the pool's was taken and recorded as the pool
/// read: the pool's own configuration, read through the layout, says
/// whose it is. And a member is the file, not its spelling: named one
/// way on the command line and another in the hints, it was "not among
/// the members given".
#[test]
fn hints_are_read_strictly() {
    let dir = scratch("hints-strict");
    let (_, mut members) =
        configured_two_top_members("tank", 0x7070, 12, [2, 3], &[(100, 1)], SIZE);
    members.iter_mut().for_each(|m| wipe_configs(m));
    let paths = write_members(&dir, &members);
    let all: Vec<&str> = paths.iter().map(String::as_str).collect();
    let layout = || {
        serde_json::json!({"ashift": 12, "tops": [
            {"kind": "mirror", "members": [&paths[0], &paths[1]]},
            {"kind": "mirror", "members": [&paths[2], &paths[3], &paths[4]]}]})
    };
    let with = |command: &str, members: &[&str], hints: &serde_json::Value| {
        let file = dir.join("layout.hints");
        std::fs::write(&file, hints.to_string()).unwrap();
        let file = file.to_string_lossy().into_owned();
        let mut args = vec!["-q", "-f", "json", command];
        args.extend(members);
        args.extend(["--hints", &file]);
        run(&args)
    };

    // As written it reads, and the pool is named by its own word: its
    // configuration in the MOS, no label being left to say.
    let (code, out, err) = with("list", &all, &layout());
    assert_eq!(code, 0, "{err}");
    assert_eq!(json(&out)["pool"], "tank", "{out}");
    assert_eq!(json(&out)["pool_guid"], "0x0000000000007070", "{out}");

    // A key nothing reads, wherever it is written.
    let mut misspelt = layout();
    misspelt["ashfit"] = 9.into();
    let mut parity = layout();
    parity["tops"][0]["nparty"] = 1.into();
    let mut member = layout();
    member["tops"][1]["members"][0] = serde_json::json!({"path": &paths[2], "offset": 0});
    for (hints, said) in [
        (&misspelt, "\"ashfit\" is not a key of the layout"),
        (&parity, "tops[0]: \"nparty\" is not a key of a vdev"),
        (
            &member,
            "tops[1].members[0]: \"offset\" is not a key of a member",
        ),
    ] {
        for command in ["list", "scan"] {
            let (code, _, err) = with(command, &all, hints);
            assert_eq!(code, 1, "{command}: {err}");
            assert!(err.contains(said), "{command}: {err}");
        }
    }
    // A note is no key to refuse.
    let mut noted = layout();
    noted["comment"] = "from the case file".into();
    noted["tops"][0]["comment"] = serde_json::json!(["zpool status of 2026-11-01"]);
    noted["tops"][1]["members"][0] =
        serde_json::json!({"path": &paths[2], "comment": "the disk that was replaced"});
    let (code, _, err) = with("list", &all, &noted);
    assert_eq!(code, 0, "{err}");

    // The pool's GUID, in either notation, or not this pool's.
    for own in [serde_json::json!("0x7070"), serde_json::json!(0x7070)] {
        let mut hints = layout();
        hints["guid"] = own;
        let (code, out, err) = with("list", &all, &hints);
        assert_eq!(code, 0, "{err}");
        assert_eq!(json(&out)["pool_guid"], "0x0000000000007070", "{out}");
    }
    let mut foreign = layout();
    foreign["guid"] = "0x10".into();
    let (code, _, err) = with("list", &all, &foreign);
    assert_eq!(code, 1, "{err}");
    assert!(
        err.contains("guid 0x0000000000000010 is not this pool's")
            && err.contains("says 0x0000000000007070"),
        "{err}"
    );

    // The same files under another spelling on the command line.
    let respelt: Vec<String> = (0..paths.len())
        .map(|i| {
            dir.join(".")
                .join(format!("member{i}.img"))
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_ne!(respelt[0], paths[0]);
    let respelt: Vec<&str> = respelt.iter().map(String::as_str).collect();
    let (code, out, err) = with("list", &respelt, &layout());
    assert_eq!(code, 0, "{err}");
    assert_eq!(json(&out)["pool"], "tank", "{out}");
    // A file that is none of them is still none of them.
    let mut absent = layout();
    absent["tops"][0]["members"][0] = dir.join("nowhere.img").to_string_lossy().into();
    let (code, _, err) = with("list", &all, &absent);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("is not among the members given"), "{err}");
}

/// The template `scan` prints for a vdev is a layout the hints take
/// when the vdev is one disk, too. A disk that is a vdev by itself —
/// the top of a stripe, a leaf beside a spare in a dRAID — was written
/// `{"kind": "disk"}`, with no member, which the hints refuse: the
/// template of such a pool, kept for the day its labels are gone,
/// described nothing.
#[test]
fn the_scanned_template_of_a_one_disk_vdev_is_a_layout() {
    let dir = scratch("hints-one-disk");
    let want = reference_sha(&dir);
    let mut pool = Pool::mirror_of("tank", 0x4242, 12, 1).txgs(&[(100, 1)]);
    pool.kind = "disk".into();
    // A disk that is a top-level vdev is one vdev: the GUID its label
    // gives the member is the vdev's own.
    pool.members[0].guid = pool.top_guid();
    let mut members = vec![vec![0u8; SIZE as usize]];
    let mut a = Alloc::new(0x20_0000);
    build_sample_mos(&mut pool, &mut members, &mut a);
    pool.write_labels(0, &mut members[0]);
    let labelled = write_members(&dir, &members);

    let (code, out, _) = run(&["-q", "-f", "json", "scan", &labelled[0]]);
    assert_eq!(code, 0, "{out}");
    let tree = &json(&out)["pools"][0]["tops"][0]["tree"];
    assert_eq!(tree["kind"], "disk", "{tree}");
    assert_eq!(tree["members"], serde_json::json!([&labelled[0]]), "{tree}");

    members.iter_mut().for_each(|m| wipe_configs(m));
    let bare = scratch("hints-one-disk-bare");
    let paths = write_members(&bare, &members);
    let hints = bare.join("layout.hints");
    std::fs::write(
        &hints,
        serde_json::json!({"name": "tank", "ashift": 12, "tops": tops_from_scan(&out, &labelled, &paths)})
            .to_string(),
    )
    .unwrap();
    let image = bare.join("out.img").to_string_lossy().into_owned();
    let (code, out, err) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &paths[0],
        "--hints",
        &hints.to_string_lossy(),
        "-o",
        &image,
    ]);
    assert_eq!(code, 0, "{out}{err}");
    assert_eq!(json(&out)["volumes"][0]["sha256"], want);
}

/// The `tree` of every top-level vdev a scan printed, as hints: the
/// members it names replaced by the same members of another set.
fn tops_from_scan(scan: &str, from: &[String], to: &[String]) -> Vec<serde_json::Value> {
    json(scan)["pools"][0]["tops"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| {
            let mut tree = t["tree"].clone();
            for m in tree["members"].as_array_mut().unwrap() {
                let at = from.iter().position(|p| Some(p.as_str()) == m.as_str());
                *m = to[at.expect("a member the scan was given")].clone().into();
            }
            tree
        })
        .collect()
}

#[test]
fn scan_tells_a_removed_vdev_from_a_missing_one() {
    let dir = scratch("scan-removed");
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
    let members = write_members(&dir, &removed_vdev_members(&mut pool, SIZE));

    let (code, out, _) = run(&["-q", "-f", "json", "scan", &members[0], &members[1]]);
    assert_eq!(code, 0);
    let pool = &json(&out)["pools"][0];
    assert_eq!(pool["readable"], true, "{pool}");
    assert_eq!(pool["removed_tops"], serde_json::json!([1]), "{pool}");
    assert_eq!(pool["missing_tops"], serde_json::json!([]), "{pool}");
    assert_eq!(pool["device_removal"], true, "{pool}");

    let (_, text, _) = run(&["-q", "scan", &members[0], &members[1]]);
    assert!(text.contains("READABLE from scanned members"), "{text}");
    assert!(
        text.contains("top-level vdev #1: removed; its blocks live on the vdevs that remain"),
        "{text}"
    );
    assert!(!text.contains("MISSING"), "{text}");
}

/// A pool checkpoint keeps the pool as it was: nothing it held then is
/// freed until the checkpoint is discarded, and the uberblock of that
/// moment is kept in the MOS, long after its transaction group has left
/// every ring. Nothing looked there. A volume destroyed after the
/// checkpoint was "not found at any of 32 verified TXG(s)" while `zdb
/// -k` showed it whole, and `list --txg` of the group was "no verified
/// uberblock matches". The checkpoint is one more group to read at:
/// listed, named for what it is, and the last place a dataset is looked
/// for.
#[test]
fn the_pool_checkpoint_is_a_txg_to_read_at() {
    let dir = scratch("checkpoint");
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(200, 2)]);
    let members = checkpointed_members(&mut pool, SIZE, (100, 1));
    let m = write_members(&dir, &members);
    let names = |doc: &serde_json::Value| -> Vec<String> {
        doc["datasets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["name"].as_str().unwrap().to_string())
            .collect()
    };

    let (code, out, err) = run(&["-q", "-f", "json", "list", &m[0], &m[1]]);
    assert_eq!(code, 0, "{err}");
    let doc = json(&out);
    assert_eq!(doc["txg"], 200, "{out}");
    assert_eq!(
        doc["available_txgs"],
        serde_json::json!([200, 100]),
        "{out}"
    );
    assert_eq!(doc["checkpoint_txg"], 100, "{out}");
    assert_eq!(doc["checkpoint_time"], "1970-01-01T00:00:01Z", "{out}");
    assert!(!names(&doc).contains(&"tank/vm/disk0".to_string()), "{out}");
    let (_, text, _) = run(&["-q", "list", &m[0], &m[1]]);
    assert!(
        text.contains("2 verified txg(s) available")
            && text.contains("pool checkpoint: txg 100 (1970-01-01T00:00:01Z)")
            && text.contains("--txg 100"),
        "{text}"
    );

    let (code, out, err) = run(&["-q", "-f", "json", "list", &m[0], &m[1], "--txg", "100"]);
    assert_eq!(code, 0, "{err}");
    let doc = json(&out);
    assert_eq!(
        (&doc["txg"], &doc["checkpoint_txg"]),
        (&100.into(), &100.into()),
        "{out}"
    );
    assert!(names(&doc).contains(&"tank/vm/disk0".to_string()), "{out}");
    let (_, text, _) = run(&["-q", "list", &m[0], &m[1], "--txg", "100"]);
    assert!(text.contains("this is the pool checkpoint"), "{text}");
    // What was destroyed since it, with the way back.
    let (code, text, err) = run(&["-q", "list", &m[0], &m[1], "--diff", "100"]);
    assert_eq!(code, 0, "{err}");
    assert!(
        text.lines().any(|l| l.contains("destroyed")
            && l.contains("tank/vm/disk0")
            && l.contains("--txg 100")),
        "{text}"
    );

    // Not named, the checkpoint is the last group the volume is looked
    // for at, and the run says where it found it.
    let image = dir.join("disk0.img");
    let (code, out, err) = run(&[
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &m[0],
        &m[1],
        "-o",
        &image.to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{err}");
    let record = json(&out);
    assert_eq!(record["checkpoint_txg"], 100, "{out}");
    assert_eq!(
        record["txgs_searched"],
        serde_json::json!([200, 100]),
        "{out}"
    );
    assert_eq!(record["volumes"][0]["txg"], 100, "{out}");
    assert_eq!(record["volumes"][0]["blocks_zeroed"], 0, "{out}");
    assert!(
        err.contains("txg 100 (1970-01-01T00:00:01Z) is the pool checkpoint (zpool checkpoint)"),
        "{err}"
    );
    let data = std::fs::read(&image).unwrap();
    assert_eq!(&data[..8192], &zvol_pattern(0)[..]);
    assert_eq!(&data[16384..24576], &zvol_pattern(2)[..]);
}

/// A pool without a checkpoint says nothing of one.
#[test]
fn a_pool_without_a_checkpoint_names_none() {
    let dir = scratch("no-checkpoint");
    let m = write_members(&dir, &plain_members());
    let (code, out, err) = run(&["-q", "-f", "json", "list", &m[0], &m[1]]);
    assert_eq!(code, 0, "{err}");
    let doc = json(&out);
    assert!(doc.get("checkpoint_txg").is_none(), "{out}");
    assert_eq!(doc["available_txgs"], serde_json::json!([100]), "{out}");
    let (_, text, _) = run(&["-q", "list", &m[0], &m[1]]);
    assert!(!text.contains("checkpoint"), "{text}");
}

/// A transaction group from before a device removal has the vdev as a
/// device in its configuration, and no mapping. Its blocks there were
/// refused as on an unknown vdev — 283 of a volume's 512, on a pool the
/// removal had left whole — and `list --txg` of it said nothing, exit 0.
/// They are read through the mapping the removal left, and the run says
/// which group it is reading.
#[test]
fn a_txg_from_before_a_removal_reads_through_the_mapping_it_left() {
    let dir = scratch("before-removal");
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1), (200, 2)]);
    let (members, _, older, newest) = removed_since_members(&mut pool, SIZE, true);
    let m = write_members(&dir, &members);
    let older = older.to_string();

    let (code, out, err) = run(&["-f", "json", "list", &m[0], &m[1], "--txg", &older]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(json(&out)["removed_since"], serde_json::json!([1]), "{out}");
    assert!(
        err.contains("is from before top-level vdev #1 was removed from the pool")
            && err.contains("is not among the members"),
        "{err}"
    );
    // Not said where it is not so, nor under -q.
    let (code, out, err) = run(&["-f", "json", "list", &m[0], &m[1]]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(json(&out)["txg"], newest, "{out}");
    assert!(json(&out).get("removed_since").is_none(), "{out}");
    assert!(!err.contains("is from before"), "{err}");
    let (_, _, err) = run(&["-q", "list", &m[0], &m[1], "--txg", &older]);
    assert!(!err.contains("is from before"), "{err}");

    let image = dir.join("disk0.img");
    let (code, out, err) = run(&[
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &m[0],
        &m[1],
        "--txg",
        &older,
        "-o",
        &image.to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{err}");
    let record = json(&out);
    assert_eq!(record["removed_since"], serde_json::json!([1]), "{out}");
    assert_eq!(record["volumes"][0]["blocks_zeroed"], 0, "{out}");
    assert!(err.contains("is from before top-level vdev #1"), "{err}");
    let data = std::fs::read(&image).unwrap();
    assert_eq!(&data[..8192], &zvol_pattern(0)[..]);
    assert_eq!(&data[16384..24576], &zvol_pattern(2)[..]);
}

/// The mapping has what was allocated when the removal ended. A block
/// the older group points at that was freed before then is on the
/// removed device only: said to be, when that device is not given, and
/// read from it when it is — it was "NOT USED: … never part of a
/// committed configuration".
#[test]
fn what_a_removal_did_not_copy_is_read_from_the_removed_device() {
    let dir = scratch("removed-device");
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1), (200, 2)]);
    let (members, gone, older, _) = removed_since_members(&mut pool, SIZE, false);
    let mut m = write_members(&dir, &members);
    let removed = dir.join("removed.img");
    std::fs::write(&removed, gone).unwrap();
    let older = older.to_string();

    let image = dir.join("without.img");
    let (code, out, err) = run(&[
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &m[0],
        &m[1],
        "--txg",
        &older,
        "-o",
        &image.to_string_lossy(),
    ]);
    assert_eq!(code, 4, "{err}");
    let record = json(&out);
    assert_eq!(record["volumes"][0]["blocks_zeroed"], 2, "{out}");
    assert!(
        record["volumes"][0]["bad"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("not in the removed vdev's mapping"),
        "{out}"
    );
    assert!(err.contains("is not among the members"), "{err}");

    m.push(removed.to_string_lossy().into_owned());
    let (_, text, _) = run(&["-q", "scan", &m[0], &m[1], &m[2]]);
    assert!(
        text.contains(
            "NOT USED: label txg 0 naming indirect vdev #1: the device was removed from the pool"
        ),
        "{text}"
    );
    assert!(text.contains("READABLE from scanned members"), "{text}");
    let image = dir.join("with.img");
    let (code, out, err) = run(&[
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &m[0],
        &m[1],
        &m[2],
        "--txg",
        &older,
        "-o",
        &image.to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(json(&out)["volumes"][0]["blocks_zeroed"], 0, "{out}");
    assert!(
        err.contains("which is among the members and is read for it"),
        "{err}"
    );
    let data = std::fs::read(&image).unwrap();
    assert_eq!(&data[..8192], &zvol_pattern(0)[..]);
    assert_eq!(&data[16384..24576], &zvol_pattern(2)[..]);
    // The newest group has its own blocks, which the removal did copy.
    let image = dir.join("newest.img");
    let (code, _, err) = run(&[
        "-q",
        "dump",
        "tank/vm/disk0",
        &m[0],
        &m[1],
        "-o",
        &image.to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        &std::fs::read(&image).unwrap()[..8192],
        &zvol_pattern(0)[..]
    );
}

#[test]
fn scan_of_a_healthy_pool_says_nothing_about_removal() {
    let dir = scratch("scan-plain");
    let members = write_members(&dir, &plain_members());
    let (code, out, _) = run(&["-q", "-f", "json", "scan", &members[0], &members[1]]);
    assert_eq!(code, 0);
    let pool = &json(&out)["pools"][0];
    assert_eq!(pool["readable"], true);
    assert_eq!(pool["removed_tops"], serde_json::json!([]));
    assert_eq!(pool["device_removal"], false);
}

#[test]
fn list_reports_properties_only_when_asked() {
    let dir = scratch("list-props");
    let members = write_members(&dir, &plain_members());

    let (code, out, _) = run(&[
        "-q",
        "-f",
        "json",
        "list",
        "-r",
        "-p",
        &members[0],
        &members[1],
    ]);
    assert_eq!(code, 0);
    let by_name: std::collections::BTreeMap<String, serde_json::Value> = json(&out)["datasets"]
        .as_array()
        .expect("datasets")
        .iter()
        .map(|d| (d["name"].as_str().unwrap().to_string(), d.clone()))
        .collect();
    assert_eq!(
        by_name["tank/vm/disk0"]["properties"],
        serde_json::json!([
            {"name": "compression", "value": 15, "means": "lz4"},
            {"name": "checksum", "value": 12, "means": "skein"},
            {"name": "org.example:ticket", "value": "RT-4471"},
        ])
    );
    // Set nothing: an empty list, not an absent key.
    assert_eq!(by_name["tank/vm"]["properties"], serde_json::json!([]));

    let (_, text, _) = run(&["-q", "list", "-r", "-p", &members[0]]);
    assert!(text.contains("property: compression = 15 (lz4)"), "{text}");
    assert!(
        text.contains("property: org.example:ticket = RT-4471"),
        "{text}"
    );

    // Not asked: not read, and not in the output at all.
    let (_, out, _) = run(&["-q", "-f", "json", "list", "-r", &members[0]]);
    for d in json(&out)["datasets"].as_array().expect("datasets") {
        assert!(d.get("properties").is_none(), "{d}");
    }
}

#[test]
fn a_deduplicated_volume_reads_like_any_other() {
    // SPEC F-28: a dedup block pointer is a block pointer. The DDT is
    // not consulted — there is none here to consult — and the bytes
    // come out the same as from the volume that was never deduplicated.
    let dir = scratch("dedup");
    let plain_dir = scratch("dedup-plain");
    let plain = write_members(&plain_dir, &plain_members());
    let dedup = write_members(&dir, &dedup_members());
    assert_ne!(
        std::fs::read(&plain[0]).unwrap(),
        std::fs::read(&dedup[0]).unwrap(),
        "the deduplicated pool is a different pool"
    );

    let (code, out, _) = run(&["-q", "-f", "json", "list", "-r", "-p", &dedup[0], &dedup[1]]);
    assert_eq!(code, 0);
    let disk0 = json(&out)["datasets"]
        .as_array()
        .expect("datasets")
        .iter()
        .find(|d| d["name"] == "tank/vm/disk0")
        .expect("tank/vm/disk0")
        .clone();
    assert!(
        disk0["properties"]
            .as_array()
            .expect("properties")
            .contains(
                &serde_json::json!({"name": "dedup", "value": 264, "means": "sha256,verify"})
            ),
        "{disk0}"
    );

    let mut images = Vec::new();
    for (name, members) in [("plain", &plain), ("dedup", &dedup)] {
        let img = dir.join(format!("{name}.img"));
        let (code, out, err) = run(&[
            "-q",
            "-f",
            "json",
            "dump",
            "tank/vm/disk0",
            &members[0],
            &members[1],
            "-o",
            &img.to_string_lossy(),
        ]);
        assert_eq!(code, 0, "{err}");
        let v = &json(&out)["volumes"][0];
        assert_eq!(v["aborted"], false, "{v}");
        assert_eq!(v["blocks_read"], 2, "{v}");
        images.push((std::fs::read(&img).expect("image"), v["sha256"].clone()));
    }
    assert_eq!(images[0].0, images[1].0, "the bytes differ");
    assert_eq!(images[0].1, images[1].1);
}

#[test]
fn dump_takes_the_legacy_digests_in_the_same_pass_and_only_when_asked() {
    let dir = scratch("dump-hash");
    let members = write_members(&dir, &plain_members());
    let out_img = dir.join("vol.img");
    let out_s = out_img.to_string_lossy().into_owned();

    let (code, out, _) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &members[0],
        &members[1],
        "--hash",
        "md5,sha1",
        "-o",
        &out_s,
    ]);
    assert_eq!(code, 0);
    let v = &json(&out)["volumes"][0];
    // What was printed is what the written file hashes to.
    let mut d = Digests::new(Extra {
        md5: true,
        sha1: true,
    });
    d.update(&std::fs::read(&out_img).expect("image"));
    let got = d.finish();
    assert_eq!(v["sha256"], got.sha256);
    assert_eq!(v["sha1"], got.sha1.expect("sha1"));
    assert_eq!(v["md5"], got.md5.expect("md5"));

    let plain = dir.join("plain.img");
    let (code, out, _) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &members[0],
        "-o",
        &plain.to_string_lossy(),
    ]);
    assert_eq!(code, 0);
    let v = &json(&out)["volumes"][0];
    assert!(v.get("sha1").is_none() && v.get("md5").is_none(), "{v}");

    let (code, _, err) = run(&[
        "-q",
        "dump",
        "tank/vm/disk0",
        &members[0],
        "--hash",
        "crc32",
        "-o",
        &dir.join("x.img").to_string_lossy(),
    ]);
    assert_eq!(code, 1);
    assert!(err.contains("unknown digest \"crc32\""), "{err}");
}

/// Blocks lost one after another for one reason are one range of the
/// image, as long as they go on: each was a record of its own, a line
/// of the summary and an entry of the evidence log, and a volume with a
/// vdev gone had them by the ten thousand. A block lost apart from them
/// is a range of its own, and the count of blocks is every block.
#[test]
fn blocks_lost_in_a_row_are_one_range() {
    use zfs_read::fixture::{dense_volume_members, Dense};

    let dir = scratch("dump-run");
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
    let dense = Dense {
        bytes: 1 << 20,
        blocksize: 8192,
        compression: zfs_ondisk::blkptr::Compression::Off,
    };
    let (mut members, _) = dense_volume_members(&mut pool, dense);
    // The volume's blocks lie one after another where the allocator
    // put them: both copies of five in a row, and of one thirty on.
    for block in [10u64, 11, 12, 13, 14, 40] {
        let at = (LABEL_START_SIZE + 0x20_0000 + block * 8192) as usize;
        for m in members.iter_mut() {
            m[at + 5] ^= 0xff;
        }
    }
    let paths = write_members(&dir, &members);
    let image = dir.join("out.img").to_string_lossy().into_owned();
    let (code, out, err) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &paths[0],
        &paths[1],
        "-o",
        &image,
    ]);
    assert_eq!(code, 4, "{out}\n{err}");
    let v = &json(&out)["volumes"][0];
    assert_eq!(v["blocks_zeroed"], 6, "{v}");
    let bad: Vec<(u64, u64, u64)> = v["bad"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| {
            (
                b["blkid"].as_u64().unwrap(),
                b["offset"].as_u64().unwrap(),
                b["len"].as_u64().unwrap(),
            )
        })
        .collect();
    let first = bad[0].0;
    assert_eq!(
        bad,
        [
            (first, first * 8192, 5 * 8192),
            (first + 30, (first + 30) * 8192, 8192)
        ],
        "{v}"
    );
    assert!(v.get("bad_unlisted").is_none(), "{v}");

    let (code, out, _) = run(&[
        "-q",
        "dump",
        "tank/vm/disk0",
        &paths[0],
        &paths[1],
        "-o",
        &image,
    ]);
    assert_eq!(code, 4, "{out}");
    assert_eq!(out.matches("  unreadable: blkid ").count(), 2, "{out}");
    assert!(
        out.contains(&format!(
            "  unreadable: blkid {first} offset {} len 40960: ",
            first * 8192
        )) && out.contains("WARNING: 2 unreadable range(s) were written as zeros (exit 4)"),
        "{out}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn an_image_with_zeroed_blocks_exits_4_and_a_healed_one_exits_0() {
    let dir = scratch("dump-zeroed");
    let mut members = plain_members();
    let at = (LABEL_START_SIZE + SAMPLE_ZVOL_BLOCK0_OFFSET) as usize;
    let intact = members[1].clone();
    // Both copies of block 0 damaged: nothing to heal from.
    members[0][at + 5] ^= 0xff;
    members[1][at + 5] ^= 0xff;
    let paths = write_members(&dir, &members);
    let (code, out, _) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &paths[0],
        &paths[1],
        "-o",
        &dir.join("zeroed.img").to_string_lossy(),
    ]);
    assert_eq!(code, 4, "{out}");
    let v = &json(&out)["volumes"][0];
    assert_eq!(v["blocks_zeroed"], 1, "{v}");
    assert_eq!(
        v["blocks_salvaged"], 0,
        "a checksum mismatch names no sector: {v}"
    );
    assert_eq!(v["aborted"], false);
    let zeroed_hash = v["sha256"].clone();

    // One copy intact: healed from it, nothing zeroed, exit 0.
    let good = dir.join("member1-intact.img");
    std::fs::write(&good, &intact).expect("write");
    let (code, out, _) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &paths[0],
        &good.to_string_lossy(),
        "-o",
        &dir.join("healed.img").to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{out}");
    let v = &json(&out)["volumes"][0];
    assert_eq!(v["blocks_zeroed"], 0, "{v}");
    assert_ne!(v["sha256"], zeroed_hash, "a zeroed block changes the image");

    // --strict on the damaged pair: aborted, and still 4.
    let (code, out, _) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &paths[0],
        &paths[1],
        "--strict",
        "-o",
        &dir.join("strict.img").to_string_lossy(),
    ]);
    assert_eq!(code, 4, "{out}");
    assert_eq!(json(&out)["volumes"][0]["aborted"], true);
}

/// Two files that are one disk of the pool — a disk imaged twice — were
/// read as whichever came first, the other never looked at: the same
/// two in the other order gave another volume, each with exit 0. The
/// run now names both and asks which; the same file under two names is
/// one disk and passes.
#[cfg(unix)]
#[test]
fn two_images_of_one_disk_are_not_read_as_one() {
    let dir = scratch("twin-leaf");
    let paths = write_members(&dir, &plain_members());
    let again = dir.join("member0-again.img");
    std::fs::copy(&paths[0], &again).unwrap();
    let again = again.to_string_lossy().into_owned();
    for order in [[&paths[0], &again], [&again, &paths[0]]] {
        let (code, _, err) = run(&["-q", "list", order[0], order[1], &paths[1]]);
        assert_eq!(code, 1, "{err}");
        assert!(
            err.contains(&format!(
                "{} and {} are the same disk of pool tank",
                order[0], order[1]
            )),
            "{err}"
        );
        assert!(err.contains("give the one to read"), "{err}");
    }
    let link = dir.join("member0-link.img");
    std::os::unix::fs::symlink(&paths[0], &link).unwrap();
    let (code, _, err) = run(&["-q", "list", &paths[0], &link.to_string_lossy(), &paths[1]]);
    assert_eq!(code, 0, "one file by two names: {err}");
}

/// The case as it comes: the same disk imaged at two times, its labels
/// and uberblocks at different transaction groups. Whichever was named
/// first was read; both orders are refused now, and the message gives
/// each its transaction groups, which is what the operator chooses by.
#[test]
fn a_disk_imaged_at_two_times_is_not_read_as_whichever_came_first() {
    let dir = scratch("twin-txgs");
    let early = write_members(&dir, &plain_members());
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1), (140, 2)]);
    let mut later = vec![vec![0u8; SIZE as usize], vec![0u8; SIZE as usize]];
    let mut a = Alloc::new(0x20_0000);
    build_sample_mos(&mut pool, &mut later, &mut a);
    for (i, m) in later.iter_mut().enumerate() {
        pool.write_labels(i, m);
    }
    let later0 = dir.join("member0-later.img");
    std::fs::write(&later0, &later[0]).unwrap();
    let later0 = later0.to_string_lossy().into_owned();
    let img = dir.join("vol.img").to_string_lossy().into_owned();
    for (first, second, txgs) in [
        (
            &early[0],
            &later0,
            "labels at txg 100 and 140, newest uberblock txg 100 and 140",
        ),
        (
            &later0,
            &early[0],
            "labels at txg 140 and 100, newest uberblock txg 140 and 100",
        ),
    ] {
        let (code, out, err) = run(&["-q", "list", first, second, &early[1]]);
        assert_eq!(code, 1, "{out}{err}");
        assert!(err.contains(txgs), "{err}");
        let (code, _, err) = run(&["-q", "dump", "tank/vm/disk0", first, second, "-o", &img]);
        assert_eq!(code, 1, "{err}");
        assert!(
            !Path::new(&img).exists(),
            "refused before anything is written"
        );
    }
    // `scan` reads no pool through them: it reports each as it is.
    let (code, _, err) = run(&["-q", "scan", &early[0], &later0, &early[1]]);
    assert_eq!(code, 0, "{err}");
}

/// A resumed dump reports what the run before it lost: the blocks it
/// wrote as zeros are in the image, and they used to be in no summary,
/// a resumed dump of a damaged volume exiting 0 with none listed.
#[test]
fn a_resumed_dump_reports_what_the_run_before_it_lost() {
    let dir = scratch("dump-resume-lost");
    let mut members = plain_members();
    let at = (LABEL_START_SIZE + SAMPLE_ZVOL_BLOCK0_OFFSET) as usize;
    members[0][at + 5] ^= 0xff;
    members[1][at + 5] ^= 0xff;
    let paths = write_members(&dir, &members);
    let img = dir.join("vol.img");
    let img_s = img.to_string_lossy().into_owned();
    let dump = |extra: &[&str]| {
        let mut args = vec![
            "-q",
            "-f",
            "json",
            "dump",
            "tank/vm/disk0",
            &paths[0],
            &paths[1],
            "-o",
            &img_s,
        ];
        args.extend_from_slice(extra);
        let (code, out, err) = run(&args);
        (code, json(&out)["volumes"][0].clone(), err)
    };
    let (code, first, _) = dump(&[]);
    assert_eq!(code, 4);
    assert_eq!(first["blocks_zeroed"], 1, "{first}");
    let bad = first["bad"].clone();
    assert_eq!(bad[0]["blkid"], 0, "{first}");

    // The state a run interrupted after block 1 leaves: block 0 is lost,
    // and the two blocks before it are what they came to.
    let state_path = dir.join("vol.img.resume.json");
    let two_blocks = 2 * first["blocksize"].as_u64().unwrap() as usize;
    let state = serde_json::json!({
        "version": 1,
        "dataset": "tank/vm/disk0",
        "dataset_guid": first["dataset_guid"],
        "txg": first["txg"],
        "volsize": first["volsize"],
        "blocksize": first["blocksize"],
        "blocks_done": 2,
        "lost": { "bad": bad, "blocks_zeroed": 1 },
        "prefix_sha256": zvol_common::evidence::sha256_hex(&std::fs::read(&img).unwrap()[..two_blocks]),
    });
    std::fs::write(&state_path, state.to_string()).unwrap();
    let (code, v, err) = dump(&["--resume"]);
    assert_eq!(v["resumed_from_block"], 2, "{err}");
    assert_eq!(code, 4, "{v}");
    assert_eq!(v["blocks_zeroed"], 1, "{v}");
    assert_eq!(v["bad"], bad);
    assert_eq!(v["sha256"], first["sha256"]);
    assert!(!state_path.exists(), "the image is whole");
}

/// `-o /dev/stdout > img` wrote the image into the file at offsets and
/// the summary into it from the start, over the image; the recorded
/// hash was of bytes the file no longer held, exit 0. The output that
/// is the run's own standard output — by that name or by its own — is
/// refused before anything is read.
#[cfg(unix)]
#[test]
fn the_runs_standard_output_is_not_taken_for_an_image() {
    let dir = scratch("dump-own-stdout");
    let members = write_members(&dir, &plain_members());
    let img = dir.join("vol.img");
    let mut names = vec![img.to_string_lossy().into_owned()];
    if Path::new("/dev/stdout").exists() {
        names.push("/dev/stdout".into());
    }
    for name in &names {
        let sink = std::fs::File::create(&img).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_zvolrescue"))
            .args(["-q", "dump", "tank/vm/disk0", &members[0], "-o", name])
            .stdout(sink)
            .output()
            .expect("run zvolrescue");
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{name}: {err}");
        assert!(err.contains("standard output of the run"), "{name}: {err}");
        assert_eq!(std::fs::metadata(&img).unwrap().len(), 0, "{name}");
    }
    // Standard error the same: what the run says there would land on
    // the image. The refusal itself goes into the file, and nothing else.
    let mut names = vec![img.to_string_lossy().into_owned()];
    if Path::new("/dev/stderr").exists() {
        names.push("/dev/stderr".into());
    }
    for name in &names {
        let sink = std::fs::File::create(&img).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_zvolrescue"))
            .args(["-q", "dump", "tank/vm/disk0", &members[0], "-o", name])
            .stderr(sink)
            .output()
            .expect("run zvolrescue");
        assert_eq!(out.status.code(), Some(1), "{name}");
        let said = std::fs::read_to_string(&img).unwrap();
        assert!(said.contains("standard error of the run"), "{name}: {said}");
        assert!(said.lines().all(|l| l.starts_with("zvolrescue:")), "{said}");
    }
}

/// A `--strict` dump stops at the first unreadable block, and its state
/// says to go on from that very block; a run without `--strict` that
/// takes it up writes the block as zeros and says so, exit 4, the image
/// that of a run that never stopped.
#[test]
fn a_strict_dump_is_resumed_at_the_block_it_stopped_at() {
    let dir = scratch("dump-strict-resume");
    let mut members = plain_members();
    // Block 2, the volume's second data block, after block 0.
    let block2 = (LABEL_START_SIZE + SAMPLE_ZVOL_BLOCK0_OFFSET + 8192) as usize;
    for m in &mut members {
        assert_eq!(
            m[block2..block2 + 8192],
            zvol_pattern(2)[..],
            "the layout moved"
        );
        m[block2 + 5] ^= 0xff;
    }
    let paths = write_members(&dir, &members);
    let dump = |out: &Path, extra: &[&str]| {
        let o = out.to_string_lossy().into_owned();
        let mut args = vec![
            "-q",
            "-f",
            "json",
            "dump",
            "tank/vm/disk0",
            &paths[0],
            &paths[1],
            "-o",
            &o,
        ];
        args.extend_from_slice(extra);
        let (code, stdout, err) = run(&args);
        (code, json(&stdout)["volumes"][0].clone(), err)
    };
    let (code, whole, _) = dump(&dir.join("whole.img"), &[]);
    assert_eq!(code, 4);
    assert_eq!(whole["bad"][0]["blkid"], 2, "{whole}");

    let img = dir.join("vol.img");
    let (code, v, err) = dump(&img, &["--strict"]);
    assert_eq!(code, 4, "{err}");
    assert_eq!(v["aborted"], true, "{v}");
    assert_eq!(v["bad"][0]["blkid"], 2, "{v}");
    let state_path = dir.join("vol.img.resume.json");
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    assert_eq!(state["blocks_done"], 2, "{state}");
    assert!(
        state.get("lost").is_none(),
        "block 2 is read again: {state}"
    );

    let (code, v, err) = dump(&img, &["--resume"]);
    assert_eq!(code, 4, "{err}");
    assert_eq!(v["resumed_from_block"], 2, "{v}");
    assert_eq!(v["blocks_zeroed"], 1, "{v}");
    assert_eq!(v["bad"][0]["blkid"], 2, "{v}");
    assert_eq!(v["sha256"], whole["sha256"]);
    assert!(!state_path.exists());
    assert_eq!(
        std::fs::read(&img).unwrap(),
        std::fs::read(dir.join("whole.img")).unwrap()
    );
}

/// `--diff` names what one transaction group has that the other does
/// not, by guid: the destroyed volume and its snapshot, with the
/// command that gets each back.
#[test]
fn list_diff_names_what_the_newest_txg_no_longer_has() {
    let dir = scratch("list-diff");
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1), (200, 2)]);
    let (members, newest, previous) = destroyed_zvol_members(&mut pool, SIZE);
    assert_eq!((newest, previous), (200, 100));
    let paths = write_members(&dir, &members);

    let (code, out, _) = run(&[
        "-q", "-f", "json", "list", "-r", "--diff", "100", &paths[0], &paths[1],
    ]);
    assert_eq!(code, 0, "{out}");
    let v = json(&out);
    assert_eq!(v["txg"], 200);
    let diff = &v["diff"];
    assert_eq!(diff["txg"], 100);
    assert_eq!(diff["created_since"], serde_json::json!([]));
    let gone: Vec<&str> = diff["destroyed_since"]
        .as_array()
        .expect("destroyed_since")
        .iter()
        .map(|d| d["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        gone,
        vec!["tank/vm/disk0", "tank/vm/disk0@before"],
        "{diff}"
    );
    // Nothing that reads properties runs here, so none are reported.
    assert!(diff["destroyed_since"][0].get("properties").is_none());

    let (_, text, _) = run(&["-q", "list", "-r", "--diff", "100", &paths[0]]);
    assert!(text.contains("compared with txg 100"), "{text}");
    assert!(
        text.contains("destroyed  tank/vm/disk0 ") && text.contains("--txg 100"),
        "{text}"
    );

    // A transaction group no uberblock verifies at is an error, not an
    // empty diff.
    let (code, _, err) = run(&["-q", "list", "-r", "--diff", "150", &paths[0]]);
    assert_eq!(code, 3);
    assert!(
        err.contains("--diff txg 150 has no verified uberblock"),
        "{err}"
    );
}

/// A pool no uberblock leads to is read at the object-set headers
/// `zvolcarve roots` found, given with `--roots` (SPEC F-64). With its
/// rings zeroed `list` had no transaction group to read at and a volume
/// destroyed since was out of every program's reach but the carver's,
/// which gives it no name. Each header is a transaction group: the
/// newest lists the pool as it is, the older one has the volume, and
/// `dump` finds it there by its name, the bytes it had. What such a run
/// read from is on its output and its record, and its time is not made
/// up. A file that is not of these members is refused.
#[test]
fn a_pool_no_uberblock_leads_to_is_read_at_the_headers_found() {
    let dir = scratch("roots");
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1), (200, 2)]);
    let (mut members, newest, previous) = destroyed_zvol_members(&mut pool, SIZE);
    assert_eq!((newest, previous), (200, 100));
    let m = write_members(&dir, &members);
    // The volume, read while the uberblocks are there.
    let whole = dir.join("whole.img").to_string_lossy().into_owned();
    let (code, _, err) = run(&[
        "-q",
        "dump",
        "tank/vm/disk0",
        "--txg",
        "100",
        "-o",
        &whole,
        &m[0],
        &m[1],
    ]);
    assert_eq!(code, 0, "{err}");

    for member in &mut members {
        zero_uberblock_rings(member);
    }
    write_members(&dir, &members);
    let (code, _, err) = run(&["-q", "list", &m[0], &m[1]]);
    assert_eq!(code, 3, "{err}");
    assert!(err.contains("no verified uberblock"), "{err}");

    // The file `zvolcarve roots` writes, and the directory it is in.
    let roots = dir.join("roots.json").to_string_lossy().into_owned();
    std::fs::write(&roots, roots_json(&members, &m)).unwrap();
    let ws = dir.to_string_lossy().into_owned();
    for given in [&roots, &ws] {
        let (code, out, err) = run(&["-f", "json", "list", "--roots", given, &m[0], &m[1]]);
        assert_eq!(code, 0, "{err}");
        let doc = json(&out);
        assert_eq!(doc["txg"], 200, "{out}");
        assert_eq!(doc["time"], "unknown", "{out}");
        assert_eq!(doc["available_txgs"], serde_json::json!([200, 100]));
        assert_eq!(doc["carved_txgs"], serde_json::json!([200, 100]));
        assert_eq!(doc["carved_root"]["member"], m[0].as_str(), "{out}");
        assert_eq!(doc["carved_root"]["found"], "plaintext", "{out}");
        assert!(doc["carved_root"]["offset"].as_u64().unwrap() > 0, "{out}");
        assert!(
            err.contains("txg 200 is read from the object-set header found at byte")
                && err.contains("not from an uberblock")
                && err.contains("no checksum vouches for the header itself"),
            "{err}"
        );
    }
    let (code, text, _) = run(&[
        "-q", "list", "--roots", &roots, &m[0], &m[1], "--txg", "100",
    ]);
    assert_eq!(code, 0, "{text}");
    assert!(
        text.contains("txg 100 (time unknown), 0 verified txg(s) available, and 2 of object-set headers found in raw space (--roots)")
            && text.contains("read from the object-set header at byte")
            && text.contains("tank/vm/disk0"),
        "{text}"
    );
    // A header says no time, and none is chosen by one.
    let (code, _, err) = run(&[
        "-q",
        "list",
        "--roots",
        &roots,
        &m[0],
        &m[1],
        "--before",
        "2030-01-01",
    ]);
    assert_eq!(code, 3, "{err}");
    assert!(
        err.contains("a header of --roots says none; --txg N reads one of 200 100"),
        "{err}"
    );

    // The destroyed volume, by its name, at the header that has it.
    let image = dir.join("disk0.img").to_string_lossy().into_owned();
    let log = dir.join("evidence.jsonl").to_string_lossy().into_owned();
    let (code, out, err) = run(&[
        "-f",
        "json",
        "--evidence-log",
        &log,
        "dump",
        "tank/vm/disk0",
        "--roots",
        &roots,
        "-o",
        &image,
        &m[0],
        &m[1],
    ]);
    assert_eq!(code, 0, "{err}");
    let doc = json(&out);
    assert_eq!(doc["txgs_searched"], serde_json::json!([200, 100]), "{out}");
    assert_eq!(doc["volumes"][0]["txg"], 100, "{out}");
    assert_eq!(doc["volumes"][0]["time"], "unknown", "{out}");
    assert_eq!(doc["carved_root"]["member"], m[0].as_str(), "{out}");
    assert!(
        err.contains("txg 100 is read from the object-set header"),
        "{err}"
    );
    assert_eq!(
        std::fs::read(&image).unwrap(),
        std::fs::read(&whole).unwrap(),
        "the volume as the uberblock of txg 100 gave it"
    );
    // The file of headers is among what the run read.
    let record: serde_json::Value = serde_json::from_str(
        std::fs::read_to_string(&log)
            .unwrap()
            .lines()
            .last()
            .unwrap(),
    )
    .unwrap();
    assert!(
        record["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["path"] == roots.as_str()),
        "{record}"
    );
    assert_eq!(record["result"]["carved_root"], doc["carved_root"]);
    // And never what it writes.
    let (code, _, err) = run(&[
        "-q",
        "dump",
        "tank/vm/disk0",
        "--roots",
        &roots,
        "-o",
        &roots,
        &m[0],
        &m[1],
    ]);
    assert_eq!(code, 5, "{err}");

    // A file that is not of these members: a header where there is
    // none, a member that was not given, a shape this build does not
    // read.
    let entry = |member: &str, offset: u64, datasets: u64| {
        serde_json::json!({
            "version": 1,
            "roots": [{"member": member, "offset": offset, "found": "plaintext",
                       "birth": 200, "datasets": datasets}],
        })
        .to_string()
    };
    let other = dir.join("other.json").to_string_lossy().into_owned();
    for (text, said) in [
        (
            entry(&m[0], 4096, 1),
            "no object-set header of txg 200 at byte 4096 of",
        ),
        (
            entry("/nowhere/member9.img", 4096, 1),
            "which is not among the members given",
        ),
        (
            r#"{"version":7,"roots":[]}"#.to_string(),
            "version 7 of the file, and this build reads version 1",
        ),
        ("not json".to_string(), "not what `zvolcarve roots` writes"),
    ] {
        std::fs::write(&other, &text).unwrap();
        let (code, _, err) = run(&["-q", "list", "--roots", &other, &m[0], &m[1]]);
        assert_eq!(code, 1, "{text}: {err}");
        assert!(err.contains(said), "{text}: {err}");
    }
    // One no pool walked out of is not read at: nothing is added.
    std::fs::write(&other, entry(&m[0], 4096, 0)).unwrap();
    let (code, _, err) = run(&["-q", "list", "--roots", &other, &m[0], &m[1]]);
    assert_eq!(code, 3, "{err}");
    assert!(
        err.contains("no object-set header in it that a pool walked out of")
            && err.contains("and --roots gave no object-set header to read at in their place"),
        "{err}"
    );
}

/// In every ring of `img`, the slot ZFS would write `txg` to, holding
/// the uberblock of `from` with that txg, that birth in its root pointer
/// and the pointer's checksum words inverted, sealed for its place. What
/// a sync leaves behind when its uberblocks reached the members and its
/// MOS did not — or a slot someone forged.
fn forge_uberblock(img: &mut [u8], from: u64, txg: u64) {
    let slot = 1usize << 12; // ashift 12
    let count = UBERBLOCK_RING_SIZE as usize / slot;
    for label_off in label_offsets(img.len() as u64).expect("four labels") {
        let ring = (label_off + UBERBLOCK_RING_OFFSET) as usize;
        let source = (0..count)
            .find(|i| {
                let s = &img[ring + i * slot..];
                u64::from_le_bytes(s[16..24].try_into().unwrap()) == from
            })
            .expect("the txg forged from is in the ring");
        let mut forged = img[ring + source * slot..ring + (source + 1) * slot].to_vec();
        forged[16..24].copy_from_slice(&txg.to_le_bytes());
        forged[40 + 80..40 + 88].copy_from_slice(&txg.to_le_bytes());
        for b in forged[40 + 96..40 + 128].iter_mut() {
            *b ^= 0xff;
        }
        let at = ring + (txg as usize % count) * slot;
        seal_label(&mut forged, at as u64);
        img[at..at + slot].copy_from_slice(&forged);
    }
}

/// A ring slot that verifies and leads nowhere — a newer txg than the
/// pool ever reached, pointing at an object set no block matches —
/// is the newest verified uberblock and not the pool's newest state.
/// `list` and `dump` pass it over for the newest TXG that reads, say
/// so, and record it; asked for it by `--txg`, they refuse with the
/// reason.
#[test]
fn a_forged_newer_txg_with_nothing_behind_it_is_passed_over() {
    let dir = scratch("forged-txg");
    let mut members = plain_members();
    for m in members.iter_mut() {
        forge_uberblock(m, 100, 103);
    }
    let paths = write_members(&dir, &members);

    let (code, out, err) = run(&["-f", "json", "list", &paths[0], &paths[1]]);
    assert_eq!(code, 0, "{out}\n{err}");
    let v = json(&out);
    assert_eq!(v["available_txgs"][0], 103, "{v}");
    assert_eq!(v["txg"], 100, "{v}");
    assert_eq!(v["unreadable_at"][0]["txg"], 103, "{v}");
    assert!(
        v["unreadable_at"][0]["error"]
            .as_str()
            .unwrap()
            .contains("checksum"),
        "{v}"
    );
    assert!(
        err.contains("txg 103: unreadable") && err.contains("trying an older TXG"),
        "{err}"
    );
    assert!(
        v["datasets"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["name"] == "tank/vm/disk0"),
        "{v}"
    );

    let (code, out, err) = run(&[
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &paths[0],
        &paths[1],
        "-o",
        &dir.join("vol.img").to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{out}\n{err}");
    let v = json(&out);
    assert_eq!(v["txgs_searched"], serde_json::json!([103, 100]), "{v}");
    assert_eq!(v["unreadable_at"][0]["txg"], 103, "{v}");
    assert_eq!(v["unreadable_at"][0]["stage"], "pool", "{v}");
    assert_eq!(v["volumes"][0]["txg"], 100, "{v}");
    assert!(
        err.contains("txg 103: unreadable") && err.contains("trying an older TXG"),
        "{err}"
    );

    // By name: that one or nothing.
    let (code, out, err) = run(&["-q", "-f", "json", "list", "--txg", "103", &paths[0]]);
    assert_eq!(code, 3, "{out}");
    assert!(err.contains("cannot read the pool at txg 103"), "{err}");
    assert_eq!(json(&out)["unreadable_at"][0]["txg"], 103, "{out}");
}

/// A destroyed volume's object set block is free to reuse from the next
/// txg on. When the ring names the volume at a txg whose object set is
/// gone and at an older one whose object set still reads, `dump` passes
/// the first over — said on stderr and in the record — and extracts at
/// the second, the same bytes; asked for the first by `--txg`, it
/// refuses with the reason.
#[test]
fn a_txg_whose_object_set_was_reused_is_passed_over_for_an_older_one() {
    let dir = scratch("objset-reused");
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1), (200, 2), (300, 3)]);
    let r = objset_reused_members(&mut pool, SIZE);
    assert_eq!((r.newest, r.reused, r.whole), (300, 200, 100));
    let (mut members, objset) = (r.members, r.objset);
    // The reference: the volume at the txg about to lose its object
    // set, while that still reads.
    let paths = write_members(&dir, &members);
    let (code, out, _) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &paths[0],
        &paths[1],
        "--txg",
        "200",
        "-o",
        &dir.join("ref.img").to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{out}");
    let reference = json(&out)["volumes"][0]["sha256"].clone();

    // Both copies of that object set block reused.
    let at = (LABEL_START_SIZE + objset) as usize;
    for m in members.iter_mut() {
        for b in &mut m[at..at + 512] {
            *b ^= 0x5a;
        }
    }
    let paths = write_members(&dir, &members);
    let (code, out, err) = run(&[
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &paths[0],
        &paths[1],
        "-o",
        &dir.join("older.img").to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{out}\n{err}");
    let v = json(&out);
    assert_eq!(v["txgs_searched"], serde_json::json!([300, 200, 100]));
    assert_eq!(v["unreadable_at"][0]["txg"], 200, "{v}");
    assert!(
        v["unreadable_at"][0]["error"]
            .as_str()
            .unwrap()
            .contains("checksum"),
        "{v}"
    );
    assert_eq!(v["volumes"][0]["txg"], 100);
    assert_eq!(v["volumes"][0]["sha256"], reference);
    assert!(
        err.contains("txg 200: unreadable") && err.contains("trying an older TXG"),
        "{err}"
    );

    // Asked for that txg by name: refused, with the reason, and the
    // record still says which txg it was.
    let (code, out, err) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &paths[0],
        &paths[1],
        "--txg",
        "200",
        "-o",
        &dir.join("exact.img").to_string_lossy(),
    ]);
    assert_eq!(code, 3, "{out}");
    assert!(
        err.contains("is named at txg 200 but does not read there"),
        "{err}"
    );
    assert_eq!(json(&out)["unreadable_at"][0]["txg"], 200);
    assert!(
        !dir.join("exact.img").exists(),
        "nothing written on a refusal"
    );
}

/// A transaction group at which the pool reads and the dataset tree
/// does not, where the dataset would be, is not one without the dataset.
/// `dump` took it for that and went on to an older one without a word:
/// an older image, exit 0, and a record naming no reason. It is said,
/// recorded at the `tree` stage, and refused by name with `--txg`.
#[test]
fn a_txg_whose_dataset_tree_does_not_read_is_not_one_without_the_dataset() {
    let dir = scratch("tree-unread");
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1), (200, 2), (300, 3)]);
    let mut members = objset_reused_members(&mut pool, SIZE).members;
    assert!(lose_children_list(&mut members, 200, "tank/vm") > 0);
    let paths = write_members(&dir, &members);
    let (code, out, err) = run(&[
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &paths[0],
        &paths[1],
        "-o",
        &dir.join("older.img").to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{out}\n{err}");
    let v = json(&out);
    assert_eq!(v["volumes"][0]["txg"], 100, "{v}");
    assert_eq!(v["unreadable_at"][0]["txg"], 200, "{v}");
    assert_eq!(v["unreadable_at"][0]["stage"], "tree", "{v}");
    assert!(
        err.contains("txg 200: the dataset tree does not read there")
            && err.contains("tank/vm: children ZAP")
            && err.contains("trying an older TXG"),
        "{err}"
    );

    let (code, out, err) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &paths[0],
        &paths[1],
        "--txg",
        "200",
        "-o",
        &dir.join("exact.img").to_string_lossy(),
    ]);
    assert_eq!(code, 3, "{out}");
    assert!(
        err.contains("at txg 200 the dataset tree does not"),
        "{err}"
    );
    assert!(!err.contains("not found"), "{err}");
    assert!(!dir.join("exact.img").exists());
}

/// A dataset tree that reads in part is listed, with what did not read
/// said — and is not a list that succeeded: it was exit 0, the datasets
/// under the part that did not read missing from it like datasets that
/// were never there.
#[test]
fn a_list_that_is_not_all_there_is_ends_4() {
    let dir = scratch("list-tree-unread");
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1), (200, 2), (300, 3)]);
    let mut members = objset_reused_members(&mut pool, SIZE).members;
    assert!(lose_children_list(&mut members, 200, "tank/vm") > 0);
    let paths = write_members(&dir, &members);
    let (code, out, err) = run(&["-f", "json", "list", &paths[0], &paths[1], "--txg", "200"]);
    assert_eq!(code, 4, "{out}\n{err}");
    let v = json(&out);
    let names: Vec<&str> = v["datasets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"tank/vm"), "{v}");
    assert!(!names.contains(&"tank/vm/disk0"), "{v}");
    assert!(
        v["errors"][0]
            .as_str()
            .unwrap()
            .contains("tank/vm: children ZAP"),
        "{v}"
    );
    assert!(err.contains("what is listed is not all there is"), "{err}");
    // The transaction group before it lists the volume, exit 0.
    let (code, out, _) = run(&["-f", "json", "list", &paths[0], &paths[1], "--txg", "100"]);
    assert_eq!(code, 0, "{out}");
}

/// The blocks a destroy frees are reused in no particular order: the
/// block of a volume's dnodes can be gone while its object set block
/// still reads (Debian 12's and FreeBSD 15's kernels did exactly that in
/// `tests/realworld/kernel-matrix.sh`'s D2). Such a TXG is passed over
/// as one whose object set is gone is, not chosen and then failed on.
#[test]
fn a_txg_whose_volume_dnodes_were_reused_is_passed_over_for_an_older_one() {
    let dir = scratch("dnodes-reused");
    let mut pool = Pool::mirror("tank", 0x4243, 12).txgs(&[(100, 1), (200, 2), (300, 3)]);
    let r = objset_reused_members(&mut pool, SIZE);
    let mut members = r.members;
    let paths = write_members(&dir, &members);
    let (code, out, _) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &paths[0],
        &paths[1],
        "--txg",
        "200",
        "-o",
        &dir.join("ref.img").to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{out}");
    let reference = json(&out)["volumes"][0]["sha256"].clone();

    // Both copies of the dnode block reused; the object set block above
    // it untouched.
    assert_ne!(r.dnodes, r.objset);
    let at = (LABEL_START_SIZE + r.dnodes) as usize;
    for m in members.iter_mut() {
        for b in &mut m[at..at + 512] {
            *b ^= 0x5a;
        }
    }
    let paths = write_members(&dir, &members);
    let (code, out, err) = run(&[
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &paths[0],
        &paths[1],
        "-o",
        &dir.join("older.img").to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{out}\n{err}");
    let v = json(&out);
    assert_eq!(v["txgs_searched"], serde_json::json!([300, 200, 100]));
    assert_eq!(v["unreadable_at"][0]["txg"], 200, "{v}");
    assert!(
        v["unreadable_at"][0]["error"]
            .as_str()
            .unwrap()
            .contains("checksum"),
        "{v}"
    );
    assert_eq!(v["volumes"][0]["txg"], 100);
    assert_eq!(v["volumes"][0]["sha256"], reference);

    // Asked for that txg by name: refused before anything is written.
    let (code, _, err) = run(&[
        "-q",
        "dump",
        "tank/vm/disk0",
        &paths[0],
        &paths[1],
        "--txg",
        "200",
        "-o",
        &dir.join("exact.img").to_string_lossy(),
    ]);
    assert_eq!(code, 3);
    assert!(
        err.contains("is named at txg 200 but does not read there"),
        "{err}"
    );
    assert!(!dir.join("exact.img").exists());
}

/// `--resume` believes a state file only as far as the output backs it
/// up: a state that names another dataset, or claims more bytes than
/// the file holds, is set aside and the extraction starts over, and
/// the image and its digests come out the same either way.
#[test]
fn a_resume_state_the_output_does_not_back_up_is_set_aside() {
    let dir = scratch("dump-resume");
    let members = write_members(&dir, &plain_members());
    let img = dir.join("vol.img");
    let img_s = img.to_string_lossy().into_owned();
    let state_path = dir.join("vol.img.resume.json");
    let dump = |extra: &[&str]| {
        let mut args = vec![
            "-q",
            "-f",
            "json",
            "dump",
            "tank/vm/disk0",
            &members[0],
            "--hash",
            "md5",
            "-o",
            &img_s,
        ];
        args.extend_from_slice(extra);
        let (code, out, err) = run(&args);
        assert_eq!(code, 0, "{out}{err}");
        (json(&out)["volumes"][0].clone(), err)
    };
    let (first, _) = dump(&[]);
    assert_eq!(first["resumed_from_block"], 0);
    assert!(!state_path.exists(), "a finished dump leaves no state");
    let want = (first["sha256"].clone(), first["md5"].clone());
    let whole = std::fs::read(&img).unwrap();
    let blocksize = first["blocksize"].as_u64().unwrap();
    // A state as a run leaves it: how far, and what those blocks came to.
    let state = |dataset: &str, blocks_done: u64| {
        serde_json::json!({
            "version": 1,
            "dataset": dataset,
            "dataset_guid": first["dataset_guid"],
            "txg": first["txg"],
            "volsize": first["volsize"],
            "blocksize": blocksize,
            "blocks_done": blocks_done,
            "prefix_sha256":
                zvol_common::evidence::sha256_hex(&whole[..(blocks_done * blocksize) as usize]),
        })
        .to_string()
    };

    // An honest state: the first two blocks are in the file, and they
    // are hashed back before the rest is read.
    std::fs::write(&state_path, state("tank/vm/disk0", 2)).unwrap();
    let (v, err) = dump(&["--resume"]);
    assert_eq!(v["resumed_from_block"], 2, "{err}");
    assert_eq!((v["sha256"].clone(), v["md5"].clone()), want);
    assert_eq!(v["blocks_read"], 1, "only block 2 is read now; 3 is a hole");

    // A state that does not say what its blocks came to — one an
    // earlier version left, or one edited — vouches for nothing: it was
    // taken up with no check of the output at all, and whatever was
    // under the name was the image.
    let mut unvouched: serde_json::Value =
        serde_json::from_str(&state("tank/vm/disk0", 2)).unwrap();
    unvouched.as_object_mut().unwrap().remove("prefix_sha256");
    std::fs::write(&state_path, unvouched.to_string()).unwrap();
    std::fs::write(&img, vec![0xffu8; whole.len()]).unwrap();
    let (v, err) = dump(&["--resume"]);
    assert!(
        err.contains("records no hash of the 16384 bytes it counts")
            && err.contains("starting over"),
        "{err}"
    );
    assert_eq!(v["resumed_from_block"], 0);
    assert_eq!((v["sha256"].clone(), v["md5"].clone()), want);
    assert_eq!(std::fs::read(&img).unwrap(), whole);

    // A state for some other dataset.
    std::fs::write(&state_path, state("tank/other", 2)).unwrap();
    let (v, err) = dump(&["--resume"]);
    assert!(
        err.contains("describes a different dataset/txg/size"),
        "{err}"
    );
    assert_eq!(v["resumed_from_block"], 0);
    assert_eq!((v["sha256"].clone(), v["md5"].clone()), want);

    // A state that claims two blocks are done when the file holds less
    // than one.
    std::fs::write(&state_path, state("tank/vm/disk0", 2)).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&img)
        .unwrap()
        .set_len(4096)
        .unwrap();
    let (v, err) = dump(&["--resume"]);
    assert!(
        err.contains("shorter than the 16384 bytes the resume state claims; starting over"),
        "{err}"
    );
    assert_eq!(v["resumed_from_block"], 0);
    assert_eq!((v["sha256"].clone(), v["md5"].clone()), want);
    assert_eq!(std::fs::metadata(&img).unwrap().len(), 32 << 20);

    // No state at all: from the start, and said — it used to start over
    // without a word.
    assert!(!state_path.exists());
    let (v, err) = dump(&["--resume"]);
    assert!(
        err.contains(&format!(
            "no resume state at {}; starting from block 0",
            state_path.display()
        )),
        "{err}"
    );
    assert_eq!(v["resumed_from_block"], 0);
    assert_eq!((v["sha256"].clone(), v["md5"].clone()), want);
}

/// An output that will not take a block — a full disk, here a file-size
/// limit — stops the run there as a signal does: exit 6, a state at that
/// block, the image of the blocks before it on the record, and a
/// `--resume` with room finishes the image. It ended as exit 3,
/// "unrecoverable", with no state and a record of no output.
#[cfg(unix)]
#[test]
fn an_output_that_refuses_a_block_is_resumed_once_it_has_room() {
    let dir = scratch("dump-output-full");
    let members = write_members(&dir, &plain_members());
    let whole = dir.join("whole.img");
    let (code, out, err) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &members[0],
        "-o",
        &whole.to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{err}");
    let want = json(&out)["volumes"][0]["sha256"].clone();

    // 32 blocks of 512 bytes: block 0 fits, block 2 — at byte 16384, the
    // next with data — does not.
    let img = dir.join("vol.img");
    let log = dir.join("ev.jsonl");
    let script = format!(
        "trap '' XFSZ; ulimit -f 32; exec \"$0\" -q -f json dump tank/vm/disk0 '{}' -o '{}' --evidence-log '{}'",
        members[0],
        img.display(),
        log.display()
    );
    let out = Command::new("/bin/sh")
        .args(["-c", &script, env!("CARGO_BIN_EXE_zvolrescue")])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(6), "{err}");
    assert!(
        err.contains("the output refused block 2, at byte 16384")
            && err.contains(
                "the image holds the blocks before it, and --resume continues there once the output has room (exit 6)"
            ),
        "{err}"
    );
    let v = json(&String::from_utf8_lossy(&out.stdout))["volumes"][0].clone();
    assert_eq!(v["interrupted_at"], 2, "{v}");
    assert_eq!(v["resume_at"], 2, "{v}");
    assert!(v["output_failed"].as_str().is_some(), "{v}");
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("vol.img.resume.json")).unwrap()).unwrap();
    assert_eq!(state["blocks_done"], 2, "{state}");
    // The record names the image, at the hash of what it holds.
    let rec: serde_json::Value = serde_json::from_str(
        std::fs::read_to_string(&log)
            .unwrap()
            .lines()
            .last()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(rec["status"], 6, "{rec}");
    let outputs = rec["outputs"].as_array().unwrap();
    assert_eq!(outputs.len(), 1, "{rec}");
    let mut d = Digests::new(Extra::none());
    d.update(&std::fs::read(&img).unwrap());
    assert_eq!(std::fs::metadata(&img).unwrap().len(), 16384);
    assert_eq!(
        outputs[0]["sha256"].as_str(),
        Some(d.finish().sha256.as_str())
    );

    let (code, out, err) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &members[0],
        "-o",
        &img.to_string_lossy(),
        "--resume",
    ]);
    assert_eq!(code, 0, "{err}");
    let v = json(&out)["volumes"][0].clone();
    assert_eq!(v["resumed_from_block"], 2, "{v}");
    assert_eq!(v["sha256"], want);
    assert_eq!(std::fs::read(&img).unwrap(), std::fs::read(&whole).unwrap());
    assert!(!dir.join("vol.img.resume.json").exists());
}

/// The state of an image written to a device is kept in the directory
/// the run is in, under the device's path, and the run says where: next
/// to the device it was written into `/dev` — where FreeBSD's devfs
/// takes no file, and Linux keeps it in memory until the next boot.
#[cfg(target_os = "linux")]
#[test]
fn the_state_of_an_image_on_a_device_is_kept_here() {
    let dir = scratch("dump-device-state");
    let members = write_members(&dir, &plain_members());
    if std::fs::metadata("/dev/full").is_err() {
        return;
    }
    let out = Command::new(env!("CARGO_BIN_EXE_zvolrescue"))
        .current_dir(&*dir)
        .args([
            "-q",
            "dump",
            "tank/vm/disk0",
            &members[0],
            "-o",
            "/dev/full",
        ])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(6), "{err}");
    assert!(
        err.contains("the output refused block 0, at byte 0")
            && err.contains(
                "(its state is dev_full.resume.json, in this directory: resume from here)"
            ),
        "{err}"
    );
    assert!(dir.join("dev_full.resume.json").exists());
    assert!(!Path::new("/dev/full.resume.json").exists());
    let _ = std::fs::remove_file(dir.join("dev_full.resume.json"));
}

/// The text report prints each legacy digest on its own line, and only
/// those that were taken.
#[test]
fn the_text_report_prints_the_legacy_digests_that_were_taken() {
    let dir = scratch("dump-text");
    let members = write_members(&dir, &plain_members());
    let img = dir.join("vol.img");
    let (code, text, _) = run(&[
        "-q",
        "dump",
        "tank/vm/disk0",
        &members[0],
        "--hash",
        "sha1",
        "-o",
        &img.to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{text}");
    let mut d = Digests::new(Extra {
        md5: false,
        sha1: true,
    });
    d.update(&std::fs::read(&img).unwrap());
    let got = d.finish();
    assert!(
        text.contains(&format!("  sha256: {}", got.sha256)),
        "{text}"
    );
    assert!(
        text.contains(&format!("  sha1:   {}", got.sha1.unwrap())),
        "{text}"
    );
    assert!(!text.contains("  md5:"), "{text}");
}

/// A member that cannot be opened is reported as such, per device, and
/// the scan exits 2: evidence was missing, nothing was refused.
#[test]
fn scan_reports_a_member_it_cannot_open_and_exits_2() {
    let dir = scratch("scan-missing");
    let missing = dir.join("nothing-here.img");
    let missing_s = missing.to_string_lossy().into_owned();
    let (code, out, _) = run(&["-q", "-f", "json", "scan", &missing_s]);
    assert_eq!(code, 2, "{out}");
    let v = json(&out);
    assert_eq!(v["pools"], serde_json::json!([]));
    let dev = &v["devices"][0];
    assert_eq!(dev["path"], missing_s);
    assert_eq!(dev["size"], 0);
    assert!(
        dev["error"].as_str().unwrap().contains("No such file"),
        "{dev}"
    );

    let (code, text, _) = run(&["-q", "scan", &missing_s]);
    assert_eq!(code, 2);
    assert!(text.contains("error: No such file"), "{text}");
}

/// A whole-disk image: protective MBR, a GPT whose one partition is
/// named and has a unique GUID, and `member` inside it.
fn gpt_wrap(member: &[u8], start: u64, name: &str, guid_bytes: [u8; 16]) -> Vec<u8> {
    let sector = 512usize;
    let mut disk = vec![0u8; start as usize + member.len() + 64 * sector];
    disk[510] = 0x55;
    disk[511] = 0xaa;
    disk[446 + 4] = 0xee;
    disk[446 + 12..446 + 16].copy_from_slice(&u32::MAX.to_le_bytes());
    disk[sector..sector + 8].copy_from_slice(b"EFI PART");
    disk[sector + 80..sector + 84].copy_from_slice(&1u32.to_le_bytes());
    disk[sector + 84..sector + 88].copy_from_slice(&128u32.to_le_bytes());
    let mut e = vec![0u8; 128];
    // freebsd-zfs, 516e7cba-6ecf-11d6-8ff8-00022d09712b, on-disk order.
    e[..16].copy_from_slice(&[
        0xba, 0x7c, 0x6e, 0x51, 0xcf, 0x6e, 0xd6, 0x11, 0x8f, 0xf8, 0x00, 0x02, 0x2d, 0x09, 0x71,
        0x2b,
    ]);
    e[16..32].copy_from_slice(&guid_bytes);
    let first = start / sector as u64;
    let last = first + (member.len() / sector) as u64 - 1;
    e[32..40].copy_from_slice(&first.to_le_bytes());
    e[40..48].copy_from_slice(&last.to_le_bytes());
    for (i, u) in name.encode_utf16().enumerate() {
        e[56 + i * 2..58 + i * 2].copy_from_slice(&u.to_le_bytes());
    }
    disk[sector * 2..sector * 2 + 128].copy_from_slice(&e);
    disk[start as usize..start as usize + member.len()].copy_from_slice(member);
    disk
}

/// Zero every label's configuration, leaving the uberblock rings.
fn wipe_configs(img: &mut [u8]) {
    let (phys_off, phys) = (16 * 1024usize, 112 * 1024usize);
    let label = LABEL_SIZE as usize;
    let aligned = img.len() & !(label - 1);
    for off in [0, label, aligned - 2 * label, aligned - label] {
        img[off + phys_off..off + phys_off + phys].fill(0);
    }
}

/// A member whose labels are gone is tied to the leaf its siblings
/// describe by the name its own disk gives it (SPEC F-71): the GPT
/// label matches the `path` the pool recorded, `scan` says which leaf
/// that is and how to bind it, and the binding reads.
#[test]
fn a_bare_member_is_named_by_its_gpt_label_and_the_pool_says_which_leaf() {
    let dir = scratch("gpt-name");
    let members = plain_members();
    let good = dir.join("member0.img");
    std::fs::write(&good, &members[0]).unwrap();
    let mut bare = members[1].clone();
    wipe_configs(&mut bare);
    let disk = dir.join("disk1.img");
    std::fs::write(&disk, gpt_wrap(&bare, 1 << 20, "tank-d1", [0x33; 16])).unwrap();
    let (good_s, disk_s) = (
        good.to_string_lossy().into_owned(),
        disk.to_string_lossy().into_owned(),
    );

    let (code, out, _) = run(&["-q", "-f", "json", "scan", &good_s, &disk_s]);
    assert_eq!(code, 0, "{out}");
    let v = json(&out);
    let d = &v["devices"][1];
    let part = &d["partitions"]["partitions"][0];
    assert_eq!(part["name"], "tank-d1");
    assert_eq!(part["guid"], "33333333-3333-3333-3333-333333333333");
    assert_eq!(
        d["names"],
        serde_json::json!([
            "/dev/gpt/tank-d1",
            "/dev/disk/by-partlabel/tank-d1",
            "/dev/gptid/33333333-3333-3333-3333-333333333333",
            "/dev/disk/by-partuuid/33333333-3333-3333-3333-333333333333",
        ])
    );
    assert!(
        d["config"].is_null(),
        "no label configuration survives: {d}"
    );
    let members = &v["pools"][0]["tops"][0]["members"];
    assert_eq!(members[0]["present"], good_s);
    assert!(members[1]["present"].is_null());
    assert_eq!(members[1]["path"], "/dev/gpt/tank-d1");
    assert_eq!(members[1]["named_by"], disk_s, "{members}");
    assert!(members[0].get("named_by").is_none());
    assert!(
        v["pools"][0].get("name_hints").is_none(),
        "matched, so not a mere hint"
    );
    let guid = members[1]["guid"].as_str().unwrap().to_owned();

    let (_, text, _) = run(&["-q", "scan", &good_s, &disk_s]);
    assert!(text.contains("named: /dev/gpt/tank-d1"), "{text}");
    assert!(
        text.contains(&format!(
            "MISSING; {disk_s} is named /dev/gpt/tank-d1 on its own disk (SPEC F-71) — bind it with --assume-member {disk_s}={guid}"
        )),
        "{text}"
    );

    // The binding the scan spelled out is accepted: a sibling with its
    // labels describes the pool (F-62), the bare disk takes the vacant
    // leaf, and the volume comes out.
    let img = dir.join("bound.img");
    let (code, out, err) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &good_s,
        &disk_s,
        "--assume-member",
        &format!("{disk_s}={guid}"),
        "-o",
        &img.to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{out}{err}");
    let (_, whole, _) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &good_s,
        "-o",
        &dir.join("whole.img").to_string_lossy(),
    ]);
    assert_eq!(
        json(&out)["volumes"][0]["sha256"],
        json(&whole)["volumes"][0]["sha256"]
    );
}

/// A name that only contains the pool's name is reported as a hint and
/// binds nothing; a name no pool recorded is just listed.
#[test]
fn a_name_that_merely_contains_the_pool_name_is_a_hint_not_a_binding() {
    let dir = scratch("gpt-hint");
    let members = plain_members();
    let good = dir.join("member0.img");
    std::fs::write(&good, &members[0]).unwrap();
    let mut bare = members[1].clone();
    wipe_configs(&mut bare);
    let disk = dir.join("disk-x.img");
    std::fs::write(&disk, gpt_wrap(&bare, 1 << 20, "tank-spare", [0x44; 16])).unwrap();
    let (good_s, disk_s) = (
        good.to_string_lossy().into_owned(),
        disk.to_string_lossy().into_owned(),
    );
    let (code, out, _) = run(&["-q", "-f", "json", "scan", &good_s, &disk_s]);
    assert_eq!(code, 0, "{out}");
    let v = json(&out);
    let members = &v["pools"][0]["tops"][0]["members"];
    assert!(members[1].get("named_by").is_none(), "{members}");
    assert_eq!(
        v["pools"][0]["name_hints"],
        serde_json::json!([
            {"device": disk_s, "name": "/dev/gpt/tank-spare"},
            {"device": disk_s, "name": "/dev/disk/by-partlabel/tank-spare"},
        ])
    );
    let (_, text, _) = run(&["-q", "scan", &good_s, &disk_s]);
    assert!(
        text.contains("hint: ") && text.contains("nothing binds on it"),
        "{text}"
    );
    assert!(text.contains(" MISSING\n"), "{text}");
}

/// `glabel`: the name is in the last sector and the provider ZFS saw
/// ends there, so the rear labels are read where the metadata says and
/// the device answers to `/dev/label/NAME`.
#[test]
fn a_glabel_names_the_member_and_says_how_long_its_provider_was() {
    let dir = scratch("glabel");
    // A member 512 bytes short of a 256 KiB boundary, so that the one
    // sector the metadata occupies moves the rear labels.
    let psize = SIZE - 512;
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
    let mut members = vec![vec![0u8; psize as usize], vec![0u8; psize as usize]];
    let mut a = Alloc::new(0x20_0000);
    build_sample_mos(&mut pool, &mut members, &mut a);
    for (i, m) in members.iter_mut().enumerate() {
        pool.write_labels(i, m);
    }
    let mut tail = vec![0u8; 512];
    tail[..11].copy_from_slice(b"GEOM::LABEL");
    tail[16..20].copy_from_slice(&2u32.to_le_bytes());
    tail[20..27].copy_from_slice(b"tank-d0");
    // As glabel writes it: the size of the provider it was put on, the
    // metadata sector included.
    tail[36..44].copy_from_slice(&SIZE.to_le_bytes());
    let mut labelled = members[0].clone();
    labelled.extend_from_slice(&tail);
    let img = dir.join("label0.img");
    std::fs::write(&img, &labelled).unwrap();
    let img_s = img.to_string_lossy().into_owned();

    let (code, out, _) = run(&["-q", "-f", "json", "scan", &img_s]);
    assert_eq!(code, 0, "{out}");
    let d = &json(&out)["devices"][0];
    assert_eq!(d["size"], SIZE);
    assert_eq!(d["vdev_size"], psize);
    assert_eq!(d["vdev_base_from"], "GEOM metadata");
    assert_eq!(d["geom"]["class"], "label");
    assert_eq!(d["geom"]["name"], "tank-d0");
    assert_eq!(d["geom"]["provsize"], SIZE);
    assert_eq!(d["names"], serde_json::json!(["/dev/label/tank-d0"]));
    let ok = d["labels"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|l| l["config_checksum"] == "ok")
        .count();
    assert_eq!(ok, 4, "{}", d["labels"]);

    let (_, text, _) = run(&["-q", "scan", &img_s]);
    assert!(
        text.contains(&format!(
            "GEOM::LABEL v2 in the last sector: this was /dev/label/tank-d0, provider {SIZE} bytes; the vdev is {psize} bytes and its rear labels were read there"
        )),
        "{text}"
    );

    // And the pool reads through it.
    let (code, out, err) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &img_s,
        "-o",
        &dir.join("out.img").to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{out}{err}");
    assert_eq!(json(&out)["volumes"][0]["blocks_zeroed"], 0);
}

/// `geli` is named for what it is: nothing under it is readable, and the
/// scan says so instead of reporting a disk with no ZFS on it.
#[test]
fn a_geli_provider_is_reported_as_encrypted() {
    let dir = scratch("geli");
    let mut img = vec![0u8; SIZE as usize];
    let at = img.len() - 512;
    img[at..at + 9].copy_from_slice(b"GEOM::ELI");
    img[at + 16..at + 20].copy_from_slice(&7u32.to_le_bytes());
    let p = dir.join("eli.img");
    std::fs::write(&p, &img).unwrap();
    let p_s = p.to_string_lossy().into_owned();
    let (_, out, _) = run(&["-q", "-f", "json", "scan", &p_s]);
    let d = &json(&out)["devices"][0];
    assert_eq!(d["geom"]["class"], "eli");
    assert!(d.get("names").is_none(), "{d}");
    let (_, text, _) = run(&["-q", "scan", &p_s]);
    assert!(
        text.contains("GEOM::ELI v7 in the last sector; the member is geli-encrypted"),
        "{text}"
    );
}

/// The SHA-256 of the volume out of any healthy fixture; what every
/// shape below has to come to.
fn reference_sha(dir: &Path) -> String {
    let refdir = dir.join("ref");
    std::fs::create_dir_all(&refdir).expect("ref dir");
    let members = write_members(&refdir, &plain_members());
    let (code, out, _) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &members[0],
        "-o",
        &dir.join("ref.img").to_string_lossy(),
    ]);
    assert_eq!(code, 0);
    json(&out)["volumes"][0]["sha256"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// A three-way mirror, the shape `zpool attach` leaves: the pool reads
/// from any one side, and the damage-matrix shape — one side's labels
/// gone, another side absent — binds the bare side by reading through
/// it, with the third describing the pool (SPEC F-62).
#[test]
fn a_three_way_mirror_reads_from_one_side_and_binds_a_bare_one() {
    let dir = scratch("mirror3");
    let want = reference_sha(&dir);
    let mut pool = Pool::mirror_of("tank", 0x4242, 12, 3).txgs(&[(100, 1)]);
    let mut members = vec![vec![0u8; SIZE as usize]; 3];
    let mut a = Alloc::new(0x20_0000);
    build_sample_mos(&mut pool, &mut members, &mut a);
    for (i, m) in members.iter_mut().enumerate() {
        pool.write_labels(i, m);
    }
    let paths = write_members(&dir, &members);

    let (code, out, _) = run(&["-q", "-f", "json", "scan", &paths[0], &paths[1], &paths[2]]);
    assert_eq!(code, 0, "{out}");
    let top = &json(&out)["pools"][0]["tops"][0];
    assert_eq!(top["kind"], "mirror");
    assert_eq!(top["members"].as_array().unwrap().len(), 3);
    assert!(top["members"]
        .as_array()
        .unwrap()
        .iter()
        .all(|m| !m["present"].is_null()));

    // Two sides gone: the third is a whole copy.
    let (code, out, _) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &paths[2],
        "-o",
        &dir.join("one-side.img").to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(json(&out)["volumes"][0]["sha256"], want);

    // The matrix shape: side 0 without labels, side 1 absent, side 2
    // intact. The bare side is bound by reading, and both sides serve.
    let mut bare = members[0].clone();
    wipe_configs(&mut bare);
    let bare_p = dir.join("bare0.img");
    std::fs::write(&bare_p, &bare).unwrap();
    let bare_s = bare_p.to_string_lossy().into_owned();
    let (code, out, err) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &bare_s,
        &paths[2],
        "--assume-member",
        &bare_s,
        "-o",
        &dir.join("bound.img").to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(err.contains("read as leaf"), "{err}");
    assert_eq!(json(&out)["volumes"][0]["sha256"], want);
}

/// A member with all four labels gone — rings included, so no anchor —
/// sitting 1 MiB into a larger image with no partition table: the
/// siblings' asize bounds where its vdev can begin, the walk confirms
/// the base, and the volume comes out through it (SPEC F-62).
#[test]
fn a_bare_member_with_no_anchor_is_read_at_the_base_the_walk_confirms() {
    let dir = scratch("no-anchor");
    let want = reference_sha(&dir);
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
    pool.asize = Some((SIZE - LABEL_START_SIZE - 2 * LABEL_SIZE) & !4095);
    let mut members = vec![vec![0u8; SIZE as usize]; 2];
    let mut a = Alloc::new(0x20_0000);
    build_sample_mos(&mut pool, &mut members, &mut a);
    for (i, m) in members.iter_mut().enumerate() {
        pool.write_labels(i, m);
    }
    let aligned = SIZE & !(LABEL_SIZE - 1);
    for off in [
        0,
        LABEL_SIZE,
        aligned - 2 * LABEL_SIZE,
        aligned - LABEL_SIZE,
    ] {
        members[0][off as usize..(off + LABEL_SIZE) as usize].fill(0);
    }
    let mut image = vec![0x5au8; 1 << 20];
    image.extend_from_slice(&members[0]);
    image.extend_from_slice(&vec![0u8; 8 << 20]);
    let bare = dir.join("bare-shifted.img");
    std::fs::write(&bare, &image).unwrap();
    let bare_s = bare.to_string_lossy().into_owned();
    let good = dir.join("member1.img");
    std::fs::write(&good, &members[1]).unwrap();
    let good_s = good.to_string_lossy().into_owned();

    // Nothing on the member says where it begins.
    let (_, out, _) = run(&["-q", "-f", "json", "scan", &bare_s]);
    let d = &json(&out)["devices"][0];
    assert!(d["config"].is_null() && d["newest_txg"].is_null(), "{d}");

    // With the sibling withheld from the read, the volume has to come
    // through the bare member at the confirmed base.
    let (code, out, err) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &bare_s,
        &good_s,
        "--assume-member",
        &bare_s,
        "-o",
        &dir.join("bound.img").to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(err.contains("with its vdev at byte 1048576"), "{err}");
    assert_eq!(json(&out)["volumes"][0]["sha256"], want);
}

/// A pool of two mirrors, the MOS on one and the volume's data on the
/// other: `scan` shows both tops with their members, the volume reads
/// across them, and with every member of the data mirror gone its
/// blocks are refused by the name of the top nothing describes.
#[test]
fn a_pool_of_two_mirrors_reads_across_both_tops() {
    let dir = scratch("striped");
    let want = reference_sha(&dir);
    let (_, members) = two_top_mirror_members("tank", 0x7070, 12, [2, 3], &[(100, 1)], SIZE);
    let paths = write_members(&dir, &members);
    let all: Vec<&str> = paths.iter().map(String::as_str).collect();

    let mut args = vec!["-q", "-f", "json", "scan"];
    args.extend(&all);
    let (code, out, _) = run(&args);
    assert_eq!(code, 0, "{out}");
    let pool = &json(&out)["pools"][0];
    assert_eq!(pool["readable"], true, "{pool}");
    assert_eq!(pool["missing_tops"], serde_json::json!([]));
    let tops = pool["tops"].as_array().unwrap();
    assert_eq!(tops.len(), 2, "{pool}");
    assert_eq!(
        (tops[0]["id"].as_u64(), tops[1]["id"].as_u64()),
        (Some(0), Some(1))
    );
    assert_eq!(
        (
            tops[0]["members"].as_array().unwrap().len(),
            tops[1]["members"].as_array().unwrap().len()
        ),
        (2, 3)
    );
    assert!(tops[0]["members"][0]["present"]
        .as_str()
        .unwrap()
        .ends_with("member0.img"));
    assert!(tops[1]["members"][2]["present"]
        .as_str()
        .unwrap()
        .ends_with("member4.img"));

    let dump = |members: &[&str], name: &str| {
        let mut args = vec!["-q", "-f", "json", "dump", "tank/vm/disk0"];
        args.extend(members);
        let out_p = dir.join(name).to_string_lossy().into_owned();
        args.extend(["-o", &out_p]);
        let (code, out, _) = run(&args);
        (code, json(&out))
    };
    let (code, v) = dump(&all, "all.img");
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["volumes"][0]["sha256"], want);

    // One side of each mirror: still the whole volume.
    let (code, v) = dump(&[all[1], all[3]], "one-each.img");
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["volumes"][0]["sha256"], want);

    // mirror-1 gone entirely: the MOS lists the volume, the data blocks
    // name a top nothing present describes, and the image is zeros with
    // the reason on every range (exit 4).
    let (code, out, _) = run(&["-q", "-f", "json", "scan", all[0], all[1]]);
    assert_eq!(code, 0);
    let pool = &json(&out)["pools"][0];
    assert_eq!(pool["missing_tops"], serde_json::json!([1]), "{pool}");
    assert_eq!(pool["readable"], false);
    let (code, v) = dump(&[all[0], all[1]], "no-data-top.img");
    assert_eq!(code, 4, "{v}");
    let vol = &v["volumes"][0];
    assert_eq!(vol["blocks_zeroed"], 2, "{vol}");
    assert!(
        vol["bad"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("unknown top-level vdev 1"),
        "{vol}"
    );
}

/// An image made with ddrescue comes with its map (SPEC F-72): the
/// sectors the imager could not read are refused before they are read,
/// so a block crossing them is kept as far as the imager read it and
/// the rest is zeros with the imager named as the reason — never a
/// checksum failure with no cause. `scan` reports the map, and which
/// labels the unread ranges touch.
#[test]
fn an_imagers_map_names_what_the_disk_never_gave() {
    let dir = scratch("ddrescue-map");
    let members = write_members(&dir, &plain_members());
    // Two sectors inside the volume's first data block, and the whole of
    // label L1, never read by the imager.
    let bad_at = LABEL_START_SIZE + SAMPLE_ZVOL_BLOCK0_OFFSET + 2048;
    let map = dir.join("member0.map");
    std::fs::write(
        &map,
        format!(
            "# Mapfile. Created by GNU ddrescue version 1.27\n# current_pos  current_status  current_pass\n{:#x}     +               1\n#      pos        size  status\n0x0  {:#x}  +\n{:#x}  0x40000  -\n{:#x}  {:#x}  +\n{:#x}  0x400  -\n{:#x}  {:#x}  +\n",
            SIZE,
            LABEL_SIZE,
            LABEL_SIZE,
            2 * LABEL_SIZE,
            bad_at - 2 * LABEL_SIZE,
            bad_at,
            bad_at + 0x400,
            SIZE - bad_at - 0x400
        ),
    )
    .unwrap();
    let spec = format!("{}={}", members[0], map.display());

    let (code, out, _) = run(&["-q", "-f", "json", "scan", &members[0], "--map", &spec]);
    assert_eq!(code, 0, "{out}");
    let d = &json(&out)["devices"][0];
    assert_eq!(d["map"]["unreadable_bytes"], 0x40000 + 0x400, "{d}");
    assert_eq!(d["map"]["labels_touched"], serde_json::json!([1]), "{d}");
    assert_eq!(d["map"]["by_status"]["-"], 0x40000 + 0x400);
    assert_eq!(
        d["labels"][1]["config_checksum"], "missing",
        "{}",
        d["labels"][1]
    );
    let (_, text, _) = run(&["-q", "scan", &members[0], "--map", &spec]);
    assert!(
        text.contains(
            "never read, touching label(s) L1; they are refused, not trusted (SPEC F-72)"
        ),
        "{text}"
    );

    // Alone, the member's block 0 is kept less the two sectors, and the
    // reason names the imager.
    let (code, out, err) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &members[0],
        "--map",
        &spec,
        "-o",
        &dir.join("mapped.img").to_string_lossy(),
    ]);
    assert_eq!(code, 4, "{out}{err}");
    let v = &json(&out)["volumes"][0];
    assert_eq!(
        (v["blocks_salvaged"].as_u64(), v["blocks_zeroed"].as_u64()),
        (Some(1), Some(0)),
        "{v}"
    );
    assert_eq!(
        (v["bad"][0]["offset"].as_u64(), v["bad"][0]["len"].as_u64()),
        (Some(2048), Some(1024)),
        "{v}"
    );
    assert!(
        v["bad"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("imager could not read (ddrescue map)"),
        "{v}"
    );
    assert!(
        err.contains("the imager's map says 263168 byte(s) in 2 range(s) were never read"),
        "{err}"
    );
    let mut want = std::fs::read(dir.join("ref.img")).unwrap_or_default();
    if want.is_empty() {
        let _ = reference_sha(&dir);
        want = std::fs::read(dir.join("ref.img")).unwrap();
    }
    want[2048..3072].fill(0);
    assert_eq!(std::fs::read(dir.join("mapped.img")).unwrap(), want);

    // The other side heals it: the map only says what this member never
    // gave, and the mirror still has it.
    let (code, out, _) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &members[0],
        &members[1],
        "--map",
        &spec,
        "-o",
        &dir.join("healed.img").to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(json(&out)["volumes"][0]["blocks_salvaged"], 0);

    // A map for a file that is not a member is a usage error.
    let (code, _, err) = run(&[
        "-q",
        "scan",
        &members[0],
        "--map",
        &format!("{}={}", members[1], map.display()),
    ]);
    assert_eq!(code, 1);
    assert!(err.contains("is not among the devices given"), "{err}");
}

/// A block device whose labels do not verify is not searched for
/// anchors (SPEC N-10): the scan says so, the JSON carries it, and the
/// exit code is 5. `/dev/null` is the one device every test host has
/// — a character device of no size, which is what a wiped disk looks
/// like to the label reader. With `--surface-scan-on-device` the search
/// runs, finds nothing on nothing, and the run is an ordinary failure.
#[test]
fn a_block_device_is_not_searched_for_anchors_without_leave() {
    if !std::path::Path::new("/dev/null").exists() {
        return;
    }
    let (code, out, _err) = run(&["-q", "scan", "/dev/null"]);
    assert_eq!(code, 5, "{out}");
    assert!(
        out.contains("zero point: not searched") && out.contains("SPEC N-10"),
        "{out}"
    );
    let (code, out, _err) = run(&["-q", "-f", "json", "scan", "/dev/null"]);
    assert_eq!(code, 5, "{out}");
    assert_eq!(
        json(&out)["devices"][0]["surface_scan_refused"],
        true,
        "{out}"
    );
    let (code, out, _err) = run(&["-q", "scan", "/dev/null", "--surface-scan-on-device"]);
    assert_ne!(code, 5, "{out}");
    assert!(!out.contains("not searched"), "{out}");
}

/// `--retries` is gone with the policy it served (SPEC F-33): a device
/// is never asked twice, and an image never needs asking twice. On
/// every subcommand — `scan` has its own flag wiring, so it is tried
/// on its own.
#[test]
fn retries_are_no_longer_an_option() {
    let (code, _out, err) = run(&[
        "dump",
        "tank/vm/disk0",
        "/dev/null",
        "--retries",
        "3",
        "-o",
        "/nonexistent/x.img",
    ]);
    // A flag the command line does not take is a usage error, exit 1.
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("--retries"), "{err}");
    let (code, _out, err) = run(&["scan", "/dev/null", "--retries", "3"]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("--retries"), "{err}");
}

/// A device reached through a symlink — `/dev/mapper/NAME`,
/// `/dev/disk/by-id/…`, the paths an operator actually types — is the
/// device it points at: the refusal follows the file the open resolves
/// to, not the name (SPEC N-10).
#[cfg(unix)]
#[test]
fn a_symlink_to_a_device_is_still_a_device() {
    if !std::path::Path::new("/dev/null").exists() {
        return;
    }
    let dir = std::env::temp_dir().join(format!("zvolrescue-symlink-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let link = dir.join("disk");
    std::os::unix::fs::symlink("/dev/null", &link).unwrap();
    let link = link.to_string_lossy().into_owned();
    let (code, out, _err) = run(&["-q", "-f", "json", "scan", &link]);
    assert_eq!(code, 5, "{out}");
    assert_eq!(
        json(&out)["devices"][0]["surface_scan_refused"],
        true,
        "{out}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A run that produces nothing — no such dataset, no such txg — still
/// ends the way every run ends: the report on stdout, and a record in
/// the evidence log with the status. Before this, such runs returned
/// their code from the middle of `run` and wrote no record at all,
/// which is how a device's refusal on the way to the dataset went
/// unrecorded (SPEC F-33, N-10). Images here, so the status is 3; the
/// device case is the same path and is checked in CI on a real device.
#[test]
fn a_run_that_produces_nothing_still_writes_its_record() {
    let dir = scratch("early-record");
    let members = write_members(&dir, &plain_members());
    let log = dir.join("ev.jsonl");
    let log_s = log.to_string_lossy().into_owned();
    let img = dir.join("nothere.img");
    let (code, out, err) = run(&[
        "-q",
        "-f",
        "json",
        "--evidence-log",
        &log_s,
        "dump",
        "tank/nothere",
        &members[0],
        &members[1],
        "-o",
        &img.to_string_lossy(),
    ]);
    assert_eq!(code, 3, "{err}");
    let v = json(&out);
    assert_eq!(v["volumes"].as_array().map(Vec::len), Some(0), "{out}");
    assert!(
        v["txgs_searched"].as_array().is_some_and(|t| !t.is_empty()),
        "{out}"
    );
    assert!(!img.exists(), "nothing was written");
    let last = |log: &Path| -> serde_json::Value {
        let text = std::fs::read_to_string(log).expect("evidence log");
        serde_json::from_str(text.lines().last().expect("a record")).expect("a JSON record")
    };
    let rec = last(&log);
    assert_eq!(rec["status"], 3, "{rec}");
    assert_eq!(
        rec["result"]["volumes"].as_array().map(Vec::len),
        Some(0),
        "{rec}"
    );
    assert!(
        rec.get("incidents")
            .is_none_or(|i| i.as_array().is_some_and(Vec::is_empty)),
        "{rec}"
    );
    // A txg no member has: the run ends before the pool is read.
    let (code, _out, err) = run(&[
        "-q",
        "--evidence-log",
        &log_s,
        "list",
        &members[0],
        &members[1],
        "--txg",
        "1",
    ]);
    assert_eq!(code, 3, "{err}");
    let rec = last(&log);
    assert_eq!(rec["status"], 3, "{rec}");
    assert_eq!(rec["result"]["produced"], false, "{rec}");
    assert_eq!(
        rec["inputs"].as_array().map(Vec::len),
        Some(2),
        "both members are inputs: {rec}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A refused `dump -r` changes nothing: every name it writes is judged
/// before any link lying there is removed — one refused over the state
/// of an image had removed the link at the image's name already — and a
/// log given an image's name in the directory is refused before it is
/// created over an image an earlier run wrote.
#[cfg(unix)]
#[test]
fn a_refused_bulk_dump_changes_nothing() {
    let dir = scratch("bulk-refused");
    let paths = write_members(&dir, &plain_members());
    let out = dir.join("bulk");
    std::fs::create_dir_all(&out).unwrap();
    let o = out.to_string_lossy().into_owned();
    let outside = dir.join("outside.txt");
    std::fs::write(&outside, "precious").unwrap();
    let link = out.join("tank_vm_disk0.img");
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    // The image's state is a member under another name.
    std::fs::hard_link(&paths[1], out.join("tank_vm_disk0.img.resume.json")).unwrap();
    let (code, _, err) = run(&["-q", "dump", "-r", "tank", &paths[0], &paths[1], "-o", &o]);
    assert_eq!(code, 5, "{err}");
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink(),
        "the link was removed by a run that was refused"
    );
    std::fs::remove_file(out.join("tank_vm_disk0.img.resume.json")).unwrap();
    std::fs::remove_file(&link).unwrap();

    // An image an earlier run wrote, and a debug log given its name.
    let (code, _, err) = run(&["-q", "dump", "-r", "tank", &paths[0], &paths[1], "-o", &o]);
    assert_eq!(code, 0, "{err}");
    let image = std::fs::read(&link).unwrap();
    let names = [
        link.clone(),
        out.join("not-yet.img"),
        out.join("not-yet.img.resume.json"),
        out.join("manifest.json"),
    ];
    for flag in ["--debug-log", "--evidence-log"] {
        for log in &names {
            let l = log.to_string_lossy().into_owned();
            let (code, _, err) = run(&[
                "-q", flag, &l, "dump", "-r", "tank", &paths[0], &paths[1], "-o", &o,
            ]);
            assert_eq!(code, 5, "{flag} {l}: {err}");
            assert!(err.contains(&format!("refusing {flag}")), "{err}");
        }
    }
    assert_eq!(std::fs::read(&link).unwrap(), image);
    assert!(!out.join("not-yet.img").exists());
    assert!(!out.join("not-yet.img.resume.json").exists());
    // A log of another name in that directory is no image, and is kept.
    let log = out.join("case.jsonl").to_string_lossy().into_owned();
    let (code, _, err) = run(&[
        "-q",
        "--evidence-log",
        &log,
        "dump",
        "-r",
        "tank",
        &paths[0],
        &paths[1],
        "-o",
        &o,
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(Path::new(&log).exists());
}

/// `dump -r` replaces a link already lying in its directory under a name
/// it writes, rather than writing through it to a file outside the tree;
/// an evidence log that cannot be written stops the run before anything
/// is read; and a directory with no volume under it is no success.
#[test]
fn a_bulk_dump_writes_only_its_own_files() {
    let dir = scratch("bulk-own-files");
    let paths = write_members(&dir, &plain_members());
    let out = dir.join("bulk");
    std::fs::create_dir_all(&out).unwrap();
    let outside = dir.join("outside.txt");
    std::fs::write(&outside, "precious").unwrap();
    std::os::unix::fs::symlink(&outside, out.join("tank_vm_disk0.img")).unwrap();
    std::os::unix::fs::symlink(&outside, out.join("manifest.json")).unwrap();
    let o = out.to_string_lossy().into_owned();
    let (code, _, err) = run(&["-q", "dump", "-r", "tank", &paths[0], &paths[1], "-o", &o]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(std::fs::read_to_string(&outside).unwrap(), "precious");
    for name in ["tank_vm_disk0.img", "manifest.json"] {
        let m = std::fs::symlink_metadata(out.join(name)).unwrap();
        assert!(m.is_file(), "{name} is a file of its own");
    }
    // A link to a member is replaced the same way: the guard followed it
    // and refused the run (exit 5), the member never at risk.
    let member = std::fs::read(&paths[0]).unwrap();
    std::fs::remove_file(out.join("tank_vm_disk0.img")).unwrap();
    std::os::unix::fs::symlink(&paths[0], out.join("tank_vm_disk0.img")).unwrap();
    let (code, _, err) = run(&["-q", "dump", "-r", "tank", &paths[0], &paths[1], "-o", &o]);
    assert_eq!(code, 0, "{err}");
    assert!(
        std::fs::read(&paths[0]).unwrap() == member,
        "the member is untouched"
    );
    assert!(std::fs::symlink_metadata(out.join("tank_vm_disk0.img"))
        .unwrap()
        .is_file());

    let img = dir.join("e.img").to_string_lossy().into_owned();
    let log = dir
        .join("no/such/dir/case.jsonl")
        .to_string_lossy()
        .into_owned();
    let (code, _, err) = run(&[
        "--evidence-log",
        &log,
        "-q",
        "dump",
        "tank/vm/disk0",
        &paths[0],
        &paths[1],
        "-o",
        &img,
    ]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("cannot write evidence log"), "{err}");
    assert!(!Path::new(&img).exists(), "nothing was extracted first");

    // A filesystem with no volume under it.
    let mut pool = Pool::mirror("tank", 0x5eed_0000_0000_0004, 12)
        .txgs(&[(4816228, 1757100000), (4816229, 1757100005)]);
    let zpl = write_members(&dir.join("zpl"), &{
        std::fs::create_dir_all(dir.join("zpl")).unwrap();
        zpl_members(&mut pool, 64 * 1024 * 1024)
    });
    let empty = dir.join("empty").to_string_lossy().into_owned();
    let (code, _, err) = run(&[
        "-q", "dump", "-r", "tank/fs", &zpl[0], &zpl[1], "-o", &empty,
    ]);
    assert_eq!(code, 3, "{err}");
    assert!(err.contains("no volume under tank/fs"), "{err}");
    assert!(!Path::new(&empty).exists());
    // A filesystem given to `dump` is the wrong command, not an
    // unreadable pool: exit 1, the companion that reads it named.
    let img = dir.join("fs.img").to_string_lossy().into_owned();
    let (code, _, err) = run(&["-q", "dump", "tank/fs", &zpl[0], &zpl[1], "-o", &img]);
    assert_eq!(code, 1, "{err}");
    assert!(
        err.contains("is a filesystem, not a volume") && !err.contains("I/O error"),
        "{err}"
    );
}

/// An image sent to `/dev/null` is hashed on the way and kept nowhere:
/// the record carries its hash in the result and no output to check it
/// against. It was an output of 0 bytes over the image's hash, which
/// `zvolreport verify` called changed as soon as it was made.
#[test]
fn an_image_sent_to_dev_null_is_no_output_on_the_record() {
    if !std::path::Path::new("/dev/null").exists() {
        return;
    }
    let dir = scratch("dev-null-record");
    let m = write_members(&dir, &plain_members());
    let log = dir.join("ev.jsonl").to_string_lossy().into_owned();
    let (code, _, err) = run(&[
        "-q",
        "--evidence-log",
        &log,
        "dump",
        "tank/vm/disk0",
        &m[0],
        &m[1],
        "-o",
        "/dev/null",
    ]);
    assert_eq!(code, 0, "{err}");
    let record: serde_json::Value =
        serde_json::from_str(std::fs::read_to_string(&log).unwrap().trim()).unwrap();
    assert_eq!(record["outputs"], serde_json::json!([]), "{record}");
    assert_eq!(record["result"]["volumes"][0]["output"], "/dev/null");
    assert!(record["result"]["volumes"][0]["sha256"].is_string());
}

/// An argument the command line cannot take is a usage error, exit 1,
/// as the manual says: clap's own 2 is "evidence unreadable" here, and a
/// misspelt flag read to a script as a disk that would not open. Help
/// and the version still end with 0.
#[test]
fn a_command_line_that_does_not_parse_is_a_usage_error() {
    for args in [
        &["--no-such-flag"][..],
        &["dump"],
        &["scan", "--txg", "x"],
        &[],
    ] {
        let (code, _, err) = run(args);
        assert_eq!(code, 1, "{args:?}: {err}");
    }
    for args in [&["--help"][..], &["--version"], &["dump", "--help"]] {
        let (code, out, _) = run(args);
        assert_eq!(code, 0, "{args:?}");
        assert!(!out.is_empty(), "{args:?}");
    }
}

/// `dump -r --resume` keeps an image the run it takes up finished, when
/// the file still hashes to what that run's manifest records, and
/// extracts again one that does not. It used to extract every finished
/// image again from block 0: hours, for a run stopped at its last volume.
#[test]
fn a_bulk_resume_keeps_the_images_already_finished() {
    let dir = scratch("bulk-resume-keeps");
    let paths = write_members(&dir, &plain_members());
    let out = dir.join("bulk");
    let o = out.to_string_lossy().into_owned();
    let (code, _, err) = run(&["-q", "dump", "-r", "tank", &paths[0], &paths[1], "-o", &o]);
    assert_eq!(code, 0, "{err}");
    let image = out.join("tank_vm_disk0.img");
    let whole = std::fs::read(&image).unwrap();
    let modified = std::fs::metadata(&image).unwrap().modified().unwrap();

    let (code, text, err) = run(&[
        "dump", "-r", "--resume", "--hash", "md5", "tank", &paths[0], &paths[1], "-o", &o,
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("keeping tank/vm/disk0"), "{err}");
    assert!(!err.contains("starting from block 0"), "{err}");
    assert!(text.contains("(kept: whole"), "{text}");
    assert!(text.contains("0 volume(s) written, 1 kept"), "{text}");
    assert!(
        text.contains("md5:"),
        "the digest asked for is taken: {text}"
    );
    assert_eq!(
        std::fs::metadata(&image).unwrap().modified().unwrap(),
        modified,
        "the image was not written again"
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["volumes"][0]["kept"], true, "{manifest}");

    // The same directory by another spelling of its path is the same
    // images: a manifest names them as the run that wrote it was told.
    let respelt = dir
        .join("..")
        .join(dir.file_name().unwrap())
        .join("bulk")
        .to_string_lossy()
        .into_owned();
    let (code, _, err) = run(&[
        "dump", "-r", "--resume", "tank", &paths[0], &paths[1], "-o", &respelt,
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("keeping tank/vm/disk0"), "{err}");

    // A byte changed since: not the image that run finished.
    let mut changed = whole.clone();
    changed[4096] ^= 0xff;
    std::fs::write(&image, &changed).unwrap();
    let (code, _, err) = run(&[
        "-q", "-f", "json", "dump", "-r", "--resume", "tank", &paths[0], &paths[1], "-o", &o,
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("its sha256 differs"), "{err}");
    assert_eq!(std::fs::read(&image).unwrap(), whole);

    // An image with blocks written as zeros is not whole, and is
    // extracted again: what did not read then may read now, with the
    // member that was missing given.
    let mut m = manifest.clone();
    m["volumes"][0]["blocks_zeroed"] = 1.into();
    std::fs::write(out.join("manifest.json"), m.to_string()).unwrap();
    let (code, _, err) = run(&[
        "dump", "-r", "--resume", "tank", &paths[0], &paths[1], "-o", &o,
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(!err.contains("keeping"), "{err}");
    assert!(
        !out.join("manifest.json.tmp").exists(),
        "the manifest is renamed into place"
    );

    // A manifest of another pool keeps nothing, and says so; one made
    // before the pool's GUID was known is taken by its volumes.
    for (guid, kept) in [("0x0000000000000bad", false), ("0x0000000000000000", true)] {
        let mut m = manifest.clone();
        m["pool_guid"] = guid.into();
        std::fs::write(out.join("manifest.json"), m.to_string()).unwrap();
        let (code, _, err) = run(&[
            "dump", "-r", "--resume", "tank", &paths[0], &paths[1], "-o", &o,
        ]);
        assert_eq!(code, 0, "{err}");
        assert_eq!(err.contains("keeping tank/vm/disk0"), kept, "{guid}: {err}");
        assert_eq!(err.contains("is of pool"), !kept, "{guid}: {err}");
    }

    // The record of a kept image is this run's own. The manifest's
    // entry was copied whole into it, and one edited to name another
    // dataset at another time — an escape sequence in the name — was
    // printed so and written to the evidence log as what this run
    // found.
    let mut m = manifest.clone();
    m["volumes"][0]["dataset"] = "tank/secret\u{1b}[2K\rFORGED".into();
    m["volumes"][0]["time"] = "1999-01-01T00:00:00Z".into();
    m["volumes"][0]["warnings"] = serde_json::json!(["nothing to see"]);
    std::fs::write(out.join("manifest.json"), m.to_string()).unwrap();
    let (code, text, err) = run(&[
        "-f", "json", "dump", "-r", "--resume", "tank", &paths[0], &paths[1], "-o", &o,
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("keeping tank/vm/disk0"), "{err}");
    assert!(!text.contains("FORGED") && !text.contains("1999"), "{text}");
    let v = &json(&text)["volumes"][0];
    assert_eq!(v["dataset"], "tank/vm/disk0", "{v}");
    assert_eq!(v["kept"], true, "{v}");
    assert_eq!(v["time"], manifest["volumes"][0]["time"], "{v}");
    assert!(v.get("warnings").is_none(), "{v}");

    // Counts that are not this volume's are not taken with it: the
    // image is extracted again. Nor is an image whole whose blocks
    // written as zeros and salvaged add up to none.
    for (key, value, why) in [
        (
            "blocks_total",
            serde_json::json!(4097),
            "is not this volume's",
        ),
        ("blocksize", serde_json::json!(512), "is not this volume's"),
        (
            "blocks_read",
            serde_json::json!(u64::MAX),
            "is not this volume's",
        ),
        ("blocks_zeroed", serde_json::json!(u64::MAX), ""),
    ] {
        let mut m = manifest.clone();
        m["volumes"][0][key] = value;
        if key == "blocks_zeroed" {
            m["volumes"][0]["blocks_salvaged"] = 1.into();
        }
        std::fs::write(out.join("manifest.json"), m.to_string()).unwrap();
        let (code, _, err) = run(&[
            "dump", "-r", "--resume", "tank", &paths[0], &paths[1], "-o", &o,
        ]);
        assert_eq!(code, 0, "{key}: {err}");
        assert!(!err.contains("keeping"), "{key}: {err}");
        assert!(err.contains(why), "{key}: {err}");
        assert_eq!(std::fs::read(&image).unwrap(), whole, "{key}");
    }
}

/// `dump -r VOL@SNAP` extracts that snapshot of every volume under VOL
/// which has one; it was "no volume under …", exit 3, while a plain
/// `dump` of the same name read it.
#[test]
fn a_bulk_dump_takes_a_snapshot_name() {
    let dir = scratch("bulk-snapshot");
    let (_, members) = two_top_mirror_members("tank", 0x7070, 12, [2, 3], &[(100, 1)], SIZE);
    let paths = write_members(&dir, &members);
    let mut args: Vec<String> = ["-q", "-f", "json", "dump", "-r", "tank/vm/disk0@before"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    args.extend(paths.iter().cloned());
    let out = dir.join("bulk");
    args.extend(["-o".to_string(), out.to_string_lossy().into_owned()]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (code, text, err) = run(&args);
    assert_eq!(code, 0, "{err}");
    let volumes = json(&text)["volumes"].as_array().unwrap().clone();
    assert_eq!(volumes.len(), 1, "{text}");
    assert_eq!(volumes[0]["dataset"], "tank/vm/disk0@before");
    assert!(out.join("tank_vm_disk0@before.img").is_file());
    assert!(
        !out.join("tank_vm_disk0.img").exists(),
        "the head is not the snapshot"
    );
}

/// `list --before` a time older than every TXG says so in times: it
/// named the TXGs there are, which said nothing of when they were.
#[test]
fn before_every_txg_is_said_in_times() {
    let dir = scratch("before-oldest");
    let paths = write_members(&dir, &plain_members());
    // The fixture's one TXG was written one second into 1970.
    let (code, _, err) = run(&["-q", "list", "--before", "0", &paths[0], &paths[1]]);
    assert_eq!(code, 3, "{err}");
    assert!(
        err.contains(
            "no verified uberblock at or before 1970-01-01T00:00:00Z; the oldest is txg 100 at 1970-01-01T00:00:01Z"
        ),
        "{err}"
    );
}

/// A pool that went down with a write in a volume's intent log. The
/// image is the volume as its transaction group left it, every block
/// read; what the log holds is said in the summary and in the record,
/// and is not the exit status — that is for what could not be read. On
/// a pool that went down under load nearly every volume has such a log:
/// exit 4 for it, which is what it was for a while, told an image with
/// nothing lost from one with blocks written as zeros no more.
#[test]
fn what_the_intent_log_holds_is_said_and_is_not_the_exit_status() {
    use zfs_read::fixture::build_sample_mos_variant;

    let dir = scratch("intent-log");
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
    let mut members = vec![vec![0u8; SIZE as usize], vec![0u8; SIZE as usize]];
    let mut a = Alloc::new(0x20_0000);
    a.log_left = Some(101);
    build_sample_mos(&mut pool, &mut members, &mut a);
    for (i, m) in members.iter_mut().enumerate() {
        pool.write_labels(i, m);
    }
    let paths = write_members(&dir, &members);
    let image = dir.join("disk0.img").to_string_lossy().into_owned();
    let (code, out, err) = run(&["dump", "tank/vm/disk0", &paths[0], &paths[1], "-o", &image]);
    assert_eq!(code, 0, "{out}\n{err}");
    let said = out
        .lines()
        .find(|l| l.contains("INTENT LOG NOT APPLIED"))
        .unwrap_or_else(|| panic!("nothing about the log: {out}"));
    assert!(
        said.contains("the intent log holds 1 record(s) of txg 101, newer than the txg 100 that was read (1 TX_WRITE on object(s) 1, 4096 byte(s) written)")
            && said.contains("an import replays such records, and they are NOT applied here")
            && !said.contains("exit"),
        "{said}"
    );
    assert!(out.contains("0 zeroed (unreadable)"), "{out}");
    let again = dir.join("again.img").to_string_lossy().into_owned();
    let (code, out, _) = run(&[
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &paths[0],
        &paths[1],
        "-o",
        &again,
    ]);
    assert_eq!(code, 0, "{out}");
    let log = &json(&out)["volumes"][0]["intent_log"];
    assert_eq!(log["unreplayed"], 1, "{log}");
    assert_eq!(log["write_bytes"], 4096, "{log}");

    // The volume read at a transaction group that is not the pool's
    // newest — here the last one it is at, the one after has it
    // destroyed. The log that group had is no log an import replays,
    // and is not said to be one.
    let dir = scratch("intent-log-older");
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1), (101, 2)]);
    let mut members = vec![vec![0u8; SIZE as usize], vec![0u8; SIZE as usize]];
    let mut a = Alloc::new(0x20_0000);
    a.log_left = Some(101);
    let with = build_sample_mos_variant(&mut members, &mut a, true);
    a.log_left = None;
    a.born = Some(101);
    let without = build_sample_mos_variant(&mut members, &mut a, false);
    pool.rootbp = Some(with);
    pool.rootbp_by_txg = vec![(101, without)];
    for (i, m) in members.iter_mut().enumerate() {
        pool.write_labels(i, m);
    }
    let paths = write_members(&dir, &members);
    let image = dir.join("disk0.img").to_string_lossy().into_owned();
    let (code, out, err) = run(&["dump", "tank/vm/disk0", &paths[0], &paths[1], "-o", &image]);
    assert_eq!(code, 0, "{out}\n{err}");
    let said = out
        .lines()
        .find(|l| l.contains("INTENT LOG NOT APPLIED"))
        .unwrap_or_else(|| panic!("nothing about the log: {out}"));
    assert!(
        said.contains("they are of what came after txg 100, which is not the pool's newest, and are NOT applied here")
            && !said.contains("import"),
        "{said}"
    );
}

/// A dataset's name is whatever the pool says, and one written by
/// something other than ZFS may hold an escape sequence or a newline.
/// `list` and `dump` print it as text — it reached the terminal as it
/// was, where `ESC [2J` cleared the screen above it — and `dump -r`
/// names no file with it. The JSON has the name itself.
#[test]
fn a_name_from_the_pool_is_printed_as_text() {
    let name = "x\u{1b}[2Jy\nnp";
    let dir = scratch("name-of-codes");
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
    let mut members = vec![vec![0u8; SIZE as usize], vec![0u8; SIZE as usize]];
    let mut a = Alloc::new(0x20_0000);
    a.volume_name = Some(name);
    build_sample_mos(&mut pool, &mut members, &mut a);
    for (i, m) in members.iter_mut().enumerate() {
        pool.write_labels(i, m);
    }
    let paths = write_members(&dir, &members);
    let full = format!("tank/vm/{name}");
    let shown = "tank/vm/x\\u{1b}[2Jy\\u{a}np";
    let clean = |text: &str| !text.contains('\u{1b}') && !text.contains("y\nnp");

    let (code, out, err) = run(&["list", &paths[0], &paths[1]]);
    assert_eq!(code, 0, "{out}\n{err}");
    assert!(
        out.contains(shown) && clean(&out) && clean(&err),
        "{out}\n{err}"
    );
    let (code, out, _) = run(&["-f", "json", "list", &paths[0], &paths[1]]);
    assert_eq!(code, 0, "{out}");
    let v = json(&out);
    assert!(
        v["datasets"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["name"] == full.as_str()),
        "{v}"
    );

    let image = dir.join("one.img").to_string_lossy().into_owned();
    let (code, out, err) = run(&["dump", &full, &paths[0], &paths[1], "-o", &image]);
    assert_eq!(code, 0, "{out}\n{err}");
    assert!(
        out.contains(shown) && clean(&out) && clean(&err),
        "{out}\n{err}"
    );

    let tree = dir.join("all");
    let (code, out, err) = run(&[
        "dump",
        "-r",
        "tank/vm",
        &paths[0],
        &paths[1],
        "-o",
        tree.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{out}\n{err}");
    assert!(clean(&out) && clean(&err), "{out}\n{err}");
    assert!(tree.join("tank_vm_x_[2Jy_np.img").is_file(), "{out}");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(tree.join("manifest.json")).unwrap()).unwrap();
    assert!(
        manifest.to_string().contains("tank_vm_x_[2Jy_np.img"),
        "{manifest}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
