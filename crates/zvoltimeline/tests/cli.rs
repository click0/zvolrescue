//! The command line, end to end, on fixture members written to disk.

use std::process::Command;

use zfs_ondisk::label::LABEL_SIZE;
use zfs_read::fixture::{build_sample_mos, Alloc, Pool};
use zvol_common::scratch::Scratch;

const SIZE: u64 = 64 * LABEL_SIZE;

/// A directory for one test, removed when the test ends.
fn scratch(name: &str) -> Scratch {
    Scratch::new("zvoltimeline-cli", name)
}

/// A two-way mirror with the sample MOS at one txg, written to `dir`.
fn members(dir: &std::path::Path) -> Vec<String> {
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
    let mut members = vec![vec![0u8; SIZE as usize], vec![0u8; SIZE as usize]];
    let mut a = Alloc::new(0x20_0000);
    build_sample_mos(&mut pool, &mut members, &mut a);
    members
        .iter_mut()
        .enumerate()
        .map(|(i, m)| {
            pool.write_labels(i, m);
            let p = dir.join(format!("member{i}.img"));
            std::fs::write(&p, &m).expect("write member");
            p.to_string_lossy().into_owned()
        })
        .collect()
}

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_zvoltimeline"))
        .args(args)
        .output()
        .expect("run zvoltimeline");
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// `-o` is never a file the run reads: naming a member replaced the
/// member with the report and exited 0. A report beside the members is
/// still written.
#[test]
fn the_report_is_never_written_over_a_member() {
    let dir = scratch("over-member");
    let m = members(&dir);
    let before = std::fs::read(&m[1]).unwrap();
    let (code, err) = run(&["-q", &m[0], &m[1], "-o", &m[1]]);
    assert_eq!(code, 5, "{err}");
    assert!(err.contains("refusing -o"), "{err}");
    assert_eq!(
        std::fs::read(&m[1]).unwrap(),
        before,
        "the member was written"
    );
    let report = dir.join("timeline.txt").to_string_lossy().into_owned();
    let (code, err) = run(&["-q", &m[0], &m[1], "-o", &report]);
    assert_eq!(code, 0, "{err}");
    assert!(std::fs::metadata(&report).unwrap().len() > 0);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A member that cannot be opened is exit 2, as `list` says it, and a
/// pool none of whose transaction groups can be walked is exit 3 — a
/// history of nothing but "unreadable" used to exit 0, its header
/// counting the unreadable groups as readable.
#[test]
fn a_history_with_nothing_readable_or_a_member_missing_says_so() {
    let dir = scratch("nothing-readable");
    let m = members(&dir);
    let missing = dir.join("gone.img").to_string_lossy().into_owned();
    let (code, err) = run(&["-q", &missing, &m[0], &m[1]]);
    assert_eq!(code, 2, "{err}");
    // Said in this program's name, not in zvolrescue's.
    assert!(
        err.contains("zvoltimeline: ") && !err.contains("zvolrescue: "),
        "{err}"
    );
    // Every block of the MOS gone, the labels and their uberblocks kept.
    for p in &m {
        let mut b = std::fs::read(p).unwrap();
        let end = b.len() - 0x10_0000;
        b[0x40_0000..end].fill(0);
        std::fs::write(p, b).unwrap();
    }
    let out = Command::new(env!("CARGO_BIN_EXE_zvoltimeline"))
        .args([&m[0], &m[1]])
        .output()
        .expect("run");
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(3), "{text}");
    assert!(
        text.contains("0 transaction group(s) still readable"),
        "{text}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// T-05: a destroyed snapshot says when it was last there and how to
/// read it back, in the text as in the JSON — the text had neither, and
/// the JSON no command. `--pending` with `--dataset` shows what is
/// pending, which the manual's own example asks for and the filter took
/// away; and a `--dataset` that names nothing is not "no change", exit
/// 0, but nothing found (exit 3).
#[test]
fn a_destroyed_snapshot_says_how_to_get_it_back() {
    use zfs_read::fixture::destroyed_zvol_members;
    let dir = scratch("snapshot");
    let mut pool = Pool::mirror("tank", 0x5eed_0000_0000_0001, 12).txgs(&[
        (4816228, 1757100000),
        (4816229, 1757100005),
        (4816230, 1757100010),
    ]);
    let (images, _, last_with) = destroyed_zvol_members(&mut pool, 64 * 1024 * 1024);
    let m: Vec<String> = images
        .iter()
        .enumerate()
        .map(|(i, img)| {
            let p = dir.join(format!("member{i}.img"));
            std::fs::write(&p, img).expect("write member");
            p.to_string_lossy().into_owned()
        })
        .collect();
    let out = Command::new(env!("CARGO_BIN_EXE_zvoltimeline"))
        .args([
            "--dataset",
            "tank/vm/disk0@before",
            "--pending",
            &m[0],
            &m[1],
        ])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text
        .lines()
        .find(|l| l.contains("snapshot-destroyed"))
        .unwrap_or_else(|| panic!("{text}"));
    assert!(
        line.contains(&format!("last seen at txg {last_with}")),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "-> zvolrescue dump tank/vm/disk0@before {} {} --txg {last_with} -o",
            m[0], m[1]
        )),
        "{text}"
    );
    assert!(text.lines().any(|l| l.contains(" pending ")), "{text}");

    let (code, err) = run(&["--dataset", "tank/nosuch", &m[0], &m[1]]);
    assert_eq!(code, 3, "{err}");
    assert!(err.contains("no dataset or snapshot of that name"), "{err}");
}

/// A GUID as `zfs get guid` prints it, in decimal, names the object as
/// the hex this tool prints does: given that way, it matched nothing
/// (exit 3).
#[test]
fn a_guid_in_decimal_names_its_dataset() {
    let dir = scratch("guid-decimal");
    let m = members(&dir);
    let events = |want: &str| {
        let out = Command::new(env!("CARGO_BIN_EXE_zvoltimeline"))
            .args(["-f", "json", "--dataset", want, &m[0], &m[1]])
            .output()
            .expect("run");
        assert_eq!(
            out.status.code(),
            Some(0),
            "{want}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        v["events"].clone()
    };
    let by_name = events("tank/vm/disk0");
    let hex = by_name[0]["guid"].as_str().unwrap().to_owned();
    let decimal = u64::from_str_radix(hex.trim_start_matches("0x"), 16)
        .unwrap()
        .to_string();
    assert_eq!(events(&hex), by_name);
    assert_eq!(events(&decimal), by_name);
}

/// `-o /dev/stdout` into a pipe ends: the report was read back from it to
/// be hashed for the record, and the run waited for ever on the pipe it
/// had written into — `| cat` hung, with or without `--evidence-log`.
#[cfg(unix)]
#[test]
fn a_report_into_a_pipe_is_not_read_back() {
    let dir = scratch("pipe");
    let m = members(&dir);
    let log = dir.join("case.jsonl");
    let mut child = Command::new(env!("CARGO_BIN_EXE_zvoltimeline"))
        .args([
            "-q",
            "--evidence-log",
            log.to_str().unwrap(),
            "-o",
            "/dev/stdout",
            &m[0],
            &m[1],
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("run zvoltimeline");
    let mut out = String::new();
    std::io::Read::read_to_string(child.stdout.as_mut().unwrap(), &mut out).ok();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if std::time::Instant::now() > deadline {
            child.kill().ok();
            panic!("still running a minute after its report was written: {out}");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    assert_eq!(status.code(), Some(0));
    assert!(out.contains("transaction group(s) still readable"), "{out}");
    let rec: serde_json::Value = serde_json::from_str(
        std::fs::read_to_string(&log)
            .unwrap()
            .lines()
            .last()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        rec["outputs"],
        serde_json::json!([]),
        "a pipe is no output to check"
    );
}

/// Write `members` to `dir` with the labels of `pool`.
fn written(dir: &std::path::Path, pool: &Pool, mut members: Vec<Vec<u8>>) -> Vec<String> {
    members
        .iter_mut()
        .enumerate()
        .map(|(i, m)| {
            pool.write_labels(i, m);
            let p = dir.join(format!("member{i}.img"));
            std::fs::write(&p, &m).expect("write member");
            p.to_string_lossy().into_owned()
        })
        .collect()
}

/// The exit status and what was printed.
fn printed(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_zvoltimeline"))
        .args(args)
        .output()
        .expect("run zvoltimeline");
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// A clock set back is not an import with rewind. The pool's newest
/// group, dated two hours before the two it was made from, was "a line
/// of history an import with rewind left behind; not read": the
/// destruction it holds, and the command that undoes it, were not in
/// the report, which ended 0. It is read, and the dates are said not to
/// be the order of things.
#[test]
fn a_clock_set_back_is_not_a_line_left_behind() {
    let dir = scratch("clock");
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 9000), (101, 9005), (102, 2000)]);
    let (members, _, _) = zfs_read::fixture::destroyed_zvol_members(&mut pool, SIZE);
    let m = written(&dir, &pool, members);
    let (code, text) = printed(&[&m[0], &m[1]]);
    assert_eq!(code, 0, "{text}");
    assert!(
        text.contains("3 transaction group(s) still readable"),
        "{text}"
    );
    assert!(!text.contains("abandoned"), "{text}");
    let destroyed = text
        .lines()
        .position(|l| l.contains(" destroyed ") && l.contains("tank/vm/disk0"))
        .unwrap_or_else(|| panic!("the volume's destruction is not there: {text}"));
    assert!(
        text.lines().nth(destroyed).unwrap().starts_with("102 ")
            && text
                .lines()
                .nth(destroyed)
                .unwrap()
                .contains("last seen at txg 101")
            && text
                .lines()
                .nth(destroyed + 1)
                .unwrap()
                .contains("--txg 101"),
        "{text}"
    );
    let clock = text
        .lines()
        .find(|l| l.contains(" clock "))
        .unwrap_or_else(|| panic!("nothing about the clock: {text}"));
    assert!(
        clock.starts_with("102 ") && clock.contains("dated before txg 101"),
        "{clock}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The groups an import with rewind left behind are told by what they
/// hold, wherever they are numbered and whenever they were written.
/// Here the pool went back from txg 102 to txg 100 and on: 101 and 102,
/// where the volume was destroyed, are older than the group that
/// followed and numbered below it, and were read as the pool's history
/// — the volume destroyed at 101 and created again at 103. And a range
/// is taken from the pool's line, not the line from the range:
/// `--from 101` made the group left behind the baseline.
#[test]
fn a_line_a_rewind_left_behind_is_told_by_what_it_holds() {
    use zfs_read::fixture::build_sample_mos_variant;

    let dir = scratch("rewind");
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[
        (100, 1000),
        (101, 1005),
        (102, 1010),
        (103, 2000),
    ]);
    let mut members = vec![vec![0u8; SIZE as usize], vec![0u8; SIZE as usize]];
    let mut a = Alloc::new(0x20_0000);
    let with = build_sample_mos_variant(&mut members, &mut a, true);
    a.born = Some(101);
    let without = build_sample_mos_variant(&mut members, &mut a, false);
    // The MOS of txg 100 is the pool's again at 103.
    pool.rootbp = Some(with);
    pool.rootbp_by_txg = vec![(101, without), (102, without)];
    let m = written(&dir, &pool, members);

    let (code, text) = printed(&[&m[0], &m[1]]);
    assert_eq!(code, 0, "{text}");
    assert!(
        text.contains("2 transaction group(s) still readable"),
        "{text}"
    );
    let abandoned: Vec<&str> = text.lines().filter(|l| l.contains(" abandoned ")).collect();
    assert_eq!(abandoned.len(), 2, "{text}");
    assert!(
        abandoned[0].starts_with("101 ")
            && abandoned[1].starts_with("102 ")
            && abandoned[1].contains("not on the line of history that leads to txg 103")
            && abandoned[1].contains("txg 103 holds the root of the MOS as txg 100 wrote it"),
        "{text}"
    );
    assert!(
        !text.contains("destroyed") && !text.contains(" clock "),
        "{text}"
    );

    // The range begins on the line left behind: it is still that, and
    // the first group of the pool's own in the range is the baseline.
    let (code, text) = printed(&[&m[0], &m[1], "--from", "101"]);
    assert_eq!(code, 0, "{text}");
    assert_eq!(text.matches(" abandoned ").count(), 2, "{text}");
    assert!(
        text.contains("already there at the oldest readable txg 103")
            && !text.contains("destroyed"),
        "{text}"
    );

    // Nothing but the line left behind in the range: said, and exit 3.
    let (code, text) = printed(&[&m[0], &m[1], "--from", "101", "--to", "102"]);
    assert_eq!(code, 3, "{text}");
    assert!(
        text.contains("no transaction group read: the 2 in that range are of a line of history the pool did not go on from"),
        "{text}"
    );
    assert_eq!(text.matches(" abandoned ").count(), 2, "{text}");
    std::fs::remove_dir_all(&dir).unwrap();
}
