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
