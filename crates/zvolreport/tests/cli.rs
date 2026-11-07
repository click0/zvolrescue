//! `build` then `verify` on a hand-written evidence log: the legacy
//! digests travel from the record into the report and are checked back,
//! one row each (SPEC F-53).

use std::path::{Path, PathBuf};
use std::process::Command;

use zvol_common::evidence::{digests_of, Extra, FORMAT_VERSION};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zvolreport-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_zvolreport"))
        .args(args)
        .output()
        .expect("run zvolreport");
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// One record of a `dump --hash md5,sha1` run over `img`, as the tool
/// would have written it.
fn evidence_log(dir: &Path, img: &Path) -> PathBuf {
    let d = digests_of(
        img,
        Extra {
            md5: true,
            sha1: true,
        },
    )
    .expect("hash");
    let size = std::fs::metadata(img).expect("stat").len();
    let evidence = dir.join("evidence.img");
    std::fs::write(&evidence, b"the pool member").expect("write");
    let record = serde_json::json!({
        "v": FORMAT_VERSION,
        "ts": 1_757_100_000u64,
        "tool": "zvolrescue",
        "version": "0.7.5",
        "argv": ["zvolrescue", "dump", "tank/vm/disk0", "--hash", "md5,sha1"],
        "inputs": [{"path": evidence, "kind": "file", "size": 15}],
        "outputs": [{"path": img, "kind": "file", "size": size,
                     "sha256": d.sha256, "sha1": d.sha1, "md5": d.md5}],
        "result": {"volumes": [{"dataset": "tank/vm/disk0", "txg": 100, "output": img,
                                "volsize": size, "sha256": d.sha256, "sha1": d.sha1,
                                "md5": d.md5, "blocks_zeroed": 0, "aborted": false}]},
        "status": 0,
    });
    let log = dir.join("case.jsonl");
    std::fs::write(&log, format!("{record}\n")).expect("write log");
    log
}

#[test]
fn the_legacy_digests_reach_the_report_and_are_checked_back() {
    let dir = scratch("digests");
    let img = dir.join("vol.img");
    std::fs::write(&img, b"the bytes of a volume, such as they are").expect("write");
    let log = evidence_log(&dir, &img);
    let report = dir.join("report.json");

    let (code, _, err) = run(&[
        "-q",
        "build",
        &log.to_string_lossy(),
        "-o",
        &report.to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{err}");
    let r: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report).expect("report")).expect("json");
    assert!(
        r["outputs"][0]["sha1"].is_string() && r["outputs"][0]["md5"].is_string(),
        "{r}"
    );
    assert!(
        r["extractions"][0]["sha1"].is_string() && r["extractions"][0]["md5"].is_string(),
        "{r}"
    );

    let (code, out, err) = run(&["-q", "-f", "json", "verify", &report.to_string_lossy()]);
    assert_eq!(code, 0, "{err}\n{out}");
    let v: serde_json::Value = serde_json::from_str(&out).expect("json");
    // Three digests of the image, and the log the report was built from.
    assert_eq!(v["passed"], 4, "{v}");
    assert_eq!(v["failed"], 0);
    let rows: Vec<(String, String)> = v["checked"]
        .as_array()
        .expect("rows")
        .iter()
        .filter(|c| c["kind"] == "output")
        .map(|c| {
            (
                c["algorithm"].as_str().unwrap().into(),
                c["status"].as_str().unwrap().into(),
            )
        })
        .collect();
    assert_eq!(
        rows,
        vec![
            ("sha256".to_string(), "pass".to_string()),
            ("sha1".to_string(), "pass".to_string()),
            ("md5".to_string(), "pass".to_string()),
        ],
        "{v}"
    );

    // One byte changed, and every digest says so, with the run's status.
    let mut bytes = std::fs::read(&img).expect("read");
    bytes[7] ^= 0x01;
    std::fs::write(&img, bytes).expect("tamper");
    let (code, out, _) = run(&["-q", "-f", "json", "verify", &report.to_string_lossy()]);
    assert_eq!(code, 4, "{out}");
    let v: serde_json::Value = serde_json::from_str(&out).expect("json");
    assert_eq!(v["failed"], 3, "{v}");
    // The log is as it was.
    assert_eq!(v["passed"], 1);
}

/// `verify` reads and hashes every file the report names, and a log may
/// not be written over one: `--debug-log member.img verify report.json`
/// truncated the member to a trace, and then reported it tampered with.
#[test]
fn a_log_is_never_written_over_a_file_the_report_names() {
    let dir = scratch("verify-log");
    let img = dir.join("vol.img");
    std::fs::write(&img, b"the bytes of a volume, such as they are").expect("write");
    let log = evidence_log(&dir, &img);
    let report = dir.join("report.json").to_string_lossy().into_owned();
    let (code, _, err) = run(&["-q", "build", &log.to_string_lossy(), "-o", &report]);
    assert_eq!(code, 0, "{err}");
    for named in [dir.join("evidence.img"), img.clone(), log.clone()] {
        let before = std::fs::read(&named).unwrap();
        let (code, _, err) = run(&[
            "--debug-log",
            &named.to_string_lossy(),
            "-q",
            "verify",
            &report,
        ]);
        assert_eq!(code, 5, "{}: {err}", named.display());
        assert!(err.contains("refusing --debug-log"), "{err}");
        assert_eq!(
            std::fs::read(&named).unwrap(),
            before,
            "{}",
            named.display()
        );
    }
    let trace = dir.join("trace.log").to_string_lossy().into_owned();
    let (code, _, err) = run(&["--debug-log", &trace, "-q", "verify", &report]);
    assert_eq!(code, 0, "{err}");
}

/// The report's own logs are checked back: one edited since the report
/// was built breaks the chain, and verify says so (exit 4) instead of
/// passing everything else.
#[test]
fn an_edited_log_breaks_the_report() {
    let dir = scratch("edited-log");
    let img = dir.join("vol.img");
    std::fs::write(&img, b"the bytes of a volume, such as they are").expect("write");
    let log = evidence_log(&dir, &img);
    let report = dir.join("report.json").to_string_lossy().into_owned();
    let (code, _, err) = run(&["-q", "build", &log.to_string_lossy(), "-o", &report]);
    assert_eq!(code, 0, "{err}");
    let mut text = std::fs::read_to_string(&log).unwrap();
    text.push_str("{}\n");
    std::fs::write(&log, text).unwrap();
    let (code, out, err) = run(&["-q", "-f", "json", "verify", &report]);
    assert_eq!(code, 4, "{err}\n{out}");
    let v: serde_json::Value = serde_json::from_str(&out).expect("json");
    assert!(
        v["checked"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["kind"] == "log" && c["status"] == "fail"),
        "{v}"
    );
}

/// `--evidence-log` and `--hash-inputs` do what they say for this tool
/// too: a build records the logs it read and the hashes of what it
/// wrote, and a verify what it checked. Both flags were accepted and did
/// nothing.
#[test]
fn a_report_run_is_on_the_evidence_record() {
    let dir = scratch("own-record");
    let img = dir.join("vol.img");
    std::fs::write(&img, b"the bytes of a volume, such as they are").expect("write");
    let log = evidence_log(&dir, &img);
    let report = dir.join("report.json").to_string_lossy().into_owned();
    let ev = dir.join("runs.jsonl").to_string_lossy().into_owned();
    let (code, _, err) = run(&[
        "--evidence-log",
        &ev,
        "--hash-inputs",
        "-q",
        "build",
        &log.to_string_lossy(),
        "-o",
        &report,
    ]);
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = run(&["--evidence-log", &ev, "-q", "verify", &report]);
    assert_eq!(code, 0, "{err}");
    let records: Vec<serde_json::Value> = std::fs::read_to_string(&ev)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(records.len(), 2, "{records:?}");
    assert!(records.iter().all(|r| r["tool"] == "zvolreport"));
    let build = &records[0];
    assert!(build["inputs"][0]["sha256"].is_string(), "{build}");
    assert!(
        build["outputs"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |o| o["path"].as_str().unwrap().ends_with("report.json") && o["sha256"].is_string()
            ),
        "{build}"
    );
    assert!(
        records[1]["inputs"].as_array().unwrap().len() >= 3,
        "{}",
        records[1]
    );
}
