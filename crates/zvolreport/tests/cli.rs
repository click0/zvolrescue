//! `build` then `verify` on a hand-written evidence log: the legacy
//! digests travel from the record into the report and are checked back,
//! one row each (SPEC F-53).

use std::path::{Path, PathBuf};
use std::process::Command;

use zvol_common::evidence::{digests_of, Extra, FORMAT_VERSION};
use zvol_common::scratch::Scratch;

/// A directory for one test, removed when the test ends.
fn scratch(name: &str) -> Scratch {
    Scratch::new("zvolreport-cli", name)
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
    // Three digests of the image, the log the report was built from,
    // and the report against that log.
    assert_eq!(v["passed"], 5, "{v}");
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
    // The log is as it was, and so is what the report says of it.
    assert_eq!(v["passed"], 2);

    // An unsigned report edited to match: the image's new hash written
    // over the recorded one. Every file hashes to what the report says
    // now, and the log still holds the old hash — which is what says so.
    let found = v["checked"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["kind"] == "output" && c["algorithm"] == "sha256")
        .unwrap()["found"]
        .as_str()
        .unwrap()
        .to_string();
    let text = std::fs::read_to_string(&report).unwrap();
    let mut edited: serde_json::Value = serde_json::from_str(&text).unwrap();
    for section in ["outputs", "extractions"] {
        for o in edited[section].as_array_mut().unwrap() {
            o["sha256"] = serde_json::Value::from(found.clone());
            o.as_object_mut().unwrap().remove("sha1");
            o.as_object_mut().unwrap().remove("md5");
        }
    }
    std::fs::write(&report, serde_json::to_string_pretty(&edited).unwrap()).unwrap();
    let (code, out, _) = run(&["-q", "-f", "json", "verify", &report.to_string_lossy()]);
    assert_eq!(code, 4, "{out}");
    let v: serde_json::Value = serde_json::from_str(&out).expect("json");
    let row = v["checked"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["kind"] == "report")
        .expect("a row for the report against its logs");
    assert_eq!(row["status"], "fail", "{v}");
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

    // Nor over what verify reads without the report naming it there: a
    // log recorded under a path that is not where it is now is looked for
    // beside the report, and the signature lies beside it too.
    let moved = scratch("verify-log-moved");
    let rel = PathBuf::from("case.jsonl");
    let rec = std::fs::read_to_string(&log).unwrap();
    std::fs::write(moved.join(&rel), &rec).unwrap();
    let elsewhere = scratch("verify-log-cwd");
    let run_in = |cwd: &Path, args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_zvolreport"))
            .current_dir(cwd)
            .args(args)
            .output()
            .expect("run zvolreport");
        (
            out.status.code().expect("exit code"),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let (code, err) = run_in(&moved, &["-q", "build", "case.jsonl", "-o", "report.json"]);
    assert_eq!(code, 0, "{err}");
    let moved_report = moved.join("report.json").to_string_lossy().into_owned();
    for target in [moved.join("case.jsonl"), moved.join("report.json.sig")] {
        let before = std::fs::read(&target).ok();
        let (code, err) = run_in(
            &elsewhere,
            &[
                "--debug-log",
                &target.to_string_lossy(),
                "-q",
                "verify",
                &moved_report,
            ],
        );
        assert_eq!(code, 5, "{}: {err}", target.display());
        assert_eq!(std::fs::read(&target).ok(), before, "{}", target.display());
    }
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
    // Edited inside what the report was built from (appending is not
    // editing: a log is appended to).
    let text = std::fs::read_to_string(&log).unwrap();
    std::fs::write(&log, text.replace("\"status\":0", "\"status\":9")).unwrap();
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
    // A report edited since it was built fails against its logs, which
    // have no one hash to show: its reason, and no "recorded —" and
    // "found —" under it.
    let log = evidence_log(&dir, &img);
    let (code, _, err) = run(&["-q", "build", &log.to_string_lossy(), "-o", &report]);
    assert_eq!(code, 0, "{err}");
    let mut r: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report).unwrap()).unwrap();
    r["commands"][0]["status"] = 4.into();
    std::fs::write(&report, serde_json::to_vec(&r).unwrap()).unwrap();
    let (code, out, err) = run(&["-q", "verify", &report]);
    assert_eq!(code, 4, "{err}\n{out}");
    assert!(out.contains("commands[0]: the report says"), "{out}");
    assert!(!out.contains("—\n"), "{out}");
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

/// One byte of a signed report that is not UTF-8 is a report somebody
/// changed, and the signature says so (exit 4, COMPANIONS §4.4): it was
/// refused as unreadable before the signature was asked (exit 2).
#[test]
fn a_signed_report_with_a_byte_that_is_not_text_breaks_its_signature() {
    let dir = scratch("not-text");
    let img = dir.join("vol.img");
    std::fs::write(&img, b"the bytes of a volume, such as they are").expect("write");
    let log = evidence_log(&dir, &img);
    let key = dir.join("k").to_string_lossy().into_owned();
    let (code, _, err) = run(&["-q", "keygen", "-o", &key]);
    assert_eq!(code, 0, "{err}");
    let report = dir.join("report.json");
    let r = report.to_string_lossy().into_owned();
    let (code, _, err) = run(&[
        "-q",
        "build",
        &log.to_string_lossy(),
        "-o",
        &r,
        "--sign",
        &key,
    ]);
    assert_eq!(code, 0, "{err}");
    let mut bytes = std::fs::read(&report).unwrap();
    let at = bytes.iter().position(|&b| b == b'"').unwrap() + 1;
    bytes[at] = 0xff;
    std::fs::write(&report, bytes).unwrap();
    let (code, _, err) = run(&["-q", "verify", &r, "--key", &format!("{key}.pub")]);
    assert_eq!(code, 4, "{err}");
    assert!(err.contains("signature"), "{err}");
}

/// `keygen` makes a pair or nothing, and makes it at the names given:
/// a link there that leads nowhere is something there, not a way to
/// put the key somewhere else.
#[test]
fn keygen_writes_a_whole_pair_and_never_through_a_link() {
    let dir = scratch("keygen");
    let key = dir.join("k");
    let far = dir.join("far.key");
    std::os::unix::fs::symlink(&far, &key).unwrap();
    let k = key.to_string_lossy().into_owned();
    let (code, _, err) = run(&["-q", "keygen", "-o", &k]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("already exists"), "{err}");
    assert!(!far.exists());
    let (code, _, err) = run(&["-q", "keygen", "-o", &k, "--force"]);
    assert_eq!(code, 0, "{err}");
    assert!(!far.exists());
    assert!(std::fs::symlink_metadata(&key)
        .unwrap()
        .file_type()
        .is_file());
    // The public half cannot be written: no private half is left either.
    let lone = dir.join("lone");
    let (code, _, err) = run(&[
        "-q",
        "keygen",
        "-o",
        &lone.to_string_lossy(),
        "--public",
        &dir.join("no/such/dir/lone.pub").to_string_lossy(),
    ]);
    assert_ne!(code, 0, "{err}");
    assert!(!lone.exists());
}

/// What a report is held to, and what it is not: no build writes over a
/// file its logs name; a record appended to a log after the build is not
/// held against the report; a file the report recorded that is now a
/// directory fails; a section the logs do not give fails the report; and
/// a relative path is taken from where its run started, wherever
/// `verify` runs.
#[test]
fn a_report_holds_to_its_logs_and_to_nothing_else() {
    let dir = scratch("holds");
    let img = dir.join("vol.img");
    std::fs::write(&img, b"the bytes of a volume, such as they are").expect("write");
    let log = evidence_log(&dir, &img);
    let l = log.to_string_lossy().into_owned();
    let member = dir.join("evidence.img");
    let before = std::fs::read(&member).unwrap();

    // Not over the evidence, and not over an output.
    for (flag, over) in [("-o", &member), ("--md", &img)] {
        let report = dir.join("r.json").to_string_lossy().into_owned();
        let target = over.to_string_lossy().into_owned();
        let args = if flag == "-o" {
            vec!["-q", "build", &l, "-o", &target]
        } else {
            vec!["-q", "build", &l, "-o", &report, "--md", &target]
        };
        let (code, _, err) = run(&args);
        assert_eq!(code, 5, "{flag}: {err}");
        assert!(err.contains("which the logs name"), "{err}");
    }
    assert_eq!(std::fs::read(&member).unwrap(), before);

    let report = dir.join("report.json").to_string_lossy().into_owned();
    let (code, _, err) = run(&["-q", "build", &l, "-o", &report]);
    assert_eq!(code, 0, "{err}");
    // A later run's record is appended: said, not a failure.
    let mut text = std::fs::read_to_string(&log).unwrap();
    let first = text.lines().next().unwrap().to_string();
    text.push_str(&first.replace("\"status\":0", "\"status\":3"));
    text.push('\n');
    std::fs::write(&log, text).unwrap();
    let (code, out, err) = run(&["-q", "verify", &report]);
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(out.contains("appended since the report was built"), "{out}");

    // From another directory: the paths in it are absolute now.
    let elsewhere = dir.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_zvolreport"))
        .args(["-q", "verify", &report])
        .current_dir(&elsewhere)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );

    // A section of its own fails the report.
    let mut r: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report).unwrap()).unwrap();
    r["summary"] = "all good".into();
    let edited = dir.join("edited.json");
    std::fs::write(&edited, serde_json::to_vec(&r).unwrap()).unwrap();
    let (code, out, _) = run(&["-q", "verify", &edited.to_string_lossy()]);
    assert_eq!(code, 4, "{out}");
    assert!(out.contains("summary: the report says"), "{out}");

    // Evidence that is a directory now is not "present, at the size
    // recorded".
    std::fs::remove_file(&member).unwrap();
    std::fs::create_dir(&member).unwrap();
    let (code, out, _) = run(&["-q", "verify", &report]);
    assert_eq!(code, 4, "{out}");
    assert!(out.contains("FAIL      kind"), "{out}");
}

/// A path a record gives relative to where its run started is found
/// there, not where `verify` runs.
#[test]
fn a_relative_path_is_taken_from_where_its_run_started() {
    let dir = scratch("cwd");
    std::fs::write(dir.join("out.img"), b"an image").unwrap();
    let sha = zvol_common::evidence::sha256_hex(b"an image");
    let record = serde_json::json!({
        "v": FORMAT_VERSION, "ts": 1_757_100_000u64, "tool": "zvolrescue", "version": "0.9.12",
        "cwd": dir.to_string_lossy(),
        "argv": ["zvolrescue", "dump", "tank/vm/disk0", "-o", "out.img"],
        "inputs": [],
        "outputs": [{"path": "out.img", "kind": "file", "size": 8, "sha256": sha}],
        "result": {},
        "status": 0,
    });
    let log = dir.join("case.jsonl");
    std::fs::write(&log, format!("{record}\n")).unwrap();
    let report = dir.join("r.json").to_string_lossy().into_owned();
    let (code, _, err) = run(&["-q", "build", &log.to_string_lossy(), "-o", &report]);
    assert_eq!(code, 0, "{err}");
    let elsewhere = dir.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_zvolreport"))
        .args(["-q", "verify", &report])
        .current_dir(&elsewhere)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{text}");
    assert!(text.contains("PASS") && text.contains("out.img"), "{text}");
}

/// A tree `zvolfiles extract` wrote is an extraction in the report —
/// its manifest and how many files — and every file of it is checked
/// back: one changed since fails `verify`. Only the manifest was.
#[test]
fn every_file_of_an_extracted_tree_is_checked_back() {
    let dir = scratch("tree");
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let hello = out.join("hello.txt");
    std::fs::write(&hello, b"hello, world\n").unwrap();
    let manifest = out.join("manifest.json");
    std::fs::write(&manifest, b"{\"files\": []}").unwrap();
    let sha = |p: &Path| zvol_common::evidence::sha256_hex(&std::fs::read(p).unwrap());
    let size = |p: &Path| std::fs::metadata(p).unwrap().len();
    let member = dir.join("member0.img");
    std::fs::write(&member, b"the pool member").unwrap();
    let record = serde_json::json!({
        "v": FORMAT_VERSION, "ts": 1_757_100_000u64, "tool": "zvolfiles", "version": "0.9.12",
        "argv": ["zvolfiles", "extract", "tank/fs", "-o", out],
        "inputs": [{"path": member, "kind": "file", "size": 15}],
        "outputs": [
            {"path": manifest, "kind": "file", "size": size(&manifest), "sha256": sha(&manifest)},
            {"path": hello, "kind": "file", "size": size(&hello), "sha256": sha(&hello)},
        ],
        "result": {"dataset": "tank/fs", "txg": 100, "output": out,
                   "files": [{"path": "hello.txt", "size": size(&hello), "sha256": sha(&hello)},
                             {"path": "sub", "type": "d"}],
                   "incomplete": 0, "failed": 0, "stopped": null},
        "status": 0,
    });
    let log = dir.join("case.jsonl");
    std::fs::write(&log, format!("{record}\n")).unwrap();
    let report = dir.join("report.json").to_string_lossy().into_owned();
    let (code, _, err) = run(&["-q", "build", &log.to_string_lossy(), "-o", &report]);
    assert_eq!(code, 0, "{err}");
    let r: serde_json::Value = serde_json::from_slice(&std::fs::read(&report).unwrap()).unwrap();
    let e = &r["extractions"][0];
    assert_eq!(e["dataset"], "tank/fs", "{r}");
    assert_eq!(e["files"], 1, "one file written: {e}");
    assert_eq!(e["output"], manifest.to_string_lossy().as_ref(), "{e}");
    let (code, out_text, _) = run(&["-q", "verify", &report]);
    assert_eq!(code, 0, "{out_text}");

    std::fs::write(&hello, b"hello, world!\n").unwrap();
    let (code, out_text, _) = run(&["-q", "verify", &report]);
    assert_eq!(code, 4, "{out_text}");
    assert!(
        out_text
            .lines()
            .any(|l| l.contains("FAIL") && l.contains("hello.txt")),
        "{out_text}"
    );
}

/// A log cut short since the report was built is not "appended to":
/// the bytes the report was built from are no longer there, and every
/// check of it fails. Evidence that is a FIFO now is not present at its
/// size either. A report built again over the one an earlier build
/// wrote is no evidence of the case, and is allowed.
#[cfg(unix)]
#[test]
fn a_log_cut_short_and_evidence_that_became_a_fifo_fail() {
    let dir = scratch("short");
    let img = dir.join("vol.img");
    std::fs::write(&img, b"the bytes of a volume").unwrap();
    let log = evidence_log(&dir, &img);
    let l = log.to_string_lossy().into_owned();
    let report = dir.join("report.json").to_string_lossy().into_owned();
    let (code, _, err) = run(&["-q", "build", &l, "-o", &report]);
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = run(&["-q", "build", &l, "-o", &report]);
    assert_eq!(code, 0, "built again in place: {err}");

    let text = std::fs::read(&log).unwrap();
    std::fs::write(&log, &text[..text.len() - 10]).unwrap();
    let (code, out, _) = run(&["-q", "verify", &report]);
    assert_eq!(code, 4, "{out}");
    assert!(out.contains("shorter than the"), "{out}");
    std::fs::write(&log, &text).unwrap();
    let (code, out, _) = run(&["-q", "verify", &report]);
    assert_eq!(code, 0, "{out}");

    let member = dir.join("evidence.img");
    std::fs::remove_file(&member).unwrap();
    let made = Command::new("mkfifo").arg(&member).status().unwrap();
    assert!(made.success());
    let (code, out, _) = run(&["-q", "verify", &report]);
    assert_eq!(code, 4, "{out}");
    assert!(out.contains("FAIL      kind"), "{out}");
}

/// What `verify` reads is bounded by what was recorded: a device named
/// as evidence is read to its recorded size, once its own size is that
/// size, and `/dev/zero` — which `verify` read without end — fails at
/// once. A report that does not hold to its logs is not taken at its
/// word for what to read: what it names is said, not hashed.
#[cfg(unix)]
#[test]
fn verify_reads_no_more_than_was_recorded() {
    if !Path::new("/dev/zero").exists() {
        return;
    }
    let dir = scratch("dev-zero");
    let record = serde_json::json!({
        "v": FORMAT_VERSION, "ts": 1_757_100_000u64, "tool": "zvolrescue", "version": "0.9.12",
        "argv": ["zvolrescue", "scan", "/dev/zero"],
        "inputs": [{"path": "/dev/zero", "kind": "device", "size": 1u64 << 40,
                    "sha256": "00".repeat(32)}],
        "outputs": [],
        "result": {},
        "status": 0,
    });
    let log = dir.join("case.jsonl");
    std::fs::write(&log, format!("{record}\n")).unwrap();
    let report = dir.join("r.json").to_string_lossy().into_owned();
    let (code, _, err) = run(&["-q", "build", &log.to_string_lossy(), "-o", &report]);
    assert_eq!(code, 0, "{err}");
    let mut child = Command::new(env!("CARGO_BIN_EXE_zvolreport"))
        .args(["verify", &report])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if std::time::Instant::now() > deadline {
            child.kill().ok();
            panic!("verify was still reading /dev/zero after 30 seconds");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let mut out = String::new();
    std::io::Read::read_to_string(child.stdout.as_mut().unwrap(), &mut out).ok();
    assert_eq!(status.code(), Some(4), "{out}");
    assert!(out.contains("not read"), "{out}");

    // An edited report: its evidence is not read on its word.
    let mut r: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report).unwrap()).unwrap();
    r["summary"] = "all good".into();
    let edited = dir.join("edited.json");
    std::fs::write(&edited, serde_json::to_vec(&r).unwrap()).unwrap();
    let (code, out, _) = run(&["-q", "verify", &edited.to_string_lossy()]);
    assert_eq!(code, 4, "{out}");
    assert!(out.contains("not read: the report did not hold"), "{out}");
}
