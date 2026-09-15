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
    assert_eq!(v["passed"], 3, "{v}");
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
    assert_eq!(v["passed"], 0);
}
