//! The binary imports nothing that opens a socket, runs a program or
//! loads code (SPEC §8.3 (3)). The reader lives in tests/support.

#[path = "../../../tests/support/imports.rs"]
mod support;

#[test]
fn the_binary_asks_its_platform_for_no_network_and_no_exec() {
    support::assert_clean(env!("CARGO_BIN_EXE_zvolrescue"));
}

/// The check is only worth what it can see. A program that does connect
/// and does run another program is built here, and the reader has to
/// name both — else a clean result above would mean nothing.
#[test]
fn the_check_names_a_socket_and_an_exec_when_a_program_has_them() {
    let dir = std::env::temp_dir().join(format!("zvolrescue-imports-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("probe.rs");
    std::fs::write(
        &src,
        "fn main() {\n    let _ = std::net::TcpStream::connect(\"127.0.0.1:1\");\n    let _ = std::process::Command::new(\"true\").status();\n}\n",
    )
    .unwrap();
    let probe = dir.join("probe");
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let status = std::process::Command::new(rustc)
        .arg("-o")
        .arg(&probe)
        .arg(&src)
        .status()
        .expect("rustc runs where cargo test runs");
    assert!(status.success(), "the probe did not build");
    let bad = support::violations(probe.to_str().unwrap());
    let _ = std::fs::remove_dir_all(&dir);
    let Some(bad) = bad else {
        eprintln!("not ELF64 here; the reader is not exercised on this platform");
        return;
    };
    for want in ["connect", "socket"] {
        assert!(
            bad.iter()
                .any(|b| b.ends_with(&format!(" {want}")) || b.contains(&format!(" {want}@"))),
            "the probe's {want} was not seen: {bad:?}"
        );
    }
    assert!(
        bad.iter()
            .any(|b| b.contains("exec") || b.contains("posix_spawn") || b.contains("fork")),
        "the probe's exec was not seen: {bad:?}"
    );
}
