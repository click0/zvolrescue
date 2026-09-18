//! The binary imports nothing that opens a socket, runs a program or
//! loads code (SPEC §8.3 (3)). The reader lives in tests/support.

#[path = "../../../tests/support/imports.rs"]
mod support;

#[test]
fn the_binary_asks_its_platform_for_no_network_and_no_exec() {
    support::assert_clean(env!("CARGO_BIN_EXE_zvolreport"));
}
