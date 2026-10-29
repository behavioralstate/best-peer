//! The binary's help, run as an operator runs it: it answers on its own, without a peer, a driver or an engine.

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_best-peer"))
        .args(args)
        .env(
            "BEST_PEER_DATA",
            std::env::temp_dir().join("best-peer-help-has-no-data"),
        )
        .output()
        .unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn help_names_every_command_and_the_settings_an_operator_starts_with() {
    for flag in ["--help", "-h", "help"] {
        let o = run(&[flag]);
        assert!(o.status.success(), "{flag}: {o:?}");
        let text = stdout(&o);
        for named in [
            "best-peer approve <code>",
            "best-peer revoke <name>",
            "best-peer hold",
            "best-peer release",
            "best-peer --version",
            "BEST_PEER_LISTEN",
            "BEST_PEER_ENDPOINT",
            "BEST_PEER_DATA",
            "BEST_PEER_RUNTIME",
            "BEST_PEER_GPU",
            "BEST_PEER_DISK_HELPER",
            "default 127.0.0.1:7777",
        ] {
            assert!(text.contains(named), "{flag} does not name {named}: {text}");
        }
    }
}

#[test]
fn a_commands_help_is_its_usage_and_reaches_no_peer() {
    for (command, usage) in [
        ("approve", "usage: best-peer approve <code>"),
        ("revoke", "usage: best-peer revoke <name>"),
        ("hold", "usage: best-peer hold"),
        ("release", "usage: best-peer release"),
    ] {
        for flag in ["--help", "-h"] {
            let o = run(&[command, flag]);
            assert!(o.status.success(), "{command} {flag}: {o:?}");
            assert!(stdout(&o).starts_with(usage), "{command} {flag}: {o:?}");
        }
        // After the arguments too, where a person adds it on finding they do not know the rest.
        let o = run(&[command, "ABCD-EFGH", "--help"]);
        assert!(
            o.status.success() && stdout(&o).starts_with(usage),
            "{command} … --help: {o:?}"
        );
    }
}

#[test]
fn an_unknown_command_fails_with_the_help() {
    let o = run(&["serve"]);
    assert_eq!(o.status.code(), Some(2));
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.starts_with("unknown command \"serve\"") && err.contains("best-peer --help"),
        "{err}"
    );
    assert!(o.stdout.is_empty());
}
