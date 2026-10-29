//! `best-peer-disk`: run by systemd for each connection to `best-peer-disk.socket` (`Accept=yes`), the connection on
//! its standard input and output (`StandardInput=socket`), it answers the one request there and exits. What it did
//! is one line on its standard error, which the journal keeps.

use std::process::ExitCode;

fn main() -> ExitCode {
    let given: Vec<String> = std::env::args().skip(1).collect();
    match given.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["--version"] => {
            println!("best-peer-disk {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        ["--help"] => {
            println!("{}", best_peer_disk::USAGE);
            return ExitCode::SUCCESS;
        }
        _ => {}
    }
    match run(&given) {
        Ok(()) => ExitCode::SUCCESS,
        Err(why) => {
            eprintln!("best-peer-disk: {why}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "linux")]
fn run(given: &[String]) -> Result<(), String> {
    use std::os::fd::FromRawFd;
    let args = best_peer_disk::args(given)?;
    let passwd = std::fs::read_to_string("/etc/passwd").map_err(|e| format!("/etc/passwd cannot be read: {e}"))?;
    let peer = best_peer_disk::peer_in(&passwd, &args.peer_user)
        .ok_or_else(|| format!("--peer-user {} is no user in /etc/passwd", args.peer_user))?;
    let conn = std::os::unix::net::UnixStream::from(unsafe { std::os::fd::OwnedFd::from_raw_fd(0) });
    let helper = best_peer_disk::helper::Helper::new(args.dir, peer, args.limits);
    let answered = helper.serve(&conn);
    eprintln!(
        "best-peer-disk: {}",
        serde_json::to_string(&answered).unwrap_or_default()
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn run(given: &[String]) -> Result<(), String> {
    best_peer_disk::args(given)?;
    Err("a job's disk is a file system on a loop device, which this helper makes on Linux only".into())
}
