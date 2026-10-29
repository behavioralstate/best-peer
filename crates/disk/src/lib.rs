//! A job's disk for a peer that may not mount (behavioralstate/spec#169): `best-peer-disk`, run as root by systemd
//! for each connection to its socket, answers one request and exits, and the Docker runtime asks it with [`ask`].
//! A request is one JSON line and so is its answer: `make` a disk of `bytes` for an id, `release` what the job left
//! under `out/` to the peer, `remove` a disk, and `list` the disks there with the helper's directory. Nothing but the
//! request comes from the caller: the directory, the peer, the bounds and every option are the helper's own, and the
//! caller is the one uid and gid its unit names, or is refused. What needs no root is here and unit-tested: the
//! requests read and checked, the room a disk may take, the peer found in the passwd file, the arguments, and the
//! client; the syscalls are in [`helper`] and the walk of a release in [`release`], Linux only.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
pub mod helper;
#[cfg(target_os = "linux")]
pub mod release;

/// The smallest disk the helper makes: smaller holds little more than its own file system.
pub const LEAST_BYTES: u64 = 16 << 20;

/// How deep a release walks under `out/`: a tree deeper fails the release rather than hold a descriptor per level.
pub const MOST_DEPTH: usize = 256;

/// The longest line a request may be.
pub const MOST_LINE: usize = 4096;

/// One request, as its JSON line names it by `request`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Make { id: String, bytes: u64 },
    Release { id: String },
    Remove { id: String },
    List {},
}

/// Why a request was refused, by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    NotThePeer,
    UnknownRequest,
    BadId,
    TooSmall,
    TooLarge,
    NoRoom,
    TooManyDisks,
    Exists,
    Failed,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = serde_json::to_value(self).ok();
        f.write_str(name.as_ref().and_then(|n| n.as_str()).unwrap_or("refused"))
    }
}

/// A request refused, by name and in words.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refused(pub Refusal, pub String);

/// The answer to one request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "answer", rename_all = "snake_case")]
pub enum Answer {
    Made {
        path: PathBuf,
    },
    Released,
    Removed,
    Listed {
        dir: PathBuf,
        ids: Vec<String>,
        most_bytes: u64,
        most_disks: usize,
    },
    Refused {
        code: Refusal,
        reason: String,
    },
}

impl From<Refused> for Answer {
    fn from(r: Refused) -> Self {
        Answer::Refused { code: r.0, reason: r.1 }
    }
}

/// The peer the helper serves: the one caller it answers, and the owner it gives what it makes and releases to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peer {
    pub uid: u32,
    pub gid: u32,
}

/// The bounds the helper's unit sets: the largest disk, and how many there may be at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub most_bytes: u64,
    pub most_disks: usize,
}

/// What the helper does on the host, one request at a time; [`answer`] checks a request before it reaches it.
pub trait Disks {
    /// A disk of `bytes` for `id`, mounted, and where; checked against the room and the number of disks under a lock.
    fn make(&self, id: &str, bytes: u64) -> Result<PathBuf, Refused>;
    /// What the job left under the disk's `out/`, given to the peer.
    fn release(&self, id: &str) -> Result<(), Refused>;
    /// The disk gone; one already gone is no error.
    fn remove(&self, id: &str) -> Result<(), Refused>;
    /// The helper's directory and the ids of the disks in it.
    fn list(&self) -> Result<(PathBuf, Vec<String>), Refused>;
}

/// Whether `id` may name a disk: `^[a-z0-9][a-z0-9-]{3,63}$`, so a slash, a dot, NUL or a leading `-` never reaches a
/// path or an argument.
pub fn valid_id(id: &str) -> Result<(), Refused> {
    let bytes = id.as_bytes();
    let fits = (4..=64).contains(&bytes.len())
        && bytes[0] != b'-'
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-');
    match fits {
        true => Ok(()),
        false => Err(Refused(
            Refusal::BadId,
            format!("the id {id:?} is not 4 to 64 of a-z, 0-9 and -, beginning with a letter or a digit"),
        )),
    }
}

/// The disk an entry of the helper's directory named `name` stands for: an image `<id>.img`, or a mount point `<id>`
/// that is a directory, a link never; none for anything else. The one rule the helper counts disks by, and the peer
/// with it.
pub fn id_of(name: &str, is_dir: bool) -> Option<&str> {
    let id = match name.strip_suffix(".img") {
        Some(id) => id,
        None if is_dir => name,
        None => return None,
    };
    valid_id(id).ok().map(|_| id)
}

/// The ids of the disks in the directory `dir`, each once, by [`id_of`]; none when it cannot be read.
pub fn ids_at(dir: &Path) -> Vec<String> {
    let ids: std::collections::BTreeSet<String> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let is_dir = e.file_type().is_ok_and(|t| t.is_dir());
            id_of(e.file_name().to_str()?, is_dir).map(str::to_string)
        })
        .collect();
    ids.into_iter().collect()
}

/// The arguments a disk's image is formatted with: ext4 with no journal, which a disk that lives as long as its job
/// does not need, nothing kept for root, and no discard, which on an image file would punch out the room reserved
/// for it.
pub const MKFS_ARGS: &[&str] = &["-q", "-F", "-m", "0", "-O", "^has_journal", "-E", "nodiscard"];

/// Formats the image at `image` with `mkfs.ext4` and [`MKFS_ARGS`], run with a cleared environment and no standard
/// input or output of this process; why not, in its words.
pub fn format(image: &Path) -> Result<(), String> {
    let out = std::process::Command::new("mkfs.ext4")
        .args(MKFS_ARGS)
        .arg(image)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| format!("mkfs.ext4 could not run: {e}"))?;
    match out.status.success() {
        true => Ok(()),
        false => Err(format!(
            "mkfs.ext4 failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )),
    }
}

/// The request one line holds, its id checked; refused by name when it is none of the four, or its id cannot name a
/// disk.
pub fn parse(line: &str) -> Result<Request, Refused> {
    let request: Request = serde_json::from_str(line.trim_end()).map_err(|e| {
        Refused(
            Refusal::UnknownRequest,
            format!("not a request: {e}; one of make {{id, bytes}}, release {{id}}, remove {{id}} or list"),
        )
    })?;
    match &request {
        Request::Make { id, .. } | Request::Release { id } | Request::Remove { id } => valid_id(id)?,
        Request::List {} => {}
    }
    Ok(request)
}

/// Whether a disk of `bytes` is within the helper's bounds: [`LEAST_BYTES`] at least, `limits.most_bytes` at most.
pub fn sized(bytes: u64, limits: Limits) -> Result<(), Refused> {
    if bytes < LEAST_BYTES {
        return Err(Refused(
            Refusal::TooSmall,
            format!("a disk of {bytes} bytes is under the least, {LEAST_BYTES}"),
        ));
    }
    if bytes > limits.most_bytes {
        return Err(Refused(
            Refusal::TooLarge,
            format!(
                "a disk of {bytes} bytes is past the most this helper makes, {} (--most-bytes)",
                limits.most_bytes
            ),
        ));
    }
    Ok(())
}

/// Whether the caller is the peer, by its uid and its gid.
pub fn caller(peer: Peer, uid: u32, gid: u32) -> Result<(), Refused> {
    match (uid, gid) == (peer.uid, peer.gid) {
        true => Ok(()),
        false => Err(Refused(
            Refusal::NotThePeer,
            format!(
                "the caller is uid {uid} gid {gid}, not the peer this helper serves (uid {} gid {})",
                peer.uid, peer.gid
            ),
        )),
    }
}

/// What a disk is never promised of the file system it is made on: 1 GiB, or a twentieth of it when that is more, so
/// the peer's own log and the engine can always still write there.
pub fn kept_free(total: u64) -> u64 {
    (total / 20).max(1 << 30)
}

/// Whether a disk of `bytes` may be made where `avail` of `total` bytes are free and `disks` are there already.
pub fn room(bytes: u64, avail: u64, total: u64, disks: usize, limits: Limits) -> Result<(), Refused> {
    if disks >= limits.most_disks {
        return Err(Refused(
            Refusal::TooManyDisks,
            format!("{disks} disks are there, the most this helper keeps at once (--most-disks)"),
        ));
    }
    let free = avail.saturating_sub(kept_free(total));
    if bytes > free {
        return Err(Refused(
            Refusal::NoRoom,
            format!("no room for a disk of {bytes} bytes: {free} are free beyond what is kept free"),
        ));
    }
    Ok(())
}

/// A size in bytes, as a number or with a binary suffix: `K`, `M`, `G` or `T`.
pub fn bytes_of(text: &str) -> Option<u64> {
    let (digits, shift) = match text.chars().last()? {
        'K' => (&text[..text.len() - 1], 10),
        'M' => (&text[..text.len() - 1], 20),
        'G' => (&text[..text.len() - 1], 30),
        'T' => (&text[..text.len() - 1], 40),
        _ => (text, 0),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u64>().ok()?.checked_mul(1 << shift)
}

/// The peer `user` names, by its name or its uid, as the passwd file `passwd` has it: its uid and its primary group.
pub fn peer_in(passwd: &str, user: &str) -> Option<Peer> {
    passwd.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        let (name, uid, gid) = (fields.first()?, fields.get(2)?, fields.get(3)?);
        let peer = Peer {
            uid: uid.parse().ok()?,
            gid: gid.parse().ok()?,
        };
        (*name == user || *uid == user).then_some(peer)
    })
}

/// The helper's settings, from its command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Args {
    pub dir: PathBuf,
    pub peer_user: String,
    pub limits: Limits,
}

/// The usage `best-peer-disk --help` prints.
pub const USAGE: &str =
    "best-peer-disk: makes, releases and removes a job's disk for best-peer, one request per connection

Run by systemd (best-peer-disk.socket, Accept=yes), the connection on its standard input and output.

  --dir <absolute path>   where the disks are made; root's, and writable by no one else
  --peer-user <name|uid>  the one caller it answers, by uid and primary group, and the owner of what it releases
  --most-bytes <size>     the largest disk it makes, in bytes or with K, M, G or T
  --most-disks <count>    how many disks there may be at once
  --version               prints its version";

/// The settings `list` names, every one required.
pub fn args(list: &[String]) -> Result<Args, String> {
    let mut dir = None;
    let mut peer_user = None;
    let mut most_bytes = None;
    let mut most_disks = None;
    let mut rest = list.iter();
    while let Some(name) = rest.next() {
        let value = rest.next().ok_or_else(|| format!("{name} needs a value"))?;
        match name.as_str() {
            "--dir" => {
                let path = PathBuf::from(value);
                if !path.is_absolute() {
                    return Err(format!("--dir must be an absolute path, not {value:?}"));
                }
                dir = Some(path);
            }
            "--peer-user" => peer_user = Some(value.clone()),
            "--most-bytes" => {
                most_bytes = Some(bytes_of(value).filter(|b| *b >= LEAST_BYTES).ok_or_else(|| {
                    format!("--most-bytes must be a size of {LEAST_BYTES} bytes or more, not {value:?}")
                })?)
            }
            "--most-disks" => {
                most_disks = Some(
                    value
                        .parse::<usize>()
                        .ok()
                        .filter(|n| *n >= 1)
                        .ok_or_else(|| format!("--most-disks must be a count of 1 or more, not {value:?}"))?,
                )
            }
            other => return Err(format!("unknown argument {other:?}\n\n{USAGE}")),
        }
    }
    let missing = |name: &str| format!("{name} is required\n\n{USAGE}");
    Ok(Args {
        dir: dir.ok_or_else(|| missing("--dir"))?,
        peer_user: peer_user.ok_or_else(|| missing("--peer-user"))?,
        limits: Limits {
            most_bytes: most_bytes.ok_or_else(|| missing("--most-bytes"))?,
            most_disks: most_disks.ok_or_else(|| missing("--most-disks"))?,
        },
    })
}

/// The answer to the line a caller of `uid` and `gid` sent: refused before `disks` is asked for anything when the
/// caller is not the peer, the line is no request, its id names no disk or its size is out of bounds.
pub fn answer(line: &str, uid: u32, gid: u32, peer: Peer, limits: Limits, disks: &impl Disks) -> Answer {
    let done = || -> Result<Answer, Refused> {
        caller(peer, uid, gid)?;
        Ok(match parse(line)? {
            Request::Make { id, bytes } => {
                sized(bytes, limits)?;
                Answer::Made {
                    path: disks.make(&id, bytes)?,
                }
            }
            Request::Release { id } => disks.release(&id).map(|_| Answer::Released)?,
            Request::Remove { id } => disks.remove(&id).map(|_| Answer::Removed)?,
            Request::List {} => {
                let (dir, ids) = disks.list()?;
                Answer::Listed {
                    dir,
                    ids,
                    most_bytes: limits.most_bytes,
                    most_disks: limits.most_disks,
                }
            }
        })
    };
    done().unwrap_or_else(Answer::from)
}

/// Asks the helper listening on `socket`, waiting `within` at most for each read and write; its answer, or why there
/// is none.
#[cfg(unix)]
pub fn ask(socket: &Path, request: &Request, within: std::time::Duration) -> Result<Answer, String> {
    use std::io::{BufRead, Write};
    let said = |e: std::io::Error| format!("the disk helper at {} did not answer: {e}", socket.display());
    let mut stream = std::os::unix::net::UnixStream::connect(socket).map_err(said)?;
    stream.set_read_timeout(Some(within)).map_err(said)?;
    stream.set_write_timeout(Some(within)).map_err(said)?;
    let mut line = serde_json::to_string(request).map_err(|e| e.to_string())?;
    line.push('\n');
    stream.write_all(line.as_bytes()).map_err(said)?;
    stream.shutdown(std::net::Shutdown::Write).map_err(said)?;
    let mut answered = String::new();
    std::io::BufReader::new(std::io::Read::take(&stream, 1 << 20))
        .read_line(&mut answered)
        .map_err(said)?;
    serde_json::from_str(answered.trim_end()).map_err(|e| {
        format!(
            "the disk helper at {} answered {answered:?}, not an answer: {e}",
            socket.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const PEER: Peer = Peer { uid: 990, gid: 985 };
    const LIMITS: Limits = Limits {
        most_bytes: 1 << 40,
        most_disks: 8,
    };

    #[derive(Default)]
    struct Asked(RefCell<Vec<String>>);

    impl Disks for Asked {
        fn make(&self, id: &str, bytes: u64) -> Result<PathBuf, Refused> {
            self.0.borrow_mut().push(format!("make {id} {bytes}"));
            Ok(PathBuf::from("/var/lib/best-peer-disk").join(id))
        }
        fn release(&self, id: &str) -> Result<(), Refused> {
            self.0.borrow_mut().push(format!("release {id}"));
            Ok(())
        }
        fn remove(&self, id: &str) -> Result<(), Refused> {
            self.0.borrow_mut().push(format!("remove {id}"));
            Ok(())
        }
        fn list(&self) -> Result<(PathBuf, Vec<String>), Refused> {
            self.0.borrow_mut().push("list".into());
            Ok(("/var/lib/best-peer-disk".into(), vec!["job-0123456789ab".into()]))
        }
    }

    fn refused(answer: Answer) -> Refusal {
        match answer {
            Answer::Refused { code, .. } => code,
            other => panic!("not refused: {other:?}"),
        }
    }

    #[test]
    fn an_id_is_four_to_sixty_four_of_lowercase_letters_digits_and_dashes_never_led_by_a_dash() {
        for good in ["job-0123456789ab", "abcd", "0abc", &"a".repeat(64), "a-b-"] {
            assert_eq!(valid_id(good), Ok(()), "{good}");
        }
        for bad in [
            "",
            "abc",
            &"a".repeat(65),
            "-abc",
            "Job-1",
            "job/..",
            "..",
            "job.img",
            "job 1",
            "job\u{0}1",
            "jöb-1",
            "../../etc",
        ] {
            assert_eq!(valid_id(bad).unwrap_err().0, Refusal::BadId, "{bad:?}");
        }
    }

    #[test]
    fn each_request_is_read_from_its_line_and_anything_else_is_refused_by_name() {
        assert_eq!(
            parse(r#"{"request":"make","id":"job-0123456789ab","bytes":1073741824}"#),
            Ok(Request::Make {
                id: "job-0123456789ab".into(),
                bytes: 1 << 30
            })
        );
        assert_eq!(
            parse("{\"request\":\"release\",\"id\":\"job-0123456789ab\"}\n"),
            Ok(Request::Release {
                id: "job-0123456789ab".into()
            })
        );
        assert_eq!(
            parse(r#"{"request":"remove","id":"job-0123456789ab"}"#),
            Ok(Request::Remove {
                id: "job-0123456789ab".into()
            })
        );
        assert_eq!(parse(r#"{"request":"list"}"#), Ok(Request::List {}));
        for unknown in [
            r#"{"request":"mount","id":"job-0123456789ab"}"#,
            r#"{"request":"make","id":"job-0123456789ab"}"#,
            r#"{"request":"make","id":"job-0123456789ab","bytes":-1}"#,
            r#"{"request":"make","id":"job-0123456789ab","bytes":1073741824,"path":"/etc"}"#,
            r#"{"request":"remove","id":"job-0123456789ab","options":"bind"}"#,
            r#"{"request":"list","path":"/"}"#,
            r#"{"id":"job-0123456789ab"}"#,
            "make job-0123456789ab",
            "",
        ] {
            assert_eq!(parse(unknown).unwrap_err().0, Refusal::UnknownRequest, "{unknown}");
        }
        assert_eq!(
            parse(r#"{"request":"release","id":"../etc"}"#).unwrap_err().0,
            Refusal::BadId
        );
    }

    #[test]
    fn a_disk_is_sixteen_mib_at_least_and_most_bytes_at_most() {
        assert_eq!(sized(LEAST_BYTES, LIMITS), Ok(()));
        assert_eq!(sized(1 << 40, LIMITS), Ok(()));
        assert_eq!(sized(LEAST_BYTES - 1, LIMITS).unwrap_err().0, Refusal::TooSmall);
        let past = sized((1 << 40) + 1, LIMITS).unwrap_err();
        assert_eq!(past.0, Refusal::TooLarge);
        assert!(past.1.contains("--most-bytes"), "{}", past.1);
    }

    #[test]
    fn the_caller_is_the_peer_by_its_uid_and_its_gid() {
        assert_eq!(caller(PEER, 990, 985), Ok(()));
        assert_eq!(caller(PEER, 991, 985).unwrap_err().0, Refusal::NotThePeer);
        assert_eq!(caller(PEER, 990, 0).unwrap_err().0, Refusal::NotThePeer);
        assert_eq!(caller(PEER, 0, 0).unwrap_err().0, Refusal::NotThePeer);
    }

    #[test]
    fn a_disk_takes_no_room_kept_free_and_no_place_past_the_most_disks() {
        let gib = 1u64 << 30;
        assert_eq!(kept_free(10 * gib), gib);
        assert_eq!(kept_free(100 * gib), 5 * gib);
        assert_eq!(room(4 * gib, 10 * gib, 100 * gib, 0, LIMITS), Ok(()));
        assert_eq!(room(5 * gib, 10 * gib, 100 * gib, 0, LIMITS), Ok(()));
        assert_eq!(
            room(5 * gib + 1, 10 * gib, 100 * gib, 0, LIMITS).unwrap_err().0,
            Refusal::NoRoom
        );
        assert_eq!(
            room(LEAST_BYTES, gib / 2, 2 * gib, 0, LIMITS).unwrap_err().0,
            Refusal::NoRoom
        );
        assert_eq!(room(gib, 10 * gib, 100 * gib, 7, LIMITS), Ok(()));
        assert_eq!(
            room(gib, 10 * gib, 100 * gib, 8, LIMITS).unwrap_err().0,
            Refusal::TooManyDisks
        );
    }

    #[test]
    fn a_size_is_bytes_or_a_binary_suffix() {
        assert_eq!(bytes_of("17179869184"), Some(16 << 30));
        assert_eq!(bytes_of("16M"), Some(16 << 20));
        assert_eq!(bytes_of("512G"), Some(512 << 30));
        assert_eq!(bytes_of("1T"), Some(1 << 40));
        assert_eq!(bytes_of("2K"), Some(2048));
        for bad in ["", "T", "1.5G", "-1", "1g", "1TB", "99999999999T"] {
            assert_eq!(bytes_of(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_peer_is_found_in_the_passwd_file_by_its_name_or_its_uid_with_its_primary_group() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\nbest-peer:x:990:985::/var/lib/best-peer:/usr/sbin/nologin\n";
        assert_eq!(peer_in(passwd, "best-peer"), Some(PEER));
        assert_eq!(peer_in(passwd, "990"), Some(PEER));
        assert_eq!(peer_in(passwd, "nobody"), None);
        assert_eq!(peer_in(passwd, "985"), None);
        assert_eq!(peer_in("broken:x:abc:1::/:/bin/sh\n", "broken"), None);
    }

    #[test]
    fn the_arguments_are_every_one_required_and_checked() {
        let given = |s: &str| s.split_whitespace().map(str::to_string).collect::<Vec<_>>();
        assert_eq!(
            args(&given(
                "--dir /var/lib/best-peer-disk --peer-user best-peer --most-bytes 1T --most-disks 16"
            )),
            Ok(Args {
                dir: "/var/lib/best-peer-disk".into(),
                peer_user: "best-peer".into(),
                limits: Limits {
                    most_bytes: 1 << 40,
                    most_disks: 16
                },
            })
        );
        for (bad, says) in [
            ("--dir disks --peer-user w --most-bytes 1T --most-disks 1", "absolute"),
            ("--dir /d --peer-user w --most-bytes 1M --most-disks 1", "--most-bytes"),
            ("--dir /d --peer-user w --most-bytes 1T --most-disks 0", "--most-disks"),
            ("--peer-user w --most-bytes 1T --most-disks 1", "--dir is required"),
            ("--dir /d --most-bytes 1T --most-disks 1", "--peer-user is required"),
            ("--dir /d --peer-user w --most-disks 1", "--most-bytes is required"),
            ("--dir /d --peer-user w --most-bytes 1T", "--most-disks is required"),
            (
                "--dir /d --peer-user w --most-bytes 1T --most-disks 1 --options bind",
                "unknown argument",
            ),
            ("--dir", "needs a value"),
        ] {
            let why = args(&given(bad)).unwrap_err();
            assert!(why.contains(says), "{bad}: {why}");
        }
    }

    #[test]
    fn a_request_reaches_the_disks_only_from_the_peer_checked_and_bounded() {
        let asked = Asked::default();
        let make = r#"{"request":"make","id":"job-0123456789ab","bytes":1073741824}"#;
        assert_eq!(
            refused(answer(make, 991, 985, PEER, LIMITS, &asked)),
            Refusal::NotThePeer
        );
        assert_eq!(
            refused(answer(make, 990, 1000, PEER, LIMITS, &asked)),
            Refusal::NotThePeer
        );
        assert_eq!(
            refused(answer(r#"{"request":"format"}"#, 990, 985, PEER, LIMITS, &asked)),
            Refusal::UnknownRequest
        );
        assert_eq!(
            refused(answer(
                r#"{"request":"make","id":"ab/cd","bytes":1073741824}"#,
                990,
                985,
                PEER,
                LIMITS,
                &asked
            )),
            Refusal::BadId
        );
        assert_eq!(
            refused(answer(
                r#"{"request":"make","id":"job-0123456789ab","bytes":2199023255552}"#,
                990,
                985,
                PEER,
                LIMITS,
                &asked
            )),
            Refusal::TooLarge
        );
        assert!(asked.0.borrow().is_empty(), "{:?}", asked.0.borrow());

        assert_eq!(
            answer(make, 990, 985, PEER, LIMITS, &asked),
            Answer::Made {
                path: "/var/lib/best-peer-disk/job-0123456789ab".into()
            }
        );
        assert_eq!(
            answer(
                r#"{"request":"release","id":"job-0123456789ab"}"#,
                990,
                985,
                PEER,
                LIMITS,
                &asked
            ),
            Answer::Released
        );
        assert_eq!(
            answer(
                r#"{"request":"remove","id":"job-0123456789ab"}"#,
                990,
                985,
                PEER,
                LIMITS,
                &asked
            ),
            Answer::Removed
        );
        assert_eq!(
            answer(r#"{"request":"list"}"#, 990, 985, PEER, LIMITS, &asked),
            Answer::Listed {
                dir: "/var/lib/best-peer-disk".into(),
                ids: vec!["job-0123456789ab".into()],
                most_bytes: 1 << 40,
                most_disks: 8
            }
        );
        assert_eq!(
            *asked.0.borrow(),
            [
                "make job-0123456789ab 1073741824",
                "release job-0123456789ab",
                "remove job-0123456789ab",
                "list"
            ]
        );
    }

    #[test]
    fn an_answer_is_one_json_line_named_by_answer() {
        let line = |a: &Answer| serde_json::to_string(a).unwrap();
        assert_eq!(
            line(&Answer::Made {
                path: "/d/job-1abc".into()
            }),
            r#"{"answer":"made","path":"/d/job-1abc"}"#
        );
        assert_eq!(line(&Answer::Released), r#"{"answer":"released"}"#);
        assert_eq!(Refusal::TooManyDisks.to_string(), "too_many_disks");
        assert_eq!(
            line(&Answer::Refused {
                code: Refusal::NotThePeer,
                reason: "r".into()
            }),
            r#"{"answer":"refused","code":"not_the_peer","reason":"r"}"#
        );
    }

    #[test]
    fn list_is_sent_and_read_as_the_bare_request() {
        assert_eq!(
            serde_json::to_string(&Request::List {}).unwrap(),
            r#"{"request":"list"}"#
        );
        assert_eq!(parse(r#"{"request":"list"}"#), Ok(Request::List {}));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_disk_formatted_keeps_the_room_reserved_for_it() {
        use std::os::unix::fs::MetadataExt;
        let tmp = tempfile::tempdir().unwrap();
        let image = tmp.path().join("job-0123456789ab.img");
        let file = std::fs::File::create(&image).unwrap();
        rustix::fs::fallocate(&file, rustix::fs::FallocateFlags::empty(), 0, 64 << 20).unwrap();
        drop(file);
        format(&image).unwrap();
        let allocated = std::fs::metadata(&image).unwrap().blocks() * 512;
        assert!(allocated >= 64 << 20, "{allocated} bytes allocated of a disk of 64 MiB");
    }

    #[cfg(unix)]
    #[test]
    fn the_disks_in_a_directory_are_its_images_and_its_mount_points_named_by_an_id_each_once() {
        let tmp = tempfile::tempdir().unwrap();
        for file in ["job-0123456789ab.img", "job-ffffffffffff.img", "notes.txt", "Bad.img"] {
            std::fs::write(tmp.path().join(file), "").unwrap();
        }
        for dir in ["job-0123456789ab", "job-aaaaaaaaaaaa", "lost+found"] {
            std::fs::create_dir(tmp.path().join(dir)).unwrap();
        }
        std::os::unix::fs::symlink("/etc", tmp.path().join("job-bbbbbbbbbbbb")).unwrap();
        assert_eq!(
            ids_at(tmp.path()),
            ["job-0123456789ab", "job-aaaaaaaaaaaa", "job-ffffffffffff"]
        );
        assert!(ids_at(&tmp.path().join("none")).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn the_client_sends_one_line_and_reads_one_answer_or_says_why_there_is_none() {
        use std::io::{BufRead, Write};
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("helper.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let serving = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut line = String::new();
            std::io::BufReader::new(&conn).read_line(&mut line).unwrap();
            conn.write_all(
                b"{\"answer\":\"listed\",\"dir\":\"/d\",\"ids\":[\"job-1abc\"],\"most_bytes\":1099511627776,\"most_disks\":16}\n",
            )
            .unwrap();
            line
        });
        let answered = ask(&socket, &Request::List {}, std::time::Duration::from_secs(5)).unwrap();
        assert_eq!(
            answered,
            Answer::Listed {
                dir: "/d".into(),
                ids: vec!["job-1abc".into()],
                most_bytes: 1 << 40,
                most_disks: 16
            }
        );
        assert_eq!(serving.join().unwrap(), "{\"request\":\"list\"}\n");

        let gone = ask(
            &dir.path().join("none.sock"),
            &Request::List {},
            std::time::Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(gone.contains("did not answer") && gone.contains("none.sock"), "{gone}");
    }
}
