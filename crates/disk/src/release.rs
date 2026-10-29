//! The walk of a release: everything under a disk's `out/` given to the peer, by descriptor and never by path. `out`
//! is opened from a descriptor of the disk's root, and each directory under it from its parent's, with `openat` and
//! `O_NOFOLLOW | O_DIRECTORY`, so never through a link, and each is checked after it is opened to be on the disk's
//! device, so never on another mount. Not `openat2`: systemd's `RestrictSUIDSGID`, which the helper's unit sets,
//! cannot read its flags and answers it `ENOSYS`; and the disk's root is root's and the peer's group's `0750`, so
//! neither the peer nor the job can put anything else where `out` is. Each entry is changed with
//! `fchownat(AT_SYMLINK_NOFOLLOW)`, so a link is changed itself and never what it names, and a FIFO is never opened.
//! What holds the walk to the disk is the device: nothing enters the disk but by a mount, and only root mounts. The
//! directories open at once are one per level, at most [`MOST_DEPTH`].

use std::os::fd::{BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};

use crate::{Peer, MOST_DEPTH};

/// Gives everything under `out/` of the disk whose root is `root` to `peer`, telling `changed` each path changed,
/// relative to `out/`; fails past `most_depth` levels, or when `out` is no directory of the disk itself.
pub fn release(
    root: BorrowedFd<'_>,
    peer: Peer,
    most_depth: usize,
    changed: &mut dyn FnMut(&Path),
) -> Result<(), String> {
    let dev = rustix::fs::fstat(root)
        .map_err(|e| format!("the disk's root cannot be read: {e}"))?
        .st_dev;
    let out = rustix::fs::openat(
        root,
        "out",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|e| format!("the disk's out/ cannot be opened as a directory of its own: {e}"))?;
    let mut open = vec![(on_the_disk(out, dev)?, PathBuf::new())];
    loop {
        let depth = open.len();
        let Some((dir, at)) = open.last_mut() else {
            break;
        };
        let entry = match dir.read() {
            None => {
                open.pop();
                continue;
            }
            Some(entry) => entry.map_err(|e| format!("{} cannot be read: {e}", shown(at)))?,
        };
        let name = entry.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        let path = at.join(<std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(
            name.to_bytes(),
        ));
        let fd = dir.fd().map_err(|e| e.to_string())?;
        let st = match rustix::fs::statat(fd, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) => st,
            Err(rustix::io::Errno::NOENT) => continue,
            Err(e) => return Err(format!("{} cannot be read: {e}", shown(&path))),
        };
        if st.st_dev != dev {
            continue;
        }
        rustix::fs::chownat(
            fd,
            name,
            Some(rustix::fs::Uid::from_raw(peer.uid)),
            Some(rustix::fs::Gid::from_raw(peer.gid)),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|e| format!("{} cannot be given to the peer: {e}", shown(&path)))?;
        changed(&path);
        if FileType::from_raw_mode(st.st_mode) != FileType::Directory {
            continue;
        }
        if depth > most_depth {
            return Err(format!(
                "out/ is nested deeper than {most_depth} directories: {}",
                shown(&path)
            ));
        }
        let child = match rustix::fs::openat(
            fd,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(child) => child,
            Err(rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR | rustix::io::Errno::NOENT) => continue,
            Err(e) => return Err(format!("{} cannot be opened: {e}", shown(&path))),
        };
        open.push((on_the_disk(child, dev)?, path));
    }
    Ok(())
}

/// The directory `fd` to read, once it is checked to be on the disk's device `dev`.
fn on_the_disk(fd: OwnedFd, dev: u64) -> Result<Dir, String> {
    let st = rustix::fs::fstat(&fd).map_err(|e| e.to_string())?;
    if st.st_dev != dev {
        return Err("a directory under out/ is on another device than the disk".into());
    }
    Dir::new(fd).map_err(|e| e.to_string())
}

fn shown(path: &Path) -> String {
    format!("out/{}", path.display())
}

/// [`release`] at the depth every helper keeps.
pub fn release_out(root: BorrowedFd<'_>, peer: Peer) -> Result<(), String> {
    release(root, peer, MOST_DEPTH, &mut |_| {})
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::os::fd::AsFd;

    fn me() -> Peer {
        Peer {
            uid: rustix::process::getuid().as_raw(),
            gid: rustix::process::getgid().as_raw(),
        }
    }

    fn open(path: &Path) -> OwnedFd {
        rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
    }

    fn walked(root: &Path, most_depth: usize) -> Result<BTreeSet<PathBuf>, String> {
        let mut seen = BTreeSet::new();
        release(open(root).as_fd(), me(), most_depth, &mut |p| {
            seen.insert(p.to_path_buf());
        })
        .map(|_| seen)
    }

    #[test]
    fn a_release_changes_every_entry_under_out_and_a_link_itself_never_what_it_names() {
        let tmp = tempfile::tempdir().unwrap();
        let (root, elsewhere) = (tmp.path().join("disk"), tmp.path().join("etc"));
        std::fs::create_dir_all(root.join("out/frames/deep")).unwrap();
        std::fs::create_dir_all(root.join("in")).unwrap();
        std::fs::create_dir_all(elsewhere.join("inner")).unwrap();
        std::fs::write(elsewhere.join("passwd"), "x").unwrap();
        std::fs::write(root.join("in/scene.txt"), "x").unwrap();
        std::fs::write(root.join("out/a.png"), "x").unwrap();
        std::fs::write(root.join("out/frames/deep/b.png"), "x").unwrap();
        std::os::unix::fs::symlink(&elsewhere, root.join("out/etc")).unwrap();
        std::os::unix::fs::symlink(elsewhere.join("passwd"), root.join("out/frames/passwd")).unwrap();
        rustix::fs::mknodat(
            open(&root.join("out")).as_fd(),
            "pipe",
            FileType::Fifo,
            Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();

        let seen = walked(&root, MOST_DEPTH).unwrap();
        let expected: BTreeSet<PathBuf> = [
            "a.png",
            "frames",
            "frames/deep",
            "frames/deep/b.png",
            "frames/passwd",
            "etc",
            "pipe",
        ]
        .into_iter()
        .map(PathBuf::from)
        .collect();
        assert_eq!(seen, expected);
    }

    #[test]
    fn an_out_that_is_a_link_or_no_directory_is_refused_and_nothing_changed() {
        let tmp = tempfile::tempdir().unwrap();
        let elsewhere = tmp.path().join("etc");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("passwd"), "x").unwrap();

        let linked = tmp.path().join("linked");
        std::fs::create_dir_all(&linked).unwrap();
        std::os::unix::fs::symlink(&elsewhere, linked.join("out")).unwrap();
        assert!(walked(&linked, MOST_DEPTH).is_err());

        let fifo = tmp.path().join("fifo");
        std::fs::create_dir_all(&fifo).unwrap();
        rustix::fs::mknodat(
            open(&fifo).as_fd(),
            "out",
            FileType::Fifo,
            Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        assert!(walked(&fifo, MOST_DEPTH).is_err());

        let none = tmp.path().join("none");
        std::fs::create_dir_all(&none).unwrap();
        assert!(walked(&none, MOST_DEPTH).is_err());
    }

    #[test]
    fn a_tree_deeper_than_the_cap_fails_the_release() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("out/1/2/3")).unwrap();
        assert_eq!(walked(tmp.path(), 3).unwrap().len(), 3);
        std::fs::create_dir_all(tmp.path().join("out/1/2/3/4")).unwrap();
        let why = walked(tmp.path(), 3).unwrap_err();
        assert!(why.contains("deeper than 3"), "{why}");
    }
}
