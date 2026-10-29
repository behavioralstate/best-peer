//! The helper's work on the host, by syscalls: a disk's image reserved whole with `fallocate` under a lock on the
//! directory, formatted by `mkfs.ext4` without discard ([`crate::format`]; a program: writing ext4 by hand is no part
//! of this helper), attached to a free loop device that passes no discard on ([`crate::no_discard`]), so neither the
//! format nor a later trim gives the room reserved back; the device is attached with `LOOP_CONFIGURE` and
//! `LO_FLAGS_AUTOCLEAR`, so it goes when the disk is unmounted or the mount fails; and the disk is mounted with
//! `mount(2)`, `nosuid,nodev`; unmounted plainly, never lazily, and only its mount point removed with `rmdir`.
//! Everything under the directory is reached from a descriptor of it, without following a link, and the directory
//! itself must be root's and writable by no one else, and is closed to all but the peer's group, as each disk's root
//! is.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rustix::fs::{AtFlags, Dir, FileType, FlockOperation, Mode, OFlags};

use crate::{answer, id_of, room, Answer, Disks, Limits, Peer, Refusal, Refused, MOST_LINE};

/// How long `remove` keeps trying to unmount a disk that is busy, as one the engine is still letting go of is.
const BUSY_FOR: Duration = Duration::from_secs(5);

/// The helper on its directory, for its peer and within its bounds.
pub struct Helper {
    dir: PathBuf,
    peer: Peer,
    limits: Limits,
}

fn failed(what: &str, e: impl std::fmt::Display) -> Refused {
    Refused(Refusal::Failed, format!("{what}: {e}"))
}

fn image_of(id: &str) -> String {
    format!("{id}.img")
}

impl Helper {
    pub fn new(dir: PathBuf, peer: Peer, limits: Limits) -> Self {
        Self { dir, peer, limits }
    }

    /// Answers the one request on `conn`, from the caller the socket says it is.
    pub fn serve(&self, conn: &std::os::unix::net::UnixStream) -> Answer {
        use std::io::{BufRead, Write};
        let asked = || -> Result<Answer, Refused> {
            let cred =
                rustix::net::sockopt::socket_peercred(conn).map_err(|e| failed("the caller cannot be told", e))?;
            conn.set_read_timeout(Some(Duration::from_secs(10)))
                .map_err(|e| failed("the connection", e))?;
            let mut line = String::new();
            std::io::BufReader::new(std::io::Read::take(conn, MOST_LINE as u64))
                .read_line(&mut line)
                .map_err(|e| Refused(Refusal::UnknownRequest, format!("no request was read: {e}")))?;
            if line.len() >= MOST_LINE && !line.ends_with('\n') {
                return Err(Refused(
                    Refusal::UnknownRequest,
                    format!("the request is longer than {MOST_LINE} bytes"),
                ));
            }
            Ok(answer(
                &line,
                cred.uid.as_raw(),
                cred.gid.as_raw(),
                self.peer,
                self.limits,
                self,
            ))
        };
        let answered = asked().unwrap_or_else(Answer::from);
        let mut said = serde_json::to_string(&answered).unwrap_or_default();
        said.push('\n');
        let mut conn = conn;
        let _ = conn.write_all(said.as_bytes());
        answered
    }

    /// The directory, made when it is not there, open, and closed to all but root and the peer's group; refused when
    /// it is a link, not root's, or writable by another.
    fn dir(&self) -> Result<(OwnedFd, u64), Refused> {
        match rustix::fs::mkdir(&self.dir, Mode::from_raw_mode(0o750)) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(e) => return Err(failed(&format!("{} cannot be made", self.dir.display()), e)),
        }
        let fd = rustix::fs::open(
            &self.dir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| failed(&format!("{} cannot be opened as a directory", self.dir.display()), e))?;
        let st = rustix::fs::fstat(&fd).map_err(|e| failed(&self.dir.display().to_string(), e))?;
        trusted(st.st_uid, st.st_mode).map_err(|why| failed(&self.dir.display().to_string(), why))?;
        close_to_the_peer(fd.as_fd(), self.peer).map_err(|why| failed(&self.dir.display().to_string(), why))?;
        Ok((fd, st.st_dev))
    }

    /// Unmounts the disk `id` when it is mounted, and removes its mount point and its image; what is gone already is
    /// no error.
    fn remove_in(&self, dir: BorrowedFd<'_>, dev: u64, id: &str) -> Result<(), Refused> {
        match rustix::fs::statat(dir, id, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) => {
                if st.st_dev != dev {
                    unmount(&self.dir.join(id))?;
                }
                match rustix::fs::unlinkat(dir, id, AtFlags::REMOVEDIR) {
                    Ok(()) | Err(rustix::io::Errno::NOENT) => {}
                    Err(e) => return Err(failed(&format!("the mount point of {id} cannot be removed"), e)),
                }
            }
            Err(rustix::io::Errno::NOENT) => {}
            Err(e) => return Err(failed(&format!("the mount point of {id} cannot be read"), e)),
        }
        match rustix::fs::unlinkat(dir, image_of(id), AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => Ok(()),
            Err(e) => Err(failed(&format!("the image of {id} cannot be removed"), e)),
        }
    }

    /// The disk `id`, once its image is reserved: formatted, attached, mounted and laid out.
    fn ready(&self, dir: BorrowedFd<'_>, dev: u64, id: &str, image: &OwnedFd) -> Result<PathBuf, Refused> {
        crate::format(&self.dir.join(image_of(id))).map_err(|e| failed("the disk cannot be formatted", e))?;
        let (device, number) = attach(image.as_fd()).map_err(|e| failed("no loop device could be attached", e))?;
        crate::no_discard(&format!("loop{number}"))
            .map_err(|e| failed("the disk's room could not be kept reserved", e))?;
        rustix::fs::mkdirat(dir, id, Mode::from_raw_mode(0o750)).map_err(|e| failed("the mount point", e))?;
        let mount = self.dir.join(id);
        rustix::mount::mount(
            format!("/dev/loop{number}"),
            &mount,
            "ext4",
            rustix::mount::MountFlags::NOSUID | rustix::mount::MountFlags::NODEV,
            None,
        )
        .map_err(|e| failed("the disk cannot be mounted", e))?;
        drop(device);
        let root = rustix::fs::openat(
            dir,
            id,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| failed("the disk's root", e))?;
        if rustix::fs::fstat(&root)
            .map_err(|e| failed("the disk's root", e))?
            .st_dev
            == dev
        {
            return Err(failed("the disk's root", "it is not mounted"));
        }
        lay_out(root.as_fd(), self.peer, 0o750).map_err(|e| failed("the disk cannot be laid out", e))?;
        Ok(mount)
    }
}

impl Disks for Helper {
    fn make(&self, id: &str, bytes: u64) -> Result<PathBuf, Refused> {
        let (dir, dev) = self.dir()?;
        rustix::fs::flock(&dir, FlockOperation::LockExclusive).map_err(|e| failed("the directory's lock", e))?;
        for name in [id.to_string(), image_of(id)] {
            match rustix::fs::statat(&dir, &name, AtFlags::SYMLINK_NOFOLLOW) {
                Err(rustix::io::Errno::NOENT) => {}
                _ => {
                    return Err(Refused(
                        Refusal::Exists,
                        format!("{name} is there already: a disk is never made twice for one id"),
                    ))
                }
            }
        }
        let disks = ids_in(dir.as_fd()).map_err(|e| failed("the disks there cannot be counted", e))?;
        let vfs = rustix::fs::fstatvfs(&dir).map_err(|e| failed("the room there cannot be read", e))?;
        room(
            bytes,
            vfs.f_bavail.saturating_mul(vfs.f_frsize),
            vfs.f_blocks.saturating_mul(vfs.f_frsize),
            disks.len(),
            self.limits,
        )?;
        let image = rustix::fs::openat(
            &dir,
            image_of(id),
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|e| failed("the image cannot be made", e))?;
        let made = rustix::fs::fallocate(&image, rustix::fs::FallocateFlags::empty(), 0, bytes)
            .map_err(|e| Refused(Refusal::NoRoom, format!("no room for a disk of {bytes} bytes: {e}")))
            .and_then(|_| {
                rustix::fs::flock(&dir, FlockOperation::Unlock).map_err(|e| failed("the directory's lock", e))?;
                self.ready(dir.as_fd(), dev, id, &image)
            });
        drop(image);
        if made.is_err() {
            let _ = self.remove_in(dir.as_fd(), dev, id);
        }
        made
    }

    fn release(&self, id: &str) -> Result<(), Refused> {
        let (dir, dev) = self.dir()?;
        let root = rustix::fs::openat(
            &dir,
            id,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| failed(&format!("the disk {id}"), e))?;
        if rustix::fs::fstat(&root)
            .map_err(|e| failed(&format!("the disk {id}"), e))?
            .st_dev
            == dev
        {
            return Err(failed(&format!("the disk {id}"), "it is not mounted"));
        }
        crate::release::release_out(root.as_fd(), self.peer).map_err(|e| failed(&format!("the disk {id}"), e))
    }

    fn remove(&self, id: &str) -> Result<(), Refused> {
        let (dir, dev) = self.dir()?;
        self.remove_in(dir.as_fd(), dev, id)
    }

    fn list(&self) -> Result<(PathBuf, Vec<String>), Refused> {
        let (dir, _) = self.dir()?;
        let ids = ids_in(dir.as_fd()).map_err(|e| failed("the disks there cannot be listed", e))?;
        Ok((self.dir.clone(), ids))
    }
}

/// Whether a directory of owner `uid` and mode `mode` may hold the disks: a directory, root's, writable by root alone.
pub fn trusted(uid: u32, mode: u32) -> Result<(), String> {
    if FileType::from_raw_mode(mode) != FileType::Directory {
        return Err("it is not a directory".into());
    }
    if uid != 0 {
        return Err(format!("it is owned by uid {uid}, not root"));
    }
    if mode & 0o022 != 0 {
        return Err(format!(
            "its group or others may write in it (mode {:o})",
            mode & 0o7777
        ));
    }
    Ok(())
}

/// The ids of the disks in the directory `dir`, each once, by [`id_of`]: each image `<id>.img`, and each mount point
/// `<id>`, with its image or without.
pub fn ids_in(dir: BorrowedFd<'_>) -> Result<Vec<String>, String> {
    let mut ids = std::collections::BTreeSet::new();
    for entry in Dir::read_from(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name().to_string_lossy();
        if let Some(id) = id_of(&name, entry.file_type() == FileType::Directory) {
            ids.insert(id.to_string());
        }
    }
    Ok(ids.into_iter().collect())
}

/// Closes the directory `dir` to all but its owner and the peer's group: the peer's group, `0750`. Only root, the
/// engine and the peer reach what is under it; a job reaches its `in/` and `out/` through its binds alone.
pub fn close_to_the_peer(dir: BorrowedFd<'_>, peer: Peer) -> Result<(), String> {
    rustix::fs::fchown(dir, None, Some(rustix::fs::Gid::from_raw(peer.gid))).map_err(|e| e.to_string())?;
    rustix::fs::fchmod(dir, Mode::from_raw_mode(0o750)).map_err(|e| e.to_string())
}

/// Lays a disk's root out: the root itself the peer's group's, `root_mode` (`0750` where root owns it, `0700` where
/// the peer does), so no other user reaches what is on it; `peer/`, the peer's `0700`, for the job's record; `in/`,
/// the peer's `0755`, for its inputs; and `out/`, `0777`, for whoever the job runs as, reached through its bind.
pub fn lay_out(root: BorrowedFd<'_>, peer: Peer, root_mode: u32) -> Result<(), String> {
    rustix::fs::fchown(root, None, Some(rustix::fs::Gid::from_raw(peer.gid))).map_err(|e| format!("the root: {e}"))?;
    rustix::fs::fchmod(root, Mode::from_raw_mode(root_mode)).map_err(|e| format!("the root: {e}"))?;
    for (name, mode, owned) in [("peer", 0o700, true), ("in", 0o755, true), ("out", 0o777, false)] {
        let said = |e: rustix::io::Errno| format!("{name}/: {e}");
        rustix::fs::mkdirat(root, name, Mode::from_raw_mode(mode)).map_err(said)?;
        rustix::fs::chmodat(root, name, Mode::from_raw_mode(mode), AtFlags::empty()).map_err(said)?;
        if owned {
            rustix::fs::chownat(
                root,
                name,
                Some(rustix::fs::Uid::from_raw(peer.uid)),
                Some(rustix::fs::Gid::from_raw(peer.gid)),
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(said)?;
        }
    }
    Ok(())
}

/// Unmounts `mount`, plainly and not following a link, trying again for [`BUSY_FOR`] while it is busy; one not
/// mounted is no error.
fn unmount(mount: &Path) -> Result<(), Refused> {
    let until = std::time::Instant::now() + BUSY_FOR;
    loop {
        match rustix::mount::unmount(mount, rustix::mount::UnmountFlags::NOFOLLOW) {
            Ok(()) | Err(rustix::io::Errno::INVAL) => return Ok(()),
            Err(rustix::io::Errno::BUSY) if std::time::Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(250))
            }
            Err(e) => return Err(failed(&format!("{} cannot be unmounted", mount.display()), e)),
        }
    }
}

struct GetFree;

unsafe impl rustix::ioctl::Ioctl for GetFree {
    type Output = u32;
    const IS_MUTATING: bool = false;

    fn opcode(&self) -> rustix::ioctl::Opcode {
        linux_raw_sys::loop_device::LOOP_CTL_GET_FREE as rustix::ioctl::Opcode
    }

    fn as_ptr(&mut self) -> *mut core::ffi::c_void {
        std::ptr::null_mut()
    }

    unsafe fn output_from_ptr(out: rustix::ioctl::IoctlOutput, _: *mut core::ffi::c_void) -> rustix::io::Result<u32> {
        Ok(out as u32)
    }
}

/// A free loop device attached to `image`, cleared by the kernel once nothing holds it, and its number; another
/// process taking the same device first is tried again on the next.
fn attach(image: BorrowedFd<'_>) -> Result<(OwnedFd, u32), String> {
    use linux_raw_sys::loop_device::{loop_config, LOOP_CONFIGURE, LO_FLAGS_AUTOCLEAR};
    let control = rustix::fs::open("/dev/loop-control", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())
        .map_err(|e| format!("/dev/loop-control: {e}"))?;
    let mut last = String::new();
    for _ in 0..16 {
        let number =
            unsafe { rustix::ioctl::ioctl(&control, GetFree) }.map_err(|e| format!("LOOP_CTL_GET_FREE: {e}"))?;
        let device = rustix::fs::open(
            format!("/dev/loop{number}"),
            OFlags::RDWR | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| format!("/dev/loop{number}: {e}"))?;
        let mut config: loop_config = unsafe { std::mem::zeroed() };
        config.fd = image.as_raw_fd() as u32;
        config.info.lo_flags = LO_FLAGS_AUTOCLEAR as u32;
        let configure =
            unsafe { rustix::ioctl::Setter::<{ LOOP_CONFIGURE as rustix::ioctl::Opcode }, loop_config>::new(config) };
        match unsafe { rustix::ioctl::ioctl(&device, configure) } {
            Ok(()) => return Ok((device, number)),
            Err(rustix::io::Errno::BUSY) => last = format!("/dev/loop{number} was taken first"),
            Err(e) => return Err(format!("LOOP_CONFIGURE on /dev/loop{number} (Linux 5.8 or newer): {e}")),
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
    }

    /// What `helper` answers to a caller that sent `sent`, as the caller reads it back: the answer, and the line.
    fn served(helper: &Helper, sent: &[u8]) -> (Answer, String) {
        use std::io::{BufRead, Write};
        let (theirs, mut ours) = std::os::unix::net::UnixStream::pair().unwrap();
        ours.write_all(sent).unwrap();
        let answered = helper.serve(&theirs);
        let mut line = String::new();
        std::io::BufReader::new(&ours).read_line(&mut line).unwrap();
        (answered, line)
    }

    fn code(answer: &Answer) -> Refusal {
        match answer {
            Answer::Refused { code, .. } => *code,
            other => panic!("not refused: {other:?}"),
        }
    }

    const LIMITS: Limits = Limits {
        most_bytes: 1 << 40,
        most_disks: 16,
    };

    #[test]
    fn a_connection_is_answered_once_with_one_json_line_and_a_caller_not_the_peer_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let helper = Helper::new(tmp.path().join("disks"), me(), LIMITS);
        let (answered, line) = served(&helper, b"{\"request\":\"list\"}\n");
        assert!(line.ends_with('\n') && line.matches('\n').count() == 1, "{line:?}");
        assert_eq!(serde_json::from_str::<Answer>(&line).unwrap(), answered);
        assert_eq!(code(&answered), Refusal::Failed, "a directory not root's is refused");

        let stranger = Helper::new(
            tmp.path().join("disks"),
            Peer {
                uid: me().uid + 1,
                gid: me().gid,
            },
            LIMITS,
        );
        let (answered, line) = served(&stranger, b"{\"request\":\"list\"}\n");
        assert_eq!(code(&answered), Refusal::NotThePeer);
        assert_eq!(serde_json::from_str::<Answer>(&line).unwrap(), answered);
        let other_group = Helper::new(
            tmp.path().join("disks"),
            Peer {
                uid: me().uid,
                gid: me().gid + 1,
            },
            LIMITS,
        );
        assert_eq!(
            code(&served(&other_group, b"{\"request\":\"list\"}\n").0),
            Refusal::NotThePeer
        );
    }

    #[test]
    fn a_line_past_the_longest_or_not_utf8_is_refused_and_never_waited_on() {
        let tmp = tempfile::tempdir().unwrap();
        let helper = Helper::new(tmp.path().join("disks"), me(), LIMITS);
        let (answered, line) = served(&helper, &vec![b'a'; MOST_LINE + 100]);
        assert_eq!(code(&answered), Refusal::UnknownRequest);
        assert!(line.contains("longer than"), "{line}");
        let (answered, _) = served(&helper, b"{\"request\":\"li\xff\xfest\"}\n");
        assert_eq!(code(&answered), Refusal::UnknownRequest);
    }

    #[test]
    fn the_directory_is_roots_alone() {
        assert_eq!(trusted(0, 0o040755), Ok(()));
        assert_eq!(trusted(0, 0o040700), Ok(()));
        assert!(trusted(990, 0o040755).unwrap_err().contains("uid 990"));
        assert!(trusted(0, 0o040775).unwrap_err().contains("775"));
        assert!(trusted(0, 0o040757).is_err());
        assert!(trusted(0, 0o120777).unwrap_err().contains("not a directory"));
    }

    #[test]
    fn the_disks_listed_are_the_images_and_the_mount_points_named_by_an_id() {
        let tmp = tempfile::tempdir().unwrap();
        for file in [
            "job-0123456789ab.img",
            "job-ffffffffffff.img",
            "notes.txt",
            "Bad.img",
            "x.img",
        ] {
            std::fs::write(tmp.path().join(file), "").unwrap();
        }
        for dir in ["job-0123456789ab", "job-aaaaaaaaaaaa", "lost+found"] {
            std::fs::create_dir(tmp.path().join(dir)).unwrap();
        }
        std::os::unix::fs::symlink("/etc", tmp.path().join("job-bbbbbbbbbbbb")).unwrap();
        assert_eq!(
            ids_in(open(tmp.path()).as_fd()).unwrap(),
            ["job-0123456789ab", "job-aaaaaaaaaaaa", "job-ffffffffffff"]
        );
    }

    fn group(path: &Path) -> u32 {
        use std::os::unix::fs::MetadataExt;
        std::fs::symlink_metadata(path).unwrap().gid()
    }

    #[test]
    fn a_disk_is_laid_out_closed_to_all_but_root_and_the_peer_with_its_record_inputs_and_an_out_for_the_job() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("disk");
        std::fs::create_dir(&root).unwrap();
        lay_out(open(&root).as_fd(), me(), 0o750).unwrap();
        assert_eq!((mode(&root), group(&root)), (0o750, me().gid));
        assert_eq!(mode(&root.join("peer")), 0o700);
        assert_eq!(mode(&root.join("in")), 0o755);
        assert_eq!(mode(&root.join("out")), 0o777);
        assert!(
            lay_out(open(&root).as_fd(), me(), 0o750).is_err(),
            "a disk is laid out once"
        );
    }

    #[test]
    fn the_directory_is_closed_to_all_but_root_and_the_peers_group() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("disks");
        std::fs::create_dir(&dir).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        }
        close_to_the_peer(open(&dir).as_fd(), me()).unwrap();
        assert_eq!((mode(&dir), group(&dir)), (0o750, me().gid));
    }
}
