//! A workspace's store, where its jobs' inputs come from and their outputs go (behavioralstate/spec#66). It speaks S3,
//! so any S3-compatible store serves, Verda's object storage the first proven. The workspace's credential stays with
//! its door: for each order the door signs short-lived URLs (S3 presigned, Signature Version 4, path-style), a GET for
//! each input and a PUT for the outputs, and a member peer is handed those URLs and nothing else. The bytes go between
//! the machine and the store; the door carries only keys and sizes.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

/// The longest a signed URL may live, by Signature Version 4: seven days.
pub const MOST_SECONDS: u64 = 7 * 24 * 60 * 60;

/// A workspace's store, as its owner set it.
#[derive(Clone, Serialize, Deserialize)]
pub struct Store {
    /// The S3 endpoint, scheme and host: `https://objects.example.com`.
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
}

impl Store {
    /// A URL that lets whoever holds it do `method` on `key` for `expires` seconds from `now`, and nothing else.
    pub fn presign(&self, method: &str, key: &str, expires: u64, now: OffsetDateTime) -> String {
        let endpoint = self.endpoint.trim_end_matches('/');
        let host = endpoint.split_once("://").map_or(endpoint, |(_, h)| h);
        let path = format!("/{}/{}", self.bucket, encode(key, false));
        let query = signed_query(
            method,
            host,
            &path,
            &self.access_key_id,
            &self.secret_access_key,
            &self.region,
            now,
            expires.min(MOST_SECONDS),
        );
        format!("{endpoint}{path}?{query}")
    }

    /// The sizes of the objects at `keys`, in their order, asked as many at a time as `asking` lets, which every
    /// order of the workspace shares, and all answered by `by`. Each question holds a thread until it is answered,
    /// and none outlives `by`.
    pub async fn sizes_of(
        &self,
        keys: &[String],
        asking: &Arc<tokio::sync::Semaphore>,
        by: tokio::time::Instant,
    ) -> Result<Vec<u64>, Unsized> {
        let now = OffsetDateTime::now_utc();
        let mut asked = tokio::task::JoinSet::new();
        for (n, key) in keys.iter().enumerate() {
            let url = self.presign("HEAD", key, 300, now);
            let asking = asking.clone();
            asked.spawn(async move {
                let Ok(turn) = asking.acquire_owned().await else {
                    return (n, Err("the store is no longer asked".to_string()));
                };
                let limit = by.saturating_duration_since(tokio::time::Instant::now());
                if limit.is_zero() {
                    return (n, Err("not asked: the time ran out".to_string()));
                }
                let answer = tokio::task::spawn_blocking(move || {
                    let _turn = turn;
                    head(&url, limit)
                })
                .await
                .map_err(|e| e.to_string());
                (n, answer.and_then(|a| a))
            });
        }
        let mut sizes = vec![None; keys.len()];
        while let Ok(Some(answered)) = tokio::time::timeout_at(by, asked.join_next()).await {
            match answered {
                Ok((n, Ok(Some(bytes)))) => sizes[n] = Some(bytes),
                Ok((n, Ok(None))) => return Err(Unsized::Missing(n)),
                // Past the time, an error is the time running out, whatever the store would have said.
                Ok((_, Err(_))) if tokio::time::Instant::now() >= by => {}
                Ok((n, Err(why))) => return Err(Unsized::Unreachable(n, why)),
                Err(_) => {}
            }
        }
        let late: Vec<usize> = (0..sizes.len()).filter(|n| sizes[*n].is_none()).collect();
        match late.is_empty() {
            true => Ok(sizes.into_iter().flatten().collect()),
            false => Err(Unsized::Late(late)),
        }
    }
}

/// How many questions a workspace's store is asked at once, by all its orders together.
pub const ASKED_AT_ONCE: usize = 8;

/// How long an order's inputs may take to be sized, all of them together.
pub const SIZING: Duration = Duration::from_secs(60);

/// Why an order's inputs were not sized, each input by its place in the order.
#[derive(Debug, PartialEq)]
pub enum Unsized {
    /// The store holds no object at this one.
    Missing(usize),
    /// The store did not answer as a store does about this one.
    Unreachable(usize, String),
    /// The time ran out with these not answered.
    Late(Vec<usize>),
}

/// The size of what `url` names, asked within `limit`: none when the store holds nothing there.
fn head(url: &str, limit: Duration) -> Result<Option<u64>, String> {
    match agent(|c| c.timeout_global(Some(limit))).head(url).call() {
        Ok(r) if r.status().is_success() => Ok(r
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .or(Some(0))),
        Ok(r) => Err(format!("the store answered {}", r.status().as_u16())),
        Err(ureq::Error::StatusCode(404)) => Ok(None),
        Err(ureq::Error::StatusCode(code)) => Err(format!("the store answered {code}")),
        Err(e) => Err(format!("the store did not answer: {e}")),
    }
}

/// How long connecting to the store may take, and how long it may take to start answering a transfer.
const ASKING: Duration = Duration::from_secs(60);
const STARTING: Duration = Duration::from_secs(600);

/// The slowest a transfer may go, on average, before it is given up as stalled: a mebibyte a second.
const SLOWEST: u64 = 1 << 20;

/// How long a transfer of `bytes` may take: ten minutes, and a second more for each mebibyte; a day when its size
/// is not known. Past it the transfer fails, so a store that stops answering holds no job for ever.
pub fn within(bytes: Option<u64>) -> Duration {
    match bytes {
        Some(b) => STARTING + Duration::from_secs(b / SLOWEST),
        None => Duration::from_secs(24 * 60 * 60),
    }
}

/// What a transfer's client is built from.
type Limits = ureq::config::ConfigBuilder<ureq::typestate::AgentScope>;

/// The HTTP client of the store's transfers, `limits` set on it: a minute to connect, every status but a success an
/// error, and no redirect followed, so a URL cannot lead a machine on to a place it may not go.
fn agent(limits: impl FnOnce(Limits) -> Limits) -> ureq::Agent {
    limits(
        ureq::Agent::config_builder()
            .timeout_connect(Some(ASKING))
            .http_status_as_error(true)
            .max_redirects(0),
    )
    .build()
    .into()
}

/// What a store answered that is not a success, a redirect among them, in words.
fn answered<B>(r: &ureq::http::Response<B>) -> Result<(), String> {
    match r.status().is_success() {
        true => Ok(()),
        false => Err(format!("the store answered {}", r.status().as_u16())),
    }
}

/// Whether a member peer may fetch from or send to `url`: https anywhere, plain http only to this host's loopback
/// when its operator allows it (a store on the same machine, as in a test), and never anywhere else, so an order
/// cannot point a machine at what only it can reach. A URL naming a user before its host is refused: it reaches
/// another host than it seems to.
pub fn allowed(url: &str, cleartext_loopback: bool) -> bool {
    let Ok(uri) = url.parse::<axum::http::Uri>() else {
        return false;
    };
    let Some(authority) = uri.authority() else {
        return false;
    };
    if authority.as_str().contains('@') {
        return false;
    }
    match uri.scheme_str() {
        Some("https") => !authority.host().is_empty(),
        Some("http") => cleartext_loopback && matches!(authority.host(), "127.0.0.1" | "localhost" | "[::1]"),
        _ => false,
    }
}

/// Whether `endpoint` is a store's address a machine may reach, as [`allowed`] says, and the address alone: a
/// scheme and a host, with no path or query.
pub fn endpoint_allowed(endpoint: &str, cleartext_loopback: bool) -> bool {
    let Ok(uri) = endpoint.parse::<axum::http::Uri>() else {
        return false;
    };
    allowed(endpoint, cleartext_loopback) && matches!(uri.path(), "" | "/") && uri.query().is_none()
}

/// Fetches `url` into `to`, answering the bytes written; `bytes` is its size when known, which bounds how long it
/// may take.
pub fn fetch(url: &str, to: &Path, bytes: Option<u64>) -> Result<u64, String> {
    fetch_within(url, to, STARTING, within(bytes))
}

/// The same, the store given `starting` to answer and `body` to send it all.
fn fetch_within(url: &str, to: &Path, starting: Duration, body: Duration) -> Result<u64, String> {
    if let Some(dir) = to.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("cannot make {}: {e}", dir.display()))?;
    }
    let mut file = std::fs::File::create(to).map_err(|e| format!("cannot write {}: {e}", to.display()))?;
    let agent = agent(|c| c.timeout_recv_response(Some(starting)).timeout_recv_body(Some(body)));
    let mut response = agent.get(url).call().map_err(|e| match e {
        ureq::Error::StatusCode(code) => format!("the store answered {code}"),
        e => format!("the store did not answer: {e}"),
    })?;
    answered(&response)?;
    std::io::copy(&mut response.body_mut().as_reader(), &mut file)
        .map_err(|e| format!("fetching into {} stopped: {e}", to.display()))
}

/// Sends `body`, `bytes` long, to `url`: the store given `starting` to answer and `sending` to take the body.
fn put_body(url: &str, mut body: impl Read, bytes: u64, starting: Duration, sending: Duration) -> Result<(), String> {
    let agent = agent(|c| c.timeout_send_body(Some(sending)).timeout_recv_response(Some(starting)));
    let response = agent
        .put(url)
        .header("content-length", &bytes.to_string())
        .send(ureq::SendBody::from_reader(&mut body))
        .map_err(|e| match e {
            ureq::Error::StatusCode(code) => format!("the store answered {code}"),
            e => format!("the store did not take it: {e}"),
        })?;
    answered(&response)
}

/// What a job's outputs are made of: what its `out` holds that is a directory, a regular file or a link, by path
/// relative to it. A pipe, a device or a socket the job left there is not an output, and is left out.
enum Output {
    Dir {
        path: PathBuf,
        mtime: u64,
    },
    File {
        path: PathBuf,
        from: PathBuf,
        bytes: u64,
        mtime: u64,
        mode: u32,
    },
    Link {
        path: PathBuf,
        to: PathBuf,
        mtime: u64,
    },
}

/// The outputs under `dir`, in name order, a directory before what it holds. A link is kept as a link and never
/// followed, wherever it points. The job has exited, so nothing changes them while they are read.
fn outputs(dir: &Path) -> std::io::Result<Vec<Output>> {
    fn walk(dir: &Path, under: &Path, out: &mut Vec<Output>) -> std::io::Result<()> {
        let mut names: Vec<std::ffi::OsString> = std::fs::read_dir(dir.join(under))?
            .map(|e| e.map(|e| e.file_name()))
            .collect::<Result<_, _>>()?;
        names.sort();
        for name in names {
            let path = under.join(&name);
            let from = dir.join(&path);
            let meta = std::fs::symlink_metadata(&from)?;
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs());
            let kind = meta.file_type();
            if kind.is_symlink() {
                let to = std::fs::read_link(&from)?;
                out.push(Output::Link { path, to, mtime });
            } else if kind.is_dir() {
                out.push(Output::Dir {
                    path: path.clone(),
                    mtime,
                });
                walk(dir, &path, out)?;
            } else if kind.is_file() {
                out.push(Output::File {
                    path,
                    from,
                    bytes: meta.len(),
                    mtime,
                    mode: mode_of(&meta),
                });
            }
        }
        Ok(())
    }
    let mut out = vec![];
    walk(dir, Path::new(""), &mut out)?;
    Ok(out)
}

/// The permission bits a file's entry carries: its own on Unix, where an executable stays one.
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o777
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        0o644
    }
}

/// Writes the tar archive of `outputs` to `to`, paths relative to the outputs' directory; answers the bytes of file
/// contents left out. Without `contents`, each file's header is written and its contents are not: the archive's
/// length is then what was written plus what is answered, each file's size rounded up to a whole block, counted
/// without reading a byte or spending time on a file's size.
fn archive(outputs: &[Output], to: impl Write, contents: bool) -> std::io::Result<u64> {
    let mut left_out = 0;
    let mut tar = tar::Builder::new(to);
    for o in outputs {
        let mut h = tar::Header::new_gnu();
        match o {
            Output::Dir { path, mtime } => {
                h.set_entry_type(tar::EntryType::Directory);
                h.set_mode(0o755);
                h.set_mtime(*mtime);
                h.set_size(0);
                tar.append_data(&mut h, path, std::io::empty())?;
            }
            Output::File {
                path,
                from,
                bytes,
                mtime,
                mode,
            } => {
                h.set_entry_type(tar::EntryType::Regular);
                h.set_mode(*mode);
                h.set_mtime(*mtime);
                h.set_size(*bytes);
                match contents {
                    true => tar.append_data(&mut h, path, Exact::new(std::fs::File::open(from)?, *bytes))?,
                    false => {
                        tar.append_data(&mut h, path, std::io::empty())?;
                        left_out += bytes.div_ceil(512) * 512;
                    }
                }
            }
            Output::Link { path, to, mtime } => {
                h.set_entry_type(tar::EntryType::Symlink);
                h.set_mode(0o777);
                h.set_mtime(*mtime);
                h.set_size(0);
                tar.append_link(&mut h, path, to)?;
            }
        }
    }
    tar.into_inner()?.flush()?;
    Ok(left_out)
}

/// Exactly `left` bytes of a file, or an error when it holds fewer: the archive's length was told before.
struct Exact<R> {
    inner: R,
    left: u64,
}

impl<R: Read> Exact<R> {
    fn new(inner: R, left: u64) -> Self {
        Self { inner, left }
    }
}

impl<R: Read> Read for Exact<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.left == 0 {
            return Ok(0);
        }
        let most = buf.len().min(usize::try_from(self.left).unwrap_or(usize::MAX));
        let n = self.inner.read(&mut buf[..most])?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "a file was shorter than when it was counted",
            ));
        }
        self.left -= n as u64;
        Ok(n)
    }
}

/// How many bytes pass through it.
#[derive(Default)]
struct Count(u64);

impl Write for Count {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len() as u64;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A body that fails as soon as `stop` is set, so a stop ends a transfer at the store's next read.
struct Stoppable<R> {
    inner: R,
    stop: Arc<AtomicBool>,
}

impl<R: Read> Read for Stoppable<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.stop.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("stopped"));
        }
        self.inner.read(buf)
    }
}

/// Packs the outputs under `dir` into one tar archive and sends it to `url` as it is made, so nothing of it is
/// written beside the job's disk; answers its bytes. The store is told the archive's length before its body, so the
/// length is counted first, from the files' sizes. `stop` ends it at the store's next read.
pub fn send_outputs(dir: &Path, url: &str, stop: Arc<AtomicBool>) -> Result<u64, String> {
    let outputs = outputs(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    let mut count = Count::default();
    let left_out = archive(&outputs, &mut count, false).map_err(|e| format!("cannot pack {}: {e}", dir.display()))?;
    let bytes = count.0 + left_out;
    let (reader, writer) = std::io::pipe().map_err(|e| e.to_string())?;
    let packer = std::thread::spawn(move || archive(&outputs, writer, true));
    let sent = put_body(
        url,
        Stoppable {
            inner: reader,
            stop: stop.clone(),
        },
        bytes,
        STARTING,
        within(Some(bytes)),
    );
    let packed = packer
        .join()
        .map_err(|_| "the packer stopped unexpectedly".to_string())?;
    // A store that refused the body ends the packing with a broken pipe: what the store said is the reason.
    match (sent, packed) {
        _ if stop.load(Ordering::SeqCst) => Err("stopped".into()),
        (Err(e), _) => Err(e),
        (Ok(()), Err(e)) => Err(format!("cannot pack {}: {e}", dir.display())),
        (Ok(()), Ok(_)) => Ok(bytes),
    }
}

/// The query string of a URL signed with Signature Version 4 for `method` on `path` at `host`, the payload
/// unsigned, signing the host header alone.
#[allow(clippy::too_many_arguments)]
fn signed_query(
    method: &str,
    host: &str,
    path: &str,
    key_id: &str,
    secret: &str,
    region: &str,
    now: OffsetDateTime,
    expires: u64,
) -> String {
    let date = format!("{:04}{:02}{:02}", now.year(), now.month() as u8, now.day());
    let stamp = format!("{date}T{:02}{:02}{:02}Z", now.hour(), now.minute(), now.second());
    let scope = format!("{date}/{region}/s3/aws4_request");
    let query = format!(
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={}&X-Amz-Date={stamp}&X-Amz-Expires={expires}&X-Amz-SignedHeaders=host",
        encode(&format!("{key_id}/{scope}"), true)
    );
    let canonical = format!("{method}\n{path}\n{query}\nhost:{host}\n\nhost\nUNSIGNED-PAYLOAD");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}",
        hex(&Sha256::digest(canonical.as_bytes()))
    );
    let mut key = hmac(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    for part in [region, "s3", "aws4_request"] {
        key = hmac(&key, part.as_bytes());
    }
    format!("{query}&X-Amz-Signature={}", hex(&hmac(&key, to_sign.as_bytes())))
}

/// HMAC-SHA256 of `message` under `key`.
fn hmac(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let pad = |b: u8| block.iter().map(|k| k ^ b).collect::<Vec<u8>>();
    let inner = Sha256::new().chain_update(pad(0x36)).chain_update(message).finalize();
    Sha256::new()
        .chain_update(pad(0x5c))
        .chain_update(inner)
        .finalize()
        .to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `s` percent-encoded as Signature Version 4 asks: every byte but the unreserved, and `/` too when `slash`.
fn encode(s: &str, slash: bool) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
            b'/' if !slash => "/".to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_url_is_signed_as_the_s3_documentation_signs_its_example() {
        // AWS's own example of a presigned GET: the signature it documents for these inputs.
        let now =
            OffsetDateTime::parse("2013-05-24T00:00:00Z", &time::format_description::well_known::Rfc3339).unwrap();
        let q = signed_query(
            "GET",
            "examplebucket.s3.amazonaws.com",
            "/test.txt",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            now,
            86400,
        );
        assert!(
            q.ends_with("X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"),
            "{q}"
        );
        assert!(q.contains("X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request"));
    }

    #[test]
    fn a_store_signs_path_style_urls_for_a_key_and_never_longer_than_seven_days() {
        let s = Store {
            endpoint: "https://objects.test/".into(),
            bucket: "renders".into(),
            region: "fin-01".into(),
            access_key_id: "id".into(),
            secret_access_key: "secret".into(),
        };
        let url = s.presign("PUT", "out/job 1.tar", 30 * 24 * 3600, OffsetDateTime::now_utc());
        assert!(
            url.starts_with("https://objects.test/renders/out/job%201.tar?X-Amz-Algorithm="),
            "{url}"
        );
        assert!(url.contains("X-Amz-Expires=604800"), "{url}");
        assert!(!url.contains("secret"), "the secret never leaves: {url}");
    }

    #[test]
    fn a_machine_reaches_a_store_over_https_and_plain_http_only_on_loopback_when_allowed() {
        assert!(allowed("https://objects.test/b/k?x", false));
        assert!(!allowed("http://objects.test/b/k", true));
        assert!(!allowed("http://127.0.0.1:9000/b/k", false));
        assert!(allowed("http://127.0.0.1:9000/b/k", true));
        assert!(allowed("http://[::1]/b/k", true) && allowed("http://localhost:9000/b/k", true));
        assert!(!allowed("http://169.254.169.254/latest/meta-data", true));
        assert!(!allowed("file:///etc/passwd", true));
        // A user named before the host: the connection goes to the host after it, wherever the first part points.
        assert!(!allowed("http://127.0.0.1:80@169.254.169.254/latest/meta-data", true));
        assert!(!allowed("https://user:pass@objects.test/b/k", false));
        assert!(!allowed("not a url", true));
        // A store's endpoint is its address alone.
        assert!(endpoint_allowed("https://objects.test", false) && endpoint_allowed("https://objects.test/", false));
        assert!(!endpoint_allowed("https://objects.test/bucket", false));
        assert!(!endpoint_allowed("https://objects.test?x=1", false));
        assert!(!endpoint_allowed("http://127.0.0.1:1@evil.test", true));
    }

    #[test]
    fn a_transfer_may_take_ten_minutes_and_a_second_a_mebibyte_and_a_day_when_its_size_is_not_known() {
        assert_eq!(within(Some(0)), Duration::from_secs(600));
        assert_eq!(within(Some(1 << 30)), Duration::from_secs(600 + 1024));
        assert_eq!(within(None), Duration::from_secs(86_400));
    }

    /// A store on loopback that takes each connection, reads what comes, and says `said` and then nothing more,
    /// holding the connection open: a store that stopped answering.
    fn stalled(said: &'static [u8]) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let at = format!("http://{}/b/k", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                std::thread::spawn(move || {
                    let mut stream = stream;
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                    let mut buf = [0u8; 4096];
                    let _ = stream.read(&mut buf);
                    let _ = stream.write_all(said);
                    let _ = stream.flush();
                    std::thread::sleep(Duration::from_secs(10));
                });
            }
        });
        at
    }

    #[test]
    fn a_store_that_stops_answering_fails_the_question_the_fetch_and_the_upload_within_their_bounds() {
        let second = Duration::from_secs(1);
        let dir = tempfile::tempdir().unwrap();
        let started = std::time::Instant::now();
        // Says nothing at all.
        let silent = stalled(b"");
        let why = head(&silent, second).unwrap_err();
        assert!(why.contains("did not answer"), "{why}");
        let why = fetch_within(&silent, &dir.path().join("a"), second, second).unwrap_err();
        assert!(why.contains("did not answer"), "{why}");
        let why = put_body(&silent, &b"x"[..], 1, second, second).unwrap_err();
        assert!(why.contains("did not take it"), "{why}");
        // Starts the body, then stops.
        let halfway = stalled(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\nten bytes!");
        let why = fetch_within(&halfway, &dir.path().join("b"), second, second).unwrap_err();
        assert!(why.contains("stopped"), "{why}");
        assert!(started.elapsed() < Duration::from_secs(9), "each gave up at its bound");
    }

    #[tokio::test]
    async fn a_store_that_answers_with_a_redirect_is_not_followed_and_its_body_is_not_taken_for_the_input() {
        // A store that sends every request on, to a place on this machine.
        let app = axum::Router::new().fallback(|| async {
            (
                axum::http::StatusCode::TEMPORARY_REDIRECT,
                [(axum::http::header::LOCATION, "http://127.0.0.1:1/secret")],
                "nope",
            )
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = format!("http://{}/b/k", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let dir = tempfile::tempdir().unwrap();
        let to = dir.path().join("in");
        let (fetched, sent) = {
            let to = to.clone();
            tokio::task::spawn_blocking(move || {
                (
                    fetch(&at, &to, Some(4)),
                    put_body(&at, &b"x"[..], 1, STARTING, STARTING),
                )
            })
            .await
            .unwrap()
        };
        let why = fetched.unwrap_err();
        assert!(why.contains("307"), "{why}");
        assert_ne!(std::fs::read(&to).unwrap_or_default(), b"nope");
        let why = sent.unwrap_err();
        assert!(why.contains("307"), "{why}");
    }

    /// A store on loopback that takes one PUT and hands back its length header and body.
    async fn taking() -> (String, tokio::sync::oneshot::Receiver<(Option<u64>, Vec<u8>)>) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let tx = Arc::new(std::sync::Mutex::new(Some(tx)));
        let app = axum::Router::new().fallback(move |headers: axum::http::HeaderMap, body: axum::body::Bytes| {
            let tx = tx.clone();
            async move {
                let length = headers
                    .get(axum::http::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok()?.parse().ok());
                if let Some(tx) = tx.lock().unwrap().take() {
                    let _ = tx.send((length, body.to_vec()));
                }
                axum::http::StatusCode::OK
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = format!("http://{}/b/out.tar", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (at, rx)
    }

    /// Each entry of an archive: its path, its kind, and what it holds or where it points.
    fn listed(archive: &[u8]) -> Vec<(String, String)> {
        tar::Archive::new(archive)
            .entries()
            .unwrap()
            .map(|e| {
                let mut e = e.unwrap();
                let path = e.path().unwrap().to_string_lossy().replace('\\', "/");
                let what = match e.header().entry_type() {
                    tar::EntryType::Directory => "dir".to_string(),
                    tar::EntryType::Symlink => format!("link to {}", e.link_name().unwrap().unwrap().display()),
                    _ => {
                        let mut text = String::new();
                        e.read_to_string(&mut text).unwrap();
                        format!("file {text}")
                    }
                };
                (path, what)
            })
            .collect()
    }

    #[tokio::test]
    async fn outputs_are_streamed_to_the_store_as_their_files_and_directories_with_the_length_counted_first() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        std::fs::create_dir_all(out.join("frames")).unwrap();
        std::fs::write(out.join("result.txt"), "rendered").unwrap();
        std::fs::write(out.join("frames").join("0001.png"), vec![7u8; 70_000]).unwrap();
        let deep = "a-name-longer-than-a-hundred-bytes-".repeat(4);
        std::fs::write(out.join(&deep), "long").unwrap();
        let (at, took) = taking().await;
        let sent = {
            let out = out.clone();
            tokio::task::spawn_blocking(move || send_outputs(&out, &at, Arc::new(AtomicBool::new(false))))
                .await
                .unwrap()
        };
        let bytes = sent.unwrap();
        let (length, body) = took.await.unwrap();
        assert_eq!(length, Some(bytes), "the length told is the length sent");
        assert_eq!(body.len() as u64, bytes);
        let list = listed(&body);
        assert!(
            list.contains(&("result.txt".into(), "file rendered".into())),
            "{list:?}"
        );
        assert!(list.contains(&("frames".into(), "dir".into())), "{list:?}");
        assert!(list.contains(&(deep.clone(), "file long".into())), "{list:?}");
        let mut archive = tar::Archive::new(&body[..]);
        let frame = archive
            .entries()
            .unwrap()
            .map(|e| e.unwrap())
            .find(|e| e.path().unwrap().ends_with("0001.png"))
            .unwrap();
        assert_eq!(frame.header().size().unwrap(), 70_000);
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            1,
            "nothing was written beside the outputs"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_pipe_a_job_leaves_is_no_output_and_a_link_is_stored_as_a_link_never_followed() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("result.txt"), "rendered").unwrap();
        let made = std::process::Command::new("mkfifo")
            .arg(out.join("pipe"))
            .status()
            .unwrap();
        assert!(made.success());
        std::os::unix::fs::symlink("/etc/passwd", out.join("passwords")).unwrap();
        let (at, took) = taking().await;
        let sent = {
            let out = out.clone();
            tokio::task::spawn_blocking(move || send_outputs(&out, &at, Arc::new(AtomicBool::new(false))))
                .await
                .unwrap()
        };
        sent.unwrap();
        let (_, body) = took.await.unwrap();
        let list = listed(&body);
        assert_eq!(
            list,
            vec![
                ("passwords".to_string(), "link to /etc/passwd".to_string()),
                ("result.txt".to_string(), "file rendered".to_string()),
            ],
            "no pipe, and the link as a link"
        );
    }

    #[test]
    fn a_file_shorter_than_counted_fails_the_sending_rather_than_send_a_broken_archive() {
        let mut short = Exact::new(&b"ab"[..], 3);
        let mut read = vec![];
        let e = short.read_to_end(&mut read).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof);
        let mut longer = Exact::new(&b"abcd"[..], 3);
        let mut read = vec![];
        longer.read_to_end(&mut read).unwrap();
        assert_eq!(read, b"abc", "no more than was counted");
    }

    /// Linux only: a file there may claim a terabyte and hold nothing, which Windows does not let an ordinary file do.
    #[cfg(unix)]
    #[test]
    fn a_files_apparent_size_is_counted_without_reading_or_writing_it() {
        let dir = tempfile::tempdir().unwrap();
        let big = std::fs::File::create(dir.path().join("sparse")).unwrap();
        // A file that claims a terabyte and holds nothing: counting it must take no time.
        big.set_len(1 << 40).unwrap();
        let sparse = outputs(dir.path()).unwrap();
        let started = std::time::Instant::now();
        let mut count = Count::default();
        let left_out = archive(&sparse, &mut count, false).unwrap();
        assert!(started.elapsed() < Duration::from_secs(1), "{:?}", started.elapsed());
        assert_eq!(left_out, 1 << 40);
    }

    #[test]
    fn an_archive_counted_without_its_contents_is_exactly_as_long_as_the_archive_written_whole() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("frames")).unwrap();
        std::fs::write(dir.path().join("odd"), vec![1u8; 1000]).unwrap();
        std::fs::write(dir.path().join("frames").join("empty"), b"").unwrap();
        std::fs::write(dir.path().join("a".repeat(150)), b"long name").unwrap();
        let odd = outputs(dir.path()).unwrap();
        let (mut count, mut whole) = (Count::default(), vec![]);
        let left_out = archive(&odd, &mut count, false).unwrap();
        archive(&odd, &mut whole, true).unwrap();
        assert_eq!(count.0 + left_out, whole.len() as u64);
    }

    #[tokio::test]
    async fn a_store_that_refuses_a_large_body_is_the_reason_given_not_the_broken_pipe_it_leaves() {
        // A store that answers 403 at once, without reading what is sent.
        let app = axum::Router::new().fallback(|| async { axum::http::StatusCode::FORBIDDEN });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = format!("http://{}/b/out.tar", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("big"), vec![1u8; 8 << 20]).unwrap();
        let why = {
            let dir = dir.path().to_path_buf();
            tokio::task::spawn_blocking(move || send_outputs(&dir, &at, Arc::new(AtomicBool::new(false))))
                .await
                .unwrap()
                .unwrap_err()
        };
        assert!(why.contains("403") || why.contains("did not take it"), "{why}");
        assert!(!why.contains("cannot pack"), "{why}");
    }

    #[test]
    fn a_sending_stopped_before_it_reads_ends_at_its_first_read() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("big"), vec![1u8; 4 << 20]).unwrap();
        // A store that reads nothing: the body waits on it, and the stop is what ends the wait.
        let silent = stalled(b"");
        let stop = Arc::new(AtomicBool::new(true));
        let started = std::time::Instant::now();
        let why = send_outputs(dir.path(), &silent, stop).unwrap_err();
        assert_eq!(why, "stopped");
        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
    }
}
