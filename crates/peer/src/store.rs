//! A workspace's store, where its jobs' inputs come from and their outputs go (behavioralstate/spec#66). It speaks S3,
//! so any S3-compatible store serves, Verda's object storage the first proven. The workspace's credential stays with
//! its door: for each order the door signs short-lived URLs (S3 presigned, Signature Version 4, path-style), a GET for
//! each input and a PUT for the outputs, and a member peer is handed those URLs and nothing else. The bytes go between
//! the machine and the store; the door carries only keys and sizes.

use std::path::Path;
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

    /// The size of the object at `key`, or none when the store holds no such object; an error is the store not
    /// answering as a store does.
    pub async fn size_of(&self, key: &str) -> Result<Option<u64>, String> {
        let url = self.presign("HEAD", key, 300, OffsetDateTime::now_utc());
        tokio::task::spawn_blocking(move || head(&url, ASKING))
            .await
            .map_err(|e| e.to_string())?
    }
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

/// How long a question to the store may take, and how long it may take to start answering a transfer.
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

/// Sends the file `from` to `url` whole, answering its bytes.
pub fn put(url: &str, from: &Path) -> Result<u64, String> {
    put_within(url, from, STARTING, |bytes| within(Some(bytes)))
}

/// The same, the archive given `body` of its bytes to be sent and the store `starting` to answer then.
fn put_within(url: &str, from: &Path, starting: Duration, body: impl FnOnce(u64) -> Duration) -> Result<u64, String> {
    let file = std::fs::File::open(from).map_err(|e| format!("cannot read {}: {e}", from.display()))?;
    let bytes = file.metadata().map_err(|e| e.to_string())?.len();
    let agent = agent(|c| {
        c.timeout_send_body(Some(body(bytes)))
            .timeout_recv_response(Some(starting))
    });
    let response = agent
        .put(url)
        .header("content-length", &bytes.to_string())
        .send(ureq::SendBody::from_reader(&mut std::io::BufReader::new(file)))
        .map_err(|e| match e {
            ureq::Error::StatusCode(code) => format!("the store answered {code}"),
            e => format!("the store did not take it: {e}"),
        })?;
    answered(&response)?;
    Ok(bytes)
}

/// Packs the directory `dir` into the archive `to`, paths relative to it; answers the archive's bytes.
pub fn pack(dir: &Path, to: &Path) -> Result<u64, String> {
    let file = std::fs::File::create(to).map_err(|e| format!("cannot write {}: {e}", to.display()))?;
    let mut archive = tar::Builder::new(file);
    archive.follow_symlinks(false);
    archive
        .append_dir_all(".", dir)
        .and_then(|_| archive.finish())
        .map_err(|e| format!("cannot pack {}: {e}", dir.display()))?;
    std::fs::metadata(to).map(|m| m.len()).map_err(|e| e.to_string())
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
        let from = dir.path().join("out.tar");
        std::fs::write(&from, b"x").unwrap();
        let started = std::time::Instant::now();
        // Says nothing at all.
        let silent = stalled(b"");
        let why = head(&silent, second).unwrap_err();
        assert!(why.contains("did not answer"), "{why}");
        let why = fetch_within(&silent, &dir.path().join("a"), second, second).unwrap_err();
        assert!(why.contains("did not answer"), "{why}");
        let why = put_within(&silent, &from, second, |_| second).unwrap_err();
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
        let (to, from) = (dir.path().join("in"), dir.path().join("out.tar"));
        std::fs::write(&from, b"x").unwrap();
        let (fetched, sent) = {
            let to = to.clone();
            tokio::task::spawn_blocking(move || (fetch(&at, &to, Some(4)), put(&at, &from)))
                .await
                .unwrap()
        };
        let why = fetched.unwrap_err();
        assert!(why.contains("307"), "{why}");
        assert_ne!(std::fs::read(&to).unwrap_or_default(), b"nope");
        let why = sent.unwrap_err();
        assert!(why.contains("307"), "{why}");
    }
}
