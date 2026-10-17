//! TLS on the door, and the client side of `best-peer approve`. Rustls on ring: no system library, so the binary
//! stays one file on every target. The certificate is the operator's (`BEST_PEER_TLS_CERT` and `BEST_PEER_TLS_KEY`,
//! PEM files) or one the peer makes for itself at first start and keeps in its data directory, named in its log so
//! that every client can pin it. The peer checks nothing about a certificate beyond that it loads: whose name it
//! carries is the operator's business. ACME is not here: a private cloud has its own CA or pins.
//!
//! What the peer serves and where is written to `<data>/door` at start, the certificate it loaded included, so
//! `best-peer approve`, which runs on the same machine with the same data directory, knows where to go and which
//! certificate to trust: that one, by its bytes, and no other, whatever the file it came from holds by then.

use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

/// Whether the door serves TLS, and with whose certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tls {
    /// Plain HTTP: the endpoint is `http://` and no certificate was given.
    Off,
    /// The operator's certificate chain and private key, PEM files.
    Given { cert: PathBuf, key: PathBuf },
    /// The peer's own, made at first start in its data directory.
    Own,
}

impl Tls {
    /// The decision from the endpoint's scheme and the two variables: a certificate comes with its key or not at
    /// all, and serves an `https://` endpoint only.
    pub fn decide(endpoint: &str, cert: Option<&str>, key: Option<&str>) -> Result<Self, String> {
        let https = endpoint.starts_with("https://");
        match (cert, key) {
            (Some(cert), Some(key)) if https => Ok(Tls::Given {
                cert: PathBuf::from(cert),
                key: PathBuf::from(key),
            }),
            (Some(_), Some(_)) => Err(format!(
                "BEST_PEER_ENDPOINT is {endpoint}, but a certificate is set: the endpoint a certificate serves starts with https://"
            )),
            (Some(_), None) => Err("BEST_PEER_TLS_CERT is set without BEST_PEER_TLS_KEY: name the key's PEM file too, or unset both and the peer makes its own certificate".into()),
            (None, Some(_)) => Err("BEST_PEER_TLS_KEY is set without BEST_PEER_TLS_CERT: name the certificate's PEM file too, or unset both and the peer makes its own certificate".into()),
            (None, None) if https => Ok(Tls::Own),
            (None, None) => Ok(Tls::Off),
        }
    }
}

/// What the peer serves and where, for `best-peer approve`.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Record {
    pub listen: SocketAddr,
    pub endpoint: String,
    /// The certificate the door serves, PEM, when it serves TLS: the one it loaded at start, so the pin holds
    /// through a renewal on disk until the peer restarts with the new one.
    pub certificate: Option<String>,
}

impl Record {
    const FILE: &'static str = "door";

    pub fn write(&self, dir: &Path) -> std::io::Result<()> {
        std::fs::write(dir.join(Self::FILE), serde_json::to_vec_pretty(self)?)
    }

    pub fn read(dir: &Path) -> std::io::Result<Self> {
        let text = read_plain(&dir.join(Self::FILE), 1 << 20)?;
        serde_json::from_str(&text).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Where `approve` connects: the listen address, or this machine's loopback when the peer listens on every
    /// interface, which is no address to dial.
    pub fn dial(&self) -> SocketAddr {
        let ip = match self.listen.ip() {
            ip if !ip.is_unspecified() => ip,
            std::net::IpAddr::V4(_) => std::net::Ipv4Addr::LOCALHOST.into(),
            std::net::IpAddr::V6(_) => std::net::Ipv6Addr::LOCALHOST.into(),
        };
        SocketAddr::new(ip, self.listen.port())
    }

    /// Where `approve` connects, when that is an address of this machine: the token never leaves it, whoever wrote
    /// the record.
    pub fn dial_here(&self) -> Result<SocketAddr, String> {
        let addr = self.dial();
        match std::net::UdpSocket::bind(SocketAddr::new(addr.ip(), 0)) {
            Ok(_) => Ok(addr),
            Err(_) => Err(format!(
                "the record of the running peer names {addr}, which is not an address of this machine: the admin token goes nowhere else"
            )),
        }
    }
}

/// A file's text when it is the file itself, at most `limit` bytes: never a link to another, by name or by a second
/// hard link, so a command run with more rights than the data directory's owner reads nothing that owner did not write.
pub fn read_plain(path: &Path, limit: u64) -> std::io::Result<String> {
    use std::io::Read;
    let refuse = |why: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{}: {why}", path.display()));
    let named = std::fs::symlink_metadata(path)?;
    if !named.file_type().is_file() {
        return Err(refuse("not a plain file"));
    }
    let file = std::fs::File::open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = file.metadata()?;
        if (opened.dev(), opened.ino()) != (named.dev(), named.ino()) {
            return Err(refuse("replaced while it was opened"));
        }
        if opened.nlink() != 1 {
            return Err(refuse("a hard link to another file"));
        }
    }
    let mut text = String::new();
    file.take(limit + 1).read_to_string(&mut text)?;
    if text.len() as u64 > limit {
        return Err(refuse("larger than it can be"));
    }
    Ok(text)
}

/// The names the peer's own certificate carries: this machine's loopback by its three names, the host the endpoint
/// names, and the address the door listens on when it is one.
pub fn names_for(endpoint: &str, listen: &SocketAddr) -> Vec<String> {
    let mut names = vec!["localhost".to_string(), "127.0.0.1".to_string(), "::1".to_string()];
    let host = endpoint
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or_default();
    let host = match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or_default(),
        None => host.split(':').next().unwrap_or_default(),
    };
    let mut wanted = vec![host.to_string()];
    if !listen.ip().is_unspecified() {
        wanted.push(listen.ip().to_string());
    }
    for name in wanted {
        if !name.is_empty() && !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

/// What the door serves over TLS.
#[derive(Debug)]
pub struct Served {
    pub config: Arc<ServerConfig>,
    /// The PEM file the certificate came from, as given or as made.
    pub file: PathBuf,
    /// The certificate itself, the first block of that file as loaded: what `approve` pins.
    pub certificate: String,
    /// Whether the peer's own certificate was made or remade at this start, so the start-up line can say so.
    pub made: bool,
}

/// The server's TLS configuration and the certificate it serves, or nothing when the door is plain HTTP. The
/// operator's files are loaded as given; the peer's own are made under `<dir>/tls` the first time and read back
/// after, remade when the names they must carry change or their end is near.
pub fn serving(tls: &Tls, dir: &Path, names: &[String]) -> Result<Option<Served>, String> {
    let (cert, key, made) = match tls {
        Tls::Off => return Ok(None),
        Tls::Given { cert, key } => (cert.clone(), key.clone(), false),
        Tls::Own => own(&dir.join("tls"), names)?,
    };
    let text = std::fs::read_to_string(&cert)
        .map_err(|e| format!("cannot read the certificate in {}: {e}", cert.display()))?;
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(text.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|e| format!("cannot read the certificate in {}: {e}", cert.display()))?;
    if chain.is_empty() {
        return Err(format!(
            "{} holds no certificate: a PEM file with at least one CERTIFICATE block",
            cert.display()
        ));
    }
    let certificate = first_block(&text).to_string();
    let key_der = PrivateKeyDer::from_pem_file(&key)
        .map_err(|e| format!("cannot read the private key in {}: {e}", key.display()))?;
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS is not available: {e}"))?
        .with_no_client_auth()
        .with_single_cert(chain, key_der)
        .map_err(|e| {
            format!(
                "the certificate in {} and the key in {} do not make a TLS identity: {e}",
                cert.display(),
                key.display()
            )
        })?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Some(Served {
        config: Arc::new(config),
        file: cert,
        certificate,
        made,
    }))
}

/// The first PEM block of a file: the certificate the door presents, without the chain behind it.
fn first_block(pem: &str) -> &str {
    const END: &str = "-----END CERTIFICATE-----";
    match (pem.find("-----BEGIN CERTIFICATE-----"), pem.find(END)) {
        (Some(start), Some(end)) if start < end => pem[start..end + END.len()].trim_end(),
        _ => pem.trim(),
    }
}

/// What the peer's own certificate was made for, kept next to it: the names it carries and when it ends, so a
/// start with other names, or near the end, makes a new one.
#[derive(Serialize, Deserialize, PartialEq, Eq)]
struct Made {
    names: Vec<String>,
    not_after: String,
}

/// The peer's own certificate and key under `dir`, and whether they were made at this start: self-signed on an
/// ECDSA P-256 key, valid ten years, carrying `names`, the key file readable by its owner alone. The pair is kept
/// across starts, and made again when the names change or fewer than thirty days remain.
fn own(dir: &Path, names: &[String]) -> Result<(PathBuf, PathBuf, bool), String> {
    let (cert, key, made) = (dir.join("cert.pem"), dir.join("key.pem"), dir.join("made.json"));
    let now = time::OffsetDateTime::now_utc();
    if cert.is_file() && key.is_file() {
        let kept = std::fs::read_to_string(&made)
            .ok()
            .and_then(|t| serde_json::from_str::<Made>(&t).ok());
        let ends = kept.as_ref().and_then(|m| {
            time::OffsetDateTime::parse(&m.not_after, &time::format_description::well_known::Rfc3339).ok()
        });
        if kept.as_ref().is_some_and(|m| m.names == names) && ends.is_some_and(|e| e - now > time::Duration::days(30)) {
            return Ok((cert, key, false));
        }
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot make {}: {e}", dir.display()))?;
    let mut params = rcgen::CertificateParams::new(names.to_vec())
        .map_err(|e| format!("cannot put {names:?} on a certificate: {e}"))?;
    params.distinguished_name.push(rcgen::DnType::CommonName, "best-peer");
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(10 * 365);
    let pair = rcgen::KeyPair::generate().map_err(|e| format!("cannot make a key: {e}"))?;
    let signed = params
        .self_signed(&pair)
        .map_err(|e| format!("cannot make a certificate: {e}"))?;
    write_private(&key, pair.serialize_pem().as_bytes()).map_err(|e| format!("cannot write {}: {e}", key.display()))?;
    std::fs::write(&cert, signed.pem()).map_err(|e| format!("cannot write {}: {e}", cert.display()))?;
    let record = Made {
        names: names.to_vec(),
        not_after: params
            .not_after
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| format!("cannot write the certificate's end: {e}"))?,
    };
    std::fs::write(&made, serde_json::to_vec_pretty(&record).map_err(|e| e.to_string())?)
        .map_err(|e| format!("cannot write {}: {e}", made.display()))?;
    Ok((cert, key, true))
}

/// Writes a file its owner alone can read, whatever was there before: an existing file is removed first, since
/// a mode on creation does not touch one that exists, and the mode is set again after.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A request to the peer at `addr`: over TLS when `pin` is the PEM of the certificate it serves, and then that
/// certificate is the only one accepted, by its bytes, whatever name it carries. The answer's status and its body
/// as JSON, or nothing when the body is not JSON.
pub async fn call(
    addr: SocketAddr,
    pin: Option<&str>,
    req: Request<Body>,
) -> Result<(StatusCode, serde_json::Value), String> {
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| format!("cannot reach the peer at {addr}: {e}"))?;
    let Some(pin) = pin else {
        return exchange(tcp, req).await;
    };
    let pinned = CertificateDer::from_pem_slice(pin.as_bytes())
        .map_err(|e| format!("the record of the peer's certificate is not a certificate: {e}"))?;
    let config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS is not available: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned {
            cert: pinned,
            provider: provider(),
        }))
        .with_no_client_auth();
    let name = ServerName::IpAddress(addr.ip().into());
    let stream = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .map_err(|e| format!("the peer at {addr} does not serve the certificate it recorded at start: {e}"))?;
    exchange(stream, req).await
}

async fn exchange<S>(stream: S, req: Request<Body>) -> Result<(StatusCode, serde_json::Value), String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| format!("the peer did not speak HTTP: {e}"))?;
    tokio::spawn(connection);
    let res = sender
        .send_request(req)
        .await
        .map_err(|e| format!("the peer did not answer: {e}"))?;
    let status = res.status();
    let bytes = axum::body::to_bytes(Body::new(res.into_body()), 1 << 20)
        .await
        .map_err(|e| format!("the peer's answer could not be read: {e}"))?;
    Ok((status, serde_json::from_slice(&bytes).unwrap_or_default()))
}

/// Accepts one certificate, by its bytes, and no other: the one the peer on this machine serves.
#[derive(Debug)]
struct Pinned {
    cert: CertificateDer<'static>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.cert.as_ref() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_certificate_comes_with_its_key_and_serves_https_only() {
        assert_eq!(Tls::decide("http://127.0.0.1:7777", None, None).unwrap(), Tls::Off);
        assert_eq!(Tls::decide("https://127.0.0.1:7777", None, None).unwrap(), Tls::Own);
        assert_eq!(
            Tls::decide("https://peer.example.com", Some("c.pem"), Some("k.pem")).unwrap(),
            Tls::Given {
                cert: "c.pem".into(),
                key: "k.pem".into()
            }
        );
        let why = Tls::decide("http://peer.example.com", Some("c.pem"), Some("k.pem")).unwrap_err();
        assert!(why.contains("https://"), "{why}");
        let why = Tls::decide("https://peer.example.com", Some("c.pem"), None).unwrap_err();
        assert!(why.contains("BEST_PEER_TLS_KEY"), "{why}");
        let why = Tls::decide("https://peer.example.com", None, Some("k.pem")).unwrap_err();
        assert!(why.contains("BEST_PEER_TLS_CERT"), "{why}");
    }

    #[test]
    fn the_own_certificate_names_loopback_the_endpoint_host_and_the_listen_address() {
        let names = names_for("https://peer.example.com:7777/", &"0.0.0.0:7777".parse().unwrap());
        assert_eq!(names, ["localhost", "127.0.0.1", "::1", "peer.example.com"]);
        let names = names_for("https://10.0.0.5:7777", &"10.0.0.5:7777".parse().unwrap());
        assert_eq!(names, ["localhost", "127.0.0.1", "::1", "10.0.0.5"]);
        let names = names_for("https://[::1]:7777", &"[::]:7777".parse().unwrap());
        assert_eq!(names, ["localhost", "127.0.0.1", "::1"]);
        let names = names_for("https://box.lan", &"192.168.1.9:443".parse().unwrap());
        assert_eq!(names, ["localhost", "127.0.0.1", "::1", "box.lan", "192.168.1.9"]);
    }

    #[test]
    fn the_own_certificate_is_kept_until_its_names_change_and_the_operators_files_are_refused_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let names = names_for("https://127.0.0.1:7777", &"127.0.0.1:7777".parse().unwrap());
        let served = serving(&Tls::Own, dir.path(), &names).unwrap().unwrap();
        assert_eq!(served.file, dir.path().join("tls").join("cert.pem"));
        assert!(served.made);
        let first = std::fs::read_to_string(&served.file).unwrap();
        assert!(first.starts_with("-----BEGIN CERTIFICATE-----"));
        assert_eq!(
            served.certificate,
            first.trim_end(),
            "the record carries the file's one block"
        );
        let again = serving(&Tls::Own, dir.path(), &names).unwrap().unwrap();
        assert!(!again.made);
        assert_eq!(
            again.certificate, served.certificate,
            "a second start made a new certificate"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join("tls").join("key.pem"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "the key is readable beyond its owner");
        }

        // Other names, for an endpoint moved to another host: a new certificate, so the pin changes.
        let moved = names_for("https://peer.example.com:7777", &"0.0.0.0:7777".parse().unwrap());
        let remade = serving(&Tls::Own, dir.path(), &moved).unwrap().unwrap();
        assert!(remade.made);
        assert_ne!(remade.certificate, served.certificate);
        assert!(!serving(&Tls::Own, dir.path(), &moved).unwrap().unwrap().made);

        // The operator's files: the ones just made load, and the pin is the file's first block; a missing one is
        // refused by its path.
        let given = Tls::Given {
            cert: remade.file.clone(),
            key: dir.path().join("tls").join("key.pem"),
        };
        let given_served = serving(&given, dir.path(), &[]).unwrap().unwrap();
        assert_eq!(given_served.certificate, remade.certificate);
        assert!(!given_served.made);
        let missing = Tls::Given {
            cert: dir.path().join("nowhere.pem"),
            key: dir.path().join("tls").join("key.pem"),
        };
        let why = serving(&missing, dir.path(), &[]).unwrap_err();
        assert!(why.contains("nowhere.pem"), "{why}");
        assert!(serving(&Tls::Off, dir.path(), &[]).unwrap().is_none());
    }

    #[test]
    fn the_first_block_of_a_chain_is_the_certificate_presented() {
        let chain = "-----BEGIN CERTIFICATE-----\\nAAAA\\n-----END CERTIFICATE-----\\n-----BEGIN CERTIFICATE-----\\nBBBB\\n-----END CERTIFICATE-----\\n";
        assert_eq!(
            first_block(chain),
            "-----BEGIN CERTIFICATE-----\\nAAAA\\n-----END CERTIFICATE-----"
        );
        assert_eq!(first_block("  x "), "x");
    }

    #[test]
    fn the_record_says_where_approve_dials() {
        let dir = tempfile::tempdir().unwrap();
        let record = Record {
            listen: "0.0.0.0:7777".parse().unwrap(),
            endpoint: "https://peer.example.com:7777".into(),
            certificate: Some("-----BEGIN CERTIFICATE-----".into()),
        };
        record.write(dir.path()).unwrap();
        let read = Record::read(dir.path()).unwrap();
        assert_eq!(read, record);
        assert_eq!(read.dial().to_string(), "127.0.0.1:7777");
        let v6 = Record {
            listen: "[::]:7777".parse().unwrap(),
            ..read
        };
        assert_eq!(v6.dial().to_string(), "[::1]:7777");
        assert!(Record::read(&dir.path().join("none")).is_err());
    }

    #[test]
    fn approve_dials_this_machine_only() {
        let here = Record {
            listen: "0.0.0.0:7777".parse().unwrap(),
            endpoint: "https://peer.example.com:7777".into(),
            certificate: None,
        };
        assert_eq!(here.dial_here().unwrap().to_string(), "127.0.0.1:7777");
        let elsewhere = Record {
            listen: "192.0.2.1:7777".parse().unwrap(),
            ..here
        };
        assert!(elsewhere
            .dial_here()
            .unwrap_err()
            .contains("not an address of this machine"));
    }

    #[cfg(unix)]
    #[test]
    fn a_link_in_the_data_directory_is_never_followed() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = dir.path().join("elsewhere");
        std::fs::write(&elsewhere, "not the peer's").unwrap();
        std::os::unix::fs::symlink(&elsewhere, dir.path().join("admin-token")).unwrap();
        assert!(read_plain(&dir.path().join("admin-token"), 1024).is_err());
        std::fs::hard_link(&elsewhere, dir.path().join("door")).unwrap();
        assert!(Record::read(dir.path()).is_err());
        std::fs::remove_file(dir.path().join("door")).unwrap();
        std::fs::write(dir.path().join("token"), "x".repeat(2048)).unwrap();
        assert!(read_plain(&dir.path().join("token"), 1024).is_err());
        std::fs::write(dir.path().join("token"), "the token\n").unwrap();
        assert_eq!(read_plain(&dir.path().join("token"), 1024).unwrap(), "the token\n");
    }
}
