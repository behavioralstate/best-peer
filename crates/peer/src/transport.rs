//! The peer transport: how this peer reaches another door (a member of the cloud it fronts) and the engines it
//! passes prompts to. One trait the crate owns; HTTP behind it, in one place, and an in-process fake for the tests,
//! which never open a socket.

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, Response};
use futures::future::BoxFuture;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;

/// A request to an absolute URL, answered as it came: the status, the headers and the body, streaming. An error is
/// the transport's own (nothing answered), never a door's refusal, which is an answer.
pub trait Transport: Send + Sync + 'static {
    fn call(&self, req: Request<Body>) -> BoxFuture<'static, Result<Response<Body>, String>>;
}

/// Where this peer carries a credential in cleartext, from `BEST_PEER_CLEARTEXT`: on loopback alone, unless the
/// operator says a VPN already encrypts the hop (`vpn`). The door it serves and the members its clouds reach are held
/// to the same rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cleartext {
    Loopback,
    Vpn,
}

impl Cleartext {
    pub fn parse(text: Option<&str>) -> Result<Self, String> {
        match text.map(str::trim) {
            None | Some("") => Ok(Cleartext::Loopback),
            Some("vpn") => Ok(Cleartext::Vpn),
            Some(t) => Err(format!(
                "BEST_PEER_CLEARTEXT must be vpn, when a VPN already encrypts every hop to and from this peer, or unset, not {t:?}"
            )),
        }
    }

    /// Whether a credential may go to or come from `url`: always over `https://`, over `http://` only to this
    /// machine's loopback or where a VPN carries it.
    pub fn allows(self, url: &str) -> bool {
        match url.split_once("://") {
            Some((scheme, _)) if scheme.eq_ignore_ascii_case("https") => true,
            Some((scheme, _)) if scheme.eq_ignore_ascii_case("http") => {
                self == Cleartext::Vpn || is_loopback(url_host(url))
            }
            _ => false,
        }
    }
}

/// The host of an absolute URL, an IPv6 address with its brackets.
pub fn url_host(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if host_port.starts_with('[') {
        return host_port.split_inclusive(']').next().unwrap_or(host_port);
    }
    host_port.rsplit_once(':').map_or(host_port, |(h, _)| h)
}

/// Whether a host name or address is this machine's loopback, an IPv4 address mapped into IPv6 included.
pub fn is_loopback(host: &str) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    bare.eq_ignore_ascii_case("localhost")
        || bare
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.to_canonical().is_loopback())
}

/// HTTP and HTTPS over TCP. HTTPS trusts the public roots and the PEM files given, which is how a member's own
/// certificate is pinned: the file the member names at start, handed to the cloud as `BEST_PEER_TRUST`. A request
/// in cleartext off loopback is refused before it is sent, unless the operator said a VPN carries it, so a cloud's
/// credential never travels in the clear to a member.
pub struct Http {
    client: Client<hyper_rustls::HttpsConnector<HttpConnector>, Body>,
    cleartext: Cleartext,
}

impl Http {
    pub fn new(trust: &[PathBuf], cleartext: Cleartext) -> Result<Self, String> {
        let mut roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        for file in trust {
            let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(file)
                .and_then(|certs| certs.collect())
                .map_err(|e| format!("cannot read the certificates in {}: {e}", file.display()))?;
            if certs.is_empty() {
                return Err(format!("{} holds no certificate to trust", file.display()));
            }
            for cert in certs {
                roots
                    .add(cert)
                    .map_err(|e| format!("a certificate in {} cannot be trusted: {e}", file.display()))?;
            }
        }
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("TLS is not available: {e}"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(config)
            .https_or_http()
            .enable_http1()
            .build();
        Ok(Self {
            client: Client::builder(TokioExecutor::new()).build(connector),
            cleartext,
        })
    }
}

impl Transport for Http {
    fn call(&self, req: Request<Body>) -> BoxFuture<'static, Result<Response<Body>, String>> {
        let client = self.client.clone();
        let url = req.uri().to_string();
        if !self.cleartext.allows(&url) {
            return Box::pin(async move {
                Err(format!(
                    "{url} is cleartext off loopback, and the credential would travel unencrypted: name the member by its https:// endpoint, or set BEST_PEER_CLEARTEXT=vpn on this peer when a VPN carries it"
                ))
            });
        }
        Box::pin(async move {
            let res = client.request(req).await.map_err(|e| e.to_string())?;
            let (parts, body) = res.into_parts();
            Ok(Response::from_parts(parts, Body::new(body)))
        })
    }
}

/// A door in this process: the fake of the transport, for tests. Every call goes straight into the router, as the
/// network would deliver it, with no socket.
#[cfg(test)]
pub struct InProcess {
    pub router: axum::Router,
}

#[cfg(test)]
impl Transport for InProcess {
    fn call(&self, req: Request<Body>) -> BoxFuture<'static, Result<Response<Body>, String>> {
        use tower::ServiceExt;
        let router = self.router.clone();
        Box::pin(async move { router.oneshot(req).await.map_err(|e| e.to_string()) })
    }
}
