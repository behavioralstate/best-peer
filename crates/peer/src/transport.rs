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

/// HTTP and HTTPS over TCP. HTTPS trusts the public roots and the PEM files given, which is how a member's own
/// certificate is pinned: the file the member names at start, handed to the cloud as `BEST_PEER_TRUST`.
pub struct Http {
    client: Client<hyper_rustls::HttpsConnector<HttpConnector>, Body>,
}

impl Http {
    pub fn new(trust: &[PathBuf]) -> Result<Self, String> {
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
        })
    }
}

impl Transport for Http {
    fn call(&self, req: Request<Body>) -> BoxFuture<'static, Result<Response<Body>, String>> {
        let client = self.client.clone();
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
