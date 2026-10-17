//! The inference endpoint, behind the door's credential. `DeploymentReady` names a base URL on this door, under the
//! deployment, at the engine's OpenAI-compatible path; a request there or under it, with the credential that drove
//! the deploy, as the door's own header or as the `Authorization: Bearer` the OpenAI-compatible clients send, goes
//! to the engine as it is and the answer comes back as it comes, streaming included. The door reads the headers it
//! checks and nothing else: no token is recorded, and its events still say what the machine runs, never what the
//! model answered. Without the credential the answer is the door's 401; a deployment that is not ready, is ending
//! or is gone answers 404 with what to do; one another credential holds is refused by name unless the caller acts
//! for every holder; a path under the deployment that is not the endpoint (the engine's own API, which may delete
//! or pull models) is 404 with the endpoint named, and a method the OpenAI-compatible API does not use is 405; an
//! engine that does not answer is 502 with what to do.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderName, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use best_peer_door::auth::{Credential, AUTH_HEADER};
use best_peer_door::error::BestError;
use best_peer_door::Auth;

use crate::transport::Transport;

/// Where the endpoints live on the door: `/deployments/<deployment>` and the engine's path under it.
const PREFIX: &str = "/deployments/";

/// Where a deployment's prompts go: the base URL the rest of the path is appended to, the one path under it the
/// door forwards (the engine's OpenAI-compatible one, with everything under it; the rest of the engine's API is
/// not the endpoint), the credential that opens it when it is another door's (a member of this cloud), and the
/// transport to reach it.
pub struct Route {
    pub base: String,
    pub path: String,
    pub key: Option<String>,
    pub transport: Arc<dyn Transport>,
}

/// What stands behind the endpoints: a peer's engines on this host, or a cloud's members.
pub trait Upstream: Send + Sync + 'static {
    /// The route for `deployment` while it is ready, or the refusal that says what to do.
    fn upstream_of(&self, deployment: &str, who: &Credential) -> Result<Route, BestError>;
}

#[derive(Clone)]
struct Gateway {
    upstream: Arc<dyn Upstream>,
    auth: Arc<Auth>,
}

/// The routes `DeploymentReady` names: the deployment's endpoint and everything under it go to that deployment's
/// engine, with the path and query as the client sent them; anything else under the deployment is refused.
pub fn router(upstream: Arc<dyn Upstream>, auth: Arc<Auth>) -> Router {
    Router::new()
        .route("/deployments/:deployment", any(pass_through))
        .route("/deployments/:deployment/", any(pass_through))
        .route("/deployments/:deployment/*rest", any(pass_through))
        .with_state(Gateway { upstream, auth })
}

/// The most a request to an engine may carry: a prompt with its context, never a file.
const MAX_PROMPT_BODY: usize = 8 * 1024 * 1024;

fn too_large() -> BestError {
    BestError::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        "PAYLOAD_TOO_LARGE",
        format!(
            "the endpoint takes a request of {MAX_PROMPT_BODY} bytes at most: a prompt with its context, not a file"
        ),
    )
}

async fn pass_through(State(gw): State<Gateway>, req: Request) -> Response {
    forward(&gw, req).await.unwrap_or_else(IntoResponse::into_response)
}

async fn forward(gw: &Gateway, req: Request) -> Result<Response, BestError> {
    let key = credential(req.headers());
    let Some(who) = (!key.is_empty()).then(|| gw.auth.authenticate(key)).flatten() else {
        return Err(BestError::unauthorized());
    };
    // The deployment and the rest are read from the request line as sent, never decoded: what the client encoded
    // reaches the engine encoded, and `..` or a `?` inside a segment stays inside it.
    let sent = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".into());
    let after = sent.strip_prefix(PREFIX).unwrap_or("");
    let end = after.find(['/', '?']).unwrap_or(after.len());
    let (deployment, rest) = after.split_at(end);
    if deployment.is_empty() {
        return Err(BestError::not_found(
            "NO_SUCH_DEPLOYMENT",
            "the endpoint names a deployment: /deployments/<deployment>/v1, as DeploymentReady said",
        ));
    }
    let route = gw.upstream.upstream_of(deployment, &who)?;
    if !at_or_under(rest, &route.path) {
        return Err(BestError::not_found(
            "NOT_AN_ENDPOINT",
            format!(
                "the endpoint of {deployment} is {PREFIX}{deployment}{} and what is under it, as DeploymentReady said; the engine's own API is not reached through the door",
                route.path
            ),
        ));
    }
    if req.method() != Method::GET && req.method() != Method::POST {
        return Err(BestError::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "METHOD_NOT_ALLOWED",
            format!(
                "the endpoint takes GET and POST, as the OpenAI-compatible API does, not {}",
                req.method()
            ),
        ));
    }
    let uri: Uri = format!("{}{rest}", route.base)
        .parse()
        .map_err(|e| BestError::bad_request("BAD_REQUEST", format!("the path cannot be forwarded: {e}")))?;
    if req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|n| n > MAX_PROMPT_BODY)
    {
        return Err(too_large());
    }
    let (mut parts, body) = req.into_parts();
    // A body that says no length is bounded as it streams: the engine buffers what it is sent.
    let body = axum::body::Body::new(http_body_util::Limited::new(body, MAX_PROMPT_BODY));
    parts.uri = uri;
    // The engine is reached over HTTP/1.1 whatever the client negotiated with the door (h2 over TLS, as curl does).
    parts.version = axum::http::Version::HTTP_11;
    // The engine gets the request as the client made it, less what is this hop's: the host it was sent to, the
    // credential, which ends here, and the headers that govern one connection, not the request.
    parts.headers.remove(header::HOST);
    parts.headers.remove(AUTH_HEADER);
    parts.headers.remove(header::AUTHORIZATION);
    strip_hop_by_hop(&mut parts.headers);
    // A member's endpoint opens to this door's own credential for it, never to the caller's.
    if let Some(key) = &route.key {
        if let Ok(v) = key.parse() {
            parts.headers.insert(AUTH_HEADER, v);
        }
    }
    let res = route
        .transport
        .call(Request::from_parts(parts, body))
        .await
        .map_err(|e| {
            if e.contains("length limit exceeded") {
                return too_large();
            }
            BestError::new(
                StatusCode::BAD_GATEWAY,
                "ENGINE_UNREACHABLE",
                format!(
                    "the engine behind {deployment} did not answer: {e}. If it stopped, DeploymentEnded follows within 30 s; else read the engine's logs on the host"
                ),
            )
        })?;
    let (mut parts, body) = res.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    Ok(Response::from_parts(parts, body))
}

/// Whether `rest`, the path and query after the deployment as the client sent them, is `path` or under it: the
/// path itself, with or without a slash or a query after it, or a longer path below it. `/v1x` is not under `/v1`,
/// and the deployment's base itself is under nothing.
fn at_or_under(rest: &str, path: &str) -> bool {
    match rest.strip_prefix(path) {
        Some(after) => after.is_empty() || after.starts_with('/') || after.starts_with('?'),
        None => false,
    }
}

/// The credential, from the door's own header or the `Authorization: Bearer` the OpenAI-compatible clients send.
pub fn credential(headers: &HeaderMap) -> &str {
    let own = headers
        .get(AUTH_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .unwrap_or("");
    if !own.is_empty() {
        return own;
    }
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| v.len() > 7 && v[..7].eq_ignore_ascii_case("bearer "))
        .map(|v| v[7..].trim())
        .unwrap_or("")
}

/// Removes what belongs to one connection and not to the request or the answer (RFC 9110 §7.6.1): the headers
/// `Connection` names, and the hop-by-hop ones by name. Each hop frames its own body and keeps its own
/// connections; a client's `Connection: close` must not close the door's connection to the engine, nor the
/// engine's the door's to the client.
fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<String> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    for name in named {
        if let Ok(name) = HeaderName::from_bytes(name.as_bytes()) {
            headers.remove(name);
        }
    }
    for name in [
        header::CONNECTION,
        header::PROXY_AUTHENTICATE,
        header::PROXY_AUTHORIZATION,
        header::TE,
        header::TRAILER,
        header::TRANSFER_ENCODING,
        header::UPGRADE,
    ] {
        headers.remove(name);
    }
    headers.remove("keep-alive");
}
