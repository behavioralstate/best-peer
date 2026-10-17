//! The inference endpoint, behind the door's credential. `DeploymentReady` names a base URL on this door, under the
//! deployment; a request there with the credential that drove the deploy, as the door's own header or as the
//! `Authorization: Bearer` the OpenAI-compatible clients send, goes to the engine as it is and the answer comes back
//! as it comes, streaming included. The door reads the headers it checks and nothing else: no token is recorded, and
//! its events still say what the machine runs, never what the model answered. Without the credential the answer is
//! the door's 401; a deployment that is not ready, is ending or is gone answers 404 with what to do; one another
//! credential holds is refused by name unless the caller acts for every holder; an engine that does not answer is
//! 502 with what to do.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderName, StatusCode, Uri};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use best_peer_door::auth::{Credential, AUTH_HEADER};
use best_peer_door::error::BestError;
use best_peer_door::router::{access_log, Holder};
use best_peer_door::Auth;

use crate::transport::Transport;

/// Where the endpoints live on the door: `/deployments/<deployment>` and everything under it.
const PREFIX: &str = "/deployments/";

/// Where a deployment's prompts go: the base URL the rest of the path is appended to, the credential that opens it
/// when it is another door's (a member of this cloud), and the transport to reach it.
pub struct Route {
    pub base: String,
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

/// The routes `DeploymentReady` names: the deployment's base and everything under it go to that deployment's
/// engine, with the path and query as the client sent them.
pub fn router(upstream: Arc<dyn Upstream>, auth: Arc<Auth>) -> Router {
    Router::new()
        .route("/deployments/:deployment", any(pass_through))
        .route("/deployments/:deployment/", any(pass_through))
        .route("/deployments/:deployment/*rest", any(pass_through))
        .layer(middleware::from_fn(access_log))
        .with_state(Gateway { upstream, auth })
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
    let rest = match rest {
        "" => "/".to_string(),
        r if r.starts_with('?') => format!("/{r}"),
        r => r.to_string(),
    };
    let uri: Uri = format!("{}{rest}", route.base)
        .parse()
        .map_err(|e| BestError::bad_request("BAD_REQUEST", format!("the path cannot be forwarded: {e}")))?;
    let (mut parts, body) = req.into_parts();
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
    parts.extensions.insert(Holder(who.holder()));
    Ok(Response::from_parts(parts, body))
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
