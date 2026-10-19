//! The HTTP routes the spec names (SPEC.md, HTTP Transport and the four capabilities), over a [`Door`]. The manifest
//! and the two OAuth endpoints are public, as are the two the person at the machine uses with the admin token
//! (approve, revoke); everything else needs the credential in the `X-Api-Key` header. Every error the door answers,
//! the framework's included, is in the BEST error format. A tenant's door has the protected routes alone
//! ([`tenant_router`]): its manifest is the root's to serve, and sign-in is the root's.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Extension, Path, Query, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures::stream::{self, Stream, StreamExt};
use futures::FutureExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio_stream::wrappers::BroadcastStream;

use crate::auth::{holder_of_hash, Credential, DeviceRequest, Grant, OAuthError, TokenRequest, AUTH_HEADER};
use crate::catalogue::{CommandDef, Emitter};
use crate::envelope::Envelope;
use crate::error::BestError;
use crate::log::{Accept, Filter, Stored, MAX_PAGE};
use crate::{manifest, Door};

type Shared = Arc<Door>;

/// The most a request body may carry: a command is a few kilobytes, a prompt's conversation more, a form a few
/// hundred bytes.
pub const MAX_BODY: usize = 256 * 1024;
/// What a tenant's door keeps below [`MAX_BODY`]: a workspace's cloud passes a command on to a member's door in an
/// envelope of its own, and whatever the cloud took, the member takes.
pub const TENANT_ROOM: usize = 4 * 1024;

pub fn router(door: Shared) -> Router {
    let public = Router::new()
        .route("/.well-known/best", get(well_known))
        .route("/auth/device", post(device))
        .route("/auth/token", post(token))
        .route("/auth/verify", get(verify))
        .route("/auth/approve", post(approve))
        .route("/auth/revoke", post(revoke));
    shaped(public.merge(protected(&door)), door, MAX_BODY)
}

/// The routes of a tenant's door: the four capabilities behind the credential, and nothing public. The host mounts
/// it under the tenant's endpoint, with the path below that endpoint, and serves the tenant's manifest itself.
pub fn tenant_router(door: Shared) -> Router {
    shaped(protected(&door), door, MAX_BODY - TENANT_ROOM)
}

fn protected(door: &Shared) -> Router<Shared> {
    Router::new()
        .route("/commands", get(command_catalogue).post(ingest))
        .route("/commands/:schema/:version", get(command_document))
        .route("/events", get(list_events))
        .route("/events/stream", get(stream_events))
        .route("/events/:schema/:version", get(event_document))
        .route("/queries", get(query_catalogue))
        .route("/queries/:schema/:version", get(query_document))
        .route("/queries/:schema", get(execute_query))
        .route("/workflows", get(workflow_index))
        .route("/workflows/:id", get(workflow))
        .layer(middleware::from_fn_with_state(door.clone(), require_key))
}

/// Every refusal in the BEST shape, the body bounded at `limit` bytes, an unknown route named.
fn shaped(routes: Router<Shared>, door: Shared, limit: usize) -> Router {
    routes
        .fallback(unknown_route)
        .layer(middleware::map_response(move |res: Response| best_shaped(res, limit)))
        .layer(DefaultBodyLimit::max(limit))
        .with_state(door)
}

/// Who a request was answered for, set by whichever check opened it to a credential, for the access log: the holder
/// id, never the key. A request no credential opened has none.
#[derive(Clone, Debug, Default)]
pub struct Answered(Arc<OnceLock<String>>);

impl Answered {
    /// Records the holder a credential opened the request for, on the request's own record when it has one.
    pub fn record(req: &Request, credential: &Credential) {
        if let Some(a) = req.extensions().get::<Answered>() {
            let _ = a.0.set(credential.holder());
        }
    }
}

/// One line per request, at info, once it is answered: where it came from when the transport said, what it asked
/// (the method and the path as it arrived, without the query string), what it got, the holder when a credential
/// opened it, refused or not, and how long the answer took. A request the client gave up on before its answer is
/// still a line, with the status `-` and `abandoned`. For an event stream the line is written when the stream
/// opens, and `ms` is the time to its headers, not how long it stayed open. The headers and the body are never in
/// it: a key travels in a header, and the line never carries one. Layered once, around everything a door serves,
/// workspaces included.
pub async fn access_log(from: Option<ConnectInfo<SocketAddr>>, mut req: Request, next: Next) -> Response {
    let answered = Answered::default();
    req.extensions_mut().insert(answered.clone());
    let mut line = Line {
        from: from.map(|c| c.0.to_string()).unwrap_or_else(|| "-".into()),
        method: req.method().to_string(),
        path: req.uri().path().to_string(),
        answered,
        started: Instant::now(),
        status: None,
    };
    let res = next.run(req).await;
    line.status = Some(res.status().as_u16());
    res
}

/// The access log's line for one request, written when it is dropped: after the answer, or when the client went
/// away before one.
struct Line {
    from: String,
    method: String,
    path: String,
    answered: Answered,
    started: Instant,
    status: Option<u16>,
}

impl Drop for Line {
    fn drop(&mut self) {
        let holder = self.answered.0.get().map(String::as_str).unwrap_or("-");
        let ms = self.started.elapsed().as_millis() as u64;
        let (from, method, path) = (&self.from, &self.method, &self.path);
        match self.status {
            Some(status) => tracing::info!(%from, %method, %path, status, %holder, ms, "request"),
            None => tracing::info!(%from, %method, %path, status = %"-", %holder, ms, "request abandoned"),
        }
    }
}

async fn require_key(State(door): State<Shared>, mut req: Request, next: Next) -> Response {
    let key = req
        .headers()
        .get(AUTH_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .unwrap_or("");
    let Some(credential) = (!key.is_empty()).then(|| door.auth.authenticate(key)).flatten() else {
        return BestError::unauthorized().into_response();
    };
    Answered::record(&req, &credential);
    req.extensions_mut().insert(credential);
    next.run(req).await
}

async fn unknown_route(req: Request) -> BestError {
    BestError::not_found(
        "NOT_FOUND",
        format!(
            "no such route: {} {}. The manifest at /.well-known/best lists every capability path",
            req.method(),
            req.uri().path()
        ),
    )
}

/// The framework answers some refusals on its own (a method the route lacks, a body over the limit, a query string
/// it cannot read) in plain text; the spec wants every error in one shape, so those are rewritten here.
async fn best_shaped(res: Response, limit: usize) -> Response {
    let status = res.status();
    if !(status.is_client_error() || status.is_server_error()) {
        return res;
    }
    let is_json = res
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("application/json"));
    if is_json {
        return res;
    }
    let (parts, body) = res.into_parts();
    let text = axum::body::to_bytes(body, 64 * 1024)
        .await
        .map(|b| String::from_utf8_lossy(&b).trim().to_string())
        .unwrap_or_default();
    let (code, message): (&'static str, String) = match status {
        StatusCode::METHOD_NOT_ALLOWED => (
            "METHOD_NOT_ALLOWED",
            "this route does not take that method: the manifest's endpoints say which".into(),
        ),
        StatusCode::PAYLOAD_TOO_LARGE => (
            "PAYLOAD_TOO_LARGE",
            format!(
                "the body exceeds {limit} bytes, the most this door takes: send less in one command; for a prompt, fewer or shorter messages"
            ),
        ),
        StatusCode::BAD_REQUEST => (
            "BAD_REQUEST",
            if text.is_empty() {
                "the request could not be read".into()
            } else {
                text
            },
        ),
        StatusCode::NOT_FOUND => ("NOT_FOUND", if text.is_empty() { "no such route".into() } else { text }),
        StatusCode::UNSUPPORTED_MEDIA_TYPE => (
            "UNSUPPORTED_MEDIA_TYPE",
            if text.is_empty() {
                "unsupported Content-Type".into()
            } else {
                text
            },
        ),
        s if s.is_server_error() => ("INTERNAL", "the door failed; try again".into()),
        _ => ("REFUSED", if text.is_empty() { status.to_string() } else { text }),
    };
    let mut refusal = BestError::new(status, code, message);
    if status == StatusCode::PAYLOAD_TOO_LARGE {
        refusal = refusal.with_details(json!({ "limit_bytes": limit }));
    }
    let mut out = refusal.into_response();
    for (name, value) in parts
        .headers
        .iter()
        .filter(|(n, _)| *n != header::CONTENT_TYPE && *n != header::CONTENT_LENGTH)
    {
        out.headers_mut().insert(name.clone(), value.clone());
    }
    out
}

async fn well_known(State(door): State<Shared>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/json")],
        Json(manifest::manifest(&door)),
    )
}

// ----- sign-in -----------------------------------------------------------------------------------------------------

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::BAD_REQUEST);
        (status, [(header::CACHE_CONTROL, "no-store")], Json(self.body())).into_response()
    }
}

fn form<T: serde::de::DeserializeOwned>(headers: &HeaderMap, body: &Bytes) -> Result<T, OAuthError> {
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !ct.starts_with("application/x-www-form-urlencoded") {
        return Err(OAuthError::invalid_request(
            "the request must be form-encoded: Content-Type application/x-www-form-urlencoded",
        ));
    }
    serde_urlencoded::from_bytes(body)
        .map_err(|e| OAuthError::invalid_request(format!("the form could not be read: {e}")))
}

async fn device(
    State(door): State<Shared>,
    from: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, OAuthError> {
    let req: DeviceRequest = form(&headers, &body)?;
    let answer = door.auth.start_device_from(req, from.map(|c| c.0.ip()))?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(answer)).into_response())
}

async fn token(State(door): State<Shared>, headers: HeaderMap, body: Bytes) -> Result<Response, OAuthError> {
    let req: TokenRequest = form(&headers, &body)?;
    let answer = door.auth.token(req)?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(answer)).into_response())
}

async fn verify(State(door): State<Shared>, Query(q): Query<HashMap<String, String>>) -> Html<String> {
    Html(door.auth.verification_page(q.get("user_code").map(String::as_str)))
}

#[derive(serde::Deserialize)]
struct ApproveForm {
    user_code: String,
    proof: String,
    /// The scopes granted, comma-separated; absent for all.
    may: Option<String>,
    /// The most device memory the credential's workloads may hold together; absent for no share.
    memory_bytes: Option<u64>,
    /// The most deployments the credential may run at once; absent for no count.
    deployments: Option<u32>,
    /// The most jobs the credential may run at once; absent for no count.
    jobs: Option<u32>,
    /// Whether a credential with a share runs its jobs outside the closed box; absent for no.
    open_jobs: Option<bool>,
    /// Seconds until the credential ends, whatever lifetime the agent asked for; absent for the agent's choice.
    expires_in: Option<u64>,
    /// Whether the credential is held to the accelerators; absent for no.
    accelerators_only: Option<bool>,
}

async fn approve(State(door): State<Shared>, headers: HeaderMap, body: Bytes) -> Result<Response, OAuthError> {
    let f: ApproveForm = form(&headers, &body)?;
    let grant = Grant {
        scopes: f.may.as_deref().map(|m| {
            m.split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        }),
        memory_bytes: f.memory_bytes,
        deployments: f.deployments,
        jobs: f.jobs,
        open_jobs: f.open_jobs.unwrap_or(false),
        accelerators_only: f.accelerators_only.unwrap_or(false),
    };
    let admitted = door
        .auth
        .approve(
            f.user_code.trim(),
            f.proof.trim(),
            grant,
            f.expires_in.map(Duration::from_secs),
        )
        .await?;
    Ok(Json(json!({ "approved": true, "admitted": admitted })).into_response())
}

#[derive(serde::Deserialize)]
struct RevokeForm {
    /// The connection name or the holder id of the credential to take back.
    name: String,
    proof: String,
}

/// The person at the machine takes a credential back, with the same proof the approval takes: every live credential
/// by that name is taken at once, and the answer says which.
async fn revoke(State(door): State<Shared>, headers: HeaderMap, body: Bytes) -> Result<Response, OAuthError> {
    let f: RevokeForm = form(&headers, &body)?;
    let taken = door.auth.revoke(&f.name, f.proof.trim()).await?;
    let revoked: Vec<Value> = taken
        .iter()
        .map(|c| {
            json!({
                "name": c.name, "holder": c.holder(), "client_id": c.client_id, "agent_label": c.agent_label,
                "issued_at": c.issued_at, "revoked_at": c.revoked_at
            })
        })
        .collect();
    Ok(Json(json!({ "revoked": revoked })).into_response())
}

// ----- commands ----------------------------------------------------------------------------------------------------

async fn command_catalogue(State(door): State<Shared>) -> Json<Value> {
    Json(door.catalogue.command_catalogue(&door.endpoint))
}

async fn command_document(
    State(door): State<Shared>,
    Path((schema, version)): Path<(String, String)>,
) -> Result<Response, BestError> {
    let def = door.catalogue.command_by_schema(&schema, &version).ok_or_else(|| {
        BestError::not_found(
            "SCHEMA_NOT_FOUND",
            format!(
                "Unknown command schema '{schema}' version '{version}': GET /commands lists the ones this door accepts"
            ),
        )
    })?;
    Ok((
        [(header::CONTENT_TYPE, "application/schema+json")],
        Json(door.catalogue.command_document(&door.endpoint, def)),
    )
        .into_response())
}

async fn ingest(
    State(door): State<Shared>,
    Extension(sender): Extension<Credential>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, BestError> {
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json");
    let mime = ct.split(';').next().unwrap_or("").trim();
    if mime != "application/json" && mime != "application/cloudevents+json" {
        return Err(BestError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "UNSUPPORTED_MEDIA_TYPE",
            format!("Content-Type must be application/cloudevents+json or application/json, not {mime}"),
        ));
    }
    let value: Value = serde_json::from_slice(&body)
        .map_err(|e| BestError::bad_request("INVALID_JSON", format!("the body is not JSON: {e}")))?;
    let envelope: Envelope = serde_json::from_value(value)
        .map_err(|e| BestError::bad_request("INVALID_ENVELOPE", format!("the body is not a BEST envelope: {e}")))?;
    envelope.validate_command()?;
    let def = door.catalogue.command_by_type(&envelope.r#type).ok_or_else(|| {
        BestError::bad_request(
            "UNKNOWN_TYPE",
            format!(
                "type {} is not a command this door accepts: GET /commands lists them, and commandType is the value to send",
                envelope.r#type
            ),
        )
        .with_details(json!({ "accepted": door.catalogue.command_types() }))
    })?;
    let expected = door.schema_url("commands", &def.schema, &def.version);
    if envelope.dataschema.as_deref() != Some(expected.as_str()) {
        return Err(BestError::bad_request(
            "DATASCHEMA_MISMATCH",
            format!(
                "dataschema must be {expected}, the catalogue's value for {}",
                def.command_type
            ),
        )
        .with_details(json!({ "expected": expected })));
    }
    door.catalogue.validate_data(&envelope.r#type, &envelope.data)?;

    let correlation = envelope.effective_correlation();
    let hash = payload_hash(&envelope);
    let conflict = || {
        BestError::conflict(format!(
            "id {} was already used for a different command: a new command needs a new id",
            envelope.id
        ))
    };
    // A retry of an accepted command is answered as it was, before any state-dependent check: what was admitted
    // once is not refused on the retry because of the state it caused. The same holds for a copy still in flight.
    let key = (sender.hash.clone(), envelope.id.clone());
    match door.log.known_command(&sender.hash, &envelope.id, &hash) {
        Some(Accept::Conflict) => return Err(conflict()),
        Some(Accept::Duplicate { correlation: original }) => return Ok(created(&envelope.id, &original)),
        _ => {}
    }
    // A correlation id belongs to the sender that first used it on this door: a credential reads the facts under
    // the correlations it owns, so another sender naming one is refused, with the field and the fix (SPEC.md,
    // Security Requirements: an identifier is never proof; the replay scope includes the sender).
    let taken = || {
        BestError::bad_request(
            "CORRELATION_TAKEN",
            format!(
                "correlationid {correlation} was first used by another credential on this door and is theirs: name a correlation id of your own, or a new id when the command carries no correlationid, since the id then serves as one"
            ),
        )
        .with_details(json!({ "attribute": "correlationid", "correlationid": correlation }))
    };
    // Both checks under the one lock, so two senders racing on a new correlation cannot both pass: a command is
    // recorded before its in-flight entry goes, so a second sender finds the entry or the owner.
    let _in_flight = {
        let mut inflight = door.inflight.lock().unwrap();
        if door
            .log
            .owner_of_correlation(&correlation)
            .is_some_and(|owner| owner != sender.hash)
            || inflight
                .iter()
                .any(|((s, _), (_, c))| *s != sender.hash && *c == correlation)
        {
            return Err(taken());
        }
        match inflight.get(&key) {
            Some((h, original)) if *h == hash => return Ok(created(&envelope.id, original)),
            Some(_) => return Err(conflict()),
            None => inflight.insert(key.clone(), (hash.clone(), correlation.clone())),
        };
        InFlight {
            door: door.clone(),
            key: key.clone(),
        }
    };
    // Counted once it is new and whole, for a credential with a share: a retry of an accepted command, or one
    // refused before this or by its admission, costs nothing.
    let paced = match sender.grant.memory_bytes {
        Some(_) => match door.limits.pace.take(&sender.hash, std::time::Instant::now()) {
            Ok(when) => Some(when),
            Err(wait) => {
                let per_minute = door.limits.pace.limit();
                let mut refused = BestError::new(
                    StatusCode::TOO_MANY_REQUESTS,
                    "TOO_MANY_COMMANDS",
                    format!(
                        "this credential sent {per_minute} commands within the last sixty seconds, the most this door takes from a credential with a share: this one was not accepted; send it again in {wait} s"
                    ),
                )
                .with_details(json!({ "per_minute": per_minute, "retry_after_seconds": wait }))
                .into_response();
                refused.headers_mut().insert(header::RETRY_AFTER, wait.into());
                return Ok(refused);
            }
        },
        None => None,
    };
    if let Some(admit) = &def.admit {
        let admitted = admit(
            envelope.clone(),
            sender.clone(),
            command_key(&sender.hash, &envelope.id),
        )
        .await;
        if let (Err(_), Some(when)) = (&admitted, paced) {
            door.limits.pace.give_back(&sender.hash, when);
        }
        admitted?;
    }
    let accepted = door
        .log
        .accept_command(&sender.hash, &envelope.id, &hash, &correlation, &envelope);
    let answered = match accepted {
        Accept::Conflict => return Err(conflict()),
        Accept::Duplicate { correlation: original } => original,
        Accept::New => {
            run(&door, def, &sender.hash, envelope.clone());
            correlation
        }
    };
    Ok(created(&envelope.id, &answered))
}

/// A command between its checks and its record: its in-flight entry goes when the request ends, however it ends,
/// so a client that hangs up or a check that panics holds no correlation and no id for anyone.
struct InFlight {
    door: Shared,
    key: (String, String),
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.door.inflight.lock().unwrap().remove(&self.key);
    }
}

/// The emitter of `sender`'s command `envelope`: its correlation, its key, and what completes it.
fn emitter_for(door: &Shared, def: &CommandDef, sender: &str, envelope: &Envelope) -> Emitter {
    door.emitter(&envelope.effective_correlation())
        .with_key(&command_key(sender, &envelope.id))
        .with_completes(&def.completes)
}

/// Runs the handler of an accepted command on its own task. A handler that panics leaves a `CommandFailed`, never
/// silence.
fn run(door: &Shared, def: &CommandDef, sender: &str, envelope: Envelope) {
    let emitter = emitter_for(door, def, sender, &envelope);
    let command_type = envelope.r#type.clone();
    let handler = (def.handler)(envelope, emitter.clone());
    tokio::spawn(async move {
        if let Err(panic) = std::panic::AssertUnwindSafe(handler).catch_unwind().await {
            let reason = panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "the handler panicked".into());
            tracing::error!(command = %command_type, %reason, "a command handler panicked");
            emitter.emit("CommandFailed", json!({ "type": command_type, "reason": reason }));
        }
    });
}

/// What a restart owes: every command accepted with a `201` that no completing event was told for is run again,
/// through its admit check as if it had just arrived; one the door can no longer honour is failed with the reason.
/// Run once, after the peer's state is rebuilt and before the door opens.
pub async fn resume(door: &Shared) {
    for owed in door.log.unfinished() {
        let envelope = owed.envelope;
        let fail = |reason: String| {
            door.emitter(&envelope.effective_correlation())
                .with_key(&command_key(&owed.sender, &envelope.id))
                .emit("CommandFailed", json!({ "type": envelope.r#type, "reason": reason }));
        };
        // The stored command is believed only when it still matches its record and the catalogue of today.
        if door.log.hash_of(&owed.sender, &envelope.id) != Some(payload_hash(&envelope)) {
            fail("the command was accepted before a restart and its stored copy no longer matches its record".into());
            continue;
        }
        let Some(def) = door.catalogue.command_by_type(&envelope.r#type) else {
            fail("the command was accepted before a restart and its type is no longer offered".into());
            continue;
        };
        if let Err(refusal) = door.catalogue.validate_data(&envelope.r#type, &envelope.data) {
            fail(format!(
                "the command was accepted before a restart and no longer passes its schema: {}",
                refusal.message
            ));
            continue;
        }
        if let Some(admit) = &def.admit {
            // The sender is the credential that sent it; one that expired or is gone since cannot be honoured.
            let Some(who) = door.auth.credential_by_hash(&owed.sender) else {
                fail("the command was accepted before a restart and its sender's credential is gone: sign in again and send it again".into());
                continue;
            };
            if let Err(refusal) = admit(envelope.clone(), who, command_key(&owed.sender, &envelope.id)).await {
                emitter_for(door, def, &owed.sender, &envelope).emit(
                    "CommandFailed",
                    json!({ "type": envelope.r#type, "reason": format!("accepted before a restart and refused now: {}", refusal.message), "details": refusal.details }),
                );
                continue;
            }
        }
        tracing::info!(command = %envelope.r#type, id = %envelope.id, "running a command accepted before the restart");
        run(door, def, &owed.sender, envelope);
    }
}

/// What makes two commands the same command: the type and the data, hashed.
pub fn payload_hash(envelope: &Envelope) -> String {
    hex::encode(Sha256::digest(
        serde_json::to_vec(&json!({ "type": envelope.r#type, "data": envelope.data })).expect("json"),
    ))
}

/// The key a handler files a command's own state under: the sender and the envelope id, which together are unique.
fn command_key(sender: &str, id: &str) -> String {
    format!("{sender}:{id}")
}

fn created(id: &str, correlation: &str) -> Response {
    (
        StatusCode::CREATED,
        Json(json!({ "id": id, "correlationId": correlation })),
    )
        .into_response()
}

// ----- events ------------------------------------------------------------------------------------------------------

fn filter_from(q: &HashMap<String, String>) -> Result<Filter, BestError> {
    let bad = |param: &str, what: &str| {
        BestError::bad_request("INVALID_PARAMETER", format!("{param} must be {what}"))
            .with_details(json!({ "parameter": param }))
    };
    let time = |param: &str| -> Result<Option<OffsetDateTime>, BestError> {
        q.get(param)
            .map(|v| {
                OffsetDateTime::parse(v, &Rfc3339)
                    .map_err(|_| bad(param, "an ISO 8601 timestamp such as 2026-10-12T10:30:00Z"))
            })
            .transpose()
    };
    let limit = q
        .get("limit")
        .map(|v| match v.parse::<usize>() {
            Ok(n) if (1..=MAX_PAGE).contains(&n) => Ok(n),
            _ => Err(bad("limit", &format!("a number from 1 to {MAX_PAGE}"))),
        })
        .transpose()?;
    Ok(Filter {
        r#type: q.get("type").cloned(),
        correlation_id: q.get("correlationId").cloned(),
        source: q.get("source").cloned(),
        from: time("from")?,
        to: time("to")?,
        limit,
        after: q
            .get("after")
            .map(|v| {
                v.parse::<u64>()
                    .map_err(|_| bad("after", "a cursor from a previous response's nextCursor"))
            })
            .transpose()?,
    })
}

async fn list_events(
    State(door): State<Shared>,
    Extension(sender): Extension<Credential>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<Value>, BestError> {
    let filter = filter_from(&q)?;
    let (events, next) = door.log.list_where(&filter, |s| door.visible_to(&sender, s));
    let mut body = json!({ "events": events });
    if let Some(n) = next {
        body["nextCursor"] = json!(n);
    }
    Ok(Json(body))
}

/// How often an open event stream looks at its credential again when no event comes.
const CREDENTIAL_RECHECK: Duration = Duration::from_secs(5);

/// Replays what came after `Last-Event-ID`, then follows live; the two never overlap. A client that falls behind
/// the buffer is cut off, so it reconnects with its last id and misses nothing silently. A credential taken back or
/// run out ends the stream with it, within seconds whether or not events flow: its end is looked at on every event
/// and every few seconds between, and the credential itself whenever one was taken back since. A credential taken
/// back still reads its own AgentRevokedV1, the outcome of the revoke-agent it sent, and the stream ends after it.
/// A credential with a share holds so many streams open across the door; one more ends its oldest, which
/// reconnects with its last id if it is still there.
async fn stream_events(
    State(door): State<Shared>,
    Extension(sender): Extension<Credential>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Sse<impl Stream<Item = Result<SseEvent, Infallible>>>, BestError> {
    let filter = filter_from(&q)?;
    // A credential with a share holds so many streams at once; past that its oldest gives way to this one.
    let (slot, gave_way) = match sender.grant.memory_bytes {
        Some(_) => {
            let (slot, ends) = door.limits.streams.take(&sender.hash);
            (Some(slot), ends.map(|_| ()).boxed())
        }
        None => (None, futures::future::pending().boxed()),
    };
    let last = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let (rx, seen_up_to) = door.log.subscribe();
    let replay = match last {
        Some(id) => door.log.since_id(&id),
        None => Vec::new(),
    };
    let f1 = filter.clone();
    let (door1, who1) = (door.clone(), sender.clone());
    let replayed = stream::iter(
        replay
            .into_iter()
            .filter(move |s| f1.matches(s) && door1.visible_to(&who1, s)),
    );
    let door2 = door.clone();
    let ends = sender
        .expires_at
        .as_deref()
        .and_then(|e| OffsetDateTime::parse(e, &Rfc3339).ok());
    let (auth, hash) = (door.auth.clone(), sender.hash.clone());
    let mut seen = auth.revocations();
    let recheck = stream::unfold(tokio::time::interval(CREDENTIAL_RECHECK), |mut every| async move {
        every.tick().await;
        Some((Ok(None), every))
    });
    let live = stream::select(BroadcastStream::new(rx).map(|r| r.map(Some)), recheck)
        .take_while(|r| futures::future::ready(r.is_ok()))
        .filter_map(move |r| {
            let keep = r
                .ok()
                .flatten()
                .filter(|s| s.seq > seen_up_to && filter.matches(s) && door2.visible_to(&sender, s));
            async move { Some(keep) }
        });
    let holder = holder_of_hash(&hash);
    let mut closing: Option<tokio::time::Instant> = None;
    let mut told = false;
    let mut step = move |item: Option<Stored>| {
        if told || ends.is_some_and(|e| OffsetDateTime::now_utc() >= e) {
            return futures::future::ready(None);
        }
        if closing.is_none() && auth.revocations() != seen && auth.credential_by_hash(&hash).is_none() {
            closing = Some(tokio::time::Instant::now());
        }
        seen = auth.revocations();
        let Some(since) = closing else {
            return futures::future::ready(Some(item));
        };
        if item
            .as_ref()
            .is_some_and(|s| s.envelope.r#type == "AgentRevokedV1" && s.envelope.data["holder"] == holder)
        {
            told = true;
            return futures::future::ready(Some(item));
        }
        futures::future::ready((since.elapsed() < CREDENTIAL_RECHECK).then_some(None))
    };
    let out = replayed
        .map(Some)
        .chain(live)
        .scan((), move |_, item| step(item))
        .filter_map(futures::future::ready)
        .take_until(gave_way)
        .map(move |s| {
            let _held = &slot;
            Ok(SseEvent::default()
                .id(s.envelope.id.clone())
                .data(serde_json::to_string(&s.envelope).unwrap_or_default()))
        });
    Ok(Sse::new(out).keep_alive(KeepAlive::default().text("keepalive")))
}

async fn event_document(
    State(door): State<Shared>,
    Path((schema, version)): Path<(String, String)>,
) -> Result<Response, BestError> {
    let def = door.catalogue.event_by_schema(&schema, &version).ok_or_else(|| {
        BestError::not_found(
            "SCHEMA_NOT_FOUND",
            format!("Unknown event schema '{schema}' version '{version}'"),
        )
    })?;
    Ok((
        [(header::CONTENT_TYPE, "application/schema+json")],
        Json(door.catalogue.event_document(&door.endpoint, def)),
    )
        .into_response())
}

// ----- queries -----------------------------------------------------------------------------------------------------

async fn query_catalogue(State(door): State<Shared>) -> Json<Value> {
    Json(door.catalogue.query_catalogue(&door.endpoint))
}

fn query_not_found(schema: &str) -> BestError {
    BestError::not_found(
        "SCHEMA_NOT_FOUND",
        format!("Unknown query schema '{schema}': GET /queries lists the ones this door answers"),
    )
}

async fn query_document(
    State(door): State<Shared>,
    Path((schema, version)): Path<(String, String)>,
) -> Result<Response, BestError> {
    let def = door
        .catalogue
        .query_by_schema(&schema)
        .filter(|q| q.version == version)
        .ok_or_else(|| query_not_found(&schema))?;
    Ok((
        [(header::CONTENT_TYPE, "application/schema+json")],
        Json(door.catalogue.query_document(def)),
    )
        .into_response())
}

async fn execute_query(
    State(door): State<Shared>,
    Extension(sender): Extension<Credential>,
    Path(schema): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, BestError> {
    let def = door
        .catalogue
        .query_by_schema(&schema)
        .ok_or_else(|| query_not_found(&schema))?;
    door.catalogue.validate_params(&schema, &params)?;
    Ok(Json((def.handler)(sender, params).await?))
}

// ----- workflows ---------------------------------------------------------------------------------------------------

async fn workflow_index() -> Json<Value> {
    Json(json!({ "workflows": [] }))
}

async fn workflow(Path(id): Path<String>) -> BestError {
    BestError::not_found(
        "WORKFLOW_NOT_FOUND",
        format!("Unknown workflow '{id}': GET /workflows lists the published recipes"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{Auth, FakeApprover};
    use crate::catalogue::{Catalogue, CommandDef, EventDef, QueryDef};
    use crate::log::EventLog;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const EP: &str = "http://peer.test";

    /// The images the test door's admit hook was asked about, across every test of this module; a test looks for
    /// its own image, so the others' traffic does not count.
    static ADMITTED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

    fn admitted(image: &str) -> usize {
        ADMITTED.lock().unwrap().iter().filter(|i| *i == image).count()
    }

    /// The `stall:` images that already died once; the second run of each completes.
    static STALLED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

    /// Whether this image's command dies now: the first time, yes.
    fn stalls(image: &str) -> bool {
        let mut stalled = STALLED.lock().unwrap();
        if image.starts_with("stall:") && !stalled.iter().any(|i| i == image) {
            stalled.push(image.into());
            return true;
        }
        false
    }

    fn door() -> Shared {
        door_over(Arc::new(EventLog::ephemeral()))
    }

    /// A door over a log that may hold a previous door's commands and events.
    fn door_over(log: Arc<EventLog>) -> Shared {
        door_over_with(log, None)
    }

    /// A door over `log` with the credentials of a previous door, when it is that door restarted.
    fn door_over_with(log: Arc<EventLog>, auth: Option<Arc<Auth>>) -> Shared {
        door_built(log, auth, crate::Limits::default())
    }

    /// The same, holding credentials with a share to `limits`.
    fn door_built(log: Arc<EventLog>, auth: Option<Arc<Auth>>, limits: crate::Limits) -> Shared {
        let catalogue = Catalogue::new()
            .command(CommandDef {
                schema: "pull-image".into(),
                version: "1.0".into(),
                command_type: "PullImage".into(),
                description: "Makes an image present on the peer.".into(),
                data_schema: json!({ "type": "object", "required": ["image"], "properties": { "image": { "type": "string", "minLength": 1 } }, "additionalProperties": false }),
                produces: vec!["ImagePulled".into()],
                completes: vec!["ImagePulled".into()],
                impact: None,
                admit: Some(Arc::new(|cmd, _who, key| {
                    Box::pin(async move {
                        let image = cmd.data["image"].as_str().unwrap_or("").to_string();
                        assert!(key.ends_with(&format!(":{}", cmd.id)), "the key ends with the envelope id");
                        if image.starts_with("slow:") {
                            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        }
                        ADMITTED.lock().unwrap().push(image.clone());
                        if image.starts_with("full:") {
                            return Err(BestError::bad_request(
                                "NO_SPACE",
                                "no space for the image: remove one with RemoveImage, or ask for a smaller one",
                            )
                            .with_details(json!({ "image": cmd.data["image"] })));
                        }
                        Ok(())
                    })
                })),
                handler: Arc::new(|cmd, emitter| {
                    Box::pin(async move {
                        if cmd.data["image"] == "panic:1" {
                            panic!("the engine exploded");
                        }
                        // The peer dies here: nothing completes it, and a restart owes it.
                        if stalls(cmd.data["image"].as_str().unwrap_or("")) {
                            return;
                        }
                        emitter.emit("ImagePulled", json!({ "image": cmd.data["image"] }));
                    })
                }),
            })
            .event(EventDef {
                schema: "image-pulled".into(),
                version: "1.0".into(),
                event_type: "ImagePulled".into(),
                description: "An image is present.".into(),
                data_schema: json!({ "type": "object", "properties": { "image": { "type": "string" } } }),
            })
            .query(QueryDef {
                schema: "get-peer".into(),
                version: "1.0".into(),
                description: "Who this peer is.".into(),
                parameters: Some(json!({ "type": "object", "properties": { "x": { "type": "string", "enum": ["1", "2"] } }, "additionalProperties": false })),
                response: json!({ "type": "object", "properties": { "name": { "type": "string" } } }),
                handler: Arc::new(|_who, p| Box::pin(async move { Ok(json!({ "name": "peer", "echo": p.get("x") })) })),
            });
        let auth = auth.unwrap_or_else(|| {
            Arc::new(Auth::ephemeral(EP, Box::new(FakeApprover { proof: "ok".into() })).with_scopes(&["deploy"]))
        });
        Arc::new(Door::new(EP, "io.best.agents", "A test peer.", catalogue, log, auth).with_limits(Arc::new(limits)))
    }

    async fn call(app: &Router, req: Request) -> (StatusCode, HeaderMap, Value) {
        let res = app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::String(String::from_utf8_lossy(&bytes).into()));
        (status, headers, body)
    }

    fn get(path: &str, key: Option<&str>) -> Request {
        let mut b = Request::get(path);
        if let Some(k) = key {
            b = b.header(AUTH_HEADER, k);
        }
        b.body(Body::empty()).unwrap()
    }

    fn post_json(path: &str, key: &str, ct: &str, body: Value) -> Request {
        Request::post(path)
            .header(AUTH_HEADER, key)
            .header(header::CONTENT_TYPE, ct)
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn post_form(path: &str, fields: &[(&str, &str)]) -> Request {
        Request::post(path)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(serde_urlencoded::to_string(fields).unwrap()))
            .unwrap()
    }

    /// Registers through the device flow and returns a working key, approved with nothing said: all.
    async fn sign_in(app: &Router, client: &str, connection: &str) -> String {
        sign_in_with(app, client, connection, None).await
    }

    /// The same, approved for the scopes `may` names when given.
    async fn sign_in_with(app: &Router, client: &str, connection: &str, may: Option<&str>) -> String {
        let extra: Vec<(&str, &str)> = may.map(|m| ("may", m)).into_iter().collect();
        sign_in_approved(app, client, connection, &extra).await
    }

    /// The same, with a share of `memory` bytes when given.
    async fn sign_in_holding(
        app: &Router,
        client: &str,
        connection: &str,
        may: Option<&str>,
        memory: Option<&str>,
    ) -> String {
        let extra: Vec<(&str, &str)> = may
            .map(|m| ("may", m))
            .into_iter()
            .chain(memory.map(|m| ("memory_bytes", m)))
            .collect();
        sign_in_approved(app, client, connection, &extra).await
    }

    /// The same, approved with the `extra` fields of the approval form.
    async fn sign_in_approved(app: &Router, client: &str, connection: &str, extra: &[(&str, &str)]) -> String {
        let (s, _, a) = call(
            app,
            post_form("/auth/device", &[("client_id", client), ("connection", connection)]),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{a}");
        let mut fields = vec![("user_code", a["user_code"].as_str().unwrap()), ("proof", "ok")];
        fields.extend_from_slice(extra);
        let (s, _, ok) = call(app, post_form("/auth/approve", &fields)).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(ok["admitted"]["connection"], connection);
        let (s, h, t) = call(
            app,
            post_form(
                "/auth/token",
                &[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("device_code", a["device_code"].as_str().unwrap()),
                    ("client_id", client),
                ],
            ),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{t}");
        assert_eq!(h[header::CACHE_CONTROL], "no-store");
        t["access_token"].as_str().unwrap().to_string()
    }

    fn command(id: &str, image: Value) -> Value {
        json!({
            "specversion": "1.0", "id": id, "source": "https://agent.test/claude", "type": "PullImage",
            "datacontenttype": "application/json", "dataschema": format!("{EP}/commands/pull-image/1.0"),
            "time": "2026-10-12T10:30:00Z", "data": { "image": image }
        })
    }

    async fn settle(d: &Shared, at_least: usize) {
        for _ in 0..200 {
            if d.log.len() >= at_least {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    #[tokio::test]
    async fn the_manifest_is_public_and_everything_else_needs_the_key() {
        let app = router(door());
        let (s, h, m) = call(&app, get("/.well-known/best", None)).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(h[header::CONTENT_TYPE], "application/json");
        assert_eq!(
            m["best"]["authentication"]["deviceAuthorizationUrl"],
            format!("{EP}/auth/device")
        );
        assert_eq!(m["best"]["authentication"]["note"], crate::guidance::MANIFEST_TEXT);
        for path in [
            "/commands",
            "/events",
            "/events/stream",
            "/queries",
            "/queries/get-peer",
            "/workflows",
        ] {
            let (s, _, b) = call(&app, get(path, None)).await;
            assert_eq!(s, StatusCode::UNAUTHORIZED, "{path}");
            assert_eq!(b["error"]["code"], "UNAUTHORIZED", "{path}");
        }
        let (s, _, _) = call(&app, get("/commands", Some("bp_wrong"))).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_door_that_hosts_tenants_says_so_in_its_manifest_and_a_tenant_door_has_the_capabilities_alone() {
        let root = door();
        let template = format!("{EP}/.well-known/best/{{tenantId}}");
        let hosting = Arc::new(
            Door::new(
                EP,
                "io.best.agents",
                "A test peer.",
                Catalogue::new(),
                root.log.clone(),
                root.auth.clone(),
            )
            .with_tenants(&template),
        );
        let m = manifest::manifest(&hosting);
        assert_eq!(m["best"]["tenants"]["manifest"], template);
        assert_eq!(
            m["best"]["services"]["io.best.agents"]["authentication"]["deviceAuthorizationUrl"],
            format!("{EP}/auth/device"),
            "the root's own capabilities sit on a service with its own authentication block"
        );
        let plain = manifest::manifest(&root);
        assert!(plain["best"].get("tenants").is_none());
        assert!(plain["best"]["services"]["io.best.agents"]
            .get("authentication")
            .is_none());

        // A tenant's door: its endpoint under the root's, the same credentials, no manifest and no sign-in of its own.
        let key = sign_in(&router(root.clone()), "test", "my-peer").await;
        let tenant = door_over_with(Arc::new(EventLog::ephemeral()), Some(root.auth.clone()));
        let tenant = Arc::new(Door::new(
            &format!("{EP}/tenants/t1"),
            "io.best.agents",
            "A tenant.",
            Catalogue::new().query(QueryDef {
                schema: "get-peer".into(),
                version: "1.0".into(),
                description: "Who this tenant is.".into(),
                parameters: None,
                response: json!({ "type": "object" }),
                handler: Arc::new(|_who, _p| Box::pin(async move { Ok(json!({ "name": "t1" })) })),
            }),
            tenant.log.clone(),
            root.auth.clone(),
        ));
        let app = tenant_router(tenant);
        let (s, _, b) = call(&app, get("/queries/get-peer", Some(&key))).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["name"], "t1");
        let (s, _, c) = call(&app, get("/queries", Some(&key))).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(
            c["queries"][0]["dataschema"],
            format!("{EP}/tenants/t1/queries/get-peer/1.0")
        );
        let (s, _, _) = call(&app, get("/queries/get-peer", None)).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        let (s, _, b) = call(&app, get("/.well-known/best", None)).await;
        assert_eq!(
            s,
            StatusCode::NOT_FOUND,
            "the tenant's manifest is the root's to serve: {b}"
        );
        let (s, _, b) = call(&app, post_form("/auth/device", &[("client_id", "x")])).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "sign-in is the root's: {b}");
        assert_eq!(b["error"]["code"], "NOT_FOUND");
    }

    #[tokio::test]
    async fn a_credential_sends_so_many_new_commands_a_minute_and_is_told_when_to_send_again() {
        let d = door_built(
            Arc::new(EventLog::ephemeral()),
            None,
            crate::Limits::new(crate::Pace::per_minute(3), crate::Streams::default()),
        );
        let app = router(d.clone());
        let key = sign_in_holding(&app, "test", "my-peer", None, Some("1024")).await;
        let other = sign_in_holding(&app, "other", "other-peer", None, Some("1024")).await;
        let owner = sign_in(&app, "owner", "owner-peer").await;
        let send = |key: &str, c: Value| call(&app, post_json("/commands", key, "application/json", c));
        // A command refused before it is whole costs nothing.
        for id in ["bad-1", "bad-2"] {
            let (s, _, b) = send(&key, command(id, json!(5))).await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        }
        for id in ["p1", "p2", "p3"] {
            let (s, _, b) = send(&key, command(id, json!("ollama/ollama:0.6"))).await;
            assert_eq!(s, StatusCode::CREATED, "{b}");
        }
        let (s, h, b) = send(&key, command("p4", json!("ollama/ollama:0.6"))).await;
        assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{b}");
        assert_eq!(b["error"]["code"], "TOO_MANY_COMMANDS");
        assert_eq!(b["error"]["details"]["per_minute"], 3);
        let wait = b["error"]["details"]["retry_after_seconds"].as_u64().unwrap();
        assert!((1..=60).contains(&wait), "{b}");
        assert_eq!(h[header::RETRY_AFTER].to_str().unwrap(), wait.to_string());
        let message = b["error"]["message"].as_str().unwrap();
        assert!(
            message.contains("was not accepted") && message.contains(&format!("again in {wait} s")),
            "{message}"
        );
        // A retry of an accepted command is answered as it was, full minute or not.
        let (s, _, b) = send(&key, command("p1", json!("ollama/ollama:0.6"))).await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let (s, _, b) = send(&other, command("o1", json!("ollama/ollama:0.6"))).await;
        assert_eq!(s, StatusCode::CREATED, "another credential has its own minute: {b}");
        for i in 0..5 {
            let (s, _, b) = send(&owner, command(&format!("w{i}"), json!("ollama/ollama:0.6"))).await;
            assert_eq!(s, StatusCode::CREATED, "a credential without a share is not paced: {b}");
        }
    }

    #[tokio::test]
    async fn past_its_streams_a_credential_with_a_share_ends_its_oldest_and_a_dropped_client_gives_its_place_back() {
        let d = door_built(
            Arc::new(EventLog::ephemeral()),
            None,
            crate::Limits::new(crate::Pace::default(), crate::Streams::per_credential(2)),
        );
        let app = router(d.clone());
        let key = sign_in_holding(&app, "test", "my-peer", None, Some("1024")).await;
        let other = sign_in_holding(&app, "other", "other-peer", None, Some("1024")).await;
        let owner = sign_in(&app, "owner", "owner-peer").await;
        let hash = |k: &str| d.auth.authenticate(k).unwrap().hash;
        let open = |key: String| {
            let app = app.clone();
            async move {
                let res = app
                    .oneshot(
                        Request::get("/events/stream")
                            .header(AUTH_HEADER, &key)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(res.status(), StatusCode::OK);
                res.into_body().into_data_stream()
            }
        };
        let mut oldest = open(key.clone()).await;
        let second = open(key.clone()).await;
        assert_eq!(d.limits.streams.held(&hash(&key)), 2);
        let third = open(key.clone()).await;
        assert_eq!(d.limits.streams.held(&hash(&key)), 2, "never more than the figure");
        let ended = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while let Some(frame) = oldest.next().await {
                frame.unwrap();
            }
        })
        .await;
        assert!(ended.is_ok(), "the oldest gave way to the newest");
        let _theirs = open(other.clone()).await;
        assert_eq!(
            d.limits.streams.held(&hash(&other)),
            1,
            "another credential's streams are its own"
        );
        let mut owners = Vec::new();
        for _ in 0..3 {
            owners.push(open(owner.clone()).await);
        }
        assert_eq!(
            d.limits.streams.held(&hash(&owner)),
            0,
            "a credential without a share is not counted"
        );
        // A client that goes away gives its place back once its stream is dropped.
        drop(second);
        drop(third);
        assert_eq!(d.limits.streams.held(&hash(&key)), 0);
    }

    #[tokio::test]
    async fn every_error_the_framework_answers_is_in_the_best_shape() {
        let d = door();
        let app = router(d.clone());
        let key = sign_in(&app, "test", "my-peer").await;
        let (s, _, b) = call(&app, get("/nothing/here", Some(&key))).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert_eq!(b["error"]["code"], "NOT_FOUND");
        assert!(b["error"]["message"].as_str().unwrap().contains("/nothing/here"));
        let (s, _, b) = call(
            &app,
            Request::delete("/commands")
                .header(AUTH_HEADER, &key)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(s, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(b["error"]["code"], "METHOD_NOT_ALLOWED");
        let big = "x".repeat(MAX_BODY + 1);
        let (s, _, b) = call(
            &app,
            post_json("/commands", &key, "application/json", json!({ "pad": big })),
        )
        .await;
        assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(b["error"]["code"], "PAYLOAD_TOO_LARGE");
        assert_eq!(b["error"]["details"]["limit_bytes"], MAX_BODY);
        // A tenant's door takes a little less, so what a cloud took a member's door takes too.
        let tenant = tenant_router(d.clone());
        let near = "x".repeat(MAX_BODY - TENANT_ROOM);
        let (s, _, b) = call(
            &tenant,
            post_json("/commands", &key, "application/json", json!({ "pad": near })),
        )
        .await;
        assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE, "{b}");
        assert_eq!(b["error"]["details"]["limit_bytes"], MAX_BODY - TENANT_ROOM);
        let (s, _, b) = call(&app, get("/events?limit=0", Some(&key))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(b["error"]["details"]["parameter"], "limit");
        let (s, _, b) = call(&app, get("/events?limit=5000", Some(&key))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert!(b["error"]["message"].as_str().unwrap().contains("200"));
    }

    #[tokio::test]
    async fn sign_in_counts_registrations_by_the_address_the_connection_came_from() {
        let at = |ip: &str| {
            router(door()).layer(axum::extract::connect_info::MockConnectInfo(SocketAddr::new(
                ip.parse().unwrap(),
                40000,
            )))
        };
        let app = at("203.0.113.9");
        for i in 0..16 {
            let client = format!("client-{i}");
            let (s, _, b) = call(&app, post_form("/auth/device", &[("client_id", client.as_str())])).await;
            assert_eq!(s, StatusCode::OK, "{b}");
        }
        let (s, h, b) = call(&app, post_form("/auth/device", &[("client_id", "client-new")])).await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{b}");
        assert_eq!(h[header::CACHE_CONTROL], "no-store");
        assert!(
            b["error_description"].as_str().unwrap().contains("from your address"),
            "{b}"
        );
        let local = at("127.0.0.1");
        for i in 0..20 {
            let client = format!("client-{i}");
            let (s, _, b) = call(&local, post_form("/auth/device", &[("client_id", client.as_str())])).await;
            assert_eq!(s, StatusCode::OK, "loopback is not counted: {b}");
        }
    }

    #[tokio::test]
    async fn the_person_takes_a_credential_back_with_the_proof() {
        let d = door();
        let app = router(d.clone());
        let key = sign_in(&app, "test", "my-peer").await;
        let res = app.clone().oneshot(get("/commands", Some(&key))).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let holder = d.auth.authenticate(&key).unwrap().holder();
        // The wrong proof takes nothing; the right one takes it, and the door closes to it at once.
        let (s, _, b) = call(&app, post_form("/auth/revoke", &[("name", "my-peer"), ("proof", "no")])).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{b}");
        let (s, _, b) = call(&app, post_form("/auth/revoke", &[("name", "my-peer"), ("proof", "ok")])).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["revoked"][0]["holder"], holder);
        assert_eq!(b["revoked"][0]["name"], "my-peer");
        assert!(b["revoked"][0]["revoked_at"].is_string());
        assert!(!b.to_string().contains(&key));
        let (s, _, b) = call(&app, get("/commands", Some(&key))).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        assert_eq!(b["error"]["code"], "UNAUTHORIZED");
        let (s, _, b) = call(&app, post_form("/auth/revoke", &[("name", "my-peer"), ("proof", "ok")])).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert!(b["error_description"].as_str().unwrap().contains("none"), "{b}");
        // An approval bounded in time: the token answer says so.
        let (_, _, a) = call(
            &app,
            post_form("/auth/device", &[("client_id", "test"), ("connection", "bounded")]),
        )
        .await;
        let (s, _, ok) = call(
            &app,
            post_form(
                "/auth/approve",
                &[
                    ("user_code", a["user_code"].as_str().unwrap()),
                    ("proof", "ok"),
                    ("expires_in", "120"),
                ],
            ),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{ok}");
        assert_eq!(ok["admitted"]["expires_in"], 120);
        let (_, _, t) = call(
            &app,
            post_form(
                "/auth/token",
                &[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("device_code", a["device_code"].as_str().unwrap()),
                    ("client_id", "test"),
                ],
            ),
        )
        .await;
        assert_eq!(t["expires_in"], 120);
        assert!(t["expires_at"].is_string());
    }

    /// Opens an event stream under `key` and gives its body, frame by frame.
    async fn open_stream(app: &Router, key: &str) -> axum::body::BodyDataStream {
        let res = app
            .clone()
            .oneshot(
                Request::get("/events/stream")
                    .header(AUTH_HEADER, key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        res.into_body().into_data_stream()
    }

    /// Whether a quiet stream ends within `within`, with nothing but keep-alives before it does.
    async fn ends_within(body: &mut axum::body::BodyDataStream, within: Duration) -> bool {
        tokio::time::timeout(within, async {
            while let Some(frame) = body.next().await {
                let frame = frame.unwrap();
                assert!(
                    String::from_utf8_lossy(&frame).contains("keepalive"),
                    "no event reaches a credential taken back or run out"
                );
            }
        })
        .await
        .is_ok()
    }

    #[tokio::test(start_paused = true)]
    async fn a_quiet_stream_ends_within_seconds_of_its_credential_being_taken_back() {
        let d = door();
        let app = router(d.clone());
        let key = sign_in(&app, "test", "my-peer").await;
        let other = sign_in(&app, "test", "other").await;
        let mut body = open_stream(&app, &key).await;
        let mut others = open_stream(&app, &other).await;
        assert!(
            !ends_within(&mut body, Duration::from_secs(30)).await,
            "a live key's quiet stream stays open"
        );
        let (s, _, b) = call(&app, post_form("/auth/revoke", &[("name", "my-peer"), ("proof", "ok")])).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert!(
            ends_within(&mut body, CREDENTIAL_RECHECK * 2).await,
            "the stream outlived its credential"
        );
        assert!(
            !ends_within(&mut others, CREDENTIAL_RECHECK * 3).await,
            "another credential's stream is its own"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_quiet_stream_ends_within_seconds_of_its_credential_running_out() {
        let app = router(door());
        let key = sign_in_approved(&app, "test", "brief", &[("expires_in", "1")]).await;
        let mut body = open_stream(&app, &key).await;
        assert!(!ends_within(&mut body, Duration::from_millis(500)).await);
        std::thread::sleep(Duration::from_millis(1100));
        assert!(
            ends_within(&mut body, CREDENTIAL_RECHECK * 2).await,
            "the stream outlived its credential"
        );
    }

    #[tokio::test]
    async fn sign_in_end_to_end_then_the_catalogue_opens() {
        let app = router(door());
        let key = sign_in(&app, "test", "my-peer").await;
        let (s, _, c) = call(&app, get("/commands", Some(&key))).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(c["commands"][0]["commandType"], "PullImage");
        let (s, _, e) = call(
            &app,
            post_form("/auth/device", &[("client_id", "test"), ("connection", "Not One Word")]),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(e["error"], "invalid_request");
        assert!(e["error_description"].as_str().unwrap().contains("lowercase"));
        let (s, _, e) = call(
            &app,
            Request::post("/auth/device")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(e["error"], "invalid_request");
        let (s, _, e) = call(
            &app,
            post_form(
                "/auth/token",
                &[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("device_code", "best-validate-unknown"),
                    ("client_id", "x"),
                ],
            ),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(e["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn a_command_is_recorded_correlated_and_its_events_are_readable() {
        let d = door();
        let app = router(d.clone());
        let key = sign_in(&app, "test", "my-peer").await;
        let (s, _, b) = call(
            &app,
            post_json(
                "/commands",
                &key,
                "application/cloudevents+json",
                command("cmd-1", json!("ollama/ollama:0.6")),
            ),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        assert_eq!(b["id"], "cmd-1");
        assert_eq!(b["correlationId"], "cmd-1");
        settle(&d, 1).await;
        let (s, _, e) = call(&app, get("/events?correlationId=cmd-1", Some(&key))).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(e["events"][0]["type"], "ImagePulled");
        assert_eq!(e["events"][0]["correlationid"], "cmd-1");
        assert_eq!(e["events"][0]["dataschema"], format!("{EP}/events/image-pulled/1.0"));
        assert_eq!(e["events"][0]["source"], "io.best.agents");
        // The same id again is ignored safely and told the original correlation, even when the retry names another.
        let mut retry = command("cmd-1", json!("ollama/ollama:0.6"));
        retry["correlationid"] = json!("something-else");
        let (s, _, b) = call(&app, post_json("/commands", &key, "application/json", retry)).await;
        assert_eq!(s, StatusCode::CREATED);
        assert_eq!(b["correlationId"], "cmd-1");
        let (s, _, c) = call(
            &app,
            post_json(
                "/commands",
                &key,
                "application/json",
                command("cmd-1", json!("other:1")),
            ),
        )
        .await;
        assert_eq!(s, StatusCode::CONFLICT);
        assert_eq!(c["error"]["code"], "CONFLICT");
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert_eq!(d.log.len(), 1, "the duplicate ran no handler");
        // Another sender's identical id is their own command, but as a correlation it is the first sender's: with
        // no correlationid of their own the command is refused; with one, it goes.
        let other = sign_in(&app, "other", "other-peer").await;
        let (s, _, e) = call(
            &app,
            post_json(
                "/commands",
                &other,
                "application/json",
                command("cmd-1", json!("ollama/ollama:0.6")),
            ),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{e}");
        assert_eq!(e["error"]["code"], "CORRELATION_TAKEN");
        let mut own = command("cmd-1", json!("ollama/ollama:0.6"));
        own["correlationid"] = json!("theirs");
        let (s, _, _) = call(&app, post_json("/commands", &other, "application/json", own)).await;
        assert_eq!(s, StatusCode::CREATED);
        settle(&d, 2).await;
        assert_eq!(d.log.len(), 2);
    }

    #[tokio::test]
    async fn a_correlation_id_belongs_to_the_sender_that_first_used_it_and_another_sender_naming_it_is_refused() {
        let d = door();
        let app = router(d.clone());
        // Alice acts for every holder; Bob is approved for deploy alone, so he reads the facts under his own
        // correlations and no other.
        let alice = sign_in(&app, "test", "my-peer").await;
        let bob = sign_in_with(&app, "other", "other-peer", Some("deploy")).await;
        let with_correlation = |id: &str, corr: &str| {
            let mut c = command(id, json!("ollama/ollama:0.6"));
            c["correlationid"] = json!(corr);
            c
        };
        let (s, _, b) = call(
            &app,
            post_json(
                "/commands",
                &alice,
                "application/json",
                with_correlation("a1", "shared"),
            ),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        settle(&d, 1).await;
        // Bob names Alice's correlation on a command of his own: refused by the field, with the fix; so is an id of
        // his that would serve as that correlation. Alice's own reuse goes.
        let (s, _, e) = call(
            &app,
            post_json("/commands", &bob, "application/json", with_correlation("b1", "shared")),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{e}");
        assert_eq!(e["error"]["code"], "CORRELATION_TAKEN");
        assert_eq!(e["error"]["details"]["attribute"], "correlationid");
        assert!(e["error"]["message"].as_str().unwrap().contains("of your own"), "{e}");
        let (s, _, e) = call(
            &app,
            post_json(
                "/commands",
                &bob,
                "application/json",
                command("shared", json!("ollama/ollama:0.6")),
            ),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{e}");
        assert_eq!(e["error"]["code"], "CORRELATION_TAKEN");
        let (s, _, _) = call(
            &app,
            post_json(
                "/commands",
                &alice,
                "application/json",
                with_correlation("a2", "shared"),
            ),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        settle(&d, 2).await;
        assert_eq!(d.log.len(), 2, "the refused commands ran nothing");
        // Bob reads nothing under it, on the log and on a stream he holds open, before or after; Alice reads hers.
        let (s, _, b) = call(&app, get("/events?correlationId=shared", Some(&bob))).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(b["events"], json!([]));
        let (_, _, a) = call(&app, get("/events?correlationId=shared", Some(&alice))).await;
        assert_eq!(a["events"].as_array().unwrap().len(), 2);
        let res = app
            .clone()
            .oneshot(
                Request::get("/events/stream?correlationId=shared")
                    .header(AUTH_HEADER, &bob)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let mut body = res.into_body().into_data_stream();
        d.log.append(Envelope::event(
            "io.best.agents",
            "DeploymentReady",
            json!({ "deployment": "dep-a", "endpoint": "http://peer.test/deployments/dep-a/v1" }),
            Some("shared".into()),
            None,
        ));
        let frame = tokio::time::timeout(std::time::Duration::from_millis(300), body.next()).await;
        assert!(
            frame.is_err(),
            "nothing under Alice's correlation reaches Bob: {frame:?}"
        );
        // A correlation of Bob's own is his to read, and Alice may not take it.
        let (s, _, _) = call(
            &app,
            post_json("/commands", &bob, "application/json", with_correlation("b2", "bobs")),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        settle(&d, 4).await;
        let (_, _, b) = call(&app, get("/events?correlationId=bobs", Some(&bob))).await;
        assert_eq!(b["events"].as_array().unwrap().len(), 1);
        let (s, _, e) = call(
            &app,
            post_json("/commands", &alice, "application/json", with_correlation("a3", "bobs")),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(e["error"]["code"], "CORRELATION_TAKEN");
    }

    #[tokio::test]
    async fn a_command_the_state_cannot_honour_is_refused_before_it_is_accepted_and_a_retry_is_not_rechecked() {
        let d = door();
        let app = router(d.clone());
        let key = sign_in(&app, "test", "my-peer").await;
        let (s, _, b) = call(
            &app,
            post_json("/commands", &key, "application/json", command("cmd-9", json!("full:1"))),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        assert_eq!(b["error"]["code"], "NO_SPACE");
        assert_eq!(b["error"]["details"]["image"], "full:1");
        assert!(d.log.is_empty(), "a refused command runs no handler");
        // The id was never accepted, so the corrected command may reuse it: no conflict.
        let (s, _, b) = call(
            &app,
            post_json(
                "/commands",
                &key,
                "application/json",
                command("cmd-9", json!("small:1")),
            ),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        settle(&d, 1).await;
        let (s, _, b) = call(
            &app,
            post_json(
                "/commands",
                &key,
                "application/json",
                command("cmd-9", json!("small:1")),
            ),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        assert_eq!(
            admitted("small:1"),
            1,
            "a retry of an accepted command is answered without the state check"
        );
        assert_eq!(d.log.len(), 1, "and runs no second handler");
    }

    #[tokio::test]
    async fn a_command_accepted_before_a_restart_is_run_after_it_and_a_finished_one_is_not() {
        let d = door();
        let app = router(d.clone());
        let key = sign_in(&app, "test", "my-peer").await;
        for (id, image) in [("done-1", "small:9"), ("owed-1", "stall:1")] {
            let (s, _, b) = call(
                &app,
                post_json("/commands", &key, "application/json", command(id, json!(image))),
            )
            .await;
            assert_eq!(s, StatusCode::CREATED, "{b}");
        }
        settle(&d, 1).await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert_eq!(d.log.len(), 1, "one completed, the stalled one told nothing");
        assert_eq!(d.log.unfinished().len(), 1);
        // The peer restarts over the same log, with the same credentials on disk.
        let again = door_over_with(d.log.clone(), Some(d.auth.clone()));
        resume(&again).await;
        settle(&again, 2).await;
        let (events, _) = again.log.list(&Filter::default());
        let of = |corr: &str| {
            events
                .iter()
                .filter(|e| e.correlationid.as_deref() == Some(corr))
                .map(|e| e.r#type.as_str())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            of("owed-1"),
            vec!["ImagePulled"],
            "the stalled command ran again and completed"
        );
        assert_eq!(of("done-1"), vec!["ImagePulled"], "the finished one was not run again");
        assert!(again.log.unfinished().is_empty(), "{:?}", again.log.unfinished().len());
        // Resuming again owes nothing.
        resume(&again).await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert_eq!(again.log.len(), 2);
    }

    #[tokio::test]
    async fn a_command_the_door_cannot_honour_after_a_restart_is_failed_with_the_reason() {
        let d = door();
        let app = router(d.clone());
        let key = sign_in(&app, "test", "my-peer").await;
        // Accepted on the old state; the handler died before completing it.
        let (s, _, _) = call(
            &app,
            post_json(
                "/commands",
                &key,
                "application/json",
                command("owed-3", json!("stall:2")),
            ),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        // Make the command one the admit check refuses now, as a device full since would.
        let mut owed = d.log.unfinished();
        assert_eq!(owed.len(), 1);
        owed[0].envelope.data["image"] = json!("full:2");
        let again = door_over_with(Arc::new(EventLog::ephemeral()), Some(d.auth.clone()));
        let sender = crate::auth::hash_key(&key);
        again.log.accept_command(
            &sender,
            "owed-3",
            &payload_hash(&owed[0].envelope),
            "owed-3",
            &owed[0].envelope,
        );
        // And one whose stored copy was edited after acceptance: it no longer matches its record.
        let mut tampered = owed[0].envelope.clone();
        tampered.id = "owed-4".into();
        again
            .log
            .accept_command(&sender, "owed-4", "the-hash-of-something-else", "owed-4", &tampered);
        // And one whose sender's credential is gone: not this door's any more, so not run as anyone.
        let mut orphan = owed[0].envelope.clone();
        orphan.id = "owed-5".into();
        orphan.data["image"] = json!("small:5");
        again
            .log
            .accept_command("x", "owed-5", &payload_hash(&orphan), "owed-5", &orphan);
        resume(&again).await;
        settle(&again, 3).await;
        let (events, _) = again.log.list(&Filter::default());
        let reason = |corr: &str| {
            events
                .iter()
                .find(|e| e.correlationid.as_deref() == Some(corr))
                .map(|e| (e.r#type.clone(), e.data["reason"].as_str().unwrap_or("").to_string()))
                .unwrap()
        };
        let (t, r) = reason("owed-3");
        assert_eq!(t, "CommandFailed");
        assert!(r.contains("no space"), "{r}");
        let (t, r) = reason("owed-4");
        assert_eq!(t, "CommandFailed");
        assert!(r.contains("no longer matches its record"), "{r}");
        let (t, r) = reason("owed-5");
        assert_eq!(t, "CommandFailed");
        assert!(r.contains("credential is gone"), "{r}");
        assert!(again.log.unfinished().is_empty(), "a failed command is finished");
    }

    #[tokio::test]
    async fn two_copies_of_one_command_in_flight_are_one_command() {
        let d = door();
        let app = router(d.clone());
        let key = sign_in(&app, "test", "my-peer").await;
        let send = || {
            call(
                &app,
                post_json("/commands", &key, "application/json", command("cmd-7", json!("slow:1"))),
            )
        };
        let ((s1, _, b1), (s2, _, b2)) = tokio::join!(send(), send());
        assert_eq!((s1, s2), (StatusCode::CREATED, StatusCode::CREATED), "{b1} {b2}");
        assert_eq!(b1["correlationId"], b2["correlationId"]);
        settle(&d, 1).await;
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert_eq!(admitted("slow:1"), 1, "the state check ran once");
        assert_eq!(d.log.len(), 1, "and one handler ran");
        // A copy in flight with another payload is the conflict it would be once recorded.
        let slow = call(
            &app,
            post_json("/commands", &key, "application/json", command("cmd-8", json!("slow:2"))),
        );
        let other = async {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            call(
                &app,
                post_json(
                    "/commands",
                    &key,
                    "application/json",
                    command("cmd-8", json!("other:2")),
                ),
            )
            .await
        };
        let ((s1, _, _), (s2, _, b2)) = tokio::join!(slow, other);
        assert_eq!(s1, StatusCode::CREATED);
        assert_eq!(s2, StatusCode::CONFLICT, "{b2}");
    }

    #[tokio::test]
    async fn a_handler_that_panics_leaves_a_failure_event_not_silence() {
        let d = door();
        let app = router(d.clone());
        let key = sign_in(&app, "test", "my-peer").await;
        let (s, _, _) = call(
            &app,
            post_json("/commands", &key, "application/json", command("boom", json!("panic:1"))),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        settle(&d, 1).await;
        let (events, _) = d.log.list(&Filter::default());
        assert_eq!(events[0].r#type, "CommandFailed");
        assert_eq!(events[0].correlationid.as_deref(), Some("boom"));
        assert!(events[0].data["reason"].as_str().unwrap().contains("exploded"));
    }

    #[tokio::test]
    async fn every_refusal_says_what_to_send_instead() {
        let app = router(door());
        let key = sign_in(&app, "test", "my-peer").await;
        let mut unknown = command("c2", json!("x"));
        unknown["type"] = json!("Explode");
        let (s, _, e) = call(&app, post_json("/commands", &key, "application/json", unknown)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(e["error"]["code"], "UNKNOWN_TYPE");
        assert_eq!(e["error"]["details"]["accepted"][0], "PullImage");
        let (s, _, e) = call(
            &app,
            post_json("/commands", &key, "application/json", command("c3", json!(""))),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(e["error"]["code"], "SCHEMA_VALIDATION");
        assert_eq!(e["error"]["details"]["errors"][0]["path"], "data/image");
        let mut wrong = command("c4", json!("x"));
        wrong["dataschema"] = json!("https://elsewhere.test/schema");
        let (s, _, e) = call(&app, post_json("/commands", &key, "application/json", wrong)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(e["error"]["code"], "DATASCHEMA_MISMATCH");
        let (s, _, e) = call(&app, post_json("/commands", &key, "text/plain", json!({}))).await;
        assert_eq!(s, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(e["error"]["code"], "UNSUPPORTED_MEDIA_TYPE");
        let (s, _, e) = call(
            &app,
            post_json("/commands", &key, "application/json", json!({ "specversion": "1.0" })),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(e["error"]["code"], "INVALID_ENVELOPE");
        let mut empty_corr = command("c5", json!("x"));
        empty_corr["correlationid"] = json!("");
        let (s, _, e) = call(&app, post_json("/commands", &key, "application/json", empty_corr)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(e["error"]["details"]["attribute"], "correlationid");
        let (s, _, e) = call(&app, get("/commands/nope/1.0", Some(&key))).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert_eq!(e["error"]["code"], "SCHEMA_NOT_FOUND");
        let (s, h, doc) = call(&app, get("/commands/pull-image/1.0", Some(&key))).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(h[header::CONTENT_TYPE], "application/schema+json");
        assert_eq!(doc["commandType"], "PullImage");
    }

    #[tokio::test]
    async fn queries_are_catalogued_documented_executed_with_their_parameters_checked() {
        let app = router(door());
        let key = sign_in(&app, "test", "my-peer").await;
        let (_, _, c) = call(&app, get("/queries", Some(&key))).await;
        assert_eq!(c["queries"][0]["dataschema"], format!("{EP}/queries/get-peer/1.0"));
        let (s, _, d) = call(&app, get("/queries/get-peer/1.0", Some(&key))).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(d["response"]["type"], "object");
        assert_eq!(d["parameters"]["properties"]["x"]["type"], "string");
        let (s, _, r) = call(&app, get("/queries/get-peer?x=1", Some(&key))).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(r["echo"], "1");
        let (s, _, e) = call(&app, get("/queries/get-peer?x=9", Some(&key))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(e["error"]["code"], "INVALID_PARAMETER");
        assert_eq!(e["error"]["details"]["errors"][0]["parameter"], "x");
        let (s, _, e) = call(&app, get("/queries/get-peer?y=1", Some(&key))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{e}");
        let (s, _, e) = call(&app, get("/queries/nope", Some(&key))).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert_eq!(e["error"]["code"], "SCHEMA_NOT_FOUND");
        let (s, _, w) = call(&app, get("/workflows", Some(&key))).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(w["workflows"], json!([]));
        let (s, _, _) = call(&app, get("/workflows/nope", Some(&key))).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn the_stream_replays_after_the_last_seen_id_then_follows_live_without_overlap() {
        let d = door();
        let app = router(d.clone());
        let key = sign_in(&app, "test", "my-peer").await;
        let first = d.log.append(Envelope::event(
            "io.best.agents",
            "A",
            json!({}),
            Some("c".into()),
            None,
        ));
        let _second = d.log.append(Envelope::event(
            "io.best.agents",
            "B",
            json!({}),
            Some("c".into()),
            None,
        ));
        let res = app
            .clone()
            .oneshot(
                Request::get("/events/stream?correlationId=c")
                    .header(AUTH_HEADER, &key)
                    .header("last-event-id", &first.envelope.id)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(res.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream"));
        let mut body = res.into_body().into_data_stream();
        let replay = tokio::time::timeout(std::time::Duration::from_secs(2), body.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let replay = String::from_utf8_lossy(&replay);
        assert!(replay.contains("\"type\":\"B\""), "{replay}");
        assert!(!replay.contains("\"type\":\"A\""), "{replay}");
        d.log.append(Envelope::event(
            "io.best.agents",
            "Other",
            json!({}),
            Some("not-c".into()),
            None,
        ));
        let live = d.log.append(Envelope::event(
            "io.best.agents",
            "C",
            json!({}),
            Some("c".into()),
            None,
        ));
        let frame = tokio::time::timeout(std::time::Duration::from_secs(2), body.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let frame = String::from_utf8_lossy(&frame);
        assert!(frame.contains(&format!("id: {}", live.envelope.id)), "{frame}");
        assert!(frame.contains("\"type\":\"C\""), "{frame}");
        assert!(
            !frame.contains("\"type\":\"B\""),
            "B was replayed, not repeated: {frame}"
        );
        assert!(!frame.contains("Other"), "the filter holds on the live part: {frame}");
    }
}
