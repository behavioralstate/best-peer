//! The HTTP routes the spec names (SPEC.md, HTTP Transport and the four capabilities), over a [`Door`]. The manifest
//! and the two OAuth endpoints are public; everything else needs the credential in the `X-Api-Key` header. Every
//! error the door answers, the framework's included, is in the BEST error format. A tenant's door has the protected
//! routes alone ([`tenant_router`]): its manifest is the root's to serve, and sign-in is the root's.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Extension, Path, Query, Request, State};
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

use crate::auth::{Credential, DeviceRequest, Grant, OAuthError, TokenRequest, AUTH_HEADER};
use crate::catalogue::{CommandDef, Emitter};
use crate::envelope::Envelope;
use crate::error::BestError;
use crate::log::{Accept, Filter, MAX_PAGE};
use crate::{manifest, Door};

type Shared = Arc<Door>;

/// The most a request body may carry: a command is a few kilobytes, a form a few hundred bytes.
const MAX_BODY: usize = 256 * 1024;

pub fn router(door: Shared) -> Router {
    let public = Router::new()
        .route("/.well-known/best", get(well_known))
        .route("/auth/device", post(device))
        .route("/auth/token", post(token))
        .route("/auth/verify", get(verify))
        .route("/auth/approve", post(approve));
    shaped(public.merge(protected(&door)), door)
}

/// The routes of a tenant's door: the four capabilities behind the credential, and nothing public. The host mounts
/// it under the tenant's endpoint, with the path below that endpoint, and serves the tenant's manifest itself.
pub fn tenant_router(door: Shared) -> Router {
    shaped(protected(&door), door)
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

/// Every refusal in the BEST shape, the body bounded, an unknown route named.
fn shaped(routes: Router<Shared>, door: Shared) -> Router {
    routes
        .fallback(unknown_route)
        .layer(middleware::map_response(best_shaped))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(door)
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
async fn best_shaped(res: Response) -> Response {
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
                "the body exceeds {MAX_BODY} bytes: send less in one command; for a prompt, fewer or shorter messages"
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
    let mut out = BestError::new(status, code, message).into_response();
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

async fn device(State(door): State<Shared>, headers: HeaderMap, body: Bytes) -> Result<Response, OAuthError> {
    let req: DeviceRequest = form(&headers, &body)?;
    let answer = door.auth.start_device(req)?;
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
    };
    let admitted = door.auth.approve(f.user_code.trim(), f.proof.trim(), grant).await?;
    Ok(Json(json!({ "approved": true, "admitted": admitted })).into_response())
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
    if let Some(admit) = &def.admit {
        admit(
            envelope.clone(),
            sender.clone(),
            command_key(&sender.hash, &envelope.id),
        )
        .await?;
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

/// Replays what came after `Last-Event-ID`, then follows live; the two never overlap. A client that falls behind
/// the buffer is cut off, so it reconnects with its last id and misses nothing silently.
async fn stream_events(
    State(door): State<Shared>,
    Extension(sender): Extension<Credential>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Sse<impl Stream<Item = Result<SseEvent, Infallible>>>, BestError> {
    let filter = filter_from(&q)?;
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
    let live = BroadcastStream::new(rx)
        .take_while(|r| futures::future::ready(r.is_ok()))
        .filter_map(move |r| {
            let keep = r
                .ok()
                .filter(|s| s.seq > seen_up_to && filter.matches(s) && door2.visible_to(&sender, s));
            async move { keep }
        });
    let out = replayed.chain(live).map(|s| {
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
        Arc::new(Door::new(EP, "io.best.agents", "A test peer.", catalogue, log, auth))
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
        let (s, _, a) = call(
            app,
            post_form("/auth/device", &[("client_id", client), ("connection", connection)]),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{a}");
        let mut fields = vec![("user_code", a["user_code"].as_str().unwrap()), ("proof", "ok")];
        if let Some(m) = may {
            fields.push(("may", m));
        }
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
    async fn every_error_the_framework_answers_is_in_the_best_shape() {
        let app = router(door());
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
        let (s, _, b) = call(&app, get("/events?limit=0", Some(&key))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(b["error"]["details"]["parameter"], "limit");
        let (s, _, b) = call(&app, get("/events?limit=5000", Some(&key))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert!(b["error"]["message"].as_str().unwrap().contains("200"));
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
