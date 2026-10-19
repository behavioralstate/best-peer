//! A member of the cloud this peer fronts: another peer's door, reached through the transport with the credential
//! that door issued to this peer by its own sign-in. Everything here is the BEST surface as a consumer uses it (the
//! manifest, queries, commands, the event stream): the cloud is an agent to its members. Every call has a deadline,
//! so a member that neither answers nor refuses is unreachable, never a stall.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use best_peer_door::auth::AUTH_HEADER;
use best_peer_door::{BestError, Envelope};
use futures::{Stream, StreamExt};
use serde_json::{json, Value};

use crate::transport::Transport;

/// How long a member has to answer a query or a command before it counts as unreachable.
pub const ANSWER_WITHIN: Duration = Duration::from_secs(15);

/// Why a member did not do what was asked: it could not be reached, or it refused, with its answer.
#[derive(Debug)]
pub enum Refusal {
    Unreachable(String),
    Refused { status: StatusCode, body: Value },
}

impl Refusal {
    /// The member's refusal as this door's: the member named, the member's code and message kept.
    pub fn relayed(&self, member: &str) -> BestError {
        match self {
            Refusal::Unreachable(why) => BestError::new(
                StatusCode::BAD_GATEWAY,
                "PEER_UNREACHABLE",
                format!("peer {member} did not answer: {why}"),
            ),
            Refusal::Refused { status, body } => {
                let code = body["error"]["code"].as_str().unwrap_or("REFUSED").to_string();
                let message = body["error"]["message"].as_str().unwrap_or("refused").to_string();
                BestError::new(
                    *status,
                    "PEER_REFUSED",
                    format!("peer {member} refused ({code}): {message}"),
                )
                .with_details(json!({ "peer": member, "code": code, "details": body["error"]["details"] }))
            }
        }
    }

    /// The member no longer honours the credential this peer holds for it.
    pub fn is_unauthorized(&self) -> bool {
        matches!(self, Refusal::Refused { status, .. } if *status == StatusCode::UNAUTHORIZED)
    }

    pub fn text(&self) -> String {
        match self {
            Refusal::Unreachable(why) => why.clone(),
            Refusal::Refused { status, body } => {
                format!("{status}: {}", body["error"]["message"].as_str().unwrap_or("refused"))
            }
        }
    }
}

pub struct Member {
    pub name: String,
    /// Where this peer reaches the member: what the operator listed.
    pub endpoint: String,
    key: Mutex<Option<String>>,
    /// What the member calls itself, from its manifest: what its schema URIs are built on, which may differ from
    /// where it is reached.
    own_endpoint: Mutex<Option<String>>,
    pub transport: Arc<dyn Transport>,
}

impl Member {
    pub fn new(name: &str, endpoint: &str, key: Option<String>, transport: Arc<dyn Transport>) -> Self {
        Self {
            name: name.into(),
            endpoint: endpoint.trim_end_matches('/').into(),
            key: Mutex::new(key),
            own_endpoint: Mutex::new(None),
            transport,
        }
    }

    pub fn key(&self) -> Option<String> {
        self.key.lock().unwrap().clone()
    }

    pub fn set_key(&self, key: String) {
        *self.key.lock().unwrap() = Some(key);
    }

    /// Forgets a credential the member no longer honours, so the sign-in runs again.
    pub fn clear_key(&self) {
        *self.key.lock().unwrap() = None;
    }

    /// Admitted by this member: it issued the credential this peer holds for it.
    pub fn admitted(&self) -> bool {
        self.key.lock().unwrap().is_some()
    }

    fn request(&self, method: Method, path: &str, body: Option<(&str, String)>) -> Request<Body> {
        let mut req = Request::builder()
            .method(method)
            .uri(format!("{}{path}", self.endpoint))
            .header(header::ACCEPT, "application/json");
        if let Some(key) = self.key() {
            req = req.header(AUTH_HEADER, key);
        }
        match body {
            Some((content_type, text)) => req.header(header::CONTENT_TYPE, content_type).body(Body::from(text)),
            None => req.body(Body::empty()),
        }
        .expect("a request to a member is well formed")
    }

    async fn exchange(&self, req: Request<Body>) -> Result<Value, Refusal> {
        let answer = async {
            let res = self.transport.call(req).await.map_err(Refusal::Unreachable)?;
            let status = res.status();
            let bytes = axum::body::to_bytes(res.into_body(), 8 << 20)
                .await
                .map_err(|e| Refusal::Unreachable(format!("the answer could not be read: {e}")))?;
            let body: Value = serde_json::from_slice(&bytes).unwrap_or_default();
            if status.is_success() {
                Ok(body)
            } else {
                Err(Refusal::Refused { status, body })
            }
        };
        tokio::time::timeout(ANSWER_WITHIN, answer)
            .await
            .unwrap_or_else(|_| Err(Refusal::Unreachable(format!("no answer within {ANSWER_WITHIN:?}"))))
    }

    pub async fn get(&self, path: &str) -> Result<Value, Refusal> {
        self.exchange(self.request(Method::GET, path, None)).await
    }

    /// A query of the member, with this peer's credential.
    pub async fn query(&self, schema: &str) -> Result<Value, Refusal> {
        self.get(&format!("/queries/{schema}")).await
    }

    /// The base the member builds its schema URIs on: its own endpoint, read once from its manifest, and where it is
    /// reached until the manifest has been read.
    pub async fn schema_base(&self) -> String {
        if let Some(e) = self.own_endpoint.lock().unwrap().clone() {
            return e;
        }
        let Ok(manifest) = self.get("/.well-known/best").await else {
            return self.endpoint.clone();
        };
        let own = manifest["best"]["services"]
            .as_object()
            .and_then(|s| s.values().next())
            .and_then(|s| s["http"]["endpoint"].as_str())
            .map(|e| e.trim_end_matches('/').to_string());
        match own {
            Some(e) => {
                *self.own_endpoint.lock().unwrap() = Some(e.clone());
                e
            }
            None => self.endpoint.clone(),
        }
    }

    /// A command sent to the member, as the envelope is; its `created` answer, or the refusal.
    pub async fn send(&self, envelope: &Envelope) -> Result<Value, Refusal> {
        let text = serde_json::to_string(envelope).expect("an envelope serialises");
        self.exchange(self.request(Method::POST, "/commands", Some(("application/cloudevents+json", text))))
            .await
    }

    /// A form posted to one of the member's sign-in routes, no credential: the device flow is public.
    pub async fn sign_in_form(&self, path: &str, fields: &[(&str, &str)]) -> Result<Value, Refusal> {
        let text = serde_urlencoded::to_string(fields).expect("a form encodes");
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("{}{path}", self.endpoint))
            .header(header::ACCEPT, "application/json")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(text))
            .expect("a form request is well formed");
        self.exchange(req).await
    }

    /// The member's event stream from after `last` (its event id), as it comes: each event's id and envelope, and
    /// between events the word that the socket is alive. Ends when the member closes it; the caller reconnects with
    /// the last id it saw.
    pub async fn stream(&self, last: Option<&str>) -> Result<impl Stream<Item = Heard>, Refusal> {
        let mut req = self.request(Method::GET, "/events/stream", None);
        req.headers_mut()
            .insert(header::ACCEPT, "text/event-stream".parse().unwrap());
        if let Some(id) = last {
            if let Ok(v) = id.parse() {
                req.headers_mut().insert("last-event-id", v);
            }
        }
        let res = tokio::time::timeout(ANSWER_WITHIN, self.transport.call(req))
            .await
            .unwrap_or_else(|_| Err(format!("no answer within {ANSWER_WITHIN:?}")))
            .map_err(Refusal::Unreachable)?;
        if !res.status().is_success() {
            let status = res.status();
            let bytes = axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap_or_default();
            return Err(Refusal::Refused {
                status,
                body: serde_json::from_slice(&bytes).unwrap_or_default(),
            });
        }
        Ok(sse_events(res.into_body()))
    }
}

/// What a member's stream said: an event, by its id and envelope; or only that the member is there, when bytes
/// came that completed no event (a keep-alive comment, the first chunk of a long event). A reader that waits for
/// the next item with a deadline thereby tells a quiet member from a dead socket.
pub enum Heard {
    Event(String, Box<Envelope>),
    Alive,
}

/// Server-sent events parsed from a body as it streams: the `id` and the `data` of each event, the data as an
/// envelope. Bytes are kept until an event is complete, so a character split across chunks is read whole. Comments
/// (keep-alives) and events without an envelope carry no event, but a chunk of them says the member is alive.
fn sse_events(body: Body) -> impl Stream<Item = Heard> {
    let mut buffer: Vec<u8> = Vec::new();
    body.into_data_stream()
        .take_while(|chunk| futures::future::ready(chunk.is_ok()))
        .flat_map(move |chunk| {
            buffer.extend_from_slice(&chunk.unwrap_or_default());
            let mut out = Vec::new();
            while let Some(end) = buffer.windows(2).position(|w| w == b"\n\n") {
                let block = String::from_utf8_lossy(&buffer[..end]).into_owned();
                buffer.drain(..end + 2);
                let (mut id, mut data) = (None, String::new());
                for line in block.lines() {
                    if let Some(v) = line.strip_prefix("id:") {
                        id = Some(v.trim().to_string());
                    } else if let Some(v) = line.strip_prefix("data:") {
                        data.push_str(v.trim_start());
                    }
                }
                if let (Some(id), Ok(envelope)) = (id, serde_json::from_str::<Envelope>(&data)) {
                    out.push(Heard::Event(id, Box::new(envelope)));
                }
            }
            if out.is_empty() {
                out.push(Heard::Alive);
            }
            futures::stream::iter(out)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_stream_is_parsed_event_by_event_across_chunks_and_characters_are_read_whole() {
        let e1 = serde_json::to_string(&Envelope::event(
            "s",
            "A",
            json!({ "reason": "crème brûlée" }),
            None,
            None,
        ))
        .unwrap();
        let e2 = serde_json::to_string(&Envelope::event("s", "B", json!({}), None, None)).unwrap();
        let text = format!(": keepalive\n\nid: one\ndata: {e1}\n\nid: two\ndata: {e2}\n\n");
        // Cut inside the "û": the two bytes of the character land in different chunks.
        let cut = text.find('û').unwrap() + 1;
        let bytes = text.as_bytes();
        let chunks: Vec<Result<axum::body::Bytes, std::io::Error>> = vec![
            Ok(axum::body::Bytes::copy_from_slice(&bytes[..cut])),
            Ok(axum::body::Bytes::copy_from_slice(&bytes[cut..])),
        ];
        let body = Body::from_stream(futures::stream::iter(chunks));
        let got: Vec<(String, String, Value)> = sse_events(body)
            .filter_map(|h| {
                futures::future::ready(match h {
                    Heard::Event(id, e) => Some((id, e.r#type, e.data["reason"].clone())),
                    Heard::Alive => None,
                })
            })
            .collect()
            .await;
        assert_eq!(got.len(), 2);
        assert_eq!((got[0].0.as_str(), got[0].1.as_str()), ("one", "A"));
        assert_eq!(got[0].2, "crème brûlée");
        assert_eq!((got[1].0.as_str(), got[1].1.as_str()), ("two", "B"));
    }

    #[tokio::test]
    async fn a_keep_alive_is_heard_as_the_member_being_alive_and_is_no_event() {
        // Two keep-alive comments, as the member sends them every fifteen seconds while nothing happens, then the
        // first half of an event: none is an event, each chunk says the member is there.
        let half = format!(
            "id: one
data: {}",
            "{\"specversion\": \"1.0\""
        );
        let chunks: Vec<Result<axum::body::Bytes, std::io::Error>> = vec![
            Ok(axum::body::Bytes::from_static(
                b": keepalive

",
            )),
            Ok(axum::body::Bytes::from_static(
                b": keepalive

",
            )),
            Ok(axum::body::Bytes::from(half)),
        ];
        let heard: Vec<Heard> = sse_events(Body::from_stream(futures::stream::iter(chunks)))
            .collect()
            .await;
        assert_eq!(heard.len(), 3);
        assert!(
            heard.iter().all(|h| matches!(h, Heard::Alive)),
            "a keep-alive or a part of an event is no event"
        );
    }
}
