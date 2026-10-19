//! [`Engine`] over the engines' own HTTP APIs. Ollama: `GET /` says it is up, `POST /api/pull` streams a model into
//! its library with progress, and a model in a store it sees is checked with `POST /api/show` and loaded with
//! `POST /api/generate`. vLLM: `GET /health` answers once the model it was started with is loaded, and
//! `GET /v1/models` lists it. Every call is blocking I/O on a worker thread, never on the door's workers. Thin;
//! proven on a host by hand. The reading of a pull, which decides when a pull has ended, is tested over Ollama's
//! own stream, recorded, and over a stream that breaks or goes quiet.

use std::io::BufRead;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use best_peer_engine::{Answer, Engine, EngineError, Kind, Message, Options, Progress, Source};

#[derive(Clone)]
pub struct HttpEngine {
    agent: ureq::Agent,
    pull: PullBounds,
}

/// How a pull from the registry is watched. The engine's stream says how the pull goes, but its end is not the only
/// way to know the model arrived: when the stream says nothing for `check_after`, the engine is asked whether it has
/// the model, and a stream that says nothing for `quiet_limit` while the engine does not have it ends the pull as
/// stalled. A stream that breaks, ends without success or says the engine gave up is resumed, the engine going on
/// from what it has, up to `attempts` times in all.
#[derive(Clone, Copy, Debug)]
pub struct PullBounds {
    pub check_after: Duration,
    pub quiet_limit: Duration,
    pub attempts: u32,
}

impl PullBounds {
    /// The slowest a disk is taken to read while the engine checks a model's digests: 50 MiB a second.
    const CHECKED_PER_SECOND: u64 = 50 << 20;
}

impl Default for PullBounds {
    /// Five minutes of silence while a model downloads. Once the engine says it is verifying the model's digests, the
    /// one step of a pull that says nothing while it runs, the bound is as long as reading every byte of the model
    /// at 50 MiB a second, when that is longer: a model of 40 GB is given fourteen minutes.
    fn default() -> Self {
        Self {
            check_after: Duration::from_secs(15),
            quiet_limit: Duration::from_secs(300),
            attempts: 3,
        }
    }
}

impl Default for HttpEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpEngine {
    pub fn new() -> Self {
        // No global timeout: a pull streams for as long as it takes. The first byte must come within a minute,
        // and the short calls (readiness, the model list, an unload) carry their own bounds.
        let config = ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_secs(5)))
            .timeout_recv_response(Some(Duration::from_secs(60)))
            .timeout_global(None)
            .build();
        Self {
            agent: ureq::Agent::new_with_config(config),
            pull: PullBounds::default(),
        }
    }

    /// The same adapter, watching a pull within `bounds`.
    pub fn with_pull_bounds(mut self, bounds: PullBounds) -> Self {
        self.pull = bounds;
        self
    }

    /// `POST /api/pull` on Ollama: the model from the registry into the engine's library, its progress told as the
    /// stream says it. The pull has ended when the stream says `success`, or when the engine has the model whatever
    /// the stream says; a stream that breaks or ends short is resumed; one quiet for longer than the bounds allow while
    /// the engine does not have the model ends the pull as stalled, so a deploy never waits its whole load patience
    /// on a pull that stopped.
    fn pull_ollama(&self, base: &str, model: &str, progress: &Progress) -> Result<(), EngineError> {
        let mut stream = PullStream::default();
        let mut broke = String::new();
        let attempts = self.pull.attempts.max(1);
        for attempt in 1..=attempts {
            tracing::info!(%base, %model, attempt, "pulling the model into the engine");
            match self.pull_once(base, model, progress, &mut stream)? {
                Pulled::Ended => {
                    tracing::info!(%base, %model, "the engine has the model");
                    return Ok(());
                }
                Pulled::Broke(why) => {
                    if self.holds(base, model) {
                        tracing::info!(%base, %model, why = %why, "the engine has the model, though its pull did not say so");
                        return Ok(());
                    }
                    tracing::warn!(%base, %model, attempt, why = %why, "the pull did not complete");
                    broke = why;
                }
            }
        }
        Err(EngineError::Engine(format!(
            "the pull did not complete in {attempts} attempts: {broke}"
        )))
    }

    /// One `POST /api/pull`, its stream read on a thread of its own, so that a stream that stops saying anything is
    /// noticed whatever its connection does.
    fn pull_once(
        &self,
        base: &str,
        model: &str,
        progress: &Progress,
        stream: &mut PullStream,
    ) -> Result<Pulled, EngineError> {
        // An agent of its own: no connection kept from another call is reused for a stream that runs for minutes.
        let config = ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_secs(5)))
            .timeout_recv_response(Some(Duration::from_secs(60)))
            .timeout_global(None)
            .build();
        let res = match ureq::Agent::new_with_config(config)
            .post(format!("{base}/api/pull"))
            .send_json(serde_json::json!({ "name": model, "stream": true }))
        {
            Ok(res) => res,
            Err(ureq::Error::StatusCode(404)) => return Err(EngineError::ModelNotFound(model.into())),
            Err(ureq::Error::StatusCode(status)) => {
                return Err(EngineError::Engine(format!("the engine refused the pull: {status}")))
            }
            Err(other) => return Ok(Pulled::Broke(format!("the pull could not be asked: {other}"))),
        };
        stream.begin_attempt();
        let (tx, rx) = mpsc::channel();
        let body = res.into_body();
        std::thread::Builder::new()
            .name("ollama-pull".into())
            .spawn(move || {
                for line in std::io::BufReader::new(body.into_reader()).lines() {
                    let end = line.is_err();
                    if tx.send(line).is_err() || end {
                        return;
                    }
                }
            })
            .map_err(|e| EngineError::Engine(format!("the pull could not be read: {e}")))?;
        let mut said_last = Instant::now();
        loop {
            match rx.recv_timeout(self.pull.check_after) {
                Ok(Ok(line)) => {
                    said_last = Instant::now();
                    match stream.line(&line, model)? {
                        Said::Progress(pct) => progress(Some(pct)),
                        Said::Success => return Ok(Pulled::Ended),
                        Said::Fault(why) => return Ok(Pulled::Broke(format!("the engine said: {why}"))),
                        Said::Nothing => {}
                    }
                }
                Ok(Err(e)) => return Ok(Pulled::Broke(format!("the pull stream broke: {e}"))),
                Err(RecvTimeoutError::Disconnected) => {
                    return Ok(Pulled::Broke("the pull stream ended without success".into()))
                }
                Err(RecvTimeoutError::Timeout) => {
                    if self.holds(base, model) {
                        tracing::warn!(%base, %model, "the pull stream went quiet with the model in the engine: the pull has ended");
                        return Ok(Pulled::Ended);
                    }
                    if said_last.elapsed() >= stream.quiet_allowed(self.pull.quiet_limit) {
                        return Err(EngineError::Engine(format!(
                            "the engine said nothing of the pull for {} s and does not have the model: the registry or the engine stalled",
                            said_last.elapsed().as_secs()
                        )));
                    }
                }
            }
        }
    }

    /// Whether the engine has `model` in its library: `POST /api/show` answers, or says not with a 404.
    fn holds(&self, base: &str, model: &str) -> bool {
        self.agent
            .post(format!("{base}/api/show"))
            .config()
            .timeout_global(Some(Duration::from_secs(10)))
            .build()
            .send_json(serde_json::json!({ "model": model }))
            .is_ok()
    }

    /// A model in a store Ollama sees is served without the registry: `POST /api/show` says whether it is there (404
    /// says not), and `POST /api/generate` with no prompt loads it into memory. The load is given as long as the
    /// caller waits for it, not the minute the shared agent gives a first byte, since a large model on a slow disk
    /// answers only once it is in memory.
    fn serve_ollama(&self, base: &str, model: &str, progress: &Progress) -> Result<(), EngineError> {
        self.agent
            .post(format!("{base}/api/show"))
            .config()
            .timeout_global(Some(Duration::from_secs(30)))
            .build()
            .send_json(serde_json::json!({ "model": model }))
            .map_err(|e| match e {
                ureq::Error::StatusCode(404) => EngineError::ModelNotFound(model.into()),
                other => EngineError::Engine(other.to_string()),
            })?;
        progress(Some(0));
        let config = ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_secs(5)))
            .timeout_recv_response(None)
            .timeout_global(None)
            .http_status_as_error(false)
            .build();
        let mut res = ureq::Agent::new_with_config(config)
            .post(format!("{base}/api/generate"))
            .send_json(serde_json::json!({ "model": model, "stream": false }))
            .map_err(|e| EngineError::Engine(format!("the model is in the store but did not load: {e}")))?;
        if res.status().as_u16() != 200 {
            let text = res.body_mut().read_to_string().unwrap_or_default();
            let said = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v["error"].as_str().map(str::to_string))
                .unwrap_or(text);
            return Err(EngineError::Engine(if said.contains("does not support generate") {
                format!("{model} does not answer conversations (an embedding model?): a deployment is prompted with a conversation, so deploy a model that chats")
            } else {
                format!("the model is in the store but did not load: {said}")
            }));
        }
        progress(Some(100));
        Ok(())
    }

    /// `POST /api/generate` with `keep_alive: 0` makes Ollama drop the model from memory.
    fn unload_ollama(&self, base: &str, model: &str) -> Result<(), EngineError> {
        self.agent
            .post(format!("{base}/api/generate"))
            .config()
            .timeout_global(Some(Duration::from_secs(30)))
            .build()
            .send_json(serde_json::json!({ "model": model, "keep_alive": 0 }))
            .map(|_| ())
            .map_err(|e| EngineError::Engine(e.to_string()))
    }

    /// `POST /v1/chat/completions`, not streaming: both engines speak it, and the answer comes whole with the
    /// counts the engine kept. The engine is given as long as `within` to answer, on an agent of its own, since the
    /// shared one waits a minute for the first byte and a long generation takes longer.
    fn chat(
        &self,
        base: &str,
        model: &str,
        messages: &[Message],
        options: &Options,
        within: Duration,
    ) -> Result<Answer, EngineError> {
        // A refusal is read, not thrown: the engine's own message is what the caller needs.
        let config = ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_secs(5)))
            .timeout_recv_response(Some(within))
            .timeout_global(Some(within))
            .http_status_as_error(false)
            .build();
        let agent = ureq::Agent::new_with_config(config);
        let mut body = serde_json::json!({ "model": model, "messages": messages, "stream": false });
        if let Some(m) = options.max_tokens {
            body["max_tokens"] = serde_json::json!(m);
        }
        if let Some(t) = options.temperature {
            body["temperature"] = serde_json::json!(t);
        }
        if !options.stop.is_empty() {
            body["stop"] = serde_json::json!(options.stop);
        }
        let mut res = agent
            .post(format!("{base}/v1/chat/completions"))
            .send_json(&body)
            .map_err(|e| EngineError::Engine(e.to_string()))?;
        let status = res.status().as_u16();
        let text = res
            .body_mut()
            .read_to_string()
            .map_err(|e| EngineError::Engine(format!("the engine's answer could not be read: {e}")))?;
        let v: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
        // Both engines say why in `error`: as an object with a message (the OpenAI shape) or as a string (Ollama).
        let said = v["error"]["message"]
            .as_str()
            .or(v["error"].as_str())
            .map(str::to_string);
        if status >= 400 {
            let said = said.unwrap_or_else(|| text.trim().chars().take(300).collect());
            let lower = said.to_ascii_lowercase();
            return Err(
                if status == 404 && lower.contains("not found") && lower.contains("model") {
                    EngineError::ModelNotFound(model.into())
                } else {
                    EngineError::Engine(format!("the engine answered {status}: {said}"))
                },
            );
        }
        if let Some(said) = said {
            return Err(EngineError::Engine(said));
        }
        let choice = &v["choices"][0];
        let content = choice["message"]["content"].as_str().unwrap_or("").to_string();
        Ok(Answer {
            content,
            model: v["model"].as_str().unwrap_or(model).to_string(),
            finish: choice["finish_reason"].as_str().map(str::to_string),
            prompt_tokens: v["usage"]["prompt_tokens"].as_u64(),
            completion_tokens: v["usage"]["completion_tokens"].as_u64(),
        })
    }

    /// vLLM loads the model it was started with; `/v1/models` lists it once served.
    fn served_by_vllm(&self, base: &str, model: &str) -> Result<(), EngineError> {
        let mut res = self
            .agent
            .get(format!("{base}/v1/models"))
            .config()
            .timeout_global(Some(Duration::from_secs(30)))
            .build()
            .call()
            .map_err(|e| EngineError::Engine(e.to_string()))?;
        let v: serde_json::Value = res
            .body_mut()
            .read_json()
            .map_err(|e| EngineError::Engine(format!("the model list could not be read: {e}")))?;
        let served = v["data"].as_array().is_some_and(|d| d.iter().any(|m| m["id"] == model));
        if served {
            Ok(())
        } else {
            Err(EngineError::ModelNotFound(model.into()))
        }
    }
}

/// How one attempt of a pull ended: the engine has the model, or the stream broke or ended short of it.
enum Pulled {
    Ended,
    Broke(String),
}

/// What one line of Ollama's pull stream says.
#[derive(Debug, PartialEq, Eq)]
enum Said {
    Progress(u8),
    Success,
    /// The engine gave up on this attempt, after its own retries: a registry that dropped it, a disk that filled.
    Fault(String),
    Nothing,
}

/// The reading of Ollama's pull stream, one JSON object a line: `{ status, digest?, total?, completed? }` per step,
/// the last `{ status: "success" }`, or `{ error }`. The share is across every blob, not per blob, since the engine
/// reports each digest's own bytes, and a blob's first line names its size before any byte of it came. Kept across
/// the attempts of one pull, so a resumed stream goes on from what was told.
#[derive(Default)]
struct PullStream {
    blobs: std::collections::HashMap<String, (u64, u64)>,
    last: Option<u8>,
    /// Whether the engine said it is checking the model's digests, which it does without a word.
    verifying: bool,
}

impl PullStream {
    fn line(&mut self, line: &str, model: &str) -> Result<Said, EngineError> {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            return Ok(Said::Nothing);
        };
        if let Some(err) = v["error"].as_str() {
            // A model the registry does not have is final; anything else is this attempt's end.
            return if err.contains("not found") || err.contains("pull model manifest") {
                Err(EngineError::ModelNotFound(model.into()))
            } else {
                Ok(Said::Fault(err.into()))
            };
        }
        if v["status"] == "success" {
            return Ok(Said::Success);
        }
        self.verifying = v["status"].as_str().is_some_and(|s| s.starts_with("verifying"));
        if let (Some(digest), Some(total)) = (v["digest"].as_str(), v["total"].as_u64()) {
            if total > 0 {
                // A resumed stream names each blob again from its start; what came of it before is still there.
                let completed = v["completed"].as_u64().unwrap_or(0);
                let blob = self.blobs.entry(digest.to_string()).or_insert((0, total));
                *blob = (blob.0.max(completed).min(total), total);
            }
        }
        let (done, total) = self
            .blobs
            .values()
            .fold((0u64, 0u64), |(d, t), (c, bt)| (d + c, t + bt));
        match (done * 100).checked_div(total).map(|p| p.min(100) as u8) {
            Some(pct) if Some(pct) != self.last => {
                self.last = Some(pct);
                Ok(Said::Progress(pct))
            }
            _ => Ok(Said::Nothing),
        }
    }

    /// A new attempt says nothing of verifying until it says so: until then it is held to the download's bound.
    fn begin_attempt(&mut self) {
        self.verifying = false;
    }

    /// How long the stream may say nothing: `quiet` while the model downloads, and while the engine checks its
    /// digests, as long as reading every byte of it takes on a slow disk, when that is longer.
    fn quiet_allowed(&self, quiet: Duration) -> Duration {
        if !self.verifying {
            return quiet;
        }
        let bytes: u64 = self.blobs.values().map(|(_, total)| total).sum();
        quiet.max(Duration::from_secs(bytes / PullBounds::CHECKED_PER_SECOND))
    }
}

/// Whether `url` answers at all, within a few seconds.
fn probe(agent: &ureq::Agent, url: &str) -> bool {
    agent
        .get(url)
        .config()
        .timeout_global(Some(Duration::from_secs(5)))
        .build()
        .call()
        .is_ok()
}

#[async_trait]
impl Engine for HttpEngine {
    async fn ready(&self, kind: Kind, base: &str, within: Duration) -> Result<(), EngineError> {
        let url = match kind {
            Kind::Ollama => format!("{base}/"),
            Kind::Vllm => format!("{base}/health"),
        };
        let started = Instant::now();
        loop {
            let probe_url = url.clone();
            let agent = self.agent.clone();
            let up = tokio::task::spawn_blocking(move || probe(&agent, &probe_url))
                .await
                .unwrap_or(false);
            if up {
                return Ok(());
            }
            if started.elapsed() >= within {
                return Err(EngineError::NotReady {
                    base: base.into(),
                    within,
                });
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    async fn load(
        &self,
        kind: Kind,
        base: &str,
        model: &str,
        source: Source,
        progress: Progress,
    ) -> Result<(), EngineError> {
        let me = self.clone();
        let (base, model) = (base.to_string(), model.to_string());
        tokio::task::spawn_blocking(move || match (kind, source) {
            (Kind::Ollama, Source::Registry) => me.pull_ollama(&base, &model, &progress),
            (Kind::Ollama, Source::Store) => me.serve_ollama(&base, &model, &progress),
            (Kind::Vllm, _) => me.served_by_vllm(&base, &model),
        })
        .await
        .map_err(|e| EngineError::Engine(format!("the load did not complete: {e}")))?
    }

    async fn unload(&self, kind: Kind, base: &str, model: &str) -> Result<(), EngineError> {
        let me = self.clone();
        let (base, model) = (base.to_string(), model.to_string());
        tokio::task::spawn_blocking(move || match kind {
            Kind::Ollama => me.unload_ollama(&base, &model),
            Kind::Vllm => Ok(()),
        })
        .await
        .map_err(|e| EngineError::Engine(format!("the unload did not complete: {e}")))?
    }

    async fn complete(
        &self,
        _kind: Kind,
        base: &str,
        model: &str,
        messages: &[Message],
        options: &Options,
        within: Duration,
    ) -> Result<Answer, EngineError> {
        let me = self.clone();
        let (base, model) = (base.to_string(), model.to_string());
        let (messages, options) = (messages.to_vec(), options.clone());
        tokio::task::spawn_blocking(move || me.chat(&base, &model, &messages, &options, within))
            .await
            .map_err(|e| EngineError::Engine(format!("the prompt did not complete: {e}")))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// Ollama 0.40.6's own stream for `POST /api/pull` of qwen2.5:0.5b, one line per chunk as it sent it.
    const RECORDED: &str = include_str!("../testdata/ollama-0.40.6-pull.ndjson");

    fn told() -> (Progress, Arc<Mutex<Vec<u8>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        (
            Arc::new(move |p: Option<u8>| sink.lock().unwrap().push(p.unwrap())),
            seen,
        )
    }

    #[test]
    fn ollamas_recorded_stream_is_read_to_its_success_with_the_share_across_every_blob() {
        let mut stream = PullStream::default();
        let mut shares = Vec::new();
        let mut ended = false;
        for line in RECORDED.lines() {
            match stream.line(line, "qwen2.5:0.5b").unwrap() {
                Said::Progress(p) => shares.push(p),
                Said::Success => ended = true,
                Said::Fault(why) => panic!("{why}"),
                Said::Nothing => {}
            }
        }
        assert!(ended);
        assert_eq!(
            shares.first(),
            Some(&0),
            "a blob's first line names its size before any byte came"
        );
        // The engine's last progress line leaves a sliver of its last blob unsaid: 100 is the lifecycle's to tell, once
        // the load returned.
        assert_eq!(shares.last(), Some(&99));
        assert!(shares.windows(2).all(|w| w[0] < w[1]), "{shares:?}");
    }

    #[test]
    fn an_error_line_ends_the_attempt_with_what_the_engine_said_and_a_missing_model_ends_the_pull() {
        let mut stream = PullStream::default();
        let missing = stream.line(r#"{"error":"pull model manifest: file does not exist"}"#, "nope:1b");
        assert!(matches!(missing, Err(EngineError::ModelNotFound(m)) if m == "nope:1b"));
        let full = stream.line(r#"{"error":"no space left on device"}"#, "a:1b");
        assert_eq!(full.unwrap(), Said::Fault("no space left on device".into()));
    }

    /// What the fake engine does after the recorded lines it sends of a pull's stream: ends the stream, breaks the
    /// connection, holds it open saying nothing, or says it gave up.
    #[derive(Clone, Copy)]
    enum Then {
        End,
        Break,
        Hold,
        /// Says it gave up, as Ollama does when the registry dropped it past its own retries, and ends.
        Fail,
        /// Names a blob of 10 GiB, all of it come, says it is verifying the digests, and breaks.
        VerifyThenBreak,
    }

    type Answer = Arc<dyn Fn(usize) -> (usize, Then) + Send + Sync>;

    /// A fake Ollama on loopback: its n-th `POST /api/pull` (from 1) sends what `pull(n)` says; `POST /api/show`
    /// answers 200 once `has` says the model is in the library, 404 before.
    fn engine(
        pull: impl Fn(usize) -> (usize, Then) + Send + Sync + 'static,
        has: Arc<Mutex<bool>>,
    ) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let pulls = Arc::new(AtomicUsize::new(0));
        let count = pulls.clone();
        let pull: Answer = Arc::new(pull);
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let (mut conn, pull, count, has) = (conn.unwrap(), pull.clone(), count.clone(), has.clone());
                std::thread::spawn(move || {
                    if request(&mut conn) == "/api/show" {
                        let ok = *has.lock().unwrap();
                        let (status, body) = if ok {
                            ("200 OK", "{}")
                        } else {
                            ("404 Not Found", "{\"error\":\"not found\"}")
                        };
                        let _ = write!(
                            conn,
                            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        return;
                    }
                    let (lines, then) = pull(count.fetch_add(1, Ordering::SeqCst) + 1);
                    let _ = write!(
                        conn,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\n\r\n"
                    );
                    for line in RECORDED.lines().take(lines) {
                        let _ = write!(conn, "{:x}\r\n{line}\n\r\n", line.len() + 1);
                    }
                    match then {
                        Then::End => {
                            let _ = write!(conn, "0\r\n\r\n");
                        }
                        Then::Break => {}
                        Then::Hold => std::thread::sleep(Duration::from_secs(120)),
                        Then::VerifyThenBreak => {
                            for line in [
                                format!(
                                    r#"{{"status":"pulling big","digest":"sha256:big","total":{0},"completed":{0}}}"#,
                                    10u64 << 30
                                ),
                                r#"{"status":"verifying sha256 digest"}"#.to_string(),
                            ] {
                                let _ = write!(conn, "{:x}\r\n{line}\n\r\n", line.len() + 1);
                            }
                        }
                        Then::Fail => {
                            let line = "{\"error\":\"max retries exceeded: EOF\"}";
                            let _ = write!(conn, "{:x}\r\n{line}\n\r\n0\r\n\r\n", line.len() + 1);
                        }
                    }
                });
            }
        });
        (base, pulls)
    }

    /// Reads one request's head and body, and says its path.
    fn request(conn: &mut TcpStream) -> String {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") && conn.read(&mut byte).unwrap_or(0) == 1 {
            head.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&head).to_string();
        let length = head
            .lines()
            .find_map(|l| {
                l.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .map(|v| v.trim().parse::<usize>().unwrap_or(0))
            })
            .unwrap_or(0);
        let mut body = vec![0u8; length];
        let _ = conn.read_exact(&mut body);
        head.split_whitespace().nth(1).unwrap_or_default().to_string()
    }

    fn quick() -> PullBounds {
        PullBounds {
            check_after: Duration::from_millis(200),
            quiet_limit: Duration::from_secs(1),
            attempts: 3,
        }
    }

    const ALL: usize = usize::MAX;

    #[test]
    fn while_the_engine_checks_the_digests_the_stream_may_say_nothing_for_as_long_as_the_model_takes_to_read() {
        let quiet = Duration::from_secs(300);
        let mut stream = PullStream::default();
        let blob = |digest: &str, gb: u64| {
            format!(
                r#"{{"status":"pulling {digest}","digest":"{digest}","total":{},"completed":{}}}"#,
                gb << 30,
                gb << 30
            )
        };
        stream.line(&blob("sha256:a", 30), "big:70b").unwrap();
        stream.line(&blob("sha256:b", 10), "big:70b").unwrap();
        assert_eq!(stream.quiet_allowed(quiet), quiet, "a download is held to the bound");
        stream
            .line(r#"{"status":"verifying sha256 digest"}"#, "big:70b")
            .unwrap();
        assert_eq!(
            stream.quiet_allowed(quiet),
            Duration::from_secs((40 << 30) / (50 << 20))
        );
        stream.line(r#"{"status":"writing manifest"}"#, "big:70b").unwrap();
        assert_eq!(stream.quiet_allowed(quiet), quiet);
        let mut small = PullStream::default();
        small.line(&blob("sha256:c", 1), "small:1b").unwrap();
        small
            .line(r#"{"status":"verifying sha256 digest"}"#, "small:1b")
            .unwrap();
        assert_eq!(small.quiet_allowed(quiet), quiet, "a small model keeps the bound");
        // An attempt that ended while verifying does not lend its allowance to the next.
        stream
            .line(r#"{"status":"verifying sha256 digest"}"#, "big:70b")
            .unwrap();
        stream.begin_attempt();
        assert_eq!(
            stream.quiet_allowed(quiet),
            quiet,
            "a resumed attempt is held to the bound until it verifies"
        );
    }

    #[test]
    fn a_stream_that_ends_short_with_the_model_in_the_engine_has_ended_without_a_second_pull() {
        for then in [Then::End, Then::Break] {
            let (base, pulls) = engine(move |_| (100, then), Arc::new(Mutex::new(true)));
            let (progress, _) = told();
            HttpEngine::new()
                .with_pull_bounds(quick())
                .pull_ollama(&base, "qwen2.5:0.5b", &progress)
                .unwrap();
            assert_eq!(pulls.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn a_resumed_attempt_that_says_nothing_is_held_to_the_download_bound_not_the_digest_allowance() {
        // The first attempt verifies 10 GiB, which would allow minutes of silence, and breaks; the second says nothing.
        let (base, pulls) = engine(
            |n| {
                if n == 1 {
                    (0, Then::VerifyThenBreak)
                } else {
                    (0, Then::Hold)
                }
            },
            Arc::new(Mutex::new(false)),
        );
        let (progress, _) = told();
        let started = Instant::now();
        let err = HttpEngine::new()
            .with_pull_bounds(quick())
            .pull_ollama(&base, "big:70b", &progress)
            .unwrap_err();
        assert_eq!(pulls.load(Ordering::SeqCst), 2);
        assert!(matches!(&err, EngineError::Engine(m) if m.contains("stalled")), "{err}");
        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
    }

    #[test]
    fn an_engine_that_gives_up_on_an_attempt_is_asked_again() {
        let (base, pulls) = engine(
            |n| if n == 1 { (30, Then::Fail) } else { (ALL, Then::End) },
            Arc::new(Mutex::new(false)),
        );
        let (progress, _) = told();
        HttpEngine::new()
            .with_pull_bounds(quick())
            .pull_ollama(&base, "qwen2.5:0.5b", &progress)
            .unwrap();
        assert_eq!(pulls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_whole_stream_ends_the_pull_at_its_success() {
        let (base, pulls) = engine(|_| (ALL, Then::End), Arc::new(Mutex::new(false)));
        let (progress, seen) = told();
        HttpEngine::new()
            .with_pull_bounds(quick())
            .pull_ollama(&base, "qwen2.5:0.5b", &progress)
            .unwrap();
        assert_eq!(pulls.load(Ordering::SeqCst), 1);
        assert_eq!(seen.lock().unwrap().last(), Some(&99));
    }

    #[test]
    fn a_stream_that_goes_quiet_with_the_model_in_the_engine_has_ended() {
        // The engine finished, but the end of its stream never came: the host run of 2026-10-19 waited on that.
        let has = Arc::new(Mutex::new(false));
        let (base, pulls) = engine(|_| (100, Then::Hold), has.clone());
        let flip = has.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            *flip.lock().unwrap() = true;
        });
        let (progress, _) = told();
        let started = Instant::now();
        HttpEngine::new()
            .with_pull_bounds(quick())
            .pull_ollama(&base, "qwen2.5:0.5b", &progress)
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(pulls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_stream_quiet_past_the_bound_without_the_model_fails_and_says_it_stalled() {
        let (base, _) = engine(|_| (40, Then::Hold), Arc::new(Mutex::new(false)));
        let (progress, _) = told();
        let started = Instant::now();
        let err = HttpEngine::new()
            .with_pull_bounds(quick())
            .pull_ollama(&base, "qwen2.5:0.5b", &progress)
            .unwrap_err();
        assert!(
            matches!(&err, EngineError::Engine(m) if m.contains("said nothing of the pull") && m.contains("stalled")),
            "{err}"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_stream_that_breaks_is_resumed_and_the_share_goes_on_from_what_was_told() {
        let (base, pulls) = engine(
            |n| if n == 1 { (60, Then::Break) } else { (ALL, Then::End) },
            Arc::new(Mutex::new(false)),
        );
        let (progress, seen) = told();
        HttpEngine::new()
            .with_pull_bounds(quick())
            .pull_ollama(&base, "qwen2.5:0.5b", &progress)
            .unwrap();
        assert_eq!(pulls.load(Ordering::SeqCst), 2);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.last(), Some(&99));
        assert_eq!(
            seen.iter().filter(|p| **p == 0).count(),
            1,
            "the resumed stream is not told from 0 again: {seen:?}"
        );
    }

    #[test]
    fn a_stream_that_keeps_breaking_fails_after_its_attempts_with_the_reason() {
        let (base, pulls) = engine(|_| (20, Then::Break), Arc::new(Mutex::new(false)));
        let (progress, _) = told();
        let err = HttpEngine::new()
            .with_pull_bounds(quick())
            .pull_ollama(&base, "qwen2.5:0.5b", &progress)
            .unwrap_err();
        assert_eq!(pulls.load(Ordering::SeqCst), 3);
        assert!(
            matches!(&err, EngineError::Engine(m) if m.contains("did not complete in 3 attempts")),
            "{err}"
        );
    }
}
