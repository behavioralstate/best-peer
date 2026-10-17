//! [`Engine`] over the engines' own HTTP APIs. Ollama: `GET /` says it is up, `POST /api/pull` streams a model into
//! its library with progress. vLLM: `GET /health` answers once the model it was started with is loaded, and
//! `GET /v1/models` lists it. Every call is blocking I/O on a worker thread, never on the door's workers. Thin;
//! proven on a host by hand, never unit-tested.

use std::io::BufRead;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use best_peer_engine::{Engine, EngineError, Kind, Progress, Source};

#[derive(Clone)]
pub struct HttpEngine {
    agent: ureq::Agent,
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
        }
    }

    /// `POST /api/pull` on Ollama, one JSON line per progress step: `{ status, total?, completed? }`, the last one
    /// `{ status: "success" }`; an error line names the fault.
    fn pull_ollama(&self, base: &str, model: &str, progress: &Progress) -> Result<(), EngineError> {
        let mut res = self
            .agent
            .post(format!("{base}/api/pull"))
            .send_json(serde_json::json!({ "name": model, "stream": true }))
            .map_err(|e| match e {
                ureq::Error::StatusCode(404) => EngineError::ModelNotFound(model.into()),
                other => EngineError::Engine(other.to_string()),
            })?;
        let reader = std::io::BufReader::new(res.body_mut().as_reader());
        // Progress across every blob, not per blob: the engine reports each digest's own bytes.
        let mut blobs: std::collections::HashMap<String, (u64, u64)> = std::collections::HashMap::new();
        let mut last_pct: Option<u8> = None;
        let mut done = false;
        for line in reader.lines() {
            let line = line.map_err(|e| EngineError::Engine(format!("the pull stream broke: {e}")))?;
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
                continue;
            };
            if let Some(err) = v["error"].as_str() {
                return Err(if err.contains("not found") || err.contains("pull model manifest") {
                    EngineError::ModelNotFound(model.into())
                } else {
                    EngineError::Engine(err.into())
                });
            }
            if let (Some(digest), Some(c), Some(t)) =
                (v["digest"].as_str(), v["completed"].as_u64(), v["total"].as_u64())
            {
                if t > 0 {
                    blobs.insert(digest.to_string(), (c.min(t), t));
                }
            }
            let (done_bytes, total) = blobs.values().fold((0u64, 0u64), |(d, t), (c, bt)| (d + c, t + bt));
            if let Some(share) = (done_bytes * 100).checked_div(total) {
                let pct = Some(share.min(100) as u8);
                if pct != last_pct {
                    last_pct = pct;
                    progress(pct);
                }
            }
            if v["status"] == "success" {
                done = true;
            }
        }
        if done {
            Ok(())
        } else {
            Err(EngineError::Engine("the pull ended without success".into()))
        }
    }

    /// A model in Ollama's store is served without the registry: `POST /api/show` says whether it is there (404
    /// says not), and `POST /api/generate` with no prompt loads it into memory, so the deployment is ready to answer.
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
        self.agent
            .post(format!("{base}/api/generate"))
            .send_json(serde_json::json!({ "model": model, "stream": false }))
            .map_err(|e| EngineError::Engine(format!("the model is in the store but did not load: {e}")))?;
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
}
