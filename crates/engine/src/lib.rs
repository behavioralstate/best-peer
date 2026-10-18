//! The inference engine abstraction best-peer owns.
//!
//! A peer serves a model with an engine it did not write (Ollama, vLLM), running in a container the runtime started.
//! What to run for each engine is a [`Recipe`], pure data; what the engine is asked over its own API (is it up, make
//! this model present and tell the progress, answer a prompt) is [`Engine`], the one piece that talks to it. The
//! door's deploy and its prompt are written once against both and tested against [`Fake`]; the HTTP adapter is a
//! separate crate, proven on a host by hand, never unit-tested. The engine's API is the peer's internal matter: a
//! prompt reaches it as a command on the door and its answer leaves as an event, and nothing of the engine is on
//! the door.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use best_peer_gpu::Compute;
use best_peer_runtime::ImageRef;
use serde::{Deserialize, Serialize};

/// The engines a peer can serve a model with. The value an agent sends in `deploy-model`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Ollama,
    Vllm,
}

impl Kind {
    /// The compute APIs this engine can run on, best first; the version is open (any). A deploy fits a device
    /// offering one of these.
    pub fn runs_on(self) -> Vec<Compute> {
        match self {
            Kind::Ollama => vec![Compute::Cuda("0".into()), Compute::Rocm("0".into()), Compute::Cpu],
            Kind::Vllm => vec![Compute::Cuda("0".into())],
        }
    }

    /// Where the engine serves the OpenAI-compatible API, under its base.
    pub fn openai_path(self) -> &'static str {
        "/v1"
    }

    /// What to run to serve `model` on a device offering `compute`. The image may be overridden by the operator
    /// (`image`), for a pinned tag or a mirror; the engine's port and arguments are not negotiable.
    pub fn recipe(self, model: &str, compute: &Compute, image: Option<&str>) -> Recipe {
        match self {
            Kind::Ollama => Recipe {
                image: ImageRef(image.map(str::to_string).unwrap_or_else(|| match compute {
                    Compute::Rocm(_) => "ollama/ollama:rocm".into(),
                    _ => "ollama/ollama".into(),
                })),
                args: vec![],
                env: vec![("OLLAMA_HOST".into(), "0.0.0.0".into())],
                port: 11434,
                openai_path: "/v1".into(),
            },
            Kind::Vllm => Recipe {
                image: ImageRef(image.unwrap_or("vllm/vllm-openai").into()),
                args: vec!["--model".into(), model.into()],
                env: vec![],
                port: 8000,
                openai_path: "/v1".into(),
            },
        }
    }
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Kind::Ollama => "ollama",
            Kind::Vllm => "vllm",
        })
    }
}

/// What to run for one engine: the image, its arguments and environment, the container port it serves on, and the
/// path under which the OpenAI-compatible API is reached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recipe {
    pub image: ImageRef,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub port: u16,
    pub openai_path: String,
}

/// What a load tells while it runs: progress in percent, where the engine says. Called in order, before the call
/// returns, so the caller tells each step as a fact before the outcome.
pub type Progress = Arc<dyn Fn(Option<u8>) + Send + Sync>;

/// One turn of a conversation, as the engines take it: who said it and what.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: String,
}

/// What a prompt asks of the engine beyond the messages; absent means the engine's own default.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Options {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stop: Vec<String>,
}

/// The engine's answer to a prompt, whole: the text, the model that answered, why it stopped where the engine
/// says, and the token counts where the engine reports them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Answer {
    pub content: String,
    pub model: String,
    pub finish: Option<String>,
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("the engine at {base} did not answer within {within:?}")]
    NotReady { base: String, within: Duration },
    #[error("the engine has no model {0}")]
    ModelNotFound(String),
    #[error("the engine failed: {0}")]
    Engine(String),
}

/// What the door asks of a running engine, by the base URL (`http://host:port`) the runtime published.
#[async_trait]
pub trait Engine: Send + Sync {
    /// Waits until the engine at `base` answers, up to `within`.
    async fn ready(&self, kind: Kind, base: &str, within: Duration) -> Result<(), EngineError>;
    /// Makes `model` present and loaded in the engine at `base`, telling `progress` as it goes. An engine that
    /// loads its model at start answers once the model is served.
    async fn load(&self, kind: Kind, base: &str, model: &str, progress: Progress) -> Result<(), EngineError>;
    /// Frees the memory `model` holds in the engine at `base`, where the engine can do that without stopping; an
    /// engine that cannot answers Ok and its container's stop does it.
    async fn unload(&self, kind: Kind, base: &str, model: &str) -> Result<(), EngineError>;
    /// Asks `model` in the engine at `base` to answer `messages` with `options`, whole, within `within`: the one
    /// call that carries a conversation, so that nothing of the engine's API is on the door.
    async fn complete(
        &self,
        kind: Kind,
        base: &str,
        model: &str,
        messages: &[Message],
        options: &Options,
        within: Duration,
    ) -> Result<Answer, EngineError>;
}

/// An in-memory [`Engine`] for tests: every base is up unless a test says it is down, every model exists unless a
/// test says it does not, and a load tells progress the way a real pull would.
pub struct Fake {
    down: Mutex<Vec<String>>,
    missing: Mutex<Vec<String>>,
    loaded: Mutex<BTreeMap<String, Vec<String>>>,
    unloaded: Mutex<BTreeMap<String, Vec<String>>>,
    /// What a load reports as it goes; a real engine reports every percent, often more.
    steps: Vec<Option<u8>>,
    /// The prompts each base was asked, as they came.
    prompted: Mutex<BTreeMap<String, Vec<Prompted>>>,
}

/// One prompt a fake engine was asked: the model and the messages.
pub type Prompted = (String, Vec<Message>);

impl Default for Fake {
    fn default() -> Self {
        Self::new()
    }
}

impl Fake {
    pub fn new() -> Self {
        Self {
            down: Mutex::new(vec![]),
            missing: Mutex::new(vec![]),
            loaded: Mutex::new(BTreeMap::new()),
            unloaded: Mutex::new(BTreeMap::new()),
            steps: vec![Some(25), Some(100)],
            prompted: Mutex::new(BTreeMap::new()),
        }
    }

    /// The prompts the engine at `base` was asked, in order: the model and the messages of each.
    pub fn prompted_at(&self, base: &str) -> Vec<Prompted> {
        self.prompted.lock().unwrap().get(base).cloned().unwrap_or_default()
    }

    /// A fake whose load reports every percent from 0 to 100, as a real engine does.
    pub fn reporting_every_percent(mut self) -> Self {
        self.steps = (0..=100).map(Some).collect();
        self
    }

    /// Makes the engine at `base` never answer.
    pub fn down(&self, base: &str) {
        self.down.lock().unwrap().push(base.into());
    }

    /// Makes `model` one the engine's library does not have.
    pub fn missing(&self, model: &str) {
        self.missing.lock().unwrap().push(model.into());
    }

    /// The models loaded at `base`, in order.
    pub fn loaded_at(&self, base: &str) -> Vec<String> {
        self.loaded.lock().unwrap().get(base).cloned().unwrap_or_default()
    }

    /// The models unloaded at `base`, in order.
    pub fn unloaded_at(&self, base: &str) -> Vec<String> {
        self.unloaded.lock().unwrap().get(base).cloned().unwrap_or_default()
    }
}

#[async_trait]
impl Engine for Fake {
    async fn ready(&self, _kind: Kind, base: &str, within: Duration) -> Result<(), EngineError> {
        if self.down.lock().unwrap().iter().any(|d| d == base) {
            return Err(EngineError::NotReady {
                base: base.into(),
                within,
            });
        }
        Ok(())
    }

    async fn load(&self, _kind: Kind, base: &str, model: &str, progress: Progress) -> Result<(), EngineError> {
        if self.missing.lock().unwrap().iter().any(|m| m == model) {
            return Err(EngineError::ModelNotFound(model.into()));
        }
        for &step in &self.steps {
            progress(step);
        }
        self.loaded
            .lock()
            .unwrap()
            .entry(base.into())
            .or_default()
            .push(model.into());
        Ok(())
    }

    async fn unload(&self, _kind: Kind, base: &str, model: &str) -> Result<(), EngineError> {
        self.unloaded
            .lock()
            .unwrap()
            .entry(base.into())
            .or_default()
            .push(model.into());
        Ok(())
    }

    /// Answers with the last message echoed, so a test can see what reached the engine; a base said to be down
    /// fails as the engine would, a model said to be missing is not found. The counts are the words.
    async fn complete(
        &self,
        _kind: Kind,
        base: &str,
        model: &str,
        messages: &[Message],
        options: &Options,
        _within: Duration,
    ) -> Result<Answer, EngineError> {
        if self.down.lock().unwrap().iter().any(|d| d == base) {
            return Err(EngineError::Engine(format!("the engine at {base} did not answer")));
        }
        if self.missing.lock().unwrap().iter().any(|m| m == model) {
            return Err(EngineError::ModelNotFound(model.into()));
        }
        self.prompted
            .lock()
            .unwrap()
            .entry(base.into())
            .or_default()
            .push((model.into(), messages.to_vec()));
        let last = messages.last().map(|m| m.content.as_str()).unwrap_or("");
        let words = |t: &str| t.split_whitespace().count() as u64;
        let content = format!("fake answer to: {last}");
        let finish = if options.max_tokens.is_some_and(|m| u64::from(m) < words(&content)) {
            "length"
        } else {
            "stop"
        };
        Ok(Answer {
            content,
            model: model.into(),
            finish: Some(finish.into()),
            prompt_tokens: Some(messages.iter().map(|m| words(&m.content)).sum()),
            completion_tokens: Some(words(last) + 3),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_engine_says_what_to_run_and_where_its_api_is() {
        let o = Kind::Ollama.recipe("llama3.2:3b", &Compute::Cuda("12.4".into()), None);
        assert_eq!(o.image, ImageRef("ollama/ollama".into()));
        assert_eq!(o.port, 11434);
        assert!(o.env.contains(&("OLLAMA_HOST".into(), "0.0.0.0".into())));
        let r = Kind::Ollama.recipe("llama3.2:3b", &Compute::Rocm("6.2".into()), None);
        assert_eq!(r.image, ImageRef("ollama/ollama:rocm".into()));
        let pinned = Kind::Ollama.recipe("x", &Compute::Cpu, Some("mirror.local/ollama:0.12"));
        assert_eq!(pinned.image, ImageRef("mirror.local/ollama:0.12".into()));
        let v = Kind::Vllm.recipe("Qwen/Qwen2.5-0.5B", &Compute::Cuda("12.4".into()), None);
        assert_eq!(v.args, vec!["--model", "Qwen/Qwen2.5-0.5B"]);
        assert_eq!(v.port, 8000);
        assert_eq!(v.openai_path, "/v1");
        assert!(Kind::Vllm.runs_on().iter().all(|c| matches!(c, Compute::Cuda(_))));
        assert!(Kind::Ollama.runs_on().contains(&Compute::Cpu));
        assert_eq!(serde_json::to_value(Kind::Vllm).unwrap(), "vllm");
    }

    #[tokio::test]
    async fn the_fake_tells_progress_and_refuses_what_a_real_engine_would() {
        let e = Fake::new();
        e.ready(Kind::Ollama, "http://h:1", Duration::from_secs(1))
            .await
            .unwrap();
        let told = Arc::new(Mutex::new(Vec::new()));
        let sink = told.clone();
        e.load(
            Kind::Ollama,
            "http://h:1",
            "m",
            Arc::new(move |pct| sink.lock().unwrap().push(pct)),
        )
        .await
        .unwrap();
        assert_eq!(*told.lock().unwrap(), vec![Some(25), Some(100)]);
        assert_eq!(e.loaded_at("http://h:1"), vec!["m"]);
        e.down("http://h:2");
        assert!(matches!(
            e.ready(Kind::Ollama, "http://h:2", Duration::from_secs(1))
                .await
                .unwrap_err(),
            EngineError::NotReady { .. }
        ));
        e.missing("nobody/none");
        assert!(matches!(
            e.load(Kind::Ollama, "http://h:1", "nobody/none", Arc::new(|_| {}))
                .await
                .unwrap_err(),
            EngineError::ModelNotFound(m) if m == "nobody/none"
        ));
    }
}
