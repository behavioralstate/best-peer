//! The model lifecycle over the three abstractions: a deploy is placed on a device with the memory it asks for,
//! its image pulled, its container started, its engine made ready and its model loaded, each step a fact on the
//! stream with the command's correlation id; a job is an image run once; an undeploy and a stop end them. Progress
//! (a pull, the weights) is told to the handler as it happens and reaches the stream in order, before the outcome.
//! What the engine does on its own (exits, runs out of memory, fails) is forwarded from the runtime's events, under
//! the correlation id of the command that started the workload. The state is the fold of the facts, rebuilt from the
//! log at start and squared with what the engine still runs, then and on a timer.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use best_peer_door::auth::{holder_of_hash, Credential};
use best_peer_door::{BestError, Emitter, Envelope, EventLog};
use best_peer_engine::{Engine, EngineError, Kind, Message, Options, Source};
use best_peer_gpu::{Compute, DeviceId, Gpu, Host};
use best_peer_runtime::{Confinement, ContainerId, Event as RuntimeEvent, Mount, Runtime, RuntimeError, Spec};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::{broadcast, Semaphore};

use crate::domain::Service;
use crate::holdings::Holdings;
use crate::state::{JobPhase, Owner, Phase, Reservation, State};

/// The operator's say over the engines: their images (a pinned tag, a mirror; none means the engine's default), a
/// store of models (`BEST_PEER_MODEL_STORE`) beside the registry: a model found in it is served from it, seen
/// read-only, and nothing is pulled; one not found is pulled as before. And when a deploy or a job pulls its image.
#[derive(Clone, Debug, Default)]
pub struct Images {
    pub ollama: Option<String>,
    pub vllm: Option<String>,
    pub model_store: Option<String>,
    pub pull: Pull,
}

/// When a deploy or a job pulls its image: `Tags`, a reference by tag each time, since a tag may have moved, and one
/// pinned by digest only when it is not held; `Missing`, any image only when it is not held.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Pull {
    #[default]
    Tags,
    Missing,
}

impl Images {
    fn for_engine(&self, kind: Kind) -> Option<&str> {
        match kind {
            Kind::Ollama => self.ollama.as_deref(),
            Kind::Vllm => self.vllm.as_deref(),
        }
    }
}

/// How the containers are confined, as the operator set it. A job of a credential with a share runs code from a
/// tenant, so it gets the closed box: no network, no capabilities and a read-only filesystem, under ceilings on
/// host memory and tasks the operator sets (`BEST_PEER_JOB_MEMORY`, `BEST_PEER_JOB_PIDS`). Any other job, the
/// owner's or one whose credential was approved with `--open-jobs`, keeps the network, a writable filesystem and the
/// host's memory, under the same capability and privilege rules and the same task ceiling. An engine is confined as
/// an open job is, with its own ceilings (`BEST_PEER_ENGINE_MEMORY`, `BEST_PEER_ENGINE_PIDS`).
#[derive(Clone, Debug)]
pub struct Confine {
    pub job: Confinement,
    pub open_job: Confinement,
    pub engine: Confinement,
}

impl Default for Confine {
    fn default() -> Self {
        Self {
            job: Confinement::default(),
            open_job: Confinement::serving(),
            engine: Confinement::serving(),
        }
    }
}

/// Whether a job of `who` runs in the closed box: a credential with a share does, unless its approver opened it.
pub fn boxed(who: &Credential) -> bool {
    who.grant.memory_bytes.is_some() && !who.grant.open_jobs
}

/// How long the peer waits on an engine: to answer after its container started, to load a model, to unload one,
/// to answer a prompt.
#[derive(Clone, Copy, Debug)]
pub struct Patience {
    pub ready: Duration,
    pub load: Duration,
    pub unload: Duration,
    pub prompt: Duration,
}

impl Default for Patience {
    fn default() -> Self {
        Self {
            ready: Duration::from_secs(900),
            load: Duration::from_secs(3600),
            unload: Duration::from_secs(30),
            prompt: Duration::from_secs(600),
        }
    }
}

/// How often the state is squared with what the engine runs, for the exits the event feed may have missed.
const RECONCILE_EVERY: Duration = Duration::from_secs(30);

/// How many prompts a peer has in flight at once: each holds a blocking thread while the engine answers, and the
/// engines answer a few at a time anyway; the rest wait their turn, accepted, in order.
const PROMPTS_AT_ONCE: usize = 16;

/// The most runtime events kept for containers the state does not know yet: a job can exit before its start is
/// told, and its exit is replayed once it is.
const MAX_UNOWNED: usize = 64;

pub struct Peer {
    pub gpu: Arc<dyn Gpu>,
    pub runtime: Arc<dyn Runtime>,
    pub engine: Arc<dyn Engine>,
    pub log: Arc<EventLog>,
    service: String,
    dataschemas: Arc<HashMap<String, String>>,
    completions: Arc<HashMap<String, std::collections::HashSet<String>>>,
    /// The host the peer itself reaches the engines at: where the containers' ports are bound, on this machine.
    engine_host: String,
    images: Images,
    patience: Patience,
    confine: Confine,
    pub state: Mutex<State>,
    /// Runtime events for containers the state did not know when they arrived, by container.
    unowned: Mutex<HashMap<ContainerId, RuntimeEvent>>,
    /// The tasks that follow the engine, so a peer that stops stops hearing.
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    /// The turns to prompt the engines, `PROMPTS_AT_ONCE` of them.
    prompts: Semaphore,
    /// What a credential holds across the door, for its share: this peer's own promises and every workspace's.
    holdings: Arc<Holdings>,
}

#[derive(Deserialize)]
struct DeployData {
    model: String,
    engine: Kind,
    memory_bytes: u64,
    #[serde(default)]
    device: Option<String>,
}

#[derive(Deserialize)]
struct PromptData {
    deployment: String,
    messages: Vec<Message>,
    #[serde(default)]
    max_tokens: Option<u32>,
    #[serde(default)]
    temperature: Option<f64>,
    #[serde(default)]
    stop: Vec<String>,
}

#[derive(Deserialize)]
struct RunJobData {
    image: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    memory_bytes: Option<u64>,
    #[serde(default)]
    device: Option<String>,
}

/// Where a deploy stands when it fails: before its start was told, with the container to stop if one was started
/// anyway; or after, when the state holds it.
enum Stage {
    BeforeStart(Option<ContainerId>),
    AfterStart,
}

/// The compute APIs any job may run on: a job names an image, not an engine, so any device will do.
pub(crate) fn any_compute() -> Vec<Compute> {
    vec![
        Compute::Cuda("0".into()),
        Compute::Rocm("0".into()),
        Compute::OneApi("0".into()),
        Compute::Metal,
        Compute::Vulkan,
        Compute::Cpu,
    ]
}

impl Peer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint: &str,
        engine_host: &str,
        service: &str,
        gpu: Arc<dyn Gpu>,
        runtime: Arc<dyn Runtime>,
        engine: Arc<dyn Engine>,
        log: Arc<EventLog>,
        images: Images,
        patience: Patience,
        confine: Confine,
    ) -> Self {
        Self {
            gpu,
            runtime,
            engine,
            log,
            service: service.into(),
            dataschemas: Arc::new(crate::domain::event_dataschemas(endpoint)),
            completions: Arc::new(crate::domain::completions()),
            engine_host: engine_host.into(),
            images,
            patience,
            confine,
            state: Mutex::new(State::default()),
            unowned: Mutex::new(HashMap::new()),
            tasks: Mutex::new(Vec::new()),
            prompts: Semaphore::new(PROMPTS_AT_ONCE),
            holdings: Arc::new(Holdings::default()),
        }
    }

    /// Measures shares against the whole door's holdings, not this peer's alone.
    pub fn with_holdings(mut self, holdings: Arc<Holdings>) -> Self {
        self.holdings = holdings;
        self
    }

    /// Registers what this peer has promised with the door's holdings, so a share is counted across surfaces.
    pub fn register_holdings(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        self.holdings.add(move |holder| {
            weak.upgrade()
                .map(|p| p.state.lock().unwrap().holdings_of(holder))
                .unwrap_or_default()
        });
    }

    /// Folds every fact the log holds into the state, then squares it with the engine. Run once, before the door
    /// opens, with the runtime's events already subscribed so nothing told meanwhile is lost.
    pub async fn rebuild(&self) {
        {
            let mut state = self.state.lock().unwrap();
            self.log.replay(|e| state.apply(e));
        }
        self.reconcile(true).await;
    }

    /// Squares the state with what the engine runs: a workload whose container is gone ended while nobody watched,
    /// and is told so now; a container the peer started but never told (it died in between) is stopped. After a
    /// restart (`restarted`), a deployment still starting has no handler left to finish it, and is failed; on the
    /// timer and after a lag it is left to its handler.
    pub async fn reconcile(&self, restarted: bool) {
        let running = match self.runtime.running().await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "the engine could not be asked what runs: the state is the log's");
                return;
            }
        };
        let (deployments, jobs) = {
            let s = self.state.lock().unwrap();
            (
                s.deployments.values().cloned().collect::<Vec<_>>(),
                s.jobs.values().cloned().collect::<Vec<_>>(),
            )
        };
        for d in &deployments {
            let em = self.emitter(&d.correlation);
            let alive = running.contains(&d.container);
            match (alive, d.phase) {
                (true, Phase::Ready) | (true, Phase::Ending) => {}
                (true, Phase::Starting) if !restarted => {}
                (true, Phase::Starting) => {
                    self.fail_deployment(
                        &em,
                        &d.id,
                        &d.model,
                        "the peer restarted before the deployment was ready",
                        "deploy it again",
                        Stage::AfterStart,
                    )
                    .await
                }
                (false, phase) => {
                    if !self.claim_deployment(&d.id) {
                        continue;
                    }
                    // The engine may still hold the model (an engine outside any container): ask it to let go.
                    let _ = tokio::time::timeout(
                        self.patience.unload,
                        self.engine.unload(d.engine, &self.engine_base(d.port), &d.model),
                    )
                    .await;
                    if phase == Phase::Starting {
                        self.tell(
                            &em,
                            "DeploymentFailed",
                            json!({ "deployment": d.id, "model": d.model, "reason": "the container is not running and the deployment was not ready; its exit was not observed", "fix": "deploy it again" }),
                        );
                    } else {
                        self.tell(
                            &em,
                            "DeploymentEnded",
                            json!({ "deployment": d.id, "model": d.model, "exit_code": null, "reason": "the container is not running; its exit was not observed" }),
                        );
                    }
                }
            }
        }
        for j in &jobs {
            if !running.contains(&j.container) && self.job_running(&j.id) {
                self.tell(
                    &self.emitter(&j.correlation),
                    "JobFailed",
                    json!({ "job": j.id, "image": j.image.0, "reason": "the container is not running; its exit was not observed", "fix": "run it again" }),
                );
            }
        }
        let known: Vec<ContainerId> = deployments
            .iter()
            .map(|d| d.container.clone())
            .chain(jobs.iter().map(|j| j.container.clone()))
            .collect();
        for orphan in running.iter().filter(|c| !known.contains(c)) {
            if self.unowned.lock().unwrap().contains_key(orphan) {
                continue;
            }
            tracing::warn!(container = %orphan.0, "a container of this peer that no workload claims is stopped");
            if let Err(e) = self.runtime.stop(orphan).await {
                tracing::warn!(container = %orphan.0, error = %e, "the orphan could not be stopped");
            }
        }
    }

    /// Follows the runtime's events for as long as the peer runs, telling each as a fact under the correlation id
    /// of the command it belongs to, and squares the state with the engine on a timer.
    pub fn follow(self: &Arc<Self>, mut rx: broadcast::Receiver<RuntimeEvent>) {
        let me = self.clone();
        let listening = tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(e) => me.on_runtime(e).await,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(
                            missed = n,
                            "the engine's events outran the peer; squaring with the engine"
                        );
                        me.reconcile(false).await;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        let me = self.clone();
        let squaring = tokio::spawn(async move {
            loop {
                tokio::time::sleep(RECONCILE_EVERY).await;
                me.reconcile(false).await;
            }
        });
        self.tasks.lock().unwrap().extend([listening, squaring]);
    }

    /// Stops following the engine: what happens after this is told by the next peer over the same log.
    pub fn halt(&self) {
        for t in self.tasks.lock().unwrap().drain(..) {
            t.abort();
        }
    }

    pub fn emitter(&self, correlation: &str) -> Emitter {
        Emitter::new(self.log.clone(), &self.service, correlation, self.dataschemas.clone())
            .with_completions(self.completions.clone())
    }

    /// Tells a fact: appended to the log, then folded into the state. A fact about a workload, told by an emitter
    /// that speaks for no command, completes the command that made the workload when its type says so. Never
    /// called with the state locked.
    fn tell(&self, em: &Emitter, r#type: &str, data: Value) -> Envelope {
        let workload = data["deployment"].as_str().or(data["job"].as_str()).map(str::to_string);
        let e = em.emit(r#type, data);
        if let Some(w) = workload {
            em.completes_workload(&w, r#type);
        }
        self.state.lock().unwrap().apply(&e);
        e
    }

    pub async fn hardware(&self) -> Result<Host, BestError> {
        let gpu = self.gpu.clone();
        tokio::task::spawn_blocking(move || gpu.snapshot())
            .await
            .map_err(|e| BestError::internal(format!("the hardware query did not complete: {e}")))?
            .map_err(|e| BestError::internal(format!("the accelerator library failed: {e}")))
    }

    /// Where `model` comes from for `kind`: the operator's store when the engine reads one and the model is in it,
    /// the engine's registry otherwise.
    fn source(&self, kind: Kind, model: &str) -> Source {
        match (&self.images.model_store, kind) {
            (Some(store), Kind::Ollama) if in_store(std::path::Path::new(store), model) => Source::Store,
            _ => Source::Registry,
        }
    }

    /// The base URL the peer itself reaches an engine at.
    fn engine_base(&self, port: u16) -> String {
        format!("http://{}:{port}", self.engine_host)
    }

    // ----- prompt ---------------------------------------------------------------------------------------------------

    /// A prompt needs the prompt scope and a deployment that is ready and the caller's.
    pub fn admit_prompt(&self, cmd: Envelope, who: &Credential) -> Result<(), BestError> {
        require(who, "prompt")?;
        let id = cmd.data["deployment"].as_str().unwrap_or_default();
        ready_deployment(&self.state.lock().unwrap(), id, who).map(|_| ())
    }

    /// Asks the deployment's engine for the answer and tells it whole, under the command's correlation id; what the
    /// engine could not do is `PromptFailed` with the reason and the fix. The engine's API is reached here and
    /// nowhere else.
    pub async fn prompt(&self, cmd: Envelope, em: Emitter) {
        let data = match parse::<PromptData>(&cmd.data) {
            Ok(d) => d,
            Err(e) => {
                // Accepted by the schema and still not readable here: the outcome is told, never silence.
                self.tell(
                    &em,
                    "PromptFailed",
                    json!({ "deployment": cmd.data["deployment"], "reason": format!("the prompt could not be read: {}", e.message), "fix": "send it as the schema at the catalogue's dataschema for prompt describes" }),
                );
                return;
            }
        };
        let Some(d) = self.state.lock().unwrap().deployments.get(&data.deployment).cloned() else {
            self.tell(
                &em,
                "PromptFailed",
                json!({ "deployment": data.deployment, "reason": "the deployment ended between the prompt's admission and now", "fix": "deploy the model again, then prompt it" }),
            );
            return;
        };
        let options = Options {
            max_tokens: data.max_tokens,
            temperature: data.temperature,
            stop: data.stop,
        };
        let within = self.patience.prompt;
        // A turn: the engine is asked a few prompts at a time, the rest wait, accepted.
        let _turn = self.prompts.acquire().await;
        let asked = tokio::time::timeout(
            within,
            self.engine.complete(
                d.engine,
                &self.engine_base(d.port),
                &d.model,
                &data.messages,
                &options,
                within,
            ),
        )
        .await;
        match asked {
            Ok(Ok(a)) => self.tell(
                &em,
                "PromptAnswered",
                json!({ "deployment": d.id, "model": a.model, "content": a.content, "finish": a.finish, "prompt_tokens": a.prompt_tokens, "completion_tokens": a.completion_tokens }),
            ),
            Ok(Err(e)) => self.tell(
                &em,
                "PromptFailed",
                json!({ "deployment": d.id, "reason": e.to_string(), "fix": fix_for_engine(&e, Source::Registry) }),
            ),
            Err(_) => self.tell(
                &em,
                "PromptFailed",
                json!({ "deployment": d.id, "reason": format!("the engine did not answer within {within:?}"), "fix": "send a shorter conversation or a smaller max_tokens; if the engine is stuck, DeploymentEnded follows when it stops" }),
            ),
        };
    }

    // ----- pull-image -----------------------------------------------------------------------------------------------

    /// A pull is a deploy's first step and needs the same scope.
    pub fn admit_pull(&self, _cmd: Envelope, who: &Credential) -> Result<(), BestError> {
        require(who, "deploy")
    }

    pub async fn pull_image(self: Arc<Self>, cmd: Envelope, em: Emitter) {
        let image = best_peer_runtime::ImageRef(cmd.data["image"].as_str().unwrap_or_default().to_string());
        match self.pull(&em, &image).await {
            Ok(()) => {
                self.tell(&em, "ImagePulled", json!({ "image": image.0, "held": false }));
            }
            Err(e) => {
                self.tell(
                    &em,
                    "ImagePullFailed",
                    json!({ "image": image.0, "reason": e.to_string(), "fix": fix_for_runtime(&e) }),
                );
            }
        }
    }

    // ----- deploy-model ---------------------------------------------------------------------------------------------

    pub async fn admit_deploy(&self, cmd: Envelope, who: Credential, key: String) -> Result<(), BestError> {
        require(&who, "deploy")?;
        let data: DeployData = parse(&cmd.data)?;
        let host = self.hardware().await?;
        // One admission at a time across the door, and what the credential holds is read before the state is
        // locked, since the door's holdings read this state too.
        let _admitting = self.holdings.admitting();
        let held = self.holdings.of(&who.holder());
        let mut state = self.state.lock().unwrap();
        within_share(held.memory_bytes, &who, data.memory_bytes)?;
        within_count("deployment", held.deployments, who.grant.deployments)?;
        let (device, compute) = place(
            &host,
            &state,
            &data.engine.runs_on(),
            data.memory_bytes,
            data.device.as_deref(),
            &format!("{} on {}", data.model, data.engine),
            mine(&who).as_deref(),
        )?;
        state.reserved.insert(
            key,
            Reservation {
                id: new_id("dep"),
                device: Some(device),
                compute: Some(compute),
                memory_bytes: data.memory_bytes,
                holder: who.holder(),
                boxed: false,
            },
        );
        Ok(())
    }

    pub async fn deploy(self: Arc<Self>, cmd: Envelope, em: Emitter) {
        let Ok(data) = parse::<DeployData>(&cmd.data) else {
            return;
        };
        let reservation = self.state.lock().unwrap().reserved.get(em.command_key()).cloned();
        let Some(Reservation {
            id,
            device: Some(device),
            compute: Some(compute),
            holder,
            ..
        }) = reservation
        else {
            self.tell(
                &em,
                "CommandFailed",
                json!({ "type": cmd.r#type, "reason": "the command was accepted but its placement is gone; send it again" }),
            );
            return;
        };
        let mut recipe = data
            .engine
            .recipe(&data.model, &compute, self.images.for_engine(data.engine));
        let source = self.source(data.engine, &data.model);
        let mut mounts = Vec::new();
        if let (Source::Store, Some(store), Some(at)) = (source, &self.images.model_store, &recipe.store) {
            recipe.env.extend(at.env.iter().cloned());
            mounts.push(Mount {
                host: store.clone(),
                container: at.path.clone(),
                read_only: true,
            });
        }
        let image = recipe.image.clone();
        let held = match self.ensure(&em, &image).await {
            Ok(held) => held,
            Err(e) => {
                self.fail_deployment(
                    &em,
                    &id,
                    &data.model,
                    &e.to_string(),
                    fix_for_runtime(&e),
                    Stage::BeforeStart(None),
                )
                .await;
                return;
            }
        };
        self.tell(&em, "ImagePulled", json!({ "image": image.0, "held": held }));
        let spec = Spec {
            image,
            args: recipe.args,
            env: recipe.env,
            devices: if compute == Compute::Cpu {
                vec![]
            } else {
                vec![device.clone()]
            },
            ports: vec![recipe.port],
            mounts,
            confinement: self.confine.engine.clone(),
        };
        let started = match self.runtime.start(spec).await {
            Ok(s) => s,
            Err(e) => {
                self.fail_deployment(
                    &em,
                    &id,
                    &data.model,
                    &e.to_string(),
                    fix_for_runtime(&e),
                    Stage::BeforeStart(None),
                )
                .await;
                return;
            }
        };
        let Some(port) = started
            .ports
            .iter()
            .find(|p| p.container == recipe.port)
            .map(|p| p.host)
        else {
            self.fail_deployment(
                &em,
                &id,
                &data.model,
                &format!("the engine published no host port for container port {}", recipe.port),
                "read the container engine's logs on the host",
                Stage::BeforeStart(Some(started.id)),
            )
            .await;
            return;
        };
        self.tell(
            &em,
            "DeploymentStarted",
            json!({ "deployment": id, "model": data.model, "engine": data.engine, "device": device.0, "memory_bytes": data.memory_bytes, "container": started.id.0, "port": port, "holder": holder }),
        );
        em.bind_workload(&id);
        self.replay_unowned(&started.id).await;
        let base = self.engine_base(port);
        let loading: best_peer_engine::Progress = {
            let (me, em, id, model, pace) = (
                self.clone(),
                em.clone(),
                id.clone(),
                data.model.clone(),
                Pace::default(),
            );
            Arc::new(move |pct| {
                if pace.due(pct) {
                    me.tell(
                        &em,
                        "WeightsLoading",
                        json!({ "deployment": id, "model": model, "progress_pct": pct }),
                    );
                }
            })
        };
        let outcome = async {
            self.engine.ready(data.engine, &base, self.patience.ready).await?;
            let loaded = tokio::time::timeout(
                self.patience.load,
                self.engine
                    .load(data.engine, &base, &data.model, source, loading.clone()),
            )
            .await
            .unwrap_or_else(|_| {
                Err(EngineError::Engine(format!(
                    "the model was not loaded within {:?}",
                    self.patience.load
                )))
            });
            // A model that loaded is at 100, whether or not the engine said so on the way.
            if loaded.is_ok() {
                loading(Some(100));
            }
            loaded
        }
        .await;
        match outcome {
            Ok(()) if self.phase_of(&id) == Some(Phase::Starting) => {
                self.tell(
                    &em,
                    "DeploymentReady",
                    json!({ "deployment": id, "model": data.model, "engine": data.engine }),
                );
            }
            Ok(()) => {}
            Err(e) => {
                self.fail_deployment(
                    &em,
                    &id,
                    &data.model,
                    &e.to_string(),
                    &fix_for_engine(&e, source),
                    Stage::AfterStart,
                )
                .await
            }
        }
    }

    /// Makes an image present for a deploy or a job. A reference by tag is pulled each time unless the operator said
    /// `missing`, since a tag may have moved; one pinned by digest, or any under `missing`, is not pulled when the
    /// engine holds it, so a host with no way to a registry runs what it holds, told at 100 at once. Says whether it
    /// was held.
    async fn ensure(self: &Arc<Self>, em: &Emitter, image: &best_peer_runtime::ImageRef) -> Result<bool, RuntimeError> {
        let pinned = image.0.contains('@');
        if (pinned || self.images.pull == Pull::Missing) && self.runtime.holds(image).await? {
            self.pulling(em, image)(Some(100));
            return Ok(true);
        }
        self.pull(em, image).await.map(|()| false)
    }

    /// Pulls an image from the registry, held or not, telling its progress; a pull that completed is 100, whether or
    /// not the engine said so. What pull-image does, so that is how a held image is refreshed.
    async fn pull(self: &Arc<Self>, em: &Emitter, image: &best_peer_runtime::ImageRef) -> Result<(), RuntimeError> {
        let progress = self.pulling(em, image);
        self.runtime.pull(image, progress.clone()).await?;
        progress(Some(100));
        Ok(())
    }

    /// The progress sink of a pull: ImagePulling facts under the command's correlation, at the pace a consumer reads.
    fn pulling(self: &Arc<Self>, em: &Emitter, image: &best_peer_runtime::ImageRef) -> best_peer_runtime::Progress {
        let (me, em, image, pace) = (self.clone(), em.clone(), image.0.clone(), Pace::default());
        Arc::new(move |pct| {
            if pace.due(pct) {
                me.tell(&em, "ImagePulling", json!({ "image": image, "progress_pct": pct }));
            }
        })
    }

    fn phase_of(&self, deployment: &str) -> Option<Phase> {
        self.state.lock().unwrap().deployments.get(deployment).map(|d| d.phase)
    }

    /// Tells that a deployment failed, after its container is stopped when it has one, so the fact is true when
    /// told. After its start was told, a deployment the state no longer holds, or already ending, has told or
    /// will tell its own end: nothing is said twice.
    async fn fail_deployment(&self, em: &Emitter, id: &str, model: &str, reason: &str, fix: &str, stage: Stage) {
        let container = match stage {
            Stage::BeforeStart(c) => c,
            Stage::AfterStart => {
                if !self.claim_deployment(id) {
                    return;
                }
                self.state
                    .lock()
                    .unwrap()
                    .deployments
                    .get(id)
                    .map(|d| d.container.clone())
            }
        };
        let mut reason = reason.to_string();
        if let Some(c) = container {
            if let Err(e) = self.runtime.stop(&c).await {
                reason = format!("{reason}; its container {} could not be stopped: {e}", c.0);
            }
        }
        self.tell(
            em,
            "DeploymentFailed",
            json!({ "deployment": id, "model": model, "reason": reason, "fix": fix }),
        );
    }

    // ----- undeploy-model -------------------------------------------------------------------------------------------

    /// Admits an undeploy and claims the deployment at once, so a second undeploy admitted before the first ran is
    /// refused rather than told twice.
    pub fn admit_undeploy(&self, cmd: Envelope, who: &Credential) -> Result<(), BestError> {
        require(who, "deploy")?;
        let id = cmd.data["deployment"].as_str().unwrap_or_default();
        let mut s = self.state.lock().unwrap();
        let live: Vec<String> = s
            .deployments
            .values()
            .filter(|d| who.grant.is_all() || d.holder == who.holder())
            .map(|d| d.id.clone())
            .collect();
        match s.deployments.get_mut(id) {
            None => Err(BestError::bad_request(
                "NO_SUCH_DEPLOYMENT",
                format!(
                    "no deployment {id}: the live ones are {}; get-workloads lists them",
                    list(live.iter())
                ),
            )
            .with_details(json!({ "deployment": id, "live": live }))),
            Some(d) if !who.grant.is_all() && d.holder != who.holder() => Err(not_yours("deployment", id)),
            Some(d) if d.phase == Phase::Ending => Err(BestError::bad_request(
                "ALREADY_ENDING",
                format!("deployment {id} is already ending: its Undeployed or DeploymentFailed event follows"),
            )
            .with_details(json!({ "deployment": id }))),
            Some(d) => {
                d.phase = Phase::Ending;
                Ok(())
            }
        }
    }

    pub async fn undeploy(&self, cmd: Envelope, em: Emitter) {
        let id = cmd.data["deployment"].as_str().unwrap_or_default().to_string();
        // Ended by itself between admission and now: it is not deployed, and that is what this command asked for.
        let Some(d) = self.state.lock().unwrap().deployments.get(&id).cloned() else {
            self.tell(&em, "Undeployed", json!({ "deployment": id, "model": null }));
            return;
        };
        // The engine frees the model's memory where it can; an engine that cannot is ended with its container.
        if d.ready {
            match tokio::time::timeout(
                self.patience.unload,
                self.engine.unload(d.engine, &self.engine_base(d.port), &d.model),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    tracing::warn!(deployment = %id, error = %e, "the engine did not unload the model; its container is stopped next")
                }
                Err(_) => {
                    tracing::warn!(deployment = %id, "the engine did not answer the unload in time; its container is stopped next")
                }
            }
        }
        match self.runtime.stop(&d.container).await {
            Ok(()) | Err(RuntimeError::NoSuchContainer(_)) => {
                if !d.ready {
                    // Undeployed before it was ready: the deploy's outcome is that it did not get there.
                    self.tell(
                        &self.emitter(&d.correlation),
                        "DeploymentFailed",
                        json!({ "deployment": id, "model": d.model, "reason": "undeployed before the deployment was ready", "fix": "deploy it again if it is still wanted" }),
                    );
                }
                self.tell(&em, "Undeployed", json!({ "deployment": id, "model": d.model }));
            }
            Err(e) => {
                if let Some(d) = self.state.lock().unwrap().deployments.get_mut(&id) {
                    d.phase = if d.ready { Phase::Ready } else { Phase::Starting };
                }
                self.tell(
                    &em,
                    "CommandFailed",
                    json!({ "type": cmd.r#type, "reason": format!("{e}; the deployment stays: {}", fix_for_runtime(&e)) }),
                );
            }
        }
    }

    // ----- run-job --------------------------------------------------------------------------------------------------

    pub async fn admit_run_job(&self, cmd: Envelope, who: Credential, key: String) -> Result<(), BestError> {
        require(&who, "jobs")?;
        if !self.runtime.runs_jobs() {
            return Err(BestError::bad_request(
                "NO_CONTAINER_ENGINE",
                "no container engine on this host: a job needs Docker (BEST_PEER_RUNTIME=docker); this peer deploys to an engine already installed, and serves no job",
            ));
        }
        let data: RunJobData = parse(&cmd.data)?;
        if data.device.is_some() && data.memory_bytes.is_none() {
            return Err(BestError::bad_request(
                "DEVICE_NEEDS_MEMORY",
                "device names a device but memory_bytes is missing: send memory_bytes with it, or omit device to run with none",
            )
            .with_details(json!({ "field": "memory_bytes" })));
        }
        if has_share(&who) && data.memory_bytes.is_none() {
            return Err(BestError::bad_request(
                "JOB_NEEDS_DEVICE",
                "this credential has a share, so its jobs run on a device, where the share counts them, never on the host with no device: send memory_bytes, the device memory the job needs",
            )
            .with_details(json!({ "field": "memory_bytes" })));
        }
        let host = match data.memory_bytes {
            Some(_) => Some(self.hardware().await?),
            None => None,
        };
        let _admitting = self.holdings.admitting();
        let held = self.holdings.of(&who.holder());
        let mut state = self.state.lock().unwrap();
        within_share(held.memory_bytes, &who, data.memory_bytes.unwrap_or(0))?;
        within_count("job", held.jobs, who.grant.jobs)?;
        let placement = match (data.memory_bytes, &host) {
            (Some(needed), Some(host)) => Some(place(
                host,
                &state,
                &any_compute(),
                needed,
                data.device.as_deref(),
                &format!("a job from {}", data.image),
                mine(&who).as_deref(),
            )?),
            _ => None,
        };
        state.reserved.insert(
            key,
            Reservation {
                id: new_id("job"),
                device: placement.as_ref().map(|(d, _)| d.clone()),
                compute: placement.map(|(_, c)| c),
                memory_bytes: data.memory_bytes.unwrap_or(0),
                holder: who.holder(),
                boxed: boxed(&who),
            },
        );
        Ok(())
    }

    pub async fn run_job(self: Arc<Self>, cmd: Envelope, em: Emitter) {
        let Ok(data) = parse::<RunJobData>(&cmd.data) else {
            return;
        };
        let Some(reservation) = self.state.lock().unwrap().reserved.get(em.command_key()).cloned() else {
            self.tell(
                &em,
                "CommandFailed",
                json!({ "type": cmd.r#type, "reason": "the command was accepted but its placement is gone; send it again" }),
            );
            return;
        };
        let id = reservation.id.clone();
        let image = best_peer_runtime::ImageRef(data.image.clone());
        let fail = |reason: String, fix: &str| {
            self.tell(
                &em,
                "JobFailed",
                json!({ "job": id, "image": data.image, "reason": reason, "fix": fix }),
            );
        };
        let held = match self.ensure(&em, &image).await {
            Ok(held) => held,
            Err(e) => {
                fail(e.to_string(), fix_for_runtime(&e));
                return;
            }
        };
        self.tell(&em, "ImagePulled", json!({ "image": image.0, "held": held }));
        let devices = match (&reservation.device, &reservation.compute) {
            (Some(d), Some(c)) if *c != Compute::Cpu => vec![d.clone()],
            _ => vec![],
        };
        let spec = Spec {
            image,
            args: data.args.clone(),
            env: vec![],
            devices,
            ports: vec![],
            mounts: vec![],
            confinement: match reservation.boxed {
                true => self.confine.job.clone(),
                false => self.confine.open_job.clone(),
            },
        };
        let host_memory_bytes = match reservation.boxed {
            true => self.confine.job.memory_bytes,
            false => self.confine.open_job.memory_bytes,
        };
        match self.runtime.start(spec).await {
            Ok(started) => {
                self.tell(
                    &em,
                    "JobStarted",
                    json!({ "job": id, "image": data.image, "device": reservation.device.as_ref().map(|d| d.0.clone()), "memory_bytes": reservation.memory_bytes, "container": started.id.0, "holder": reservation.holder, "boxed": reservation.boxed, "host_memory_bytes": host_memory_bytes }),
                );
                em.bind_workload(&id);
                self.replay_unowned(&started.id).await;
            }
            Err(e) => fail(e.to_string(), fix_for_runtime(&e)),
        }
    }

    // ----- stop-job -------------------------------------------------------------------------------------------------

    /// Admits a stop and claims the job at once, so a second stop admitted before the first ran is refused rather
    /// than told twice.
    pub fn admit_stop_job(&self, cmd: Envelope, who: &Credential) -> Result<(), BestError> {
        require(who, "jobs")?;
        let id = cmd.data["job"].as_str().unwrap_or_default();
        let mut s = self.state.lock().unwrap();
        let running: Vec<String> = s
            .jobs
            .values()
            .filter(|j| who.grant.is_all() || j.holder == who.holder())
            .map(|j| j.id.clone())
            .collect();
        match s.jobs.get_mut(id) {
            None => Err(BestError::bad_request(
                "NO_SUCH_JOB",
                format!(
                    "no job {id} is running: the running ones are {}; get-workloads lists them",
                    list(running.iter())
                ),
            )
            .with_details(json!({ "job": id, "running": running }))),
            Some(j) if !who.grant.is_all() && j.holder != who.holder() => Err(not_yours("job", id)),
            Some(j) if j.phase == JobPhase::Stopping => Err(BestError::bad_request(
                "ALREADY_STOPPING",
                format!("job {id} is already stopping: its JobStopped event follows"),
            )
            .with_details(json!({ "job": id }))),
            Some(j) => {
                j.phase = JobPhase::Stopping;
                Ok(())
            }
        }
    }

    pub async fn stop_job(&self, cmd: Envelope, em: Emitter) {
        let id = cmd.data["job"].as_str().unwrap_or_default().to_string();
        let container = self.state.lock().unwrap().jobs.get(&id).map(|j| j.container.clone());
        let stopped = match &container {
            Some(c) => self.runtime.stop(c).await,
            // Ended by itself between admission and now: it is not running, and that is what was asked.
            None => Ok(()),
        };
        match stopped {
            Ok(()) | Err(RuntimeError::NoSuchContainer(_)) => {
                self.tell(&em, "JobStopped", json!({ "job": id }));
            }
            Err(e) => {
                if let Some(j) = self.state.lock().unwrap().jobs.get_mut(&id) {
                    j.phase = JobPhase::Running;
                }
                self.tell(
                    &em,
                    "CommandFailed",
                    json!({ "type": cmd.r#type, "reason": format!("{e}; the job keeps running: {}", fix_for_runtime(&e)) }),
                );
            }
        }
    }

    // ----- what the engine says on its own --------------------------------------------------------------------------

    async fn on_runtime(&self, e: RuntimeEvent) {
        let container = match &e {
            RuntimeEvent::Exited { id, .. } | RuntimeEvent::OutOfMemory { id } | RuntimeEvent::Failed { id, .. } => {
                id.clone()
            }
            RuntimeEvent::Started { .. } => return,
        };
        let Some((owner, em)) = self.owner_of(&container) else {
            // Not ours yet: a job can exit before its start is told. Kept, and replayed once it is.
            let mut unowned = self.unowned.lock().unwrap();
            if unowned.len() >= MAX_UNOWNED {
                let oldest = unowned.keys().next().cloned();
                if let Some(k) = oldest {
                    unowned.remove(&k);
                }
            }
            unowned.insert(container, e);
            return;
        };
        match (e, owner) {
            (RuntimeEvent::Exited { code, .. }, Owner::Deployment(dep)) => {
                if self.claim_deployment(&dep.id) {
                    self.tell(
                        &em,
                        "DeploymentEnded",
                        json!({ "deployment": dep.id, "model": dep.model, "exit_code": code, "reason": "the container exited by itself" }),
                    );
                }
            }
            (RuntimeEvent::Exited { code, .. }, Owner::Job(job)) => {
                if self.job_running(&job) {
                    self.tell(&em, "JobFinished", json!({ "job": job, "exit_code": code }));
                }
            }
            (RuntimeEvent::OutOfMemory { .. }, Owner::Deployment(dep)) => {
                if self.claim_deployment(&dep.id) {
                    // The engine said the device ran out, not that the container died: it is stopped so the memory
                    // the fact releases is really free.
                    if let Err(e) = self.runtime.stop(&dep.container).await {
                        tracing::warn!(container = %dep.container.0, error = %e, "the out-of-memory container could not be stopped");
                    }
                    let fix = match self.confine.engine.memory_bytes {
                        Some(ceiling) => format!("deploy a smaller model, or ask for more memory_bytes so it is placed where it fits; an engine may also hold {ceiling} bytes of host memory at most, which whoever runs the peer sets"),
                        None => "deploy a smaller model, or ask for more memory_bytes so it is placed where it fits".to_string(),
                    };
                    self.tell(
                        &em,
                        "OutOfMemory",
                        json!({ "deployment": dep.id, "model": dep.model, "device": dep.device.0, "memory_bytes": dep.memory_bytes, "fix": fix }),
                    );
                }
            }
            (RuntimeEvent::OutOfMemory { id }, Owner::Job(job)) => {
                if self.job_running(&job) {
                    let _ = self.runtime.stop(&id).await;
                    // The container's own memory ran out, the host's and not the device's: memory_bytes does not move it.
                    let ceiling = self
                        .state
                        .lock()
                        .unwrap()
                        .jobs
                        .get(&job)
                        .and_then(|j| j.host_memory_bytes);
                    let (reason, fix) = match ceiling {
                        Some(ceiling) => (
                            format!("out of host memory: a job holds {ceiling} bytes of host memory at most on this peer, device memory apart"),
                            "hold less in host memory (fewer loader workers, smaller batches, weights streamed to the device), or ask whoever runs the peer to raise the ceiling".to_string(),
                        ),
                        None => (
                            "out of host memory: the host had no more to give".to_string(),
                            "hold less in host memory (fewer loader workers, smaller batches, weights streamed to the device)".to_string(),
                        ),
                    };
                    self.tell(
                        &em,
                        "JobFailed",
                        json!({ "job": job, "reason": reason, "host_memory_bytes": ceiling, "fix": fix }),
                    );
                }
            }
            (RuntimeEvent::Failed { reason, .. }, Owner::Deployment(dep)) => {
                if self.claim_deployment(&dep.id) {
                    if dep.ready {
                        // The deploy's outcome stands; what it made has ended, and that is the deployment's own fact.
                        self.tell(
                            &em,
                            "DeploymentEnded",
                            json!({ "deployment": dep.id, "model": dep.model, "exit_code": null, "reason": reason }),
                        );
                    } else {
                        self.tell(
                            &em,
                            "DeploymentFailed",
                            json!({ "deployment": dep.id, "model": dep.model, "reason": reason, "fix": "read the container's logs on the host" }),
                        );
                    }
                }
            }
            (RuntimeEvent::Failed { reason, .. }, Owner::Job(job)) => {
                if self.job_running(&job) {
                    self.tell(
                        &em,
                        "JobFailed",
                        json!({ "job": job, "reason": reason, "fix": "read the container's logs on the host" }),
                    );
                }
            }
            (RuntimeEvent::Started { .. }, _) => {}
        }
    }

    /// Replays the runtime events that arrived for `container` before its start was told.
    async fn replay_unowned(&self, container: &ContainerId) {
        let kept = self.unowned.lock().unwrap().remove(container);
        if let Some(e) = kept {
            self.on_runtime(e).await;
        }
    }

    /// Marks a deployment as ending for the fact about to be told, unless it is already ending or gone, in which
    /// case the fact was or will be told by whoever claimed it.
    fn claim_deployment(&self, id: &str) -> bool {
        let mut s = self.state.lock().unwrap();
        match s.deployments.get_mut(id) {
            Some(d) if d.phase != Phase::Ending => {
                d.phase = Phase::Ending;
                true
            }
            _ => false,
        }
    }

    /// Who a container belongs to, with the emitter of the command that started it.
    fn owner_of(&self, container: &ContainerId) -> Option<(Owner, Emitter)> {
        let s = self.state.lock().unwrap();
        match s.by_container(container)? {
            Owner::Deployment(d) => {
                let em = self.emitter(&d.correlation);
                Some((Owner::Deployment(d), em))
            }
            Owner::Job(id) => {
                let j = s.jobs.get(&id)?;
                Some((Owner::Job(id), self.emitter(&j.correlation)))
            }
        }
    }

    fn job_running(&self, id: &str) -> bool {
        self.state
            .lock()
            .unwrap()
            .jobs
            .get(id)
            .is_some_and(|j| j.phase == JobPhase::Running)
    }

    /// `get-workloads`: what is deployed and what runs, now.
    pub fn workloads(&self, who: &Credential) -> Result<Value, BestError> {
        let held = self.holdings.held_by(&who.holder());
        let mut v = workloads_view(&self.state.lock().unwrap(), who, None);
        v["held_bytes"] = json!(held);
        Ok(v)
    }
}

#[async_trait]
impl Service for Peer {
    async fn hardware_state(&self) -> Result<Value, BestError> {
        Ok(crate::domain::host_state(&self.hardware().await?))
    }

    fn workloads(&self, who: &Credential) -> Result<Value, BestError> {
        Peer::workloads(self, who)
    }

    fn admit_pull(&self, cmd: Envelope, who: &Credential) -> Result<(), BestError> {
        Peer::admit_pull(self, cmd, who)
    }

    async fn pull_image(self: Arc<Self>, cmd: Envelope, em: Emitter) {
        Peer::pull_image(self, cmd, em).await
    }

    async fn admit_deploy(&self, cmd: Envelope, who: Credential, key: String) -> Result<(), BestError> {
        Peer::admit_deploy(self, cmd, who, key).await
    }

    async fn deploy(self: Arc<Self>, cmd: Envelope, em: Emitter) {
        Peer::deploy(self, cmd, em).await
    }

    fn admit_undeploy(&self, cmd: Envelope, who: &Credential) -> Result<(), BestError> {
        Peer::admit_undeploy(self, cmd, who)
    }

    async fn undeploy(self: Arc<Self>, cmd: Envelope, em: Emitter) {
        Peer::undeploy(&self, cmd, em).await
    }

    async fn admit_run_job(&self, cmd: Envelope, who: Credential, key: String) -> Result<(), BestError> {
        Peer::admit_run_job(self, cmd, who, key).await
    }

    async fn run_job(self: Arc<Self>, cmd: Envelope, em: Emitter) {
        Peer::run_job(self, cmd, em).await
    }

    fn admit_stop_job(&self, cmd: Envelope, who: &Credential) -> Result<(), BestError> {
        Peer::admit_stop_job(self, cmd, who)
    }

    async fn stop_job(self: Arc<Self>, cmd: Envelope, em: Emitter) {
        Peer::stop_job(&self, cmd, em).await
    }

    fn admit_prompt(&self, cmd: Envelope, who: &Credential) -> Result<(), BestError> {
        Peer::admit_prompt(self, cmd, who)
    }

    async fn prompt(self: Arc<Self>, cmd: Envelope, em: Emitter) {
        Peer::prompt(&self, cmd, em).await
    }
}

/// The deployment `id` while it is ready and the caller's to prompt; otherwise the refusal at ingest that says what
/// to do.
pub(crate) fn ready_deployment<'a>(
    state: &'a State,
    id: &str,
    who: &Credential,
) -> Result<&'a crate::state::Deployment, BestError> {
    let Some(d) = state.deployments.get(id) else {
        return Err(BestError::bad_request(
            "NO_SUCH_DEPLOYMENT",
            format!("no deployment {id}: get-workloads lists what this peer runs for you, and deploy-model starts one"),
        )
        .with_details(json!({ "deployment": id })));
    };
    if !who.grant.is_all() && d.holder != who.holder() {
        return Err(not_yours("deployment", id));
    }
    match d.phase {
        Phase::Ready => Ok(d),
        Phase::Starting => Err(BestError::bad_request(
            "DEPLOYMENT_NOT_READY",
            format!("deployment {id} is not ready yet: follow its events to DeploymentReady, then prompt it"),
        )
        .with_details(json!({ "deployment": id }))),
        Phase::Ending => Err(BestError::bad_request(
            "DEPLOYMENT_ENDING",
            format!(
                "deployment {id} is ending: an undeploy was accepted; deploy the model again if it is still wanted"
            ),
        )
        .with_details(json!({ "deployment": id }))),
    }
}

/// `get-workloads`' body: what `state` holds for `who`, each row with the `cloud` when the state is a cloud's.
/// `held_bytes` is this state's alone; a door with more than one surface puts the whole door's in.
pub(crate) fn workloads_view(s: &State, who: &Credential, cloud: Option<&str>) -> Value {
    let mine = |holder: &str| who.grant.is_all() || holder == who.holder();
    let with_cloud = |mut row: Value| {
        if let Some(c) = cloud {
            row["cloud"] = json!(c);
        }
        row
    };
    let deployments: Vec<Value> = s
        .deployments
        .values()
        .filter(|d| mine(&d.holder))
        .map(|d| {
            with_cloud(json!({
                "deployment": d.id, "model": d.model, "engine": d.engine, "device": d.device.0,
                "memory_bytes": d.memory_bytes, "holder": d.holder, "peer": d.peer,
                "phase": match d.phase { Phase::Starting => "starting", Phase::Ready => "ready", Phase::Ending => "ending" }
            }))
        })
        .collect();
    let jobs: Vec<Value> = s
        .jobs
        .values()
        .filter(|j| mine(&j.holder))
        .map(|j| {
            with_cloud(json!({
                "job": j.id, "image": j.image.0, "device": j.device.as_ref().map(|d| d.0.clone()),
                "memory_bytes": j.memory_bytes, "holder": j.holder, "peer": j.peer,
                "phase": match j.phase { JobPhase::Running => "running", JobPhase::Stopping => "stopping" }
            }))
        })
        .collect();
    json!({ "deployments": deployments, "jobs": jobs, "held_bytes": s.held_by(&who.holder()), "share_bytes": who.grant.memory_bytes })
}

/// A credential that may not use `scope` is refused with what it was approved for and what to do.
pub(crate) fn require(who: &Credential, scope: &str) -> Result<(), BestError> {
    if who.grant.allows(scope) {
        return Ok(());
    }
    Err(BestError::bad_request(
        "FORBIDDEN",
        format!(
            "this credential may not {scope}: it was approved for {}; ask whoever controls the machine to approve a credential that may (best-peer approve <code> --may {scope})",
            who.grant.said()
        ),
    )
    .with_details(json!({ "needs": scope, "may": who.grant.scopes })))
}

/// A deploy or a job past the credential's share is refused with what it holds and what to do. `held` is what the
/// credential holds across the door, admitted workloads included.
pub(crate) fn within_share(held: u64, who: &Credential, needed: u64) -> Result<(), BestError> {
    let Some(share) = who.grant.memory_bytes else {
        return Ok(());
    };
    if held.saturating_add(needed) <= share {
        return Ok(());
    }
    Err(BestError::bad_request(
        "SHARE_EXCEEDED",
        format!(
            "this credential may hold {share} bytes of device memory and holds {held} across this door, every workspace counted: {needed} more does not fit; undeploy or stop something of yours first (get-workloads on each door you use lists them, with held_bytes the total), or ask for a larger share"
        ),
    )
    .with_details(json!({ "share_bytes": share, "held_bytes": held, "needed_bytes": needed, "room_bytes": share.saturating_sub(held) })))
}

/// Whether `who` was approved for a share of device memory. Such a credential runs its jobs on a device, where its
/// share counts them: a job with no device would hold the host's memory and processors outside the share.
pub(crate) fn has_share(who: &Credential) -> bool {
    who.grant.memory_bytes.is_some()
}

/// A credential whose approver set a count runs `ceiling` workloads of `kind` at once across the door, `running` of
/// them already, every workspace counted: one more is refused with what it runs and how to make room.
pub(crate) fn within_count(kind: &str, running: usize, ceiling: Option<u32>) -> Result<(), BestError> {
    let Some(ceiling) = ceiling.map(|c| c as usize) else {
        return Ok(());
    };
    if running < ceiling {
        return Ok(());
    }
    let (code, room) = match kind {
        "job" => ("JOBS_EXCEEDED", "stop one or let one finish first"),
        _ => ("DEPLOYMENTS_EXCEEDED", "undeploy one first"),
    };
    Err(BestError::bad_request(
        code,
        format!(
            "this credential may run {ceiling} {kind}(s) at once and runs {running} across this door, every workspace counted: {room} (get-workloads on each door you use lists them), or ask whoever approved it for more"
        ),
    )
    .with_details(json!({ "ceiling": ceiling, "running": running })))
}

/// A workload another credential holds is not this one's to end.
pub(crate) fn not_yours(kind: &str, id: &str) -> BestError {
    BestError::bad_request(
        "FORBIDDEN",
        format!("{kind} {id} was started by another credential: get-workloads lists yours, and only a credential approved for all may reach another's"),
    )
    .with_details(json!({ kind: id }))
}

/// The holder a credential may be told about: every one for a credential approved for all, else its own.
pub(crate) fn mine(who: &Credential) -> Option<String> {
    (!who.grant.is_all()).then(|| who.holder())
}

/// Where a workload needing `memory_bytes` on a device offering one of `apis` goes: the fitting device with the most
/// memory free after what is already promised there, or `pinned` when the caller named one. A refusal names what is
/// in the way and what to do about it.
pub(crate) fn place(
    host: &Host,
    state: &State,
    apis: &[Compute],
    memory_bytes: u64,
    pinned: Option<&str>,
    what: &str,
    mine: Option<&str>,
) -> Result<(DeviceId, Compute), BestError> {
    let ids: Vec<String> = host.devices.iter().map(|d| d.id.0.clone()).collect();
    let candidates: Vec<&best_peer_gpu::Device> = match pinned {
        Some(p) => vec![host.devices.iter().find(|d| d.id.0 == p).ok_or_else(|| {
            BestError::bad_request(
                "NO_SUCH_DEVICE",
                format!(
                    "device {p} is not on this host: get-hardware-state lists {}",
                    list(ids.iter())
                ),
            )
            .with_details(json!({ "device": p, "devices": ids }))
        })?],
        None => host.devices.iter().collect(),
    };
    // The API each candidate offers among the wanted ones, the first wanted one winning.
    let offering: Vec<(&best_peer_gpu::Device, Compute)> = candidates
        .iter()
        .filter_map(|d| {
            apis.iter()
                .find(|w| host.fit(w, 0).iter().any(|f| f.id == d.id))
                .map(|w| (*d, w.clone()))
        })
        .collect();
    if offering.is_empty() {
        let wanted: Vec<String> = apis.iter().map(api_name).collect();
        let offered: Vec<Value> = candidates
            .iter()
            .map(|d| json!({ "id": d.id.0, "compute": d.compute }))
            .collect();
        return Err(BestError::bad_request(
            "NO_DEVICE_FOR_ENGINE",
            format!(
                "{what} runs on {} and no device here offers one: get-hardware-state says what they offer",
                wanted.join(", ")
            ),
        )
        .with_details(json!({ "wanted": wanted, "devices": offered })));
    }
    let room = |d: &best_peer_gpu::Device| {
        d.memory
            .free_bytes
            .min(d.memory.total_bytes.saturating_sub(state.reserved_on(&d.id)))
    };
    // The engine's APIs are listed in the order it prefers them (an accelerator before the CPU, which always has the
    // most room): the first API any fitting device offers wins, and among those the device with the most room.
    let rank = |c: &Compute| apis.iter().position(|w| w == c).unwrap_or(apis.len());
    let best = offering
        .iter()
        .filter(|(d, _)| room(d) >= memory_bytes)
        .min_by_key(|(d, c)| (rank(c), std::cmp::Reverse(room(d))));
    if let Some((d, c)) = best {
        return Ok((d.id.clone(), c.clone()));
    }
    let devices: Vec<Value> = offering
        .iter()
        .map(|(d, _)| {
            json!({
                "id": d.id.0, "name": d.name, "free_bytes": d.memory.free_bytes, "total_bytes": d.memory.total_bytes,
                "promised_bytes": state.reserved_on(&d.id), "room_bytes": room(d), "holders": state.holders_on(&d.id, mine)
            })
        })
        .collect();
    let told: Vec<String> = offering
        .iter()
        .map(|(d, _)| {
            format!(
                "{} ({}) has {} free of {} with {} promised",
                d.id.0,
                d.name,
                d.memory.free_bytes,
                d.memory.total_bytes,
                state.reserved_on(&d.id)
            )
        })
        .collect();
    Err(BestError::bad_request(
        "INSUFFICIENT_MEMORY",
        format!(
            "no device has {memory_bytes} bytes for {what}: {}. Undeploy a model (UndeployModel) or stop a job (StopJob) named in the details, or ask for less memory_bytes",
            told.join("; ")
        ),
    )
    .with_details(json!({ "memory_bytes": memory_bytes, "devices": devices })))
}

fn api_name(c: &Compute) -> String {
    match c {
        Compute::Cuda(_) => "cuda".into(),
        Compute::Rocm(_) => "rocm".into(),
        Compute::OneApi(_) => "one-api".into(),
        Compute::Metal => "metal".into(),
        Compute::Vulkan => "vulkan".into(),
        Compute::Cpu => "cpu".into(),
    }
}

/// The pace progress is told at. An engine reports every percent, sometimes every byte; a consumer that catches up
/// on the log reads every event told, so one workload tells its progress at steps of ten points on from the last
/// value told, at once when the value is final or went back (a new layer appeared, extraction began), and at least
/// every few seconds while the engine keeps reporting, so a slow pull is seen to move. A report without a value
/// (the engine knows it is working, not how far) is told by time alone and moves no baseline.
pub struct Pace {
    inner: Mutex<Paced>,
}

#[derive(Default)]
struct Paced {
    /// The last value told: what the next step is measured from.
    value: Option<u8>,
    /// When anything was last told.
    at: Option<Instant>,
}

impl Pace {
    pub const STEP: u8 = 10;
    pub const AT_LEAST_EVERY: Duration = Duration::from_secs(5);

    /// Whether this report is told now.
    pub fn due(&self, pct: Option<u8>) -> bool {
        self.due_at(pct, Instant::now())
    }

    /// Whether a report arriving at `now` is told, and if so it is what the next is measured from.
    pub fn due_at(&self, pct: Option<u8>, now: Instant) -> bool {
        let mut p = self.inner.lock().unwrap();
        let overdue = p.at.is_none_or(|at| now.duration_since(at) >= Self::AT_LEAST_EVERY);
        let due = match (p.value, pct) {
            (_, None) => overdue,
            (None, Some(_)) => true,
            (Some(told), Some(v)) => {
                v != told && (v == 100 || v < told || v >= told.saturating_add(Self::STEP) || overdue)
            }
        };
        if due {
            p.at = Some(now);
            if pct.is_some() {
                p.value = pct;
            }
        }
        due
    }
}

impl Default for Pace {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Paced::default()),
        }
    }
}

fn fix_for_runtime(e: &RuntimeError) -> &'static str {
    match e {
        RuntimeError::ImageNotFound(_) => "the registry has no such image: check the name and the tag",
        RuntimeError::NoSuchContainer(_) => "the container is already gone",
        RuntimeError::DeviceUnavailable(_) => {
            "the container engine cannot hand over that device: check the container toolkit on the host"
        }
        RuntimeError::Unreachable(_) => "the container engine is not running on the host: start it",
        RuntimeError::Engine(_) => "read the container engine's logs on the host",
    }
}

/// What to do about an engine's refusal; a peer serving from a store says where the model was looked for.
fn fix_for_engine(e: &EngineError, source: Source) -> String {
    match (e, source) {
        (EngineError::NotReady { .. }, _) => {
            "the engine did not come up in time: read its container's logs on the host".into()
        }
        (EngineError::ModelNotFound(_), Source::Registry) => {
            "the engine's library has no model by that name: check the name".into()
        }
        (EngineError::ModelNotFound(_), Source::Store) => {
            "the model is in the operator's model store only in part: ask whoever runs the peer to put it there again"
                .into()
        }
        (EngineError::Engine(_), _) => "read the engine's logs on the host".into(),
    }
}

/// Whether Ollama's library at `store` holds `model`: its manifest, where `ollama pull` writes one. A name with no
/// registry is Ollama's own, one with no namespace is in `library`, one with no tag is `latest`.
pub(crate) fn in_store(store: &std::path::Path, model: &str) -> bool {
    let after_slash = model.rfind('/').map(|i| i + 1).unwrap_or(0);
    let (name, tag) = match model[after_slash..].rfind(':') {
        Some(i) => (&model[..after_slash + i], &model[after_slash + i + 1..]),
        None => (model, "latest"),
    };
    let parts: Vec<&str> = name.split('/').collect();
    let path: Vec<&str> = match parts.as_slice() {
        [name] => vec!["registry.ollama.ai", "library", name],
        [namespace, name] => vec!["registry.ollama.ai", namespace, name],
        _ => parts,
    };
    if tag.is_empty() || path.iter().any(|p| p.is_empty() || *p == "." || *p == "..") {
        return false;
    }
    let mut manifest = store.join("manifests");
    for p in path.iter().chain([&tag]) {
        manifest.push(p);
    }
    manifest.is_file()
}

pub(crate) fn parse<T: serde::de::DeserializeOwned>(data: &Value) -> Result<T, BestError> {
    serde_json::from_value(data.clone())
        .map_err(|e| BestError::internal(format!("the command passed its schema but could not be read: {e}")))
}

pub(crate) fn list<'a, S: AsRef<str> + 'a>(items: impl Iterator<Item = &'a S>) -> String {
    let v: Vec<&str> = items.map(AsRef::as_ref).collect();
    if v.is_empty() {
        "none".into()
    } else {
        v.join(", ")
    }
}

/// The holder a command key names: its sender part is the credential's hash.
#[allow(dead_code)]
fn holder_of_key(key: &str) -> String {
    holder_of_hash(key.split(':').next().unwrap_or(""))
}

pub(crate) fn new_id(prefix: &str) -> String {
    format!("{prefix}-{}", &uuid::Uuid::new_v4().simple().to_string()[..12])
}

#[cfg(test)]
mod tests {
    use super::Pace;
    use std::time::Duration;

    #[test]
    fn progress_is_told_at_steps_of_ten_at_the_end_and_when_it_went_back_whatever_the_engine_reports() {
        let t0 = std::time::Instant::now();
        let pace = Pace::default();
        let told: Vec<u8> = (0..=100).filter(|&p| pace.due_at(Some(p), t0)).collect();
        assert_eq!(told, vec![0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100]);
        // A repeated final value is not told again.
        assert!(!pace.due_at(Some(100), t0));
        // A jump straight to the end is told at once, whatever the step.
        let pace = Pace::default();
        assert!(pace.due_at(Some(3), t0));
        assert!(!pace.due_at(Some(7), t0));
        assert!(pace.due_at(Some(100), t0));
        // A value that went back is told at once and is the new baseline: downloads done, extraction begun.
        assert!(pace.due_at(Some(12), t0));
        assert!(!pace.due_at(Some(19), t0));
        assert!(pace.due_at(Some(22), t0));
        assert!(
            pace.due_at(Some(100), t0),
            "the end, again, once the pull is really there"
        );
        // Time: a small move is told once the interval passed, not before.
        let pace = Pace::default();
        assert!(pace.due_at(Some(40), t0));
        assert!(!pace.due_at(Some(44), t0 + Pace::AT_LEAST_EVERY - Duration::from_millis(1)));
        assert!(pace.due_at(Some(44), t0 + Pace::AT_LEAST_EVERY));
        assert!(
            !pace.due_at(Some(44), t0 + Pace::AT_LEAST_EVERY * 2),
            "the same value is never told twice"
        );
        // A report without a value is told by time alone and does not move the baseline.
        let pace = Pace::default();
        assert!(pace.due_at(None, t0));
        assert!(!pace.due_at(None, t0));
        assert!(pace.due_at(Some(5), t0), "the first value is told whatever came before");
        assert!(!pace.due_at(Some(9), t0));
        assert!(pace.due_at(None, t0 + Pace::AT_LEAST_EVERY));
        assert!(
            pace.due_at(Some(15), t0 + Pace::AT_LEAST_EVERY),
            "the step is still measured from 5, not from the None"
        );
    }

    use super::*;

    #[test]
    fn a_card_with_room_wins_over_the_host_cpu_whatever_the_ram() {
        let mut cpu = best_peer_gpu::Fake::cuda_card("cpu-0", "host", 120, "0");
        cpu.compute = vec![Compute::Cpu];
        let host = Host {
            driver: None,
            devices: vec![cpu, best_peer_gpu::Fake::cuda_card("GPU-a", "card", 24, "12.8")],
            observed_at: std::time::SystemTime::now(),
        };
        let state = State::default();
        let ollama = best_peer_engine::Kind::Ollama.runs_on();
        let (id, api) = place(&host, &state, &ollama, 4 << 30, None, "ollama", None).unwrap();
        assert_eq!((id.0.as_str(), api), ("GPU-a", Compute::Cuda("0".into())));
        // Only when no card has the room does the CPU take it.
        let (id, api) = place(&host, &state, &ollama, 30 << 30, None, "ollama", None).unwrap();
        assert_eq!((id.0.as_str(), api), ("cpu-0", Compute::Cpu));
        // A job with no stated API goes to the card too.
        let (id, _) = place(&host, &state, &any_compute(), 1 << 30, None, "a job", None).unwrap();
        assert_eq!(id.0, "GPU-a");
    }
}
