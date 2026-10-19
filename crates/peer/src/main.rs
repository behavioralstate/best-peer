//! best-peer: one binary that puts a GPU host behind a BEST door.
//!
//! The door is built against three abstractions the workspace owns, [`best_peer_gpu::Gpu`],
//! [`best_peer_runtime::Runtime`] and [`best_peer_engine::Engine`]; which adapters stand behind them is decided here
//! and nowhere else. The host's own CPU and memory are always a device; the container engine is Docker through its
//! API, or the fakes when `BEST_PEER_RUNTIME=fake` (CI, a machine with no engine).
//!
//! `best-peer` serves; `best-peer approve <code>` admits an agent that asked, on the word of whoever controls this
//! machine, and `best-peer revoke <name>` takes a credential back. Every door hosts workspaces, the BEST tenants: an
//! identity creates one, invites others, and configures clouds in it, named pools of peers the same binary fronts and
//! places on.

mod cloud;
mod domain;
mod holdings;
mod lifecycle;
mod member;
mod state;
mod tls;
mod transport;
mod workspace;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use best_peer_door::{Auth, Door, EventLog, Limits, LocalApprover, Pace, Streams};
use best_peer_engine::Engine;
use best_peer_gpu::Gpu;
use best_peer_runtime::{Confinement, Runtime};
use lifecycle::{Confine, Images, Patience, Peer, Pull};
use tls::Tls;
use transport::{is_loopback, Cleartext};

/// Where to listen, what to advertise and whether TLS serves it, from `BEST_PEER_LISTEN` (ip:port, default
/// loopback), `BEST_PEER_ENDPOINT` (the consumer-facing base URL) and `BEST_PEER_TLS_CERT` with `BEST_PEER_TLS_KEY`
/// (the operator's certificate; an `https://` endpoint without them is served with one the peer makes). The endpoint
/// defaults to the listen address only when that address is one a consumer can use: a peer listening on every
/// interface has no address of its own to advertise, so it refuses to start until told what it is called. A
/// cleartext endpoint is served on loopback alone, both where the peer listens and what it advertises: off it the
/// credential would travel in the clear, so the peer refuses to start and says what to set, unless the operator said
/// a VPN carries the hop (`BEST_PEER_CLEARTEXT=vpn`).
pub fn config(
    listen: Option<&str>,
    endpoint: Option<&str>,
    cert: Option<&str>,
    key: Option<&str>,
    cleartext: Cleartext,
) -> Result<(SocketAddr, String, Tls), String> {
    let listen_text = listen.unwrap_or("127.0.0.1:7777");
    let listen: SocketAddr = listen_text
        .parse()
        .map_err(|_| format!("BEST_PEER_LISTEN must be ip:port, not {listen_text:?}"))?;
    let said = endpoint.is_some();
    let endpoint = match endpoint {
        Some(e) if e.starts_with("http://") || e.starts_with("https://") => e.trim_end_matches('/').to_string(),
        Some(e) => {
            return Err(format!(
                "BEST_PEER_ENDPOINT must be a base URL, http:// or https://, not {e:?}"
            ))
        }
        None if listen.ip().is_unspecified() => {
            return Err(format!(
                "BEST_PEER_LISTEN is {listen}, an address no consumer can reach: set BEST_PEER_ENDPOINT to the URL this peer is reached at"
            ))
        }
        None if cert.is_some() => format!("https://{listen}"),
        None => format!("http://{listen}"),
    };
    let tls = Tls::decide(&endpoint, cert, key)?;
    let listen_off = !listen.ip().to_canonical().is_loopback();
    let host = transport::url_host(&endpoint);
    let endpoint_off = said && !is_loopback(host);
    if tls == Tls::Off && cleartext == Cleartext::Loopback && (listen_off || endpoint_off) {
        let named = if said {
            "BEST_PEER_ENDPOINT is"
        } else {
            "the endpoint, from BEST_PEER_LISTEN, is"
        };
        let off = match (listen_off, endpoint_off) {
            (true, true) => format!("BEST_PEER_LISTEN is {listen} and the endpoint's host is {host}, neither loopback"),
            (true, false) => format!("BEST_PEER_LISTEN is {listen}, not loopback"),
            _ => format!("the endpoint's host is {host}, not loopback"),
        };
        return Err(format!(
            "{named} {endpoint}, cleartext, and {off}: a credential would travel unencrypted. Make BEST_PEER_ENDPOINT https:// (the peer makes its own certificate, or serves BEST_PEER_TLS_CERT and BEST_PEER_TLS_KEY), keep both on loopback, or set BEST_PEER_CLEARTEXT=vpn when a VPN already encrypts the hop"
        ));
    }
    Ok((listen, endpoint, tls))
}

/// The least host memory a container starts with: the container engine refuses less.
const MIN_CONTAINER_MEMORY: u64 = 6 << 20;

/// How the containers are confined, from `BEST_PEER_JOB_MEMORY` (default `4G`) and `BEST_PEER_JOB_PIDS` (default
/// 4096) for a job, `BEST_PEER_ENGINE_MEMORY` (default none) and `BEST_PEER_ENGINE_PIDS` (default 4096) for an
/// engine; `none` for a ceiling is no ceiling. These are ceilings and nothing else: a job never has a network, and
/// capabilities, privileges and a job's filesystem are never opened by a variable.
pub fn confine(
    job_memory: Option<&str>,
    job_pids: Option<&str>,
    engine_memory: Option<&str>,
    engine_pids: Option<&str>,
) -> Result<Confine, String> {
    let memory = |name: &str, text: Option<&str>, default: Option<u64>| -> Result<Option<u64>, String> {
        match text.map(str::trim) {
            None => Ok(default),
            Some("none") => Ok(None),
            Some(t) => match parse_memory(t) {
                Ok(m) if m < MIN_CONTAINER_MEMORY => Err(format!(
                    "{name}: {t:?} is less than the 6M a container starts with: write 4G, 512M or a number of bytes \
                     from 6M up, or none for no ceiling"
                )),
                Ok(m) if m > i64::MAX as u64 => Err(format!("{name}: {t:?} is more memory than exists, or none")),
                Ok(m) => Ok(Some(m)),
                Err(why) => Err(format!("{name}: {why}, or none")),
            },
        }
    };
    let pids = |name: &str, text: Option<&str>, default: u64| -> Result<Option<u64>, String> {
        match text.map(str::trim) {
            None => Ok(Some(default)),
            Some("none") => Ok(None),
            Some(t) => match t.parse::<u64>() {
                Ok(n) if n > 0 => Ok(Some(n)),
                _ => Err(format!(
                    "{name} must be a number of tasks above zero (every thread counts as one), or none, not {t:?}"
                )),
            },
        }
    };
    let mut job = Confinement::default();
    job.memory_bytes = memory("BEST_PEER_JOB_MEMORY", job_memory, job.memory_bytes)?;
    job.pids = pids("BEST_PEER_JOB_PIDS", job_pids, 4096)?;
    let mut engine = Confinement::serving();
    engine.memory_bytes = memory("BEST_PEER_ENGINE_MEMORY", engine_memory, None)?;
    engine.pids = pids("BEST_PEER_ENGINE_PIDS", engine_pids, 4096)?;
    let mut open_job = Confinement::serving();
    open_job.pids = job.pids;
    Ok(Confine { job, open_job, engine })
}

/// The peer's data directory: `BEST_PEER_DATA`, else `.best-peer` in the home directory. Never a relative path:
/// the server and the operator's shell must resolve the same directory, or `best-peer approve` finds no token.
fn data_dir() -> PathBuf {
    if let Ok(d) = std::env::var("BEST_PEER_DATA") {
        return PathBuf::from(d);
    }
    match std::env::home_dir() {
        Some(h) => h.join(".best-peer"),
        None => fail("no home directory to keep the peer's data in: set BEST_PEER_DATA to an absolute path"),
    }
}

/// The service key in the manifest, and the `source` of every event.
const SERVICE: &str = "io.best.agents";

/// The peer over the given hardware, container engine and inference engine, its state rebuilt from the log and
/// its ears on the engines' events, its promises counted in `holdings`.
#[allow(clippy::too_many_arguments)]
pub async fn peer(
    endpoint: &str,
    engine_host: &str,
    gpu: Arc<dyn Gpu>,
    runtime: Arc<dyn Runtime>,
    engine: Arc<dyn Engine>,
    log: Arc<EventLog>,
    images: Images,
    patience: Patience,
    holdings: Arc<holdings::Holdings>,
    confine: Confine,
) -> Arc<Peer> {
    // Subscribed before the rebuild, so an exit told while the state is being rebuilt is not lost.
    let events = runtime.events();
    let p = Arc::new(
        Peer::new(
            endpoint,
            engine_host,
            SERVICE,
            gpu,
            runtime,
            engine,
            log,
            images,
            patience,
            confine,
        )
        .with_holdings(holdings),
    );
    p.register_holdings();
    p.rebuild().await;
    p.follow(events);
    p
}

/// The root door of this peer: the machine's own hardware and lifecycle, and the workspaces it hosts.
pub fn door(peer: Arc<Peer>, workspaces: Arc<workspace::Workspaces>, auth: Arc<Auth>) -> Door {
    let ctx = workspaces.ctx.clone();
    Door::new(
        &ctx.endpoint,
        SERVICE,
        "A peer: a GPU host that deploys models and runs jobs on request and tells their lifecycle as events, and hosts workspaces, each with its clouds of peers.",
        domain::catalogue(peer.clone(), workspaces, auth.clone()),
        peer.log.clone(),
        auth,
    )
    .with_tenants(&ctx.manifest_template())
    .with_partition(workspace::Workspaces::root_partition(peer.log.clone()))
    .with_limits(ctx.limits.clone())
}

/// What the workspaces of this door are built with: the root's endpoint and credentials, the data directory, the
/// transport their clouds reach members through (HTTP with the trust `BEST_PEER_TRUST` adds, the PEM files of
/// members' own certificates, and cleartext only where the peer's own rule allows it), the holdings every surface
/// counts a share against, and the limits every surface holds a credential with a share to
/// (`BEST_PEER_COMMANDS_PER_MINUTE`, `BEST_PEER_STREAMS_PER_CREDENTIAL`).
fn context(
    endpoint: &str,
    dir: &std::path::Path,
    auth: Arc<Auth>,
    holdings: Arc<holdings::Holdings>,
    cleartext: Cleartext,
) -> workspace::Context {
    let per_minute = commands_per_minute(std::env::var("BEST_PEER_COMMANDS_PER_MINUTE").ok().as_deref())
        .unwrap_or_else(|why| fail(&why));
    let streams = streams_per_credential(std::env::var("BEST_PEER_STREAMS_PER_CREDENTIAL").ok().as_deref())
        .unwrap_or_else(|why| fail(&why));
    let trust: Vec<PathBuf> = std::env::var("BEST_PEER_TRUST")
        .ok()
        .map(|t| {
            t.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
                .collect()
        })
        .unwrap_or_default();
    workspace::Context {
        endpoint: endpoint.into(),
        service: SERVICE.into(),
        dir: dir.into(),
        auth,
        transport: Arc::new(transport::Http::new(&trust, cleartext).unwrap_or_else(|why| fail(&why))),
        holdings,
        cleartext,
        limits: Arc::new(Limits::new(
            Pace::per_minute(per_minute),
            Streams::per_credential(streams),
        )),
    }
}

/// When a deploy or a job pulls its image, from `BEST_PEER_PULL`: unset, a reference by tag is pulled each time, since
/// a tag may have moved, and one pinned by digest only when it is not held; `missing`, any image only when it is not
/// held, for a host with no way to a registry, whose images were put there by hand.
pub fn pull_rule(text: Option<&str>) -> Result<Pull, String> {
    match text.map(str::trim).filter(|t| !t.is_empty()) {
        None => Ok(Pull::Tags),
        Some("missing") => Ok(Pull::Missing),
        Some(t) => Err(format!(
            "BEST_PEER_PULL is {t}: set it to missing, to pull an image only when Docker does not hold it, or leave it unset to pull a tag each time"
        )),
    }
}

/// How many commands a credential may send a minute, from `BEST_PEER_COMMANDS_PER_MINUTE`: the door's default
/// unless the operator says more or less; nothing is not a pace.
pub fn commands_per_minute(text: Option<&str>) -> Result<u32, String> {
    match text.map(str::trim).filter(|t| !t.is_empty()) {
        None => Ok(best_peer_door::pace::COMMANDS_PER_MINUTE),
        Some(t) => match t.parse::<u32>() {
            Ok(n) if n > 0 => Ok(n),
            _ => Err(format!(
                "BEST_PEER_COMMANDS_PER_MINUTE is {t}: say how many commands a credential may send a minute, 1 or more"
            )),
        },
    }
}

/// How many event streams a credential with a share may hold open at once, from `BEST_PEER_STREAMS_PER_CREDENTIAL`:
/// the door's default unless the operator says more or less; a stream needs one at least.
pub fn streams_per_credential(text: Option<&str>) -> Result<usize, String> {
    match text.map(str::trim).filter(|t| !t.is_empty()) {
        None => Ok(best_peer_door::streams::STREAMS_PER_CREDENTIAL),
        Some(t) => match t.parse::<usize>() {
            Ok(n) if n > 0 => Ok(n),
            _ => Err(format!(
                "BEST_PEER_STREAMS_PER_CREDENTIAL is {t}: say how many event streams a credential with a share may hold open at once, 1 or more"
            )),
        },
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None => serve(),
        Some("approve") => approve(&args[1..]),
        Some("revoke") => revoke(&args[1..]),
        Some("--version" | "-V" | "version") => println!("best-peer {}", env!("CARGO_PKG_VERSION")),
        Some(other) => {
            eprintln!(
                "unknown command {other:?}: run with no arguments to serve, `best-peer approve <code>`, `best-peer revoke <name>`, or `best-peer --version`"
            );
            std::process::exit(2);
        }
    }
}

/// The hardware the peer places workloads on, by `BEST_PEER_GPU`: `nvml` (the default) reads the NVIDIA cards
/// through the driver's own library and refuses to start without it, since a GPU host that cannot see its cards is
/// misconfigured; `none` says this host has no accelerator, and the CPU with the system memory is the one device.
/// With cards, the host CPU is listed after them, so a CPU deploy is placed there too.
fn accelerator(kind: Option<&str>) -> Result<Arc<dyn Gpu>, String> {
    let host = best_peer_host::HostCpu::new();
    match kind {
        None | Some("nvml") => {
            let cards = best_peer_nvml::NvmlGpu::init().map_err(|e| match e {
                best_peer_gpu::GpuError::NoDriver(_) => {
                    format!("{e}; this peer needs the NVIDIA driver, or BEST_PEER_GPU=none to serve on the CPU alone")
                }
                other => format!(
                    "the NVIDIA driver is here but could not be used: {other}; fix that, or BEST_PEER_GPU=none serves on the CPU alone"
                ),
            })?;
            Ok(Arc::new(best_peer_gpu::Combined::new(vec![
                Box::new(cards),
                Box::new(host),
            ])))
        }
        Some("none") => Ok(Arc::new(host)),
        Some(other) => Err(format!("BEST_PEER_GPU must be nvml or none, not {other:?}")),
    }
}

/// The store of models beside the registry, from `BEST_PEER_MODEL_STORE`: a directory the peer reads to find a
/// model in it, and the container engine mounts read-only into the engine that serves it, so it is the same path on
/// both, which it is when they share a host. Only containers mount it: under `native` or `fake` the store would be
/// ignored, so it is refused, as is a directory the peer cannot read.
pub fn model_store(text: Option<&str>, runtime: Option<&str>) -> Result<Option<String>, String> {
    let Some(store) = text.map(str::trim).filter(|t| !t.is_empty()) else {
        return Ok(None);
    };
    if let Some(other) = runtime.map(str::trim).filter(|r| *r != "docker") {
        return Err(format!(
            "BEST_PEER_MODEL_STORE is set with BEST_PEER_RUNTIME={other}, which mounts nothing: the store serves engines in containers, so unset it or run with BEST_PEER_RUNTIME=docker"
        ));
    }
    match std::fs::read_dir(store) {
        Ok(_) => Ok(Some(store.to_string())),
        Err(e) => Err(format!(
            "BEST_PEER_MODEL_STORE is {store}, which the peer cannot read here ({e}): the peer looks for each model in the store before it starts an engine, so the store must be a directory at the same path for the peer and the container engine"
        )),
    }
}

/// The container engine and the inference engine's client, by `BEST_PEER_RUNTIME`: `docker` (the default) talks to
/// the Docker Engine on this host and refuses to start when it cannot; `native` deploys to engines already running
/// on this host outside any container (an installed Ollama), with no jobs; `fake` serves the whole surface against
/// the in-memory fakes, for CI and for a machine with no engine.
async fn engines(bind_ip: &str, engine_host: &str) -> (Arc<dyn Runtime>, Arc<dyn Engine>) {
    match std::env::var("BEST_PEER_RUNTIME").as_deref() {
        Ok("native") => (
            Arc::new(best_peer_native::NativeRuntime::new(engine_host)),
            Arc::new(best_peer_engine_http::HttpEngine::new()),
        ),
        Ok("fake") => {
            tracing::warn!("BEST_PEER_RUNTIME=fake: no workload runs; the lifecycle is told but nothing happens");
            (
                Arc::new(best_peer_runtime::Fake::new(vec![], vec![]).with_open_registry()),
                Arc::new(best_peer_engine::Fake::new()),
            )
        }
        Ok("docker") | Err(_) => {
            let docker = best_peer_docker::DockerRuntime::connect(bind_ip)
                .await
                .unwrap_or_else(|e| {
                    fail(&format!(
                        "{e}; set BEST_PEER_RUNTIME=native to deploy to an engine already running here, or fake to serve without one"
                    ))
                });
            (Arc::new(docker), Arc::new(best_peer_engine_http::HttpEngine::new()))
        }
        Ok(other) => fail(&format!(
            "BEST_PEER_RUNTIME must be docker, native or fake, not {other:?}"
        )),
    }
}

#[tokio::main]
async fn serve() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let cleartext = Cleartext::parse(std::env::var("BEST_PEER_CLEARTEXT").ok().as_deref()).unwrap_or_else(|why| {
        eprintln!("{why}");
        std::process::exit(2);
    });
    let (listen, endpoint, tls) = match config(
        std::env::var("BEST_PEER_LISTEN").ok().as_deref(),
        std::env::var("BEST_PEER_ENDPOINT").ok().as_deref(),
        std::env::var("BEST_PEER_TLS_CERT").ok().as_deref(),
        std::env::var("BEST_PEER_TLS_KEY").ok().as_deref(),
        cleartext,
    ) {
        Ok(c) => c,
        Err(why) => {
            eprintln!("{why}");
            std::process::exit(2);
        }
    };
    let dir = data_dir();
    let approver = LocalApprover::open(&dir)
        .unwrap_or_else(|e| fail(&format!("cannot keep the admin token in {}: {e}", dir.display())));
    let auth = Arc::new(
        Auth::open(&dir, &endpoint, Box::new(approver))
            .map(|a| a.with_scopes(domain::SCOPES))
            .unwrap_or_else(|e| fail(&format!("cannot keep credentials in {}: {e}", dir.display()))),
    );
    let log = Arc::new(
        EventLog::open(&dir).unwrap_or_else(|e| fail(&format!("cannot keep the event log in {}: {e}", dir.display()))),
    );
    if let Ok(members) = std::env::var("BEST_PEER_MEMBERS") {
        fail(&workspace::members_variable_replaced(&members));
    }
    let app = peer_app(&endpoint, &dir, log, auth, cleartext).await;
    let serving = tls::serving(&tls, &dir, &tls::names_for(&endpoint, &listen)).unwrap_or_else(|why| fail(&why));
    let listener = std::net::TcpListener::bind(listen)
        .and_then(|l| l.set_nonblocking(true).map(|()| l))
        .unwrap_or_else(|e| fail(&format!("cannot listen on {listen}: {e}")));
    // Where the door is and what it serves, for `best-peer approve` on this machine.
    tls::Record {
        listen,
        endpoint: endpoint.clone(),
        certificate: serving.as_ref().map(|s| s.certificate.clone()),
    }
    .write(&dir)
    .unwrap_or_else(|e| fail(&format!("cannot record the door in {}: {e}", dir.display())));
    match &serving {
        Some(s) if s.made => {
            tracing::info!(certificate = %s.file.display(), "https with a certificate this peer made at this start: a client that pins it reads this file; one that pinned an earlier file reads it again")
        }
        Some(s) if tls == Tls::Own => {
            tracing::info!(certificate = %s.file.display(), "https with a certificate this peer made: a client that pins it reads this file")
        }
        Some(s) => tracing::info!(certificate = %s.file.display(), "https with the operator's certificate"),
        None if cleartext == Cleartext::Vpn => {
            tracing::warn!(%endpoint, "cleartext, as BEST_PEER_CLEARTEXT=vpn says: credentials travel unencrypted to and from this peer, and only the VPN protects them")
        }
        None => {}
    }
    tracing::info!(%listen, %endpoint, data = %dir.display(), "best-peer is serving its door");
    let handle = axum_server::Handle::new();
    // An open event stream never ends by itself, so a graceful stop would wait for it forever: a few seconds, then out.
    let stop = handle.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        tracing::info!("stopping: open connections have three seconds");
        stop.graceful_shutdown(Some(Duration::from_secs(3)));
    });
    serve_on(listener, app, serving.map(|s| s.config), handle)
        .await
        .unwrap_or_else(|e| fail(&format!("serving failed: {e}")));
}

/// Why the peer will not start when a cloud it hosts has a member recorded at a cleartext endpoint off loopback:
/// the cloud would send its credential there in the clear. Each is named, with the way out.
fn cleartext_members_refused(members: &[(String, String, String, String)]) -> Option<String> {
    if members.is_empty() {
        return None;
    }
    let named: Vec<String> = members
        .iter()
        .map(|(ws, cloud, peer, endpoint)| format!("workspace {ws}, cloud {cloud}, peer {peer} at {endpoint}"))
        .collect();
    Some(format!(
        "a cloud here has a member recorded at a cleartext endpoint off loopback, where its credential would travel unencrypted: {}. Send configure-cloud in that workspace naming the member by its https:// endpoint, or archive the cloud; to start meanwhile, set BEST_PEER_CLEARTEXT=vpn, which is what the cloud ran under, and only when a VPN carries the hop",
        named.join("; ")
    ))
}

/// The peer over this host's hardware and engines, its door and its endpoints, and the workspaces it hosts under
/// `/workspaces`.
async fn peer_app(
    endpoint: &str,
    dir: &std::path::Path,
    log: Arc<EventLog>,
    auth: Arc<Auth>,
    cleartext: Cleartext,
) -> axum::Router {
    let gpu = accelerator(std::env::var("BEST_PEER_GPU").ok().as_deref()).unwrap_or_else(|why| fail(&why));
    // The engines' ports are bound where the peer reaches them, whatever the door listens on: a prompt reaches an
    // engine through the door, with the door's credential. On this machine that is loopback; a container engine on
    // another host (BEST_PEER_ENGINE_HOST not loopback) publishes them on that host's interfaces, as loopback there
    // is not here.
    let engine_host = std::env::var("BEST_PEER_ENGINE_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let bind_ip = if is_loopback(&engine_host) {
        "127.0.0.1"
    } else {
        "0.0.0.0"
    };
    let (runtime, engine) = engines(bind_ip, &engine_host).await;
    let images = Images {
        ollama: std::env::var("BEST_PEER_OLLAMA_IMAGE").ok(),
        vllm: std::env::var("BEST_PEER_VLLM_IMAGE").ok(),
        model_store: model_store(
            std::env::var("BEST_PEER_MODEL_STORE").ok().as_deref(),
            std::env::var("BEST_PEER_RUNTIME").ok().as_deref(),
        )
        .unwrap_or_else(|why| fail(&why)),
        pull: pull_rule(std::env::var("BEST_PEER_PULL").ok().as_deref()).unwrap_or_else(|why| fail(&why)),
    };
    let seconds = |name: &str, default: u64| {
        Duration::from_secs(std::env::var(name).ok().and_then(|s| s.parse().ok()).unwrap_or(default))
    };
    let patience = Patience {
        ready: seconds("BEST_PEER_READY_SECONDS", 900),
        load: seconds("BEST_PEER_LOAD_SECONDS", 3600),
        ..Patience::default()
    };
    for gone in ["BEST_PEER_DEPLOYMENTS_PER_HOLDER", "BEST_PEER_JOBS_PER_HOLDER"] {
        if std::env::var_os(gone).is_some() {
            fail(&format!(
                "{gone} is gone: how many deployments and jobs a credential runs at once is set when it is approved, best-peer approve <code> --deployments N --jobs N"
            ));
        }
    }
    let holdings = Arc::new(holdings::Holdings::default());
    let confine = confine(
        std::env::var("BEST_PEER_JOB_MEMORY").ok().as_deref(),
        std::env::var("BEST_PEER_JOB_PIDS").ok().as_deref(),
        std::env::var("BEST_PEER_ENGINE_MEMORY").ok().as_deref(),
        std::env::var("BEST_PEER_ENGINE_PIDS").ok().as_deref(),
    )
    .unwrap_or_else(|why| fail(&why));
    let peer = peer(
        endpoint,
        &engine_host,
        gpu,
        runtime,
        engine,
        log.clone(),
        images,
        patience,
        holdings.clone(),
        confine,
    )
    .await;
    let ctx = Arc::new(context(endpoint, dir, auth.clone(), holdings, cleartext));
    let workspaces = workspace::Workspaces::open(ctx, log);
    if let Some(why) = cleartext_members_refused(&workspaces.cleartext_members()) {
        fail(&why);
    }
    let door = Arc::new(door(peer.clone(), workspaces.clone(), auth.clone()));
    // What the last run accepted and never completed is run now, before anyone can send more: at the root, then in
    // every workspace, whose clouds then start following their members.
    best_peer_door::resume(&door).await;
    workspaces.start().await;
    let n = workspaces.all().len();
    if n > 0 {
        tracing::info!(
            workspaces = n,
            "this door hosts workspaces: their clouds follow their members"
        );
    }
    logged(best_peer_door::router(door).merge(workspaces.router()))
}

/// Every request to the door, the workspaces' included, is one line in the log, as it arrived.
fn logged(app: axum::Router) -> axum::Router {
    app.layer(axum::middleware::from_fn(best_peer_door::router::access_log))
}

/// Serves `app` on `listener`, over TLS when a configuration is given, until `handle` says to stop.
async fn serve_on(
    listener: std::net::TcpListener,
    app: axum::Router,
    tls: Option<Arc<rustls::ServerConfig>>,
    handle: axum_server::Handle<SocketAddr>,
) -> std::io::Result<()> {
    // Each connection's address goes with its requests.
    let service = app.into_make_service_with_connect_info::<SocketAddr>();
    match tls {
        Some(config) => {
            let config = axum_server::tls_rustls::RustlsConfig::from_config(config);
            axum_server::from_tcp_rustls(listener, config)?
                .handle(handle)
                .serve(service)
                .await
        }
        None => axum_server::from_tcp(listener)?.handle(handle).serve(service).await,
    }
}

/// An amount of memory as a person writes it: `40G`, `512M`, `1T`, `40GB`, or bytes.
fn parse_memory(text: &str) -> Result<u64, String> {
    let t = text.trim().to_ascii_uppercase();
    let t = t.strip_suffix('B').unwrap_or(&t);
    let (digits, unit) = match t.chars().last() {
        Some(c) if c.is_ascii_alphabetic() => (&t[..t.len() - 1], Some(c)),
        _ => (t, None),
    };
    let n: u64 = digits
        .parse()
        .map_err(|_| format!("{text:?} is not an amount of memory: write 40G, 512M, 1T or a number of bytes"))?;
    let factor: u64 = match unit {
        None => 1,
        Some('K') => 1 << 10,
        Some('M') => 1 << 20,
        Some('G') => 1 << 30,
        Some('T') => 1 << 40,
        Some(u) => return Err(format!("{u} is not a unit: K, M, G or T")),
    };
    n.checked_mul(factor)
        .ok_or_else(|| format!("{text:?} is more memory than exists"))
}

/// A span of time as a person writes it: `8h`, `30m`, `2d`, `90s`, or seconds.
fn parse_duration(text: &str) -> Result<Duration, String> {
    let t = text.trim().to_ascii_lowercase();
    let (digits, unit) = match t.chars().last() {
        Some(c) if c.is_ascii_alphabetic() => (&t[..t.len() - 1], Some(c)),
        _ => (t.as_str(), None),
    };
    let n: u64 = digits
        .parse()
        .map_err(|_| format!("{text:?} is not a span of time: write 8h, 30m, 2d, 90s or a number of seconds"))?;
    let factor: u64 = match unit {
        None | Some('s') => 1,
        Some('m') => 60,
        Some('h') => 3600,
        Some('d') => 24 * 3600,
        Some(u) => return Err(format!("{u} is not a unit of time: s, m, h or d")),
    };
    match n.checked_mul(factor).map(Duration::from_secs) {
        Some(d) if d.is_zero() => Err(format!("{text:?} is not a span of time above zero")),
        Some(d) if d <= best_peer_door::auth::MAX_EXPIRES => Ok(d),
        _ => Err(format!(
            "{text:?} is longer than a credential may be bounded to: 366d at most"
        )),
    }
}

/// The admin token and the record of the running peer, from the data directory, for the two commands the person at
/// the machine runs; a form posted to the door's `path` with the token as the proof, and the door's answer whatever
/// its status, since a refusal says why in its body.
fn as_the_authority(path: &str, mut form: Vec<(&str, String)>) -> (u16, serde_json::Value) {
    let dir = data_dir();
    let token = std::fs::read_to_string(dir.join("admin-token"))
        .map(|t| t.trim().to_string())
        .unwrap_or_else(|e| {
            fail(&format!(
                "no admin token in {}: is the peer running on this machine with the same BEST_PEER_DATA? ({e})",
                dir.display()
            ))
        });
    let record = tls::Record::read(&dir).unwrap_or_else(|e| {
        fail(&format!(
            "no record of a running peer in {}: is the peer running on this machine with the same BEST_PEER_DATA? ({e})",
            dir.display()
        ))
    });
    let addr = record.dial();
    form.push(("proof", token));
    let body = serde_urlencoded::to_string(&form).unwrap_or_else(|e| fail(&format!("cannot encode the request: {e}")));
    let req = axum::http::Request::post(path)
        .header(axum::http::header::HOST, addr.to_string())
        .header(axum::http::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|e| fail(&format!("cannot make the request: {e}")));
    let runtime = tokio::runtime::Runtime::new().unwrap_or_else(|e| fail(&format!("cannot start: {e}")));
    let (status, answer) = runtime
        .block_on(tls::call(addr, record.certificate.as_deref(), req))
        .unwrap_or_else(|why| fail(&why));
    if status.as_u16() == 403 {
        fail(&format!(
            "the peer refused the admin token in {}: it is not the token of the peer listening on {}",
            dir.display(),
            record.listen
        ));
    }
    (status.as_u16(), answer)
}

/// `best-peer revoke <name>`: takes back every live credential by that connection name or holder id, at once, with
/// this machine's admin token as the proof, the way `approve` admits.
fn revoke(args: &[String]) {
    const USAGE: &str = "usage: best-peer revoke <name>: the connection name the agent signed in under, or the holder id get-workloads and the events show";
    let (Some(name), None) = (args.first(), args.get(1)) else {
        fail(USAGE)
    };
    let (status, answer) = as_the_authority("/auth/revoke", vec![("name", name.clone())]);
    if status != 200 {
        fail(&format!(
            "the peer refused ({status}): {}",
            answer["error_description"].as_str().unwrap_or("no reason given")
        ));
    }
    for c in answer["revoked"].as_array().into_iter().flatten() {
        let who = match c["agent_label"].as_str() {
            Some(l) => format!("{l} ({})", c["client_id"].as_str().unwrap_or("?")),
            None => c["client_id"].as_str().unwrap_or("?").to_string(),
        };
        println!(
            "revoked the credential of {who} as connection {} (holder {}), issued {}: it opens nothing from now on",
            c["name"].as_str().unwrap_or("?"),
            c["holder"].as_str().unwrap_or("?"),
            c["issued_at"].as_str().unwrap_or("?")
        );
    }
}

/// `best-peer approve <code>`: presents this machine's admin token to the peer running on it, for the code the
/// person was shown. The token goes to the listen address only, never to the public endpoint, and over TLS to the
/// certificate the peer serves and no other, when it serves one.
fn approve(args: &[String]) {
    const USAGE: &str = "usage: best-peer approve <code> [--may deploy,jobs,prompt | all] [--memory 40G] [--deployments N] [--jobs N] [--open-jobs] [--expires 8h] [--accelerators-only]: the code the agent showed the person; what the credential may do (all when not said); the most device memory its workloads may hold together (no share when not said); how many deployments and jobs it may run at once across the door (no count when not said); with a share, whether its jobs leave the closed box (no network, a ceiling on host memory) a tenant's job gets; how long the credential lasts, 366d at most, and 8h at most for a session credential (the agent's choice when not said); whether it sees and uses the accelerators alone, never the host's CPU";
    let Some(code) = args.first() else { fail(USAGE) };
    let (mut may, mut memory, mut open_jobs) = (None::<String>, None::<u64>, false);
    let mut expires = None::<Duration>;
    let mut accelerators_only = false;
    let (mut deployments, mut jobs) = (None::<u32>, None::<u32>);
    let count = |flag: &str, text: Option<&String>| -> u32 {
        match text.map(|t| t.trim().parse::<u32>()) {
            Some(Ok(n)) if n > 0 => n,
            _ => fail(&format!("{flag} needs how many at once, 1 or more")),
        }
    };
    let mut rest = args[1..].iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--may" => {
                may = Some(
                    rest.next()
                        .cloned()
                        .unwrap_or_else(|| fail("--may needs the scopes, comma-separated, or all")),
                )
            }
            "--memory" => {
                let amount = rest
                    .next()
                    .unwrap_or_else(|| fail("--memory needs an amount, such as 40G, 512M or a number of bytes"));
                memory = Some(parse_memory(amount).unwrap_or_else(|why| fail(&why)));
            }
            "--expires" => {
                let span = rest.next().unwrap_or_else(|| {
                    fail("--expires needs a span of time, such as 8h, 30m, 2d or a number of seconds")
                });
                expires = Some(parse_duration(span).unwrap_or_else(|why| fail(&why)));
            }
            "--open-jobs" => open_jobs = true,
            "--deployments" => deployments = Some(count("--deployments", rest.next())),
            "--jobs" => jobs = Some(count("--jobs", rest.next())),
            "--accelerators-only" => accelerators_only = true,
            other => fail(&format!("unknown argument {other:?}. {USAGE}")),
        }
    }
    let mut form: Vec<(&str, String)> = vec![("user_code", code.clone())];
    if let Some(m) = &may {
        form.push(("may", m.clone()));
    }
    if let Some(b) = memory {
        form.push(("memory_bytes", b.to_string()));
    }
    if open_jobs {
        if memory.is_none() {
            fail("--open-jobs opens the jobs of a credential with a share, and this one has none: a credential without --memory runs its jobs open already");
        }
        form.push(("open_jobs", "true".into()));
    }
    if let Some(n) = deployments {
        form.push(("deployments", n.to_string()));
    }
    if let Some(n) = jobs {
        form.push(("jobs", n.to_string()));
    }
    if let Some(d) = expires {
        form.push(("expires_in", d.as_secs().to_string()));
    }
    if accelerators_only {
        form.push(("accelerators_only", "true".into()));
    }
    let (status, answer) = as_the_authority("/auth/approve", form);
    if status != 200 {
        fail(&format!(
            "the peer refused ({status}): {}",
            answer["error_description"]
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| format!("is {code} a live code shown by an agent in the last ten minutes?"))
        ));
    }
    println!("{}", admitted_line(&answer["admitted"]));
}

/// The one line `approve` prints for an admission the door answered: who, as which connection, what the credential
/// may do, its share, and how long it lasts.
fn admitted_line(a: &serde_json::Value) -> String {
    let who = match a["agent_label"].as_str() {
        Some(l) => format!("{l} ({})", a["client_id"].as_str().unwrap_or("?")),
        None => a["client_id"].as_str().unwrap_or("?").to_string(),
    };
    let may = match a["grant"]["scopes"].as_array() {
        Some(s) => s.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(","),
        None => "all".into(),
    };
    let mut share = match (
        a["grant"]["memory_bytes"].as_u64(),
        a["grant"]["open_jobs"].as_bool() == Some(true),
    ) {
        (Some(b), false) => format!("{b} bytes of device memory at most, its jobs in the closed box"),
        (Some(b), true) => format!("{b} bytes of device memory at most, its jobs open"),
        (None, _) => "no share set".into(),
    };
    for kind in ["deployments", "jobs"] {
        if let Some(n) = a["grant"][kind].as_u64() {
            share.push_str(&format!(", {n} {kind} at once at most"));
        }
    }
    if a["grant"]["accelerators_only"].as_bool() == Some(true) {
        share.push_str(", on the accelerators alone");
    }
    let lasts = match a["expires_in"].as_u64() {
        Some(s) => format!("ending in {s} s"),
        None => "never ending".into(),
    };
    format!(
        "admitted {who} as connection {} with a {} credential that may {may}, {share}, {lasts}: the agent's next poll gets it",
        a["connection"].as_str().unwrap_or("(the host's name)"),
        a["lifetime"].as_str().unwrap_or("durable")
    )
}

fn fail(why: &str) -> ! {
    eprintln!("{why}");
    std::process::exit(2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{header, Request, StatusCode};
    use best_peer_door::{Envelope, FakeApprover, Filter};
    use best_peer_runtime::{ContainerId, Network};
    use futures::StreamExt;
    use http_body_util::BodyExt;

    #[test]
    fn the_admission_line_says_each_part_of_the_grant_once() {
        let line = admitted_line(&json!({
            "agent_label": "the host proof",
            "client_id": "proof",
            "connection": "proof",
            "lifetime": "durable",
            "grant": { "scopes": ["deploy", "jobs"], "memory_bytes": 1024, "jobs": 2, "accelerators_only": true }
        }));
        assert_eq!(
            line,
            "admitted the host proof (proof) as connection proof with a durable credential that may deploy,jobs, 1024 bytes of device memory at most, its jobs in the closed box, 2 jobs at once at most, on the accelerators alone, never ending: the agent's next poll gets it"
        );
        let plain = admitted_line(&json!({ "client_id": "proof", "expires_in": 60, "grant": {} }));
        assert!(plain.contains("may all, no share set, ending in 60 s"), "{plain}");
        assert!(!plain.contains("accelerators"), "{plain}");
    }

    #[test]
    fn the_hardware_switch_names_its_values_and_none_is_the_host_alone() {
        let host = accelerator(Some("none")).unwrap().snapshot().unwrap();
        assert_eq!(host.devices.len(), 1);
        assert_eq!(host.devices[0].id.0, "cpu-0");
        assert!(host.driver.is_none());
        match accelerator(Some("rocm")) {
            Err(why) => assert!(why.contains("nvml or none"), "{why}"),
            Ok(_) => panic!("an unknown value was accepted"),
        }
    }
    use serde_json::{json, Value};
    use tower::ServiceExt;

    const EP: &str = "http://peer.test";
    const GB: u64 = 1024 * 1024 * 1024;

    struct Bed {
        door: Arc<Door>,
        peer: Arc<Peer>,
        gpu: Arc<best_peer_gpu::Fake>,
        runtime: Arc<best_peer_runtime::Fake>,
        engine: Arc<best_peer_engine::Fake>,
        app: axum::Router,
        key: String,
        /// The data directory the door's workspaces live under, kept for as long as the bed.
        _data: tempfile::TempDir,
    }

    /// One 24 GiB CUDA card.
    fn card() -> Arc<best_peer_gpu::Fake> {
        Arc::new(
            best_peer_gpu::Fake::new()
                .with_driver("fake 1.0")
                .with_device(best_peer_gpu::Fake::cuda_card("gpu-0", "Card A", 24, "12.4")),
        )
    }

    /// A peer over the fakes: the hardware given, a registry that serves the engines' images, and a signed-in
    /// agent. `log` carries a previous run's log across a restart.
    async fn bed(gpu: Arc<best_peer_gpu::Fake>, log: Arc<EventLog>, runtime: Arc<best_peer_runtime::Fake>) -> Bed {
        let engine_host = "engines.local";
        bed_with(
            gpu,
            log,
            runtime,
            Arc::new(best_peer_engine::Fake::new()),
            engine_host,
            None,
        )
        .await
    }

    /// A door in this process behind a test transport: every call to one of the endpoints it knows goes straight
    /// into that door's router, as the network would deliver it; a door switched off refuses the connection.
    #[derive(Default)]
    struct Switchboard {
        doors: std::sync::Mutex<std::collections::HashMap<String, (axum::Router, Arc<std::sync::atomic::AtomicBool>)>>,
    }

    impl Switchboard {
        /// Connects `endpoint` to `router`; the flag switches it off.
        fn connect(&self, endpoint: &str, router: axum::Router) -> Arc<std::sync::atomic::AtomicBool> {
            let down = Arc::new(std::sync::atomic::AtomicBool::new(false));
            self.doors
                .lock()
                .unwrap()
                .insert(endpoint.into(), (router, down.clone()));
            down
        }
    }

    impl transport::Transport for Switchboard {
        fn call(
            &self,
            req: Request<Body>,
        ) -> futures::future::BoxFuture<'static, Result<axum::response::Response, String>> {
            let origin = format!(
                "{}://{}",
                req.uri().scheme_str().unwrap_or("http"),
                req.uri().authority().map(|a| a.as_str()).unwrap_or("")
            );
            let found = self.doors.lock().unwrap().get(&origin).cloned();
            match found {
                Some((_, down)) if down.load(std::sync::atomic::Ordering::SeqCst) => {
                    Box::pin(async { Err("connection refused".to_string()) })
                }
                Some((router, _)) => transport::InProcess { router }.call(req),
                None => Box::pin(async move { Err(format!("no route to {origin}")) }),
            }
        }
    }

    /// The same, with the inference engine given too, and the credentials of a previous run when this bed is a
    /// restart: on a host `Auth::open` reads them back from disk.
    async fn bed_with(
        gpu: Arc<best_peer_gpu::Fake>,
        log: Arc<EventLog>,
        runtime: Arc<best_peer_runtime::Fake>,
        engine: Arc<best_peer_engine::Fake>,
        engine_host: &str,
        auth: Option<Arc<Auth>>,
    ) -> Bed {
        bed_imaging(gpu, log, runtime, engine, engine_host, auth, Images::default()).await
    }

    /// The same, with the operator's say over the engines and on pulling.
    async fn bed_imaging(
        gpu: Arc<best_peer_gpu::Fake>,
        log: Arc<EventLog>,
        runtime: Arc<best_peer_runtime::Fake>,
        engine: Arc<best_peer_engine::Fake>,
        engine_host: &str,
        auth: Option<Arc<Auth>>,
        images: Images,
    ) -> Bed {
        for image in ["ollama/ollama", "vllm/vllm-openai", "busybox", "ollama/ollama:0.6"] {
            runtime.registry_has(best_peer_runtime::ImageRef(image.into()));
        }
        let holdings = Arc::new(holdings::Holdings::default());
        let peer = peer(
            EP,
            engine_host,
            gpu.clone(),
            runtime.clone(),
            engine.clone(),
            log.clone(),
            images,
            Patience {
                ready: Duration::from_secs(1),
                load: Duration::from_secs(1),
                unload: Duration::from_secs(1),
                prompt: Duration::from_secs(1),
            },
            holdings.clone(),
            Confine::default(),
        )
        .await;
        let auth = auth.unwrap_or_else(|| {
            Arc::new(Auth::ephemeral(EP, Box::new(FakeApprover { proof: "ok".into() })).with_scopes(domain::SCOPES))
        });
        let data = tempfile::tempdir().unwrap();
        let workspaces = workspace::Workspaces::open(
            Arc::new(workspace::Context {
                endpoint: EP.into(),
                service: SERVICE.into(),
                dir: data.path().into(),
                auth: auth.clone(),
                transport: Arc::new(Switchboard::default()),
                holdings,
                limits: Arc::new(Limits::default()),
                cleartext: Cleartext::Loopback,
            }),
            log,
        );
        let door = Arc::new(super::door(peer.clone(), workspaces.clone(), auth.clone()));
        best_peer_door::resume(&door).await;
        let app = best_peer_door::router(door.clone()).merge(workspaces.router());
        let key = key(&app).await;
        Bed {
            door,
            peer,
            gpu,
            runtime,
            engine,
            app,
            key,
            _data: data,
        }
    }

    async fn fresh() -> Bed {
        bed(
            card(),
            Arc::new(EventLog::ephemeral()),
            Arc::new(best_peer_runtime::Fake::new(vec!["gpu-0".into()], vec![])),
        )
        .await
    }

    async fn body(res: axum::response::Response) -> Value {
        serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap()
    }

    async fn key(app: &axum::Router) -> String {
        key_with(app, None, None).await
    }

    /// A credential approved with `may` and `memory`, as `best-peer approve --may --memory` would.
    async fn key_with(app: &axum::Router, may: Option<&str>, memory: Option<u64>) -> String {
        key_full(app, may, memory, None, None, false, false).await
    }

    /// The same, held to the accelerators when `accelerators_only`, as `approve --accelerators-only` would.
    async fn key_held(app: &axum::Router, may: Option<&str>, memory: Option<u64>, accelerators_only: bool) -> String {
        key_full(app, may, memory, None, None, false, accelerators_only).await
    }

    /// The same, its jobs opened by the approver when `open_jobs`, as `best-peer approve --open-jobs` would.
    async fn key_opened(app: &axum::Router, may: Option<&str>, memory: Option<u64>, open_jobs: bool) -> String {
        key_full(app, may, memory, None, None, open_jobs, false).await
    }

    /// The same, allowed so many deployments and jobs at once when given, as `approve --deployments --jobs` would.
    async fn key_counted(
        app: &axum::Router,
        may: Option<&str>,
        memory: Option<u64>,
        deployments: Option<u32>,
        jobs: Option<u32>,
    ) -> String {
        key_full(app, may, memory, deployments, jobs, false, false).await
    }

    /// A credential approved with all of `best-peer approve`'s words: `may`, `memory`, the counts, `open_jobs` and
    /// `accelerators_only`.
    async fn key_full(
        app: &axum::Router,
        may: Option<&str>,
        memory: Option<u64>,
        deployments: Option<u32>,
        jobs: Option<u32>,
        open_jobs: bool,
        accelerators_only: bool,
    ) -> String {
        let form = |f: &[(&str, &str)]| {
            Request::post("/auth/device")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(serde_urlencoded::to_string(f).unwrap()))
                .unwrap()
        };
        let a = body(app.clone().oneshot(form(&[("client_id", "test")])).await.unwrap()).await;
        let memory = memory.map(|m| m.to_string());
        let mut fields = vec![("user_code", a["user_code"].as_str().unwrap()), ("proof", "ok")];
        if let Some(m) = may {
            fields.push(("may", m));
        }
        if let Some(m) = &memory {
            fields.push(("memory_bytes", m));
        }
        if open_jobs {
            fields.push(("open_jobs", "true"));
        }
        let (deployments, jobs) = (deployments.map(|n| n.to_string()), jobs.map(|n| n.to_string()));
        if let Some(n) = &deployments {
            fields.push(("deployments", n));
        }
        if let Some(n) = &jobs {
            fields.push(("jobs", n));
        }
        if accelerators_only {
            fields.push(("accelerators_only", "true"));
        }
        let approve = Request::post("/auth/approve")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(serde_urlencoded::to_string(fields).unwrap()))
            .unwrap();
        assert_eq!(app.clone().oneshot(approve).await.unwrap().status(), StatusCode::OK);
        let token = Request::post("/auth/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(
                serde_urlencoded::to_string([
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("device_code", a["device_code"].as_str().unwrap()),
                    ("client_id", "test"),
                ])
                .unwrap(),
            ))
            .unwrap();
        body(app.clone().oneshot(token).await.unwrap()).await["access_token"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// A command as a client sends it to the door at `base` (the root, or a workspace's endpoint on it).
    fn envelope(base: &str, id: &str, r#type: &str, schema: &str, data: Value) -> String {
        json!({
            "specversion": "1.0", "id": id, "source": "https://agent.test", "type": r#type,
            "datacontenttype": "application/json", "dataschema": format!("{base}/commands/{schema}/1.0"),
            "time": "2026-10-12T10:30:00Z", "data": data
        })
        .to_string()
    }

    /// Sends a command to `app` under `prefix` (empty for the root, `/workspaces/<id>` for a workspace) with `key`.
    async fn send_as(
        app: &axum::Router,
        prefix: &str,
        key: &str,
        id: &str,
        r#type: &str,
        schema: &str,
        data: Value,
    ) -> (StatusCode, Value) {
        let req = Request::post(format!("{prefix}/commands"))
            .header("X-Api-Key", key)
            .header(header::CONTENT_TYPE, "application/cloudevents+json")
            .body(Body::from(envelope(&format!("{EP}{prefix}"), id, r#type, schema, data)))
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        (status, body(res).await)
    }

    /// `GET` under `prefix` with `key`: the status and the body.
    async fn get_as(app: &axum::Router, prefix: &str, key: &str, path: &str) -> (StatusCode, Value) {
        let res = app
            .clone()
            .oneshot(
                Request::get(format!("{prefix}{path}"))
                    .header("X-Api-Key", key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = res.status();
        (status, body(res).await)
    }

    /// The events with `correlation` under `prefix`, as the credential reads them, oldest first, once one of type
    /// `until` is among them.
    async fn events_as(app: &axum::Router, prefix: &str, key: &str, correlation: &str, until: &str) -> Vec<Value> {
        let mut last = Vec::new();
        for _ in 0..2000 {
            let (_, b) = get_as(app, prefix, key, &format!("/events?correlationId={correlation}")).await;
            last = b["events"].as_array().cloned().unwrap_or_default();
            if last.iter().any(|e| e["type"] == until) {
                return last;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!(
            "no {until} for {correlation} under {prefix:?}; got {:?}",
            last.iter().map(|e| e["type"].clone()).collect::<Vec<_>>()
        );
    }

    impl Bed {
        /// Sends a command and answers the status and body.
        async fn send(&self, id: &str, r#type: &str, schema: &str, data: Value) -> (StatusCode, Value) {
            send_as(&self.app, "", &self.key, id, r#type, schema, data).await
        }

        async fn query(&self, schema: &str) -> Value {
            let (s, b) = get_as(&self.app, "", &self.key, &format!("/queries/{schema}")).await;
            assert_eq!(s, StatusCode::OK, "{b}");
            b
        }

        fn log_of(&self, correlation: &str) -> Vec<Envelope> {
            self.door
                .log
                .list(&Filter {
                    correlation_id: Some(correlation.into()),
                    ..Default::default()
                })
                .0
        }

        /// The events with `correlation`, oldest first, once one of type `until` is among them.
        async fn events_of(&self, correlation: &str, until: &str) -> Vec<Envelope> {
            for _ in 0..400 {
                let events = self.log_of(correlation);
                if events.iter().any(|e| e.r#type == until) {
                    return events;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            panic!(
                "no {until} for {correlation}; got {:?}",
                types(&self.log_of(correlation))
            );
        }

        async fn deploy(&self, id: &str, model: &str, engine: &str, gb: u64) -> (StatusCode, Value) {
            self.send(
                id,
                "DeployModel",
                "deploy-model",
                json!({ "model": model, "engine": engine, "memory_bytes": gb * GB }),
            )
            .await
        }

        /// Deploys on ollama and waits for ready; answers the deployment id.
        async fn deployed(&self, id: &str, model: &str, gb: u64) -> String {
            let (s, b) = self.deploy(id, model, "ollama", gb).await;
            assert_eq!(s, StatusCode::CREATED, "{b}");
            let events = self.events_of(id, "DeploymentReady").await;
            events.last().unwrap().data["deployment"].as_str().unwrap().to_string()
        }

        fn container_of(&self, deployment: &str) -> ContainerId {
            self.peer.state.lock().unwrap().deployments[deployment]
                .container
                .clone()
        }
    }

    fn types(events: &[Envelope]) -> Vec<String> {
        events.iter().map(|e| e.r#type.clone()).collect()
    }

    fn type_names(events: &[Value]) -> Vec<String> {
        events
            .iter()
            .map(|e| e["type"].as_str().unwrap_or("").to_string())
            .collect()
    }

    // ----- workspaces and clouds ----------------------------------------------------------------------------------

    /// A door that hosts workspaces: a CPU-only machine at the root, member peers in this process reachable through
    /// a switchboard by the endpoints they are known under, and an owner signed in. Its data directory holds the
    /// workspaces' logs and the clouds' credentials, so a second site over the same directory is a restart.
    struct Site {
        app: axum::Router,
        key: String,
        workspaces: Arc<workspace::Workspaces>,
        switchboard: Arc<Switchboard>,
        members: Vec<Bed>,
        down: std::collections::HashMap<String, Arc<std::sync::atomic::AtomicBool>>,
        data: Arc<tempfile::TempDir>,
        auth: Arc<Auth>,
    }

    /// The members as `endpoint => bed`, the bed's own key being what its owner's approval would give the cloud.
    async fn site(members: Vec<(&str, Bed)>) -> Site {
        site_pacing(members, Pace::default()).await
    }

    /// The same, the door taking commands at `pace`.
    async fn site_pacing(members: Vec<(&str, Bed)>, pace: Pace) -> Site {
        site_over(
            members,
            Arc::new(tempfile::tempdir().unwrap()),
            Arc::new(EventLog::ephemeral()),
            None,
            Arc::new(Limits::new(pace, Streams::default())),
        )
        .await
    }

    async fn site_over(
        members: Vec<(&str, Bed)>,
        data: Arc<tempfile::TempDir>,
        log: Arc<EventLog>,
        auth: Option<Arc<Auth>>,
        limits: Arc<Limits>,
    ) -> Site {
        site_under(members, data, log, auth, Cleartext::Loopback, limits).await
    }

    /// The same, under the cleartext rule given, the door holding credentials to `limits`.
    async fn site_under(
        members: Vec<(&str, Bed)>,
        data: Arc<tempfile::TempDir>,
        log: Arc<EventLog>,
        auth: Option<Arc<Auth>>,
        cleartext: Cleartext,
        limits: Arc<Limits>,
    ) -> Site {
        let switchboard = Arc::new(Switchboard::default());
        let mut down = std::collections::HashMap::new();
        let mut beds = Vec::new();
        for (endpoint, bed) in members {
            down.insert(endpoint.to_string(), switchboard.connect(endpoint, bed.app.clone()));
            beds.push(bed);
        }
        let cpu = best_peer_gpu::Device {
            compute: vec![best_peer_gpu::Compute::Cpu],
            ..best_peer_gpu::Fake::cuda_card("cpu-0", "Host", 16, "0")
        };
        let holdings = Arc::new(holdings::Holdings::default());
        let runtime = Arc::new(best_peer_runtime::Fake::new(vec![], vec![]));
        let peer = peer(
            EP,
            "engines.local",
            Arc::new(best_peer_gpu::Fake::new().with_device(cpu)),
            runtime,
            Arc::new(best_peer_engine::Fake::new()),
            log.clone(),
            Images::default(),
            Patience::default(),
            holdings.clone(),
            Confine::default(),
        )
        .await;
        let auth = auth.unwrap_or_else(|| {
            Arc::new(Auth::ephemeral(EP, Box::new(FakeApprover { proof: "ok".into() })).with_scopes(domain::SCOPES))
        });
        let workspaces = workspace::Workspaces::open(
            Arc::new(workspace::Context {
                endpoint: EP.into(),
                service: SERVICE.into(),
                dir: data.path().into(),
                auth: auth.clone(),
                transport: switchboard.clone(),
                holdings,
                limits,
                cleartext,
            }),
            log.clone(),
        );
        let door = Arc::new(super::door(peer.clone(), workspaces.clone(), auth.clone()));
        best_peer_door::resume(&door).await;
        workspaces.start().await;
        let app = best_peer_door::router(door).merge(workspaces.router());
        let key = key(&app).await;
        Site {
            app,
            key,
            workspaces,
            switchboard,
            members: beds,
            down,
            data,
            auth,
        }
    }

    impl Site {
        /// Creates a workspace as the owner; answers its id.
        async fn workspace(&self, id: &str, name: &str) -> String {
            let (s, b) = send_as(
                &self.app,
                "",
                &self.key,
                id,
                "CreateWorkspace",
                "create-workspace",
                json!({ "name": name }),
            )
            .await;
            assert_eq!(s, StatusCode::CREATED, "{b}");
            let events = events_as(&self.app, "", &self.key, id, "WorkspaceCreatedV1").await;
            events.last().unwrap()["data"]["workspace"]
                .as_str()
                .unwrap()
                .to_string()
        }

        /// Configures a cloud as the owner, the members already having admitted it: their credentials are written
        /// where the cloud keeps them, as a restart finds them, so the test needs no console. `members` are
        /// `(peer, endpoint, the member's key)`.
        async fn cloud(&self, ws: &str, id: &str, cloud: &str, members: &[(&str, &str, &str)]) -> Vec<Value> {
            let saved: Vec<cloud::Saved> = members
                .iter()
                .map(|(n, e, k)| cloud::Saved {
                    name: n.to_string(),
                    endpoint: e.to_string(),
                    key: Some(k.to_string()),
                    last_event: None,
                })
                .collect();
            let file = self
                .data
                .path()
                .join("workspaces")
                .join(ws)
                .join("clouds")
                .join(cloud)
                .join("members.json");
            cloud::save_members(&file, &saved).unwrap();
            let list: Vec<Value> = members
                .iter()
                .map(|(n, e, _)| json!({ "peer": n, "endpoint": e }))
                .collect();
            let prefix = format!("/workspaces/{ws}");
            let (s, b) = send_as(
                &self.app,
                &prefix,
                &self.key,
                id,
                "ConfigureCloud",
                "configure-cloud",
                json!({ "cloud": cloud, "members": list }),
            )
            .await;
            assert_eq!(s, StatusCode::CREATED, "{b}");
            events_as(&self.app, &prefix, &self.key, id, "CloudConfiguredV1").await
        }

        async fn send(&self, ws: &str, id: &str, r#type: &str, schema: &str, data: Value) -> (StatusCode, Value) {
            send_as(
                &self.app,
                &format!("/workspaces/{ws}"),
                &self.key,
                id,
                r#type,
                schema,
                data,
            )
            .await
        }

        async fn query(&self, ws: &str, schema: &str) -> Value {
            let (s, b) = get_as(
                &self.app,
                &format!("/workspaces/{ws}"),
                &self.key,
                &format!("/queries/{schema}"),
            )
            .await;
            assert_eq!(s, StatusCode::OK, "{b}");
            b
        }

        async fn events(&self, ws: &str, correlation: &str, until: &str) -> Vec<Value> {
            events_as(&self.app, &format!("/workspaces/{ws}"), &self.key, correlation, until).await
        }

        async fn deploy(
            &self,
            ws: &str,
            id: &str,
            cloud: Option<&str>,
            gb: u64,
            device: Option<&str>,
        ) -> (StatusCode, Value) {
            let mut data = json!({ "model": "llama3.2:3b", "engine": "ollama", "memory_bytes": gb * GB });
            if let Some(c) = cloud {
                data["cloud"] = json!(c);
            }
            if let Some(d) = device {
                data["device"] = json!(d);
            }
            self.send(ws, id, "DeployModel", "deploy-model", data).await
        }

        /// The live cloud behind a name, for a test that squares the state by hand.
        fn live_cloud(&self, ws: &str, cloud: &str) -> Arc<cloud::Cloud> {
            self.workspaces.get(ws).unwrap().cloud_for_test(cloud)
        }
    }

    /// Two members: `a` with a 24 GiB card, `b` with an 8 GiB card, each over the fakes.
    async fn two_members() -> (Bed, Bed) {
        let a = bed(
            card(),
            Arc::new(EventLog::ephemeral()),
            Arc::new(best_peer_runtime::Fake::new(vec!["gpu-0".into()], vec![])),
        )
        .await;
        let small = Arc::new(
            best_peer_gpu::Fake::new()
                .with_driver("fake 1.0")
                .with_device(best_peer_gpu::Fake::cuda_card("gpu-0", "Card B", 8, "12.4")),
        );
        let b = bed(
            small,
            Arc::new(EventLog::ephemeral()),
            Arc::new(best_peer_runtime::Fake::new(vec!["gpu-0".into()], vec![])),
        )
        .await;
        (a, b)
    }

    const A: &str = "https://a.test";
    const B: &str = "https://b.test";

    impl Site {
        /// The workspace's events with `correlation` once `n` of type `until` are among them.
        async fn events_n(&self, ws: &str, correlation: &str, until: &str, n: usize) -> Vec<Value> {
            let mut last = Vec::new();
            for _ in 0..2000 {
                let (_, b) = get_as(
                    &self.app,
                    &format!("/workspaces/{ws}"),
                    &self.key,
                    &format!("/events?correlationId={correlation}&limit=200"),
                )
                .await;
                last = b["events"].as_array().cloned().unwrap_or_default();
                if last.iter().filter(|e| e["type"] == until).count() >= n {
                    return last;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            panic!("not {n} {until} for {correlation}; got {:?}", type_names(&last));
        }

        /// Orders a job of `gb` GiB in cloud `lab`, with `more` merged in, and answers its JobQueued.
        async fn order(&self, ws: &str, id: &str, gb: u64, more: Value) -> Value {
            let mut data = json!({ "cloud": "lab", "image": "busybox", "memory_bytes": gb * GB });
            for (k, v) in more.as_object().into_iter().flatten() {
                data[k] = v.clone();
            }
            let (s, b) = self.send(ws, id, "RunJob", "run-job", data).await;
            assert_eq!(s, StatusCode::CREATED, "{b}");
            self.events(ws, id, "JobQueued").await[0]["data"].clone()
        }
    }

    /// The facts of a correlation, by type, oldest first, with the progress of a pull left out.
    fn facts(events: &[Value]) -> Vec<String> {
        type_names(events)
            .into_iter()
            .filter(|t| !matches!(t.as_str(), "ImagePulling" | "ImagePulled"))
            .collect()
    }

    fn later(seconds: i64) -> time::OffsetDateTime {
        time::OffsetDateTime::now_utc() + time::Duration::seconds(seconds)
    }

    #[tokio::test]
    async fn an_order_with_no_room_waits_its_turn_and_one_that_fits_now_is_not_held_back_by_it() {
        let (a, b) = two_members().await;
        let key_a = a.key.clone();
        let site = site(vec![(A, a), (B, b)]).await;
        let ws = site.workspace("c1", "Research").await;
        site.cloud(&ws, "k1", "lab", &[("a", A, &key_a)]).await;
        let lab = site.live_cloud(&ws, "lab");

        // 20 GiB of the 24 is taken and placed at once: the order whole, where it went, then the job, naming it.
        let first = site.order(&ws, "j1", 20, json!({ "args": ["sleep", "100"] })).await;
        assert_eq!(first["waiting"], false);
        assert_eq!(first["attempt"], 1);
        assert_eq!(first["args"], json!(["sleep", "100"]));
        let events = site.events(&ws, "j1", "JobStarted").await;
        assert_eq!(facts(&events), ["JobQueued", "JobPlaced", "JobStarted"]);
        assert_eq!(events[1]["data"]["peer"], "a");
        assert_eq!(events[1]["data"]["device"], "lab/a/gpu-0");
        let started = events.last().unwrap()["data"].clone();
        assert_eq!(started["order"], first["job"]);

        // 10 GiB has no room beside it, where room can come free: taken, and it waits.
        let waits = site.order(&ws, "j2", 10, json!({})).await;
        assert_eq!(waits["waiting"], true);
        assert!(waits["reason"].as_str().unwrap().contains("as soon as"), "{waits}");
        // 4 GiB fits beside the first now: placed ahead of the order that waits, which holds it back not.
        assert_eq!(site.order(&ws, "j3", 4, json!({})).await["waiting"], false);
        site.events(&ws, "j3", "JobStarted").await;
        let w = site.query(&ws, "get-workloads").await;
        assert_eq!(w["queued"].as_array().unwrap().len(), 1, "{w}");
        assert_eq!(w["queued"][0]["job"], waits["job"]);
        assert_eq!(w["queued"][0]["waiting"], true);
        assert_eq!(
            w["held_bytes"],
            34 * GB,
            "the order that waits counts against what its credential holds"
        );
        // 30 GiB fits on no device of the cloud, whatever comes free: refused at once, as before.
        let (s, b) = site
            .send(
                &ws,
                "j4",
                "RunJob",
                "run-job",
                json!({ "cloud": "lab", "image": "busybox", "memory_bytes": 30 * GB }),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        assert_eq!(b["error"]["code"], "INSUFFICIENT_MEMORY");

        // The first ends: the order that waited is placed.
        let container = ContainerId(started["container"].as_str().unwrap().into());
        site.members[0].runtime.stop(&container).await.unwrap();
        site.events(&ws, "j1", "JobFinished").await;
        lab.step(later(0)).await;
        let events = site.events(&ws, "j2", "JobStarted").await;
        assert_eq!(facts(&events), ["JobQueued", "JobPlaced", "JobStarted"]);
        assert_eq!(events.last().unwrap()["data"]["order"], waits["job"]);
        assert_eq!(site.query(&ws, "get-workloads").await["queued"], json!([]));
    }

    #[tokio::test]
    async fn an_order_waiting_past_its_queue_seconds_ends_unplaced_and_a_job_past_its_deadline_is_stopped() {
        let (a, b) = two_members().await;
        let key_a = a.key.clone();
        let site = site(vec![(A, a), (B, b)]).await;
        let ws = site.workspace("c1", "Research").await;
        site.cloud(&ws, "k1", "lab", &[("a", A, &key_a)]).await;
        let lab = site.live_cloud(&ws, "lab");
        let runs = site.order(&ws, "j1", 20, json!({ "deadline_seconds": 60 })).await;
        site.events(&ws, "j1", "JobStarted").await;
        let bounded = site.order(&ws, "j2", 10, json!({ "queue_seconds": 60 })).await;
        assert_eq!(bounded["waiting"], true);
        assert_eq!(bounded["queue_seconds"], 60);
        let unbounded = site.order(&ws, "j3", 10, json!({})).await;

        // Within both bounds nothing happens.
        lab.step(later(30)).await;
        assert_eq!(facts(&site.events(&ws, "j2", "JobQueued").await), ["JobQueued"]);
        assert_eq!(
            facts(&site.events(&ws, "j1", "JobStarted").await),
            ["JobQueued", "JobPlaced", "JobStarted"]
        );

        // Past them: the order that waited ends never placed, and the job that ran too long is stopped.
        lab.step(later(120)).await;
        let failed = site.events(&ws, "j2", "JobFailed").await;
        assert_eq!(facts(&failed), ["JobQueued", "JobFailed"]);
        let failed = &failed.last().unwrap()["data"];
        assert_eq!(failed["job"], bounded["job"]);
        assert!(failed["reason"].as_str().unwrap().contains("never placed"), "{failed}");
        let stopped = site.events(&ws, "j1", "JobStopped").await;
        let stopped = &stopped.last().unwrap()["data"];
        assert!(
            stopped["reason"].as_str().unwrap().contains("deadline_seconds"),
            "{stopped}"
        );
        assert_eq!(stopped["peer"], "a");
        let door = site.workspaces.get(&ws).unwrap().door().clone();
        assert!(
            door.log.unfinished().iter().all(|u| u.envelope.id != "j2"),
            "the order that ended unplaced completed its command"
        );
        // The stopped job freed the card: the order with no bound is placed.
        lab.step(later(120)).await;
        let placed = site.events(&ws, "j3", "JobStarted").await;
        assert_eq!(placed.last().unwrap()["data"]["order"], unbounded["job"]);
        assert_eq!(runs["deadline_seconds"], 60);
    }

    #[tokio::test]
    async fn an_order_that_names_no_wait_waits_a_day_at_most() {
        let (a, b) = two_members().await;
        let key_a = a.key.clone();
        let site = site(vec![(A, a), (B, b)]).await;
        let ws = site.workspace("c1", "Research").await;
        site.cloud(&ws, "k1", "lab", &[("a", A, &key_a)]).await;
        let lab = site.live_cloud(&ws, "lab");
        site.order(&ws, "j1", 20, json!({})).await;
        site.events(&ws, "j1", "JobStarted").await;
        let waits = site.order(&ws, "j2", 10, json!({})).await;
        assert_eq!(waits["waiting"], true);
        assert_eq!(waits["queue_seconds"], 86400, "a day, told on the order");

        lab.step(later(86400 - 60)).await;
        assert_eq!(facts(&site.events(&ws, "j2", "JobQueued").await), ["JobQueued"]);
        lab.step(later(86400 + 60)).await;
        let failed = site.events(&ws, "j2", "JobFailed").await;
        let failed = &failed.last().unwrap()["data"];
        assert_eq!(failed["job"], waits["job"]);
        assert!(failed["reason"].as_str().unwrap().contains("(86400 s)"), "{failed}");
        assert_eq!(site.query(&ws, "get-workloads").await["queued"], json!([]));
    }

    #[tokio::test]
    async fn stop_job_ends_an_order_that_waits_before_it_started_and_a_running_one_by_its_order_id() {
        let (a, b) = two_members().await;
        let key_a = a.key.clone();
        let site = site(vec![(A, a), (B, b)]).await;
        let ws = site.workspace("c1", "Research").await;
        site.cloud(&ws, "k1", "lab", &[("a", A, &key_a)]).await;
        let runs = site.order(&ws, "j1", 20, json!({})).await;
        site.events(&ws, "j1", "JobStarted").await;
        let waits = site.order(&ws, "j2", 10, json!({})).await;
        let job = waits["job"].as_str().unwrap();

        let (s, b) = site.send(&ws, "s1", "StopJob", "stop-job", json!({ "job": job })).await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let stopped = site.events(&ws, "s1", "JobStopped").await;
        assert_eq!(stopped[0]["data"]["job"], job);
        assert_eq!(stopped[0]["data"]["reason"], "stopped before it started");
        assert_eq!(
            facts(&site.events(&ws, "j2", "JobStopped").await),
            ["JobQueued", "JobStopped"],
            "the order ends under its own correlation too"
        );
        let door = site.workspaces.get(&ws).unwrap().door().clone();
        assert!(
            door.log.unfinished().iter().all(|u| u.envelope.id != "j2"),
            "its command is complete"
        );
        let w = site.query(&ws, "get-workloads").await;
        assert_eq!(w["queued"], json!([]));
        assert_eq!(w["held_bytes"], 20 * GB, "what it was promised is free");

        // A running order is stopped by its order's id as by its job's.
        let (s, b) = site
            .send(&ws, "s2", "StopJob", "stop-job", json!({ "job": runs["job"] }))
            .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        site.events(&ws, "s2", "JobStopped").await;
        assert_eq!(site.query(&ws, "get-workloads").await["jobs"], json!([]));
    }

    #[tokio::test]
    async fn every_device_says_the_isolation_it_offers_and_a_workload_asking_for_more_is_refused_with_the_fix() {
        let docker = bed(
            card(),
            Arc::new(EventLog::ephemeral()),
            Arc::new(best_peer_runtime::Fake::new(vec!["gpu-0".into()], vec![])),
        )
        .await;
        let hs = docker.query("get-hardware-state").await;
        assert_eq!(hs["devices"][0]["isolation"], "container", "{hs}");

        let deploy = |isolation: &str| json!({ "model": "a:7b", "engine": "ollama", "memory_bytes": GB, "isolation": isolation });
        let (s, b) = docker
            .send("d1", "DeployModel", "deploy-model", deploy("user-namespace"))
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        assert_eq!(b["error"]["code"], "ISOLATION_UNAVAILABLE");
        assert_eq!(b["error"]["details"]["field"], "isolation");
        assert_eq!(b["error"]["details"]["offered"], json!(["container"]));
        let message = b["error"]["message"].as_str().unwrap();
        assert!(
            message.starts_with("it asks for user-namespace isolation and this peer offers container"),
            "{message}"
        );
        assert!(message.contains("rootless"), "{message}");
        let (s, b) = docker
            .send(
                "j1",
                "RunJob",
                "run-job",
                json!({ "image": "busybox", "isolation": "vm" }),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        assert!(b["error"]["message"]
            .as_str()
            .unwrap()
            .contains("no peer runs a workload in a virtual machine yet"));
        // What is offered, or less, is met.
        let (s, b) = docker
            .send("d2", "DeployModel", "deploy-model", deploy("container"))
            .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let (s, b) = docker
            .send(
                "d3",
                "DeployModel",
                "deploy-model",
                json!({ "model": "b:7b", "engine": "ollama", "memory_bytes": GB }),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");

        // A container engine that runs rootless offers a user namespace, and the same ask is met.
        let rootless = bed(
            card(),
            Arc::new(EventLog::ephemeral()),
            Arc::new(
                best_peer_runtime::Fake::new(vec!["gpu-0".into()], vec![])
                    .with_isolation(best_peer_runtime::Isolation::UserNamespace),
            ),
        )
        .await;
        assert_eq!(
            rootless.query("get-hardware-state").await["devices"][0]["isolation"],
            "user-namespace"
        );
        let (s, b) = rootless
            .send("d1", "DeployModel", "deploy-model", deploy("user-namespace"))
            .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
    }

    #[tokio::test]
    async fn a_cloud_places_a_workload_only_on_a_device_that_offers_the_isolation_it_asks_for() {
        let a = bed(
            card(),
            Arc::new(EventLog::ephemeral()),
            Arc::new(best_peer_runtime::Fake::new(vec!["gpu-0".into()], vec![])),
        )
        .await;
        let small = Arc::new(
            best_peer_gpu::Fake::new()
                .with_driver("fake 1.0")
                .with_device(best_peer_gpu::Fake::cuda_card("gpu-0", "Card B", 8, "12.4")),
        );
        let b = bed(
            small,
            Arc::new(EventLog::ephemeral()),
            Arc::new(
                best_peer_runtime::Fake::new(vec!["gpu-0".into()], vec![])
                    .with_isolation(best_peer_runtime::Isolation::UserNamespace),
            ),
        )
        .await;
        let (key_a, key_b) = (a.key.clone(), b.key.clone());
        let site = site(vec![(A, a), (B, b)]).await;
        let ws = site.workspace("c1", "Research").await;
        site.cloud(&ws, "k1", "lab", &[("a", A, &key_a), ("b", B, &key_b)])
            .await;
        let hs = site.query(&ws, "get-hardware-state").await;
        let offered: Vec<(String, String)> = hs["devices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| {
                (
                    d["id"].as_str().unwrap().into(),
                    d["isolation"].as_str().unwrap().into(),
                )
            })
            .collect();
        assert_eq!(
            offered,
            [
                ("lab/a/gpu-0".to_string(), "container".to_string()),
                ("lab/b/gpu-0".to_string(), "user-namespace".to_string())
            ]
        );

        // Asking for a user namespace goes to b, though a has more room; asking nothing goes where the room is.
        site.order(&ws, "j1", 4, json!({ "isolation": "user-namespace" })).await;
        let started = site.events(&ws, "j1", "JobStarted").await;
        assert_eq!(started.last().unwrap()["data"]["peer"], "b");
        site.order(&ws, "j2", 4, json!({})).await;
        assert_eq!(
            site.events(&ws, "j2", "JobStarted").await.last().unwrap()["data"]["peer"],
            "a"
        );
        // More than any device offering it could hold: refused, though a could hold it.
        let (s, e) = site
            .send(
                &ws,
                "j3",
                "RunJob",
                "run-job",
                json!({ "cloud": "lab", "image": "busybox", "memory_bytes": 10 * GB, "isolation": "user-namespace" }),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{e}");
        assert_eq!(e["error"]["code"], "INSUFFICIENT_MEMORY");
        // A level no member offers: refused with what the members offer.
        let (s, e) = site
            .send(
                &ws,
                "d1",
                "DeployModel",
                "deploy-model",
                json!({ "cloud": "lab", "model": "a:7b", "engine": "ollama", "memory_bytes": GB, "isolation": "vm" }),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{e}");
        assert_eq!(e["error"]["code"], "ISOLATION_UNAVAILABLE");
        assert_eq!(e["error"]["details"]["offered"], json!(["container", "user-namespace"]));
        let said = e["error"]["message"].as_str().unwrap();
        assert!(
            said.starts_with("it asks for vm isolation and cloud lab's members offer container, user-namespace: "),
            "{said}"
        );
        // A job with no device asking for a user namespace runs on the member that offers it.
        let (s, b) = site
            .send(
                &ws,
                "j4",
                "RunJob",
                "run-job",
                json!({ "cloud": "lab", "image": "busybox", "isolation": "user-namespace" }),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        assert_eq!(
            site.events(&ws, "j4", "JobStarted").await.last().unwrap()["data"]["peer"],
            "b"
        );
    }

    #[tokio::test]
    async fn an_order_asking_for_a_user_namespace_waits_for_the_member_that_offers_it_though_another_has_room() {
        let a = bed(
            card(),
            Arc::new(EventLog::ephemeral()),
            Arc::new(best_peer_runtime::Fake::new(vec!["gpu-0".into()], vec![])),
        )
        .await;
        let small = Arc::new(
            best_peer_gpu::Fake::new()
                .with_driver("fake 1.0")
                .with_device(best_peer_gpu::Fake::cuda_card("gpu-0", "Card B", 8, "12.4")),
        );
        let b = bed(
            small,
            Arc::new(EventLog::ephemeral()),
            Arc::new(
                best_peer_runtime::Fake::new(vec!["gpu-0".into()], vec![])
                    .with_isolation(best_peer_runtime::Isolation::UserNamespace),
            ),
        )
        .await;
        let (key_a, key_b) = (a.key.clone(), b.key.clone());
        let site = site(vec![(A, a), (B, b)]).await;
        let ws = site.workspace("c1", "Research").await;
        site.cloud(&ws, "k1", "lab", &[("a", A, &key_a), ("b", B, &key_b)])
            .await;
        let lab = site.live_cloud(&ws, "lab");
        site.order(&ws, "j1", 4, json!({ "isolation": "user-namespace" })).await;
        let first = site.events(&ws, "j1", "JobStarted").await.last().unwrap()["data"].clone();
        assert_eq!(first["peer"], "b");
        // 6 GiB more does not fit b now; a has the room and not the isolation: the order waits for b.
        let waits = site.order(&ws, "j2", 6, json!({ "isolation": "user-namespace" })).await;
        assert_eq!(waits["waiting"], true);
        assert_eq!(waits["isolation"], "user-namespace", "the ask is on the order");
        lab.step(later(0)).await;
        assert_eq!(
            facts(&site.events(&ws, "j2", "JobQueued").await),
            ["JobQueued"],
            "not placed on a"
        );
        // b's job ends: the order is placed there.
        let container = ContainerId(first["container"].as_str().unwrap().into());
        site.members[1].runtime.stop(&container).await.unwrap();
        site.events(&ws, "j1", "JobFinished").await;
        lab.step(later(0)).await;
        let placed = site.events(&ws, "j2", "JobStarted").await;
        assert_eq!(placed.last().unwrap()["data"]["peer"], "b");
    }

    #[tokio::test]
    async fn a_member_that_says_nothing_of_isolation_offers_a_process_and_is_refused_for_more() {
        use axum::routing::get;
        let (a, b) = two_members().await;
        let site = site(vec![(A, a), (B, b)]).await;
        // A member from before isolation was reported: its devices say nothing of it.
        const OLD: &str = "https://old.test";
        let old = axum::Router::new()
            .route(
                "/queries/get-workloads",
                get(|| async { axum::Json(json!({ "deployments": [], "jobs": [] })) }),
            )
            .route(
                "/queries/get-hardware-state",
                get(|| async {
                    axum::Json(json!({ "driver": "fake 1.0", "observed_at": "2026-10-19T00:00:00Z", "devices": [
                        { "id": "gpu-0", "vendor": "nvidia", "name": "Old card", "memory": { "total_bytes": 24 * GB, "free_bytes": 24 * GB }, "compute": [{ "api": "cuda", "version": "12.4" }] }
                    ] }))
                }),
            );
        let old_down = site.switchboard.connect(OLD, old);
        let ws = site.workspace("c1", "Research").await;
        site.cloud(&ws, "k1", "lab", &[("old", OLD, "a-key")]).await;
        let hs = site.query(&ws, "get-hardware-state").await;
        assert_eq!(hs["devices"][0]["id"], "lab/old/gpu-0", "{hs}");
        assert_eq!(hs["devices"][0]["isolation"], "process");
        let (s, e) = site
            .send(
                &ws,
                "j1",
                "RunJob",
                "run-job",
                json!({ "cloud": "lab", "image": "busybox", "memory_bytes": GB, "isolation": "container" }),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{e}");
        assert_eq!(e["error"]["code"], "ISOLATION_UNAVAILABLE");
        assert_eq!(e["error"]["details"]["offered"], json!(["process"]));
        // No member answers: nothing to judge the ask by, and the refusal says why nothing can run.
        old_down.store(true, std::sync::atomic::Ordering::SeqCst);
        let (s, e) = site
            .send(
                &ws,
                "j2",
                "RunJob",
                "run-job",
                json!({ "cloud": "lab", "image": "busybox", "isolation": "container" }),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{e}");
        assert_eq!(e["error"]["code"], "NO_PEER");
    }

    #[tokio::test]
    async fn an_order_its_member_fails_before_it_started_ends_by_the_orders_id() {
        let (a, b) = two_members().await;
        let key_a = a.key.clone();
        let site = site(vec![(A, a), (B, b)]).await;
        let ws = site.workspace("c1", "Research").await;
        site.cloud(&ws, "k1", "lab", &[("a", A, &key_a)]).await;
        // The member cannot pull the image: it fails the job under its own id, which the caller never saw.
        let order = site.order(&ws, "j1", 4, json!({ "image": "nobody/nothing:1" })).await;
        let events = site.events(&ws, "j1", "JobFailed").await;
        assert_eq!(facts(&events), ["JobQueued", "JobPlaced", "JobFailed"]);
        let failed = &events.last().unwrap()["data"];
        assert_eq!(failed["job"], order["job"], "the order ended, by its own id");
        assert_eq!(failed["peer"], "a");
        let w = site.query(&ws, "get-workloads").await;
        assert_eq!(w["queued"], json!([]), "it no longer waits, nor is it held");
        assert_eq!(w["held_bytes"], 0);
        let door = site.workspaces.get(&ws).unwrap().door().clone();
        assert!(door.log.unfinished().iter().all(|u| u.envelope.id != "j1"));
    }

    #[tokio::test]
    async fn an_order_stopped_after_it_was_sent_is_stopped_on_the_member_when_it_starts_there() {
        let (a, b) = two_members().await;
        let key_a = a.key.clone();
        let site = site(vec![(A, a), (B, b)]).await;
        let ws = site.workspace("c1", "Research").await;
        site.cloud(&ws, "k1", "lab", &[("a", A, &key_a)]).await;
        // The member holds the pull, so the order is sent and not started when the stop comes.
        let gate = site.members[0].runtime.hold_pulls();
        let order = site.order(&ws, "j1", 4, json!({})).await;
        site.events(&ws, "j1", "JobPlaced").await;
        let (s, b) = site
            .send(&ws, "s1", "StopJob", "stop-job", json!({ "job": order["job"] }))
            .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        site.events(&ws, "s1", "JobStopped").await;
        // The member pulls on and starts it all the same, telling the pull first: the cloud stops it there.
        gate.add_permits(1);
        let member = &site.members[0];
        for _ in 0..400 {
            let stopped = member.door.log.list(&Filter {
                r#type: Some("JobStopped".into()),
                ..Default::default()
            });
            if !stopped.0.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            member.runtime.running().await.unwrap().is_empty(),
            "nothing of it runs on the member"
        );
        assert_eq!(
            facts(&site.events(&ws, "j1", "JobStopped").await),
            ["JobQueued", "JobPlaced", "JobStopped"],
            "the member's facts about it are not told"
        );
        assert_eq!(site.query(&ws, "get-workloads").await["jobs"], json!([]));
    }

    #[tokio::test]
    async fn a_member_lost_under_an_order_queues_it_again_once_and_the_second_time_it_fails() {
        let (a, b) = two_members().await;
        let (key_a, key_b) = (a.key.clone(), b.key.clone());
        let site = site(vec![(A, a), (B, b)]).await;
        let ws = site.workspace("c1", "Research").await;
        site.cloud(&ws, "k1", "lab", &[("a", A, &key_a), ("b", B, &key_b)])
            .await;
        let lab = site.live_cloud(&ws, "lab");
        let order = site.order(&ws, "j1", 4, json!({})).await;
        let first = site.events(&ws, "j1", "JobStarted").await;
        let first = first.last().unwrap()["data"].clone();
        assert_eq!(first["peer"], "a", "the device with the most room");

        // a is lost: the order waits again, attempt 2, instead of the job it had there, and runs on b.
        site.down[A].store(true, std::sync::atomic::Ordering::SeqCst);
        lab.reconcile().await;
        let events = site.events_n(&ws, "j1", "JobQueued", 2).await;
        let again = events.iter().filter(|e| e["type"] == "JobQueued").nth(1).unwrap()["data"].clone();
        assert_eq!(again["job"], order["job"]);
        assert_eq!(again["attempt"], 2);
        assert_eq!(again["instead_of"], first["job"]);
        assert!(
            again["reason"].as_str().unwrap().contains("peer a is unreachable"),
            "{again}"
        );
        lab.step(later(0)).await;
        let events = site.events_n(&ws, "j1", "JobStarted", 2).await;
        let second = events.iter().filter(|e| e["type"] == "JobStarted").nth(1).unwrap()["data"].clone();
        assert_eq!(second["peer"], "b");
        assert_eq!(second["order"], order["job"]);
        assert!(
            !events.iter().any(|e| e["type"] == "JobFailed"),
            "{:?}",
            type_names(&events)
        );

        // b is lost too: it was queued again once already, so it fails.
        site.down[B].store(true, std::sync::atomic::Ordering::SeqCst);
        lab.reconcile().await;
        let events = site.events(&ws, "j1", "JobFailed").await;
        let failed = &events.last().unwrap()["data"];
        assert_eq!(failed["job"], second["job"]);
        assert!(
            failed["reason"].as_str().unwrap().contains("queued again once already"),
            "{failed}"
        );
        assert_eq!(site.query(&ws, "get-workloads").await["queued"], json!([]));
    }

    #[tokio::test]
    async fn a_door_restarted_under_a_running_job_tells_its_end_and_places_what_waited() {
        let (a, b) = two_members().await;
        let (key_a, key_b) = (a.key.clone(), b.key.clone());
        let data = Arc::new(tempfile::tempdir().unwrap());
        let log = Arc::new(EventLog::ephemeral());
        let first = site_over(
            vec![(A, a), (B, b)],
            data.clone(),
            log.clone(),
            None,
            Arc::new(Limits::default()),
        )
        .await;
        let ws = first.workspace("c1", "Research").await;
        first
            .cloud(&ws, "k1", "lab", &[("a", A, &key_a), ("b", B, &key_b)])
            .await;
        first.order(&ws, "j1", 20, json!({})).await;
        let started = first.events(&ws, "j1", "JobStarted").await.last().unwrap()["data"].clone();
        let waits = first.order(&ws, "j2", 20, json!({})).await;
        assert_eq!(waits["waiting"], true, "a has 4 GiB left and b has 8");
        let owner = first.key.clone();
        let (auth, members) = (first.auth.clone(), first.members);
        first.workspaces.get(&ws).unwrap().cloud_for_test("lab").halt();
        drop(first.app);
        drop(first.workspaces);
        drop(first.switchboard);

        let again = site_over(Vec::new(), data.clone(), log, Some(auth), Arc::new(Limits::default())).await;
        for (endpoint, bed) in [(A, &members[0]), (B, &members[1])] {
            again.switchboard.connect(endpoint, bed.app.clone());
        }
        let again = Site { key: owner, ..again };
        let w = again.query(&ws, "get-workloads").await;
        assert_eq!(w["jobs"][0]["job"], started["job"], "{w}");
        assert_eq!(w["queued"][0]["job"], waits["job"], "the order still waits");

        // The job ends after the restart: its end is told, with its exit code, not failed.
        let container = ContainerId(started["container"].as_str().unwrap().into());
        members[0].runtime.stop(&container).await.unwrap();
        let events = again.events(&ws, "j1", "JobFinished").await;
        assert_eq!(events.last().unwrap()["data"]["exit_code"], 0);
        assert!(
            !events.iter().any(|e| e["type"] == "JobFailed"),
            "{:?}",
            type_names(&events)
        );
        // And the order that waited across the restart is placed in the room it left.
        again.live_cloud(&ws, "lab").step(later(0)).await;
        let placed = again.events(&ws, "j2", "JobStarted").await;
        assert_eq!(placed.last().unwrap()["data"]["order"], waits["job"]);
        assert_eq!(
            facts(&placed),
            ["JobQueued", "JobPlaced", "JobStarted"],
            "nothing told twice"
        );
    }

    #[tokio::test]
    async fn two_workspaces_on_one_door_each_hold_a_cloud_one_machine_serves_both_and_each_sees_places_on_and_hears_only_its_own(
    ) {
        let (a, b) = two_members().await;
        let (key_a, key_b) = (a.key.clone(), b.key.clone());
        let site = site(vec![(A, a), (B, b)]).await;

        // The root is a multi-tenant host: the template, the root service with its own authentication block, and
        // its own surface still there, the machine's.
        let (s, m) = get_as(&site.app, "", "", "/.well-known/best").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(
            m["best"]["tenants"]["manifest"],
            format!("{EP}/.well-known/best/{{tenantId}}")
        );
        assert_eq!(m["best"]["services"][SERVICE]["authentication"]["type"], "apiKey");
        assert_eq!(m["best"]["services"][SERVICE]["http"]["endpoint"], EP);
        let (s, c) = get_as(&site.app, "", &site.key, "/commands").await;
        assert_eq!(s, StatusCode::OK);
        let root_types: Vec<&str> = c["commands"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x["commandType"].as_str().unwrap())
            .collect();
        assert!(
            root_types.contains(&"CreateWorkspace") && root_types.contains(&"DeployModel"),
            "{root_types:?}"
        );
        assert!(
            !root_types.contains(&"ConfigureCloud"),
            "a cloud belongs to a workspace: {root_types:?}"
        );
        let (s, w) = get_as(&site.app, "", &site.key, "/queries/get-workspaces").await;
        assert_eq!(s, StatusCode::OK, "{w}");
        assert_eq!(w["identity"].as_str().unwrap().len(), 16);
        assert_eq!(w["workspaces"], json!([]));

        // Two workspaces, each with a cloud; machine a serves both.
        let ws1 = site.workspace("c1", "Research").await;
        let ws2 = site.workspace("c2", "Ops").await;
        assert!(ws1.starts_with("ws-") && ws1 != ws2);
        let (s, w) = get_as(&site.app, "", &site.key, "/queries/get-workspaces").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(w["workspaces"].as_array().unwrap().len(), 2);
        let first = &w["workspaces"][0];
        assert_eq!(first["role"], "owner");
        assert_eq!(
            first["endpoint"],
            format!("{EP}/workspaces/{}", first["workspace"].as_str().unwrap())
        );
        assert_eq!(
            first["manifest"],
            format!("{EP}/.well-known/best/{}", first["workspace"].as_str().unwrap())
        );
        assert_eq!(first["members"][0]["identity"], w["identity"]);
        // The tenant manifest: self-contained, the workspace's endpoint, no tenants block, the same sign-in.
        let (s, tm) = get_as(&site.app, "", "", &format!("/.well-known/best/{ws1}")).await;
        assert_eq!(s, StatusCode::OK, "{tm}");
        assert_eq!(
            tm["best"]["services"][SERVICE]["http"]["endpoint"],
            format!("{EP}/workspaces/{ws1}")
        );
        assert!(tm["best"].get("tenants").is_none());
        assert_eq!(
            tm["best"]["authentication"]["deviceAuthorizationUrl"],
            format!("{EP}/auth/device")
        );
        assert!(!tm.to_string().contains("{tenantId}"));
        let (s, e) = get_as(&site.app, "", "", "/.well-known/best/ws-nobody").await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert_eq!(e["error"]["code"], "NO_SUCH_WORKSPACE");
        assert!(e["error"]["message"].as_str().unwrap().contains("get-workspaces"));

        let configured = site
            .cloud(&ws1, "k1", "lab", &[("a", A, &key_a), ("b", B, &key_b)])
            .await;
        assert_eq!(type_names(&configured), ["CloudConfiguredV1"]);
        assert_eq!(configured[0]["data"]["workspace"], ws1);
        assert_eq!(configured[0]["data"]["members"][1]["peer"], "b");
        assert_eq!(
            configured[0]["dataschema"],
            format!("{EP}/workspaces/{ws1}/events/cloud-configured/1.0")
        );
        site.cloud(&ws2, "k2", "ops-pool", &[("a", A, &key_a)]).await;

        // Each workspace lists its own cloud and its own devices, as cloud/peer/device, and nothing of the other's.
        let clouds = site.query(&ws1, "get-clouds").await;
        assert_eq!(clouds["clouds"].as_array().unwrap().len(), 1);
        assert_eq!(clouds["clouds"][0]["cloud"], "lab");
        assert_eq!(clouds["clouds"][0]["archived"], false);
        assert_eq!(clouds["clouds"][0]["peers"][0]["state"], "up");
        let hs1 = site.query(&ws1, "get-hardware-state").await;
        let ids: Vec<&str> = hs1["devices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["lab/a/gpu-0", "lab/b/gpu-0"]);
        assert_eq!(hs1["devices"][0]["cloud"], "lab");
        assert_eq!(hs1["devices"][0]["peer"], "a");
        assert_eq!(hs1["peers"][0]["cloud"], "lab");
        assert_eq!(hs1["peers"][1]["peer"], "b");
        let hs2 = site.query(&ws2, "get-hardware-state").await;
        let ids: Vec<&str> = hs2["devices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["ops-pool/a/gpu-0"]);
        assert_eq!(site.query(&ws2, "get-clouds").await["clouds"][0]["cloud"], "ops-pool");
        // The root is still the machine itself.
        let (_, root_hs) = get_as(&site.app, "", &site.key, "/queries/get-hardware-state").await;
        assert_eq!(root_hs["devices"][0]["id"], "cpu-0");

        // A deploy in the first workspace lands on its cloud; every fact names the cloud and the peer, and the
        // endpoint is on the workspace's door.
        let (s, b) = site.deploy(&ws1, "d1", Some("lab"), 16, None).await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let events = site.events(&ws1, "d1", "DeploymentReady").await;
        assert_eq!(
            type_names(&events),
            [
                "ImagePulling",
                "ImagePulling",
                "ImagePulled",
                "DeploymentStarted",
                "WeightsLoading",
                "WeightsLoading",
                "DeploymentReady"
            ],
            "{events:#?}"
        );
        assert!(
            events
                .iter()
                .all(|e| e["data"]["cloud"] == "lab" && e["data"]["peer"] == "a"),
            "{events:#?}"
        );
        assert!(events.iter().all(|e| e["dataschema"]
            .as_str()
            .unwrap()
            .starts_with(&format!("{EP}/workspaces/{ws1}/"))));
        let started = &events[3]["data"];
        assert_eq!(started["device"], "lab/a/gpu-0");
        let dep = started["deployment"].as_str().unwrap().to_string();
        assert_eq!(events[6]["type"], "DeploymentReady");
        assert_eq!(events[6]["data"]["peer"], "a", "the ready fact names the member");
        assert!(
            events[6]["data"].get("endpoint").is_none(),
            "nothing of the engine is on the door"
        );
        let w1 = site.query(&ws1, "get-workloads").await;
        assert_eq!(w1["deployments"][0]["cloud"], "lab");
        assert_eq!(w1["deployments"][0]["peer"], "a");
        assert_eq!(w1["deployments"][0]["device"], "lab/a/gpu-0");
        assert_eq!(w1["deployments"][0]["phase"], "ready");
        // The member runs it under its own device name.
        assert_eq!(
            site.members[0].query("get-workloads").await["deployments"][0]["device"],
            "gpu-0"
        );

        // The second workspace sees none of it: no workload, no event, not even by the correlation id; it sees the
        // machine's room reduced, since the machine promised the memory.
        assert_eq!(site.query(&ws2, "get-workloads").await["deployments"], json!([]));
        let (s, none) = get_as(
            &site.app,
            &format!("/workspaces/{ws2}"),
            &site.key,
            "/events?correlationId=d1",
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(none["events"], json!([]));
        let (_, none) = get_as(&site.app, &format!("/workspaces/{ws2}"), &site.key, "/events").await;
        assert!(
            type_names(none["events"].as_array().unwrap())
                .iter()
                .all(|t| t == "CloudConfiguredV1" || t == "WorkspaceCreatedV1"),
            "{none}"
        );
        assert_eq!(
            site.query(&ws2, "get-hardware-state").await["devices"][0]["memory"]["free_bytes"],
            8 * GB
        );
        // Nor is the first's deployment the second's to end or to prompt.
        let (s, e) = site
            .send(
                &ws2,
                "u0",
                "UndeployModel",
                "undeploy-model",
                json!({ "deployment": dep }),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(e["error"]["code"], "NO_SUCH_DEPLOYMENT");
        assert_eq!(e["error"]["details"]["live"], json!([]));
        let ask = json!({ "deployment": dep, "messages": [{ "role": "user", "content": "hi" }] });
        let (s, e) = site.send(&ws2, "p0", "Prompt", "prompt", ask.clone()).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(e["error"]["code"], "NO_SUCH_DEPLOYMENT");
        // A prompt in the first workspace is placed on the member that holds the deployment, and the answer comes
        // back on the workspace's stream with the cloud and the peer named.
        let (s, b) = site.send(&ws1, "p1", "Prompt", "prompt", ask).await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let answered = events_as(
            &site.app,
            &format!("/workspaces/{ws1}"),
            &site.key,
            "p1",
            "PromptAnswered",
        )
        .await;
        let last = answered.last().unwrap();
        assert_eq!(last["type"], "PromptAnswered");
        assert_eq!(last["data"]["content"], "fake answer to: hi");
        assert_eq!(last["data"]["cloud"], "lab");
        assert_eq!(last["data"]["peer"], "a");
        assert_eq!(last["data"]["deployment"], dep);
        assert!(last["dataschema"]
            .as_str()
            .unwrap()
            .starts_with(&format!("{EP}/workspaces/{ws1}/")));

        // A placement names its cloud: by name, by the device, or not at all, which is refused with the clouds.
        let (s, e) = site.deploy(&ws2, "d2", None, 4, None).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{e}");
        assert_eq!(e["error"]["code"], "NO_CLOUD");
        assert_eq!(e["error"]["details"]["clouds"], json!(["ops-pool"]));
        let (s, e) = site.deploy(&ws2, "d2", Some("lab"), 4, None).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(e["error"]["code"], "NO_SUCH_CLOUD");
        assert!(e["error"]["message"].as_str().unwrap().contains("get-clouds"));
        let (s, e) = site.deploy(&ws2, "d2", Some("ops-pool"), 4, Some("lab/a/gpu-0")).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(e["error"]["code"], "CLOUD_MISMATCH");
        let (s, e) = site.deploy(&ws2, "d2", None, 4, Some("gpu-0")).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(e["error"]["code"], "INVALID_DEVICE");
        assert!(
            e["error"]["message"].as_str().unwrap().contains("cloud/peer/device"),
            "{e}"
        );
        let (s, b) = site.deploy(&ws2, "d2", None, 4, Some("ops-pool/a/gpu-0")).await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let events = site.events(&ws2, "d2", "DeploymentReady").await;
        let started = events.iter().find(|e| e["type"] == "DeploymentStarted").unwrap();
        assert_eq!(started["data"]["cloud"], "ops-pool");
        assert_eq!(started["data"]["device"], "ops-pool/a/gpu-0");
        assert_eq!(
            site.query(&ws1, "get-workloads").await["deployments"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        // 16 GiB more fits nowhere in the lab: a with 4 left, b with 8; the refusal names the lab's devices alone.
        let (s, e) = site.deploy(&ws1, "d3", Some("lab"), 16, None).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{e}");
        assert_eq!(e["error"]["code"], "INSUFFICIENT_MEMORY");
        let named: Vec<&str> = e["error"]["details"]["devices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["id"].as_str().unwrap())
            .collect();
        assert_eq!(named, ["lab/a/gpu-0", "lab/b/gpu-0"]);
        assert_eq!(e["error"]["details"]["devices"][0]["room_bytes"], 4 * GB);

        // An undeploy through the workspace ends it on the member, told with the cloud named.
        let (s, b) = site
            .send(
                &ws1,
                "u1",
                "UndeployModel",
                "undeploy-model",
                json!({ "deployment": dep }),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let events = site.events(&ws1, "u1", "Undeployed").await;
        assert_eq!(events.last().unwrap()["data"]["cloud"], "lab");
        assert_eq!(events.last().unwrap()["data"]["peer"], "a");
        assert_eq!(site.query(&ws1, "get-workloads").await["deployments"], json!([]));
        assert_eq!(
            site.members[0].query("get-workloads").await["deployments"]
                .as_array()
                .unwrap()
                .len(),
            1,
            "the ops deployment stays on a"
        );
    }

    #[tokio::test]
    async fn an_identity_invited_into_a_workspace_sees_it_and_deploys_in_it_and_one_that_left_sees_neither() {
        let (a, b) = two_members().await;
        let (key_a, key_b) = (a.key.clone(), b.key.clone());
        let site = site(vec![(A, a), (B, b)]).await;
        let ws1 = site.workspace("c1", "Research").await;
        let ws2 = site.workspace("c2", "Ops").await;
        site.cloud(&ws1, "k1", "lab", &[("a", A, &key_a)]).await;
        site.cloud(&ws2, "k2", "ops-pool", &[("b", B, &key_b)]).await;
        let p1 = format!("/workspaces/{ws1}");
        let p2 = format!("/workspaces/{ws2}");

        // Another identity, approved for deploy with a share: signed in, in no workspace, and told so.
        let bob = key_with(&site.app, Some("deploy"), Some(4 * GB)).await;
        let (s, w) = get_as(&site.app, "", &bob, "/queries/get-workspaces").await;
        assert_eq!(s, StatusCode::OK);
        let bob_id = w["identity"].as_str().unwrap().to_string();
        assert_eq!(w["workspaces"], json!([]));
        assert_eq!(w["invitations"], json!([]));
        let (s, e) = get_as(&site.app, &p1, &bob, "/queries/get-clouds").await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{e}");
        assert_eq!(e["error"]["code"], "NO_SUCH_WORKSPACE");
        assert!(e["error"]["message"].as_str().unwrap().contains("get-workspaces"));
        let (s, _) = get_as(&site.app, &p1, "", "/queries/get-clouds").await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "no credential: the door's 401 first");
        let (s, e) = send_as(
            &site.app,
            "",
            &bob,
            "a0",
            "AcceptInvitation",
            "accept-invitation",
            json!({ "workspace": ws1 }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(e["error"]["code"], "NOT_INVITED");
        assert_eq!(e["error"]["details"]["identity"], bob_id);
        // Nobody but the owner invites.
        let (s, e) = send_as(
            &site.app,
            "",
            &bob,
            "i0",
            "InviteMember",
            "invite-member",
            json!({ "workspace": ws1, "identity": bob_id }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(
            e["error"]["code"], "NO_SUCH_WORKSPACE",
            "a workspace one is not in does not exist for them: {e}"
        );

        // Invited into the first: the invitation shows, the acceptance is a fact, the door opens.
        let (s, b) = send_as(
            &site.app,
            "",
            &site.key,
            "i1",
            "InviteMember",
            "invite-member",
            json!({ "workspace": ws1, "identity": bob_id }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let events = events_as(&site.app, "", &site.key, "i1", "MemberInvitedV1").await;
        assert_eq!(events[0]["data"]["identity"], bob_id);
        assert_eq!(events[0]["data"]["workspace"], ws1);
        assert_eq!(events[0]["dataschema"], format!("{EP}/events/member-invited/1.0"));
        let (s, e) = send_as(
            &site.app,
            "",
            &site.key,
            "i1b",
            "InviteMember",
            "invite-member",
            json!({ "workspace": ws1, "identity": bob_id }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(e["error"]["code"], "ALREADY_INVITED");
        let (_, w) = get_as(&site.app, "", &bob, "/queries/get-workspaces").await;
        assert_eq!(w["invitations"][0]["workspace"], ws1);
        assert_eq!(w["invitations"][0]["name"], "Research");
        assert_eq!(w["workspaces"], json!([]), "invited is not in");
        let (s, e) = get_as(&site.app, &p1, &bob, "/queries/get-clouds").await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{e}");
        let (s, b) = send_as(
            &site.app,
            "",
            &bob,
            "a1",
            "AcceptInvitation",
            "accept-invitation",
            json!({ "workspace": ws1 }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let events = events_as(&site.app, "", &bob, "a1", "MemberJoinedV1").await;
        assert_eq!(events[0]["data"]["role"], "member");
        assert_eq!(events[0]["data"]["identity"], bob_id);
        let (_, w) = get_as(&site.app, "", &bob, "/queries/get-workspaces").await;
        assert_eq!(w["workspaces"].as_array().unwrap().len(), 1);
        assert_eq!(w["workspaces"][0]["workspace"], ws1);
        assert_eq!(w["workspaces"][0]["role"], "member");
        assert_eq!(w["workspaces"][0]["members"].as_array().unwrap().len(), 2);
        assert_eq!(w["invitations"], json!([]));
        let (s, e) = send_as(
            &site.app,
            "",
            &site.key,
            "i1c",
            "InviteMember",
            "invite-member",
            json!({ "workspace": ws1, "identity": bob_id }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(e["error"]["code"], "ALREADY_A_MEMBER");
        // In: the clouds, a deploy, its events; not the owner's work.
        let (s, c) = get_as(&site.app, &p1, &bob, "/queries/get-clouds").await;
        assert_eq!(s, StatusCode::OK, "{c}");
        assert_eq!(c["clouds"][0]["cloud"], "lab");
        let (s, e) = send_as(
            &site.app,
            &p1,
            &bob,
            "bk",
            "ConfigureCloud",
            "configure-cloud",
            json!({ "cloud": "mine", "members": [{ "peer": "b", "endpoint": B }] }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{e}");
        assert_eq!(e["error"]["code"], "FORBIDDEN");
        assert!(e["error"]["message"].as_str().unwrap().contains("owner"));
        let (s, b) = send_as(
            &site.app,
            &p1,
            &bob,
            "bd1",
            "DeployModel",
            "deploy-model",
            json!({ "model": "m", "engine": "ollama", "memory_bytes": 2 * GB, "cloud": "lab" }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let events = events_as(&site.app, &p1, &bob, "bd1", "DeploymentReady").await;
        let bob_dep = events[3]["data"]["deployment"].as_str().unwrap().to_string();
        assert_eq!(events[3]["data"]["holder"], bob_id, "the holder is the identity");
        let (_, w) = get_as(&site.app, &p1, &bob, "/queries/get-workloads").await;
        assert_eq!(w["deployments"].as_array().unwrap().len(), 1);
        assert_eq!(w["held_bytes"], 2 * GB);

        // Not in the second: the door is closed, and so is the deploy.
        let (s, e) = send_as(
            &site.app,
            &p2,
            &bob,
            "bd2",
            "DeployModel",
            "deploy-model",
            json!({ "model": "m", "engine": "ollama", "memory_bytes": GB, "cloud": "ops-pool" }),
        )
        .await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{e}");
        // Invited into the second too: both are theirs, and a deploy lands in each. The share counts across the
        // door: 2 GiB held in the first, 3 more does not fit in 4.
        let (s, _) = send_as(
            &site.app,
            "",
            &site.key,
            "i2",
            "InviteMember",
            "invite-member",
            json!({ "workspace": ws2, "identity": bob_id }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        events_as(&site.app, "", &site.key, "i2", "MemberInvitedV1").await;
        let (s, _) = send_as(
            &site.app,
            "",
            &bob,
            "a2",
            "AcceptInvitation",
            "accept-invitation",
            json!({ "workspace": ws2 }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        events_as(&site.app, "", &bob, "a2", "MemberJoinedV1").await;
        let (_, w) = get_as(&site.app, "", &bob, "/queries/get-workspaces").await;
        let mine: Vec<&str> = w["workspaces"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x["workspace"].as_str().unwrap())
            .collect();
        assert_eq!(mine.len(), 2);
        assert!(mine.contains(&ws1.as_str()) && mine.contains(&ws2.as_str()));
        let (s, e) = send_as(
            &site.app,
            &p2,
            &bob,
            "bd2",
            "DeployModel",
            "deploy-model",
            json!({ "model": "m", "engine": "ollama", "memory_bytes": 3 * GB, "cloud": "ops-pool" }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{e}");
        assert_eq!(e["error"]["code"], "SHARE_EXCEEDED");
        assert_eq!(e["error"]["details"]["held_bytes"], 2 * GB);
        let (s, b) = send_as(
            &site.app,
            &p2,
            &bob,
            "bd3",
            "DeployModel",
            "deploy-model",
            json!({ "model": "m", "engine": "ollama", "memory_bytes": GB, "cloud": "ops-pool" }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let events = events_as(&site.app, &p2, &bob, "bd3", "DeploymentReady").await;
        assert_eq!(events[3]["data"]["peer"], "b");
        let (_, w) = get_as(&site.app, &p2, &bob, "/queries/get-workloads").await;
        assert_eq!(
            w["deployments"].as_array().unwrap().len(),
            1,
            "the first workspace's deployment is not listed here"
        );
        assert_eq!(w["held_bytes"], 3 * GB, "but it is held, across the door");
        let (_, w) = get_as(&site.app, &p1, &bob, "/queries/get-workloads").await;
        assert_eq!(w["deployments"][0]["deployment"], bob_dep);

        // Another member, approved for all, holds the first workspace's stream open.
        let carol = key(&site.app).await;
        let (_, w) = get_as(&site.app, "", &carol, "/queries/get-workspaces").await;
        let carol_id = w["identity"].as_str().unwrap().to_string();
        let (s, _) = send_as(
            &site.app,
            "",
            &site.key,
            "i3",
            "InviteMember",
            "invite-member",
            json!({ "workspace": ws1, "identity": carol_id }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        events_as(&site.app, "", &site.key, "i3", "MemberInvitedV1").await;
        let (s, _) = send_as(
            &site.app,
            "",
            &carol,
            "a3",
            "AcceptInvitation",
            "accept-invitation",
            json!({ "workspace": ws1 }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        events_as(&site.app, "", &carol, "a3", "MemberJoinedV1").await;
        let res = site
            .app
            .clone()
            .oneshot(
                Request::get(format!("{p1}/events/stream"))
                    .header("X-Api-Key", &carol)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let mut carol_stream = res.into_body().into_data_stream();
        let (s, _) = site.deploy(&ws1, "d9", Some("lab"), 1, None).await;
        assert_eq!(s, StatusCode::CREATED);
        let frame = tokio::time::timeout(Duration::from_secs(5), carol_stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(
            String::from_utf8_lossy(&frame).contains("ImagePulling"),
            "a member hears the workspace"
        );
        site.events(&ws1, "d9", "DeploymentReady").await;

        // Leaving while holding a workload is refused: what one holds counts against one's share and is one's to
        // end. Undeployed, one leaves; a stream held open ends at the next frame; the owner cannot leave.
        let (s, e) = send_as(
            &site.app,
            "",
            &bob,
            "l2",
            "LeaveWorkspace",
            "leave-workspace",
            json!({ "workspace": ws2 }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{e}");
        assert_eq!(e["error"]["code"], "HOLDS_WORKLOADS");
        assert_eq!(e["error"]["details"]["holds"][0]["cloud"], "ops-pool");
        let bob_dep2 = e["error"]["details"]["holds"][0]["deployment"]
            .as_str()
            .unwrap()
            .to_string();
        let (s, _) = send_as(
            &site.app,
            &p2,
            &bob,
            "bu2",
            "UndeployModel",
            "undeploy-model",
            json!({ "deployment": bob_dep2 }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        events_as(&site.app, &p2, &bob, "bu2", "Undeployed").await;
        let (s, _) = send_as(
            &site.app,
            &p1,
            &bob,
            "bu1",
            "UndeployModel",
            "undeploy-model",
            json!({ "deployment": bob_dep }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        events_as(&site.app, &p1, &bob, "bu1", "Undeployed").await;
        let (s, _) = send_as(
            &site.app,
            "",
            &carol,
            "l3",
            "LeaveWorkspace",
            "leave-workspace",
            json!({ "workspace": ws1 }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        events_as(&site.app, "", &carol, "l3", "MemberLeftV1").await;
        let (s, _) = site.deploy(&ws1, "d10", Some("lab"), 1, None).await;
        assert_eq!(s, StatusCode::CREATED);
        let next = tokio::time::timeout(Duration::from_secs(5), carol_stream.next())
            .await
            .unwrap();
        assert!(next.is_none(), "the stream ended when the door closed: {next:?}");
        let (s, b) = send_as(
            &site.app,
            "",
            &bob,
            "l2",
            "LeaveWorkspace",
            "leave-workspace",
            json!({ "workspace": ws2 }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let events = events_as(&site.app, "", &bob, "l2", "MemberLeftV1").await;
        assert_eq!(events[0]["data"]["identity"], bob_id);
        let (_, w) = get_as(&site.app, "", &bob, "/queries/get-workspaces").await;
        assert_eq!(w["workspaces"].as_array().unwrap().len(), 1);
        assert_eq!(w["workspaces"][0]["workspace"], ws1);
        let (s, _) = get_as(&site.app, &p2, &bob, "/queries/get-workloads").await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        let (s, _) = send_as(
            &site.app,
            "",
            &bob,
            "l1",
            "LeaveWorkspace",
            "leave-workspace",
            json!({ "workspace": ws1 }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        events_as(&site.app, "", &bob, "l1", "MemberLeftV1").await;
        let (_, w) = get_as(&site.app, "", &bob, "/queries/get-workspaces").await;
        assert_eq!(w["workspaces"], json!([]));
        let (s, _) = get_as(&site.app, &p1, &bob, "/queries/get-workloads").await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        let (s, e) = send_as(
            &site.app,
            "",
            &bob,
            "l1b",
            "LeaveWorkspace",
            "leave-workspace",
            json!({ "workspace": ws1 }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(e["error"]["code"], "NO_SUCH_WORKSPACE");
        let (s, e) = send_as(
            &site.app,
            "",
            &site.key,
            "l0",
            "LeaveWorkspace",
            "leave-workspace",
            json!({ "workspace": ws1 }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(e["error"]["code"], "OWNER_STAYS");
        let (_, w) = get_as(&site.app, "", &site.key, "/queries/get-workspaces").await;
        assert_eq!(
            w["workspaces"][0]["members"].as_array().unwrap().len(),
            1,
            "the owner alone again"
        );
    }

    #[tokio::test]
    async fn the_root_tells_a_credential_only_the_facts_addressed_to_it_and_a_workspace_tells_its_members_its_own() {
        let (a, b) = two_members().await;
        let site = site(vec![(A, a), (B, b)]).await;
        // Four credentials: the site's owner and another approved for all, two approved for deploy alone.
        let other_owner = key(&site.app).await;
        let carol = key_with(&site.app, Some("deploy"), None).await;
        let dave = key_with(&site.app, Some("deploy"), None).await;
        let identity = |key: &str| {
            let app = site.app.clone();
            let key = key.to_string();
            async move {
                get_as(&app, "", &key, "/queries/get-workspaces").await.1["identity"]
                    .as_str()
                    .unwrap()
                    .to_string()
            }
        };
        let (carol_id, dave_id) = (identity(&carol).await, identity(&dave).await);
        let root_events = |key: &str, query: &str| {
            let app = site.app.clone();
            let (key, query) = (key.to_string(), query.to_string());
            async move {
                let (s, b) = get_as(&app, "", &key, &format!("/events{query}")).await;
                assert_eq!(s, StatusCode::OK, "{b}");
                b["events"].as_array().cloned().unwrap_or_default()
            }
        };
        let workspaces_named = |events: &[Value]| -> Vec<String> {
            events
                .iter()
                .filter_map(|e| e["data"]["workspace"].as_str().map(str::to_string))
                .collect()
        };
        // Carol holds the root stream open before anything is made.
        let res = site
            .app
            .clone()
            .oneshot(
                Request::get("/events/stream")
                    .header("X-Api-Key", &carol)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let mut carol_stream = res.into_body().into_data_stream();

        let ws1 = site.workspace("c1", "Research").await;
        let (s, _) = send_as(
            &site.app,
            "",
            &other_owner,
            "c2",
            "CreateWorkspace",
            "create-workspace",
            json!({ "name": "Ops" }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        let ws2 = events_as(&site.app, "", &other_owner, "c2", "WorkspaceCreatedV1").await[0]["data"]["workspace"]
            .as_str()
            .unwrap()
            .to_string();
        let (s, _) = send_as(
            &site.app,
            "",
            &site.key,
            "i1",
            "InviteMember",
            "invite-member",
            json!({ "workspace": ws1, "identity": carol_id }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        events_as(&site.app, "", &site.key, "i1", "MemberInvitedV1").await;

        // Each owner reads its own workspace's facts and nothing of the other's, approved for all or not.
        let mine = root_events(&site.key, "").await;
        assert!(
            type_names(&mine).contains(&"WorkspaceCreatedV1".to_string())
                && type_names(&mine).contains(&"MemberInvitedV1".to_string()),
            "{mine:#?}"
        );
        assert!(workspaces_named(&mine).iter().all(|w| *w == ws1), "{mine:#?}");
        let theirs = root_events(&other_owner, "").await;
        assert_eq!(type_names(&theirs), ["WorkspaceCreatedV1"]);
        assert_eq!(workspaces_named(&theirs), std::slice::from_ref(&ws2));
        assert_eq!(
            root_events(&other_owner, "?type=MemberInvitedV1").await,
            Vec::<Value>::new(),
            "the invitation into the first is not the second owner's to read"
        );
        // The invitee reads the invitation addressed to it before accepting, and nothing else: on the log and on
        // the stream it held open, whose first frame is that invitation.
        let hers = root_events(&carol, "").await;
        assert_eq!(type_names(&hers), ["MemberInvitedV1"], "{hers:#?}");
        assert_eq!(hers[0]["data"]["identity"], carol_id);
        let frame = tokio::time::timeout(Duration::from_secs(5), carol_stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let frame = String::from_utf8_lossy(&frame).to_string();
        assert!(
            frame.contains("MemberInvitedV1") && !frame.contains("WorkspaceCreatedV1"),
            "{frame}"
        );
        assert_eq!(
            root_events(&dave, "").await,
            Vec::<Value>::new(),
            "nothing is addressed to Dave yet"
        );

        // Joined, each reads its own join; a member of the second reads only the second's.
        let (s, _) = send_as(
            &site.app,
            "",
            &carol,
            "a1",
            "AcceptInvitation",
            "accept-invitation",
            json!({ "workspace": ws1 }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        events_as(&site.app, "", &carol, "a1", "MemberJoinedV1").await;
        let (s, _) = send_as(
            &site.app,
            "",
            &other_owner,
            "i2",
            "InviteMember",
            "invite-member",
            json!({ "workspace": ws2, "identity": dave_id }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        events_as(&site.app, "", &other_owner, "i2", "MemberInvitedV1").await;
        let (s, _) = send_as(
            &site.app,
            "",
            &dave,
            "a2",
            "AcceptInvitation",
            "accept-invitation",
            json!({ "workspace": ws2 }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        events_as(&site.app, "", &dave, "a2", "MemberJoinedV1").await;
        let hers = root_events(&carol, "").await;
        assert_eq!(type_names(&hers), ["MemberInvitedV1", "MemberJoinedV1"]);
        assert!(workspaces_named(&hers).iter().all(|w| *w == ws1));
        let his = root_events(&dave, "").await;
        assert_eq!(type_names(&his), ["MemberInvitedV1", "MemberJoinedV1"]);
        assert!(workspaces_named(&his).iter().all(|w| *w == ws2), "{his:#?}");
        assert!(
            workspaces_named(&root_events(&site.key, "").await)
                .iter()
                .all(|w| *w == ws1),
            "the first owner hears nothing of the second's join"
        );

        // The workspace's own stream tells its members its membership, whatever their grant, under the workspace's
        // schemas; the other workspace's facts are not on it.
        let (s, b) = get_as(&site.app, &format!("/workspaces/{ws1}"), &carol, "/events").await;
        assert_eq!(s, StatusCode::OK, "{b}");
        let on_ws1 = b["events"].as_array().unwrap();
        assert_eq!(
            type_names(on_ws1),
            ["WorkspaceCreatedV1", "MemberInvitedV1", "MemberJoinedV1"],
            "{on_ws1:#?}"
        );
        assert!(
            on_ws1.iter().all(|e| e["data"]["workspace"] == ws1
                && e["dataschema"]
                    .as_str()
                    .unwrap()
                    .starts_with(&format!("{EP}/workspaces/{ws1}/"))),
            "{on_ws1:#?}"
        );
        assert_eq!(on_ws1[1]["correlationid"], "i1", "told under the command that made it");
        let (_, b) = get_as(&site.app, &format!("/workspaces/{ws2}"), &dave, "/events").await;
        assert!(
            b["events"]
                .as_array()
                .unwrap()
                .iter()
                .all(|e| e["data"]["workspace"] == ws2),
            "{b}"
        );
        let (_, d) = get_as(
            &site.app,
            &format!("/workspaces/{ws1}"),
            &carol,
            "/events/member-joined/1.0",
        )
        .await;
        assert_eq!(
            d["title"], "MemberJoinedV1",
            "the workspace documents the facts its stream carries"
        );

        // A correlation another sender names opens nothing: Dave names the invitation's on a command of his own and
        // is refused by the field; the log holds nothing of it for him.
        let req = Request::post("/commands")
            .header("X-Api-Key", &dave)
            .header(header::CONTENT_TYPE, "application/cloudevents+json")
            .body(Body::from(
                json!({
                    "specversion": "1.0", "id": "dc", "correlationid": "i1", "source": "https://agent.test", "type": "CreateWorkspace",
                    "datacontenttype": "application/json", "dataschema": format!("{EP}/commands/create-workspace/1.0"),
                    "time": "2026-10-12T10:30:00Z", "data": { "name": "Dave's" }
                })
                .to_string(),
            ))
            .unwrap();
        let res = site.app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let e = body(res).await;
        assert_eq!(e["error"]["code"], "CORRELATION_TAKEN", "{e}");
        assert_eq!(e["error"]["details"]["attribute"], "correlationid");
        assert_eq!(root_events(&dave, "?correlationId=i1").await, Vec::<Value>::new());

        // Left and invited again, the second cycle is heard too: the facts are told by their ids, never deduplicated
        // away by their words.
        let (s, _) = send_as(
            &site.app,
            "",
            &carol,
            "l1",
            "LeaveWorkspace",
            "leave-workspace",
            json!({ "workspace": ws1 }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        events_as(&site.app, "", &carol, "l1", "MemberLeftV1").await;
        let (s, _) = send_as(
            &site.app,
            "",
            &site.key,
            "i1b",
            "InviteMember",
            "invite-member",
            json!({ "workspace": ws1, "identity": carol_id }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        events_as(&site.app, "", &site.key, "i1b", "MemberInvitedV1").await;
        let (s, _) = send_as(
            &site.app,
            "",
            &carol,
            "a1b",
            "AcceptInvitation",
            "accept-invitation",
            json!({ "workspace": ws1 }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        events_as(&site.app, "", &carol, "a1b", "MemberJoinedV1").await;
        let (_, b) = get_as(&site.app, &format!("/workspaces/{ws1}"), &carol, "/events").await;
        let on_ws1 = b["events"].as_array().unwrap();
        assert_eq!(
            type_names(on_ws1),
            [
                "WorkspaceCreatedV1",
                "MemberInvitedV1",
                "MemberJoinedV1",
                "MemberLeftV1",
                "MemberInvitedV1",
                "MemberJoinedV1"
            ],
            "{on_ws1:#?}"
        );
        let hers = root_events(&carol, "").await;
        assert_eq!(hers.len(), 5, "{hers:#?}");
        assert_eq!(
            hers.iter()
                .map(|e| e["id"].as_str().unwrap())
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            5
        );
        assert!(
            on_ws1.iter().skip(1).all(|e| hers.iter().any(|h| h["id"] == e["id"])),
            "the same facts, by id, on both logs"
        );
    }

    #[tokio::test]
    async fn a_cloud_is_configured_by_the_owner_with_names_that_compose_machines_that_serve_one_cloud_per_workspace_and_is_archived_empty(
    ) {
        let (a, b) = two_members().await;
        let (key_a, key_b) = (a.key.clone(), b.key.clone());
        let site = site(vec![(A, a), (B, b)]).await;
        let ws = site.workspace("c1", "Research").await;
        let configure = |id: &'static str, data: Value| site.send(&ws, id, "ConfigureCloud", "configure-cloud", data);
        // Names compose into ids, so a slash or another shape is refused by name.
        let (s, e) = configure(
            "k0",
            json!({ "cloud": "lab/x", "members": [{ "peer": "a", "endpoint": A }] }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{e}");
        assert_eq!(e["error"]["code"], "INVALID_NAME");
        assert_eq!(e["error"]["details"]["field"], "cloud");
        assert!(e["error"]["message"].as_str().unwrap().contains("no slash"));
        let (s, e) = configure(
            "k0",
            json!({ "cloud": "lab", "members": [{ "peer": "Machine A", "endpoint": A }] }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(e["error"]["details"]["field"], "peer");
        let (s, e) = configure(
            "k0",
            json!({ "cloud": "lab", "members": [{ "peer": "a", "endpoint": "a.test:7777" }] }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(e["error"]["code"], "SCHEMA_VALIDATION");
        let (s, e) = configure("k0", json!({ "cloud": "lab", "members": [{ "peer": "a", "endpoint": A }, { "peer": "a2", "endpoint": format!("{A}/") }] })).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(e["error"]["code"], "DUPLICATE_MEMBER");
        // A member in cleartext off loopback would be sent the cloud's credential unencrypted: refused, naming it.
        for endpoint in [
            "http://203.0.113.5:7777",
            "http://a.test",
            "http://[::ffff:203.0.113.5]:7777",
        ] {
            let (s, e) = configure(
                "k0",
                json!({ "cloud": "lab", "members": [{ "peer": "a", "endpoint": endpoint }] }),
            )
            .await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{endpoint}: {e}");
            assert_eq!(e["error"]["code"], "CLEARTEXT_MEMBER");
            assert_eq!(e["error"]["details"]["field"], "members");
            let message = e["error"]["message"].as_str().unwrap();
            assert!(
                message.contains("https://") && message.contains("BEST_PEER_CLEARTEXT=vpn"),
                "{message}"
            );
        }
        let (_, all) = get_as(&site.app, &format!("/workspaces/{ws}"), &site.key, "/events").await;
        assert_eq!(
            type_names(all["events"].as_array().unwrap()),
            ["WorkspaceCreatedV1"],
            "a refused command told nothing: the workspace's log holds its creation alone"
        );

        // One machine, one cloud per workspace: the second cloud may not take a's endpoint while the first has it.
        site.cloud(&ws, "k1", "lab", &[("a", A, &key_a)]).await;
        let (s, e) = configure(
            "k2",
            json!({ "cloud": "spare", "members": [{ "peer": "machine-a", "endpoint": format!("{A}/") }] }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{e}");
        assert_eq!(e["error"]["code"], "ENDPOINT_IN_ANOTHER_CLOUD");
        assert_eq!(e["error"]["details"]["cloud"], "lab");
        // Changing the members: b joins the lab, with its credential where the cloud keeps them, and its devices
        // appear; the same configure renames nothing and keeps a's credential.
        let events = site
            .cloud(&ws, "k3", "lab", &[("a", A, &key_a), ("b", B, &key_b)])
            .await;
        assert_eq!(events[0]["data"]["members"].as_array().unwrap().len(), 2);
        let hs = site.query(&ws, "get-hardware-state").await;
        let ids: Vec<&str> = hs["devices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["lab/a/gpu-0", "lab/b/gpu-0"]);
        let clouds = site.query(&ws, "get-clouds").await;
        assert!(
            clouds["clouds"][0]["peers"]
                .as_array()
                .unwrap()
                .iter()
                .all(|p| p["state"] == "up"),
            "{clouds}"
        );

        // A peer that holds a workload is not removed, and a cloud that holds one is not archived.
        let (s, b) = site.deploy(&ws, "d1", None, 4, Some("lab/b/gpu-0")).await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let dep = site.events(&ws, "d1", "DeploymentReady").await[3]["data"]["deployment"]
            .as_str()
            .unwrap()
            .to_string();
        let (s, e) = configure(
            "k4",
            json!({ "cloud": "lab", "members": [{ "peer": "a", "endpoint": A }] }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{e}");
        assert_eq!(e["error"]["code"], "PEER_HOLDS_WORKLOADS");
        assert_eq!(e["error"]["details"]["holds"][0]["deployment"], dep);
        let (s, e) = site
            .send(&ws, "x1", "ArchiveCloud", "archive-cloud", json!({ "cloud": "lab" }))
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{e}");
        assert_eq!(e["error"]["code"], "CLOUD_HOLDS_WORKLOADS");
        // a may go while b holds it.
        let (s, b) = configure(
            "k5",
            json!({ "cloud": "lab", "members": [{ "peer": "b", "endpoint": B }] }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        site.events(&ws, "k5", "CloudConfiguredV1").await;
        let hs = site.query(&ws, "get-hardware-state").await;
        assert_eq!(hs["devices"].as_array().unwrap().len(), 1);
        assert_eq!(hs["devices"][0]["id"], "lab/b/gpu-0");
        assert_eq!(
            site.query(&ws, "get-workloads").await["deployments"][0]["deployment"],
            dep,
            "the workload on b stays"
        );
        // Empty, the cloud is archived: no device, no placement, listed as archived; configured again, it is back.
        let (s, _) = site
            .send(
                &ws,
                "u1",
                "UndeployModel",
                "undeploy-model",
                json!({ "deployment": dep }),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED);
        site.events(&ws, "u1", "Undeployed").await;
        let (s, b) = site
            .send(&ws, "x2", "ArchiveCloud", "archive-cloud", json!({ "cloud": "lab" }))
            .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let events = site.events(&ws, "x2", "CloudArchivedV1").await;
        assert_eq!(events[0]["data"]["cloud"], "lab");
        assert_eq!(events[0]["data"]["workspace"], ws);
        let clouds = site.query(&ws, "get-clouds").await;
        assert_eq!(clouds["clouds"][0]["archived"], true);
        assert_eq!(clouds["clouds"][0]["peers"][0]["state"], "archived");
        assert_eq!(site.query(&ws, "get-hardware-state").await["devices"], json!([]));
        let (s, e) = site.deploy(&ws, "d2", Some("lab"), 1, None).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(e["error"]["code"], "CLOUD_ARCHIVED");
        assert!(e["error"]["message"].as_str().unwrap().contains("configure-cloud"));
        let (s, e) = site
            .send(&ws, "x3", "ArchiveCloud", "archive-cloud", json!({ "cloud": "lab" }))
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(e["error"]["code"], "CLOUD_ARCHIVED");
        let (s, e) = site
            .send(&ws, "x4", "ArchiveCloud", "archive-cloud", json!({ "cloud": "nope" }))
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(e["error"]["code"], "NO_SUCH_CLOUD");
        // While lab is archived, a is free for another cloud of this workspace.
        site.cloud(&ws, "k6", "spare", &[("machine-a", A, &key_a)]).await;
        let hs = site.query(&ws, "get-hardware-state").await;
        assert_eq!(hs["devices"][0]["id"], "spare/machine-a/gpu-0");
        site.cloud(&ws, "k7", "lab", &[("b", B, &key_b)]).await;
        let clouds = site.query(&ws, "get-clouds").await;
        let lab = clouds["clouds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["cloud"] == "lab")
            .unwrap();
        assert_eq!(lab["archived"], false);
        assert_eq!(lab["peers"][0]["state"], "up");
        let (s, b) = site.deploy(&ws, "d3", Some("lab"), 1, None).await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        assert_eq!(
            site.events(&ws, "d3", "DeploymentReady")
                .await
                .iter()
                .find(|e| e["type"] == "DeploymentStarted")
                .unwrap()["data"]["device"],
            "lab/b/gpu-0"
        );
    }

    #[tokio::test]
    async fn a_door_restarted_over_its_data_rebuilds_its_workspaces_and_clouds_and_the_old_variable_says_what_replaced_it(
    ) {
        let (a, b) = two_members().await;
        let (key_a, key_b) = (a.key.clone(), b.key.clone());
        let data = Arc::new(tempfile::tempdir().unwrap());
        let log = Arc::new(EventLog::ephemeral());
        let first = site_over(
            vec![(A, a), (B, b)],
            data.clone(),
            log.clone(),
            None,
            Arc::new(Limits::default()),
        )
        .await;
        let ws = first.workspace("c1", "Research").await;
        first
            .cloud(&ws, "k1", "lab", &[("a", A, &key_a), ("b", B, &key_b)])
            .await;
        let bob = key(&first.app).await;
        let (_, w) = get_as(&first.app, "", &bob, "/queries/get-workspaces").await;
        let bob_id = w["identity"].as_str().unwrap().to_string();
        let (s, _) = send_as(
            &first.app,
            "",
            &first.key,
            "i1",
            "InviteMember",
            "invite-member",
            json!({ "workspace": ws, "identity": bob_id }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        events_as(&first.app, "", &first.key, "i1", "MemberInvitedV1").await;
        let (s, b) = first.deploy(&ws, "d1", Some("lab"), 4, None).await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let dep = first.events(&ws, "d1", "DeploymentReady").await[3]["data"]["deployment"]
            .as_str()
            .unwrap()
            .to_string();
        let owner_key = first.key.clone();
        let (auth, members) = (first.auth.clone(), first.members);
        first.workspaces.get(&ws).unwrap().cloud_for_test("lab").halt();
        drop(first.app);
        drop(first.workspaces);
        drop(first.switchboard);

        // The door starts again over the same data directory, root log and credentials (on a host, all on disk):
        // the workspace, its members and invitations, its cloud with the members' credentials and the deployment it
        // placed are all back.
        let again = site_over(Vec::new(), data.clone(), log, Some(auth), Arc::new(Limits::default())).await;
        for (endpoint, bed) in [(A, &members[0]), (B, &members[1])] {
            again.switchboard.connect(endpoint, bed.app.clone());
        }
        let (_, w) = get_as(&again.app, "", &again.key, "/queries/get-workspaces").await;
        assert_eq!(w["workspaces"], json!([]), "another credential belongs nowhere yet");
        let (_, w) = get_as(&again.app, "", &owner_key, "/queries/get-workspaces").await;
        assert_eq!(w["workspaces"][0]["workspace"], ws);
        assert_eq!(w["workspaces"][0]["name"], "Research");
        // The workspace's own log is kept by day, as the root's is: day files under its `events/`, no single file.
        let ws_dir = data.path().join("workspaces").join(&ws);
        assert!(!ws_dir.join("events.jsonl").exists());
        let days: Vec<String> = std::fs::read_dir(ws_dir.join("events"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            !days.is_empty()
                && days
                    .iter()
                    .all(|d| d.len() == "YYYY-MM-DD.jsonl".len() && d.ends_with(".jsonl") && d.as_bytes()[4] == b'-'),
            "{days:?}"
        );
        let (_, w) = get_as(&again.app, "", &bob, "/queries/get-workspaces").await;
        assert_eq!(w["invitations"][0]["workspace"], ws, "the invitation stands");
        let (s, c) = get_as(
            &again.app,
            &format!("/workspaces/{ws}"),
            &owner_key,
            "/queries/get-clouds",
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{c}");
        assert_eq!(c["clouds"][0]["cloud"], "lab");
        assert_eq!(c["clouds"][0]["peers"].as_array().unwrap().len(), 2);
        assert!(
            c["clouds"][0]["peers"]
                .as_array()
                .unwrap()
                .iter()
                .all(|p| p["state"] == "up"),
            "the credentials were kept: {c}"
        );
        let (s, w) = get_as(
            &again.app,
            &format!("/workspaces/{ws}"),
            &owner_key,
            "/queries/get-workloads",
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(w["deployments"][0]["deployment"], dep);
        assert_eq!(w["deployments"][0]["cloud"], "lab");
        let (s, b) = send_as(
            &again.app,
            &format!("/workspaces/{ws}"),
            &owner_key,
            "u1",
            "UndeployModel",
            "undeploy-model",
            json!({ "deployment": dep }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        events_as(&again.app, &format!("/workspaces/{ws}"), &owner_key, "u1", "Undeployed").await;
        assert!(members[0].query("get-workloads").await["deployments"]
            .as_array()
            .unwrap()
            .is_empty());

        let why = workspace::members_variable_replaced("a=http://a.test");
        assert!(
            why.contains("configure-cloud") && why.contains("create-workspace"),
            "{why}"
        );
    }

    #[tokio::test]
    async fn a_member_that_stops_answering_is_told_as_lost_in_its_cloud_with_its_workloads_ended_and_as_back_when_it_answers(
    ) {
        let (a, b) = two_members().await;
        let (key_a, key_b) = (a.key.clone(), b.key.clone());
        let site = site(vec![(A, a), (B, b)]).await;
        let ws = site.workspace("c1", "Research").await;
        site.cloud(&ws, "k1", "lab", &[("a", A, &key_a), ("b", B, &key_b)])
            .await;
        let (s, b) = site.deploy(&ws, "d1", Some("lab"), 16, None).await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let dep = site.events(&ws, "d1", "DeploymentReady").await[3]["data"]["deployment"]
            .as_str()
            .unwrap()
            .to_string();
        let lab = site.live_cloud(&ws, "lab");
        let (_, none) = get_as(
            &site.app,
            &format!("/workspaces/{ws}"),
            &site.key,
            "/events?correlationId=lab/a",
        )
        .await;
        assert_eq!(
            none["events"],
            json!([]),
            "membership is the reconcile tick's to tell, not a read's"
        );

        site.down[A].store(true, std::sync::atomic::Ordering::SeqCst);
        lab.reconcile().await;
        let lost = site.events(&ws, "lab/a", "PeerLost").await;
        assert_eq!(type_names(&lost), ["PeerLost"], "{lost:#?}");
        assert_eq!(lost[0]["data"]["cloud"], "lab");
        assert!(lost[0]["data"]["reason"]
            .as_str()
            .unwrap()
            .contains("connection refused"));
        let events = site.events(&ws, "d1", "DeploymentEnded").await;
        let ended = &events.last().unwrap()["data"];
        assert_eq!(ended["deployment"], dep);
        assert_eq!(ended["cloud"], "lab");
        assert_eq!(ended["peer"], "a");
        assert!(
            ended["reason"].as_str().unwrap().contains("peer a is unreachable"),
            "{ended}"
        );
        assert_eq!(site.query(&ws, "get-workloads").await["deployments"], json!([]));
        let hs = site.query(&ws, "get-hardware-state").await;
        assert_eq!(hs["peers"][0]["state"], "unreachable");
        assert_eq!(
            site.query(&ws, "get-clouds").await["clouds"][0]["peers"][0]["state"],
            "unreachable"
        );
        let (s, e) = site.deploy(&ws, "d2", Some("lab"), 16, None).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{e}");
        assert_eq!(e["error"]["code"], "INSUFFICIENT_MEMORY");
        assert_eq!(e["error"]["details"]["devices"][0]["id"], "lab/b/gpu-0");

        // Back: the member still runs what the cloud told as ended, and the cloud ends it there.
        site.down[A].store(false, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            site.members[0].query("get-workloads").await["deployments"][0]["deployment"],
            dep
        );
        lab.reconcile().await;
        let events = site.events(&ws, "lab/a", "Undeployed").await;
        assert_eq!(
            type_names(&events),
            ["PeerLost", "PeerJoined", "Undeployed"],
            "{events:#?}"
        );
        assert_eq!(events[2]["data"]["deployment"], dep);
        assert!(site.members[0].query("get-workloads").await["deployments"]
            .as_array()
            .unwrap()
            .is_empty());
        let (s, b) = site.deploy(&ws, "d3", Some("lab"), 16, None).await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        assert_eq!(site.events(&ws, "d3", "DeploymentReady").await[3]["data"]["peer"], "a");
    }

    #[tokio::test]
    async fn a_pull_in_a_cloud_reaches_every_member_and_is_told_once_when_all_have_it() {
        let (a, b) = two_members().await;
        let (key_a, key_b) = (a.key.clone(), b.key.clone());
        let site = site(vec![(A, a), (B, b)]).await;
        let ws = site.workspace("c1", "Research").await;
        site.cloud(&ws, "k1", "lab", &[("a", A, &key_a), ("b", B, &key_b)])
            .await;
        let (s, e) = site
            .send(
                &ws,
                "p0",
                "PullImage",
                "pull-image",
                json!({ "image": "ollama/ollama:0.6" }),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{e}");
        assert_eq!(e["error"]["code"], "SCHEMA_VALIDATION", "a pull names its cloud");
        let (s, b) = site
            .send(
                &ws,
                "p1",
                "PullImage",
                "pull-image",
                json!({ "image": "ollama/ollama:0.6", "cloud": "lab" }),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let events = site.events(&ws, "p1", "ImagePulled").await;
        let pulled: Vec<&Value> = events.iter().filter(|e| e["type"] == "ImagePulled").collect();
        assert_eq!(pulled.len(), 1, "{events:#?}");
        assert!(
            pulled[0]["data"]["peer"].is_null(),
            "the outcome is the cloud's, not one member's"
        );
        assert_eq!(pulled[0]["data"]["cloud"], "lab");
        let progressed: std::collections::BTreeSet<&str> = events
            .iter()
            .filter(|e| e["type"] == "ImagePulling")
            .filter_map(|e| e["data"]["peer"].as_str())
            .collect();
        assert_eq!(progressed.into_iter().collect::<Vec<_>>(), ["a", "b"]);
        // A member that has the image is not the cloud's pull ended: 100 is told once, by the cloud, with the outcome.
        let hundreds: Vec<usize> = events
            .iter()
            .enumerate()
            .filter(|(_, e)| e["type"] == "ImagePulling" && e["data"]["progress_pct"] == 100)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(hundreds.len(), 1, "{events:#?}");
        assert!(events[hundreds[0]]["data"]["peer"].is_null(), "{events:#?}");
        assert_eq!(events[hundreds[0] + 1]["type"], "ImagePulled");
        let (s, b) = site
            .send(
                &ws,
                "p2",
                "PullImage",
                "pull-image",
                json!({ "image": "nobody/nothing:1", "cloud": "lab" }),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let events = site.events(&ws, "p2", "ImagePullFailed").await;
        let reason = events.last().unwrap()["data"]["reason"].as_str().unwrap().to_string();
        assert!(reason.contains("a:") && reason.contains("b:"), "{reason}");
    }

    #[test]
    fn the_endpoint_defaults_to_the_listen_address_only_when_a_consumer_can_reach_it() {
        let (listen, endpoint, tls) = config(None, None, None, None, Cleartext::Loopback).unwrap();
        assert_eq!(listen.to_string(), "127.0.0.1:7777");
        assert_eq!(endpoint, "http://127.0.0.1:7777");
        assert_eq!(tls, Tls::Off);
        let (_, endpoint, tls) = config(
            Some("0.0.0.0:7777"),
            Some("https://peer.example.com/"),
            None,
            None,
            Cleartext::Loopback,
        )
        .unwrap();
        assert_eq!(endpoint, "https://peer.example.com");
        assert_eq!(tls, Tls::Own);
        assert!(config(Some("0.0.0.0:7777"), None, None, None, Cleartext::Loopback)
            .unwrap_err()
            .contains("BEST_PEER_ENDPOINT"));
        assert!(config(Some("[::]:7777"), None, None, None, Cleartext::Loopback)
            .unwrap_err()
            .contains("BEST_PEER_ENDPOINT"));
        assert!(config(Some("localhost:7777"), None, None, None, Cleartext::Loopback)
            .unwrap_err()
            .contains("ip:port"));
        assert!(config(None, Some("peer.example.com"), None, None, Cleartext::Loopback)
            .unwrap_err()
            .contains("https://"));
        // Cleartext off loopback is refused, whether the endpoint was said or defaulted, whether the listen address
        // or the endpoint's host is what is off; each refusal names what is off, the variables and the ways through.
        for (listen, endpoint, off) in [
            (
                Some("192.168.1.9:7777"),
                Some("http://192.168.1.9:7777"),
                "neither loopback",
            ),
            (
                Some("192.168.1.9:7777"),
                None,
                "BEST_PEER_LISTEN is 192.168.1.9:7777, not loopback",
            ),
            (
                Some("0.0.0.0:7777"),
                Some("http://peer.example.com:7777"),
                "neither loopback",
            ),
            (
                None,
                Some("http://peer.example.com:7777"),
                "host is peer.example.com, not loopback",
            ),
            (
                Some("[::]:7777"),
                Some("http://[::1]:7777"),
                "BEST_PEER_LISTEN is [::]:7777, not loopback",
            ),
            (None, Some("http://user@203.0.113.5:7777/door"), "host is 203.0.113.5"),
        ] {
            let why = config(listen, endpoint, None, None, Cleartext::Loopback).unwrap_err();
            assert!(why.contains(off), "{why}");
            for named in ["cleartext", "https://", "BEST_PEER_TLS_CERT", "BEST_PEER_CLEARTEXT=vpn"] {
                assert!(why.contains(named), "{named} in {why}");
            }
            let opens = if endpoint.is_some() {
                "BEST_PEER_ENDPOINT is"
            } else {
                "from BEST_PEER_LISTEN"
            };
            assert!(why.contains(opens), "{why}");
        }
        // Loopback is loopback in every spelling, and a VPN the operator names lets cleartext through.
        for (listen, endpoint) in [
            (Some("127.0.0.1:7781"), Some("http://127.0.0.1:7781")),
            (Some("127.0.0.2:7781"), Some("http://localhost:7781")),
            (Some("[::1]:7781"), Some("http://[::1]:7781")),
            (Some("[::ffff:127.0.0.1]:7781"), Some("http://[::ffff:127.0.0.1]:7781")),
        ] {
            let (_, _, tls) = config(listen, endpoint, None, None, Cleartext::Loopback).unwrap();
            assert_eq!(tls, Tls::Off, "{listen:?} {endpoint:?}");
        }
        let (_, endpoint, tls) = config(Some("100.64.0.7:7777"), None, None, None, Cleartext::Vpn).unwrap();
        assert_eq!((endpoint.as_str(), tls), ("http://100.64.0.7:7777", Tls::Off));
        let (_, endpoint, tls) = config(
            Some("192.168.1.9:7777"),
            Some("https://192.168.1.9:7777"),
            None,
            None,
            Cleartext::Loopback,
        )
        .unwrap();
        assert_eq!((endpoint.as_str(), tls), ("https://192.168.1.9:7777", Tls::Own));
    }

    #[test]
    fn cleartext_goes_to_loopback_alone_unless_the_operator_names_a_vpn() {
        assert_eq!(Cleartext::parse(None).unwrap(), Cleartext::Loopback);
        assert_eq!(Cleartext::parse(Some("vpn")).unwrap(), Cleartext::Vpn);
        assert!(Cleartext::parse(Some("yes"))
            .unwrap_err()
            .contains("BEST_PEER_CLEARTEXT"));
        for (url, host) in [
            ("http://127.0.0.1:7777/x", "127.0.0.1"),
            ("http://[::1]:7777", "[::1]"),
            ("http://user:pw@localhost", "localhost"),
            ("https://peer.example.com?x=1", "peer.example.com"),
        ] {
            assert_eq!(transport::url_host(url), host);
        }
        for url in [
            "http://127.0.0.1:7777",
            "http://127.9.9.9",
            "http://localhost:7777",
            "http://LOCALHOST",
            "http://[::1]:7777",
            "http://[::ffff:127.0.0.1]:7777",
            "https://203.0.113.5:7777",
        ] {
            assert!(Cleartext::Loopback.allows(url), "{url}");
        }
        for url in [
            "http://203.0.113.5:7777",
            "http://[::ffff:203.0.113.5]:7777",
            "http://127.0.0.1.example.com",
            "http://localhost@203.0.113.5",
            "ftp://127.0.0.1",
        ] {
            assert!(!Cleartext::Loopback.allows(url), "{url}");
        }
        assert!(Cleartext::Vpn.allows("http://100.64.0.7:7777"));
    }

    #[tokio::test]
    async fn a_door_with_a_cloud_member_recorded_in_cleartext_off_loopback_names_it_at_start() {
        const OFF: &str = "http://203.0.113.5:7777";
        let (a, _) = two_members().await;
        let key_a = a.key.clone();
        let data = Arc::new(tempfile::tempdir().unwrap());
        let log = Arc::new(EventLog::ephemeral());
        let first = site_under(
            vec![(OFF, a)],
            data.clone(),
            log.clone(),
            None,
            Cleartext::Vpn,
            Arc::new(Limits::default()),
        )
        .await;
        let ws = first.workspace("c1", "Research").await;
        first.cloud(&ws, "k1", "lab", &[("a", OFF, &key_a)]).await;
        let auth = first.auth.clone();
        first.workspaces.get(&ws).unwrap().cloud_for_test("lab").halt();
        drop(first.app);
        drop(first.workspaces);

        let again = site_over(Vec::new(), data.clone(), log, Some(auth), Arc::new(Limits::default())).await;
        let found = again.workspaces.cleartext_members();
        assert_eq!(found, vec![(ws.clone(), "lab".into(), "a".into(), OFF.into())]);
        let why = cleartext_members_refused(&found).unwrap();
        for named in [
            ws.as_str(),
            "cloud lab",
            "peer a",
            OFF,
            "configure-cloud",
            "https://",
            "BEST_PEER_CLEARTEXT=vpn",
        ] {
            assert!(why.contains(named), "{named} in {why}");
        }
        assert!(cleartext_members_refused(&[]).is_none());
    }

    #[tokio::test]
    async fn the_transport_sends_nothing_in_cleartext_off_loopback() {
        use transport::Transport;
        let http = transport::Http::new(&[], Cleartext::Loopback).unwrap();
        let req = Request::builder()
            .uri("http://203.0.113.5:7777/.well-known/best")
            .header("X-Api-Key", "secret")
            .body(Body::empty())
            .unwrap();
        let why = http.call(req).await.unwrap_err();
        assert!(
            why.contains("cleartext") && why.contains("BEST_PEER_CLEARTEXT=vpn"),
            "{why}"
        );
    }

    #[test]
    fn a_certificate_makes_the_default_endpoint_https() {
        let (_, endpoint, tls) = config(None, None, Some("c.pem"), Some("k.pem"), Cleartext::Loopback).unwrap();
        assert_eq!(endpoint, "https://127.0.0.1:7777");
        assert!(matches!(tls, Tls::Given { .. }));
        let why = config(
            None,
            Some("http://127.0.0.1:7777"),
            Some("c.pem"),
            Some("k.pem"),
            Cleartext::Loopback,
        )
        .unwrap_err();
        assert!(why.contains("a certificate is set"), "{why}");
        let why = config(
            Some("192.168.1.9:7777"),
            Some("http://192.168.1.9:7777"),
            Some("c.pem"),
            Some("k.pem"),
            Cleartext::Loopback,
        )
        .unwrap_err();
        assert!(
            why.contains("a certificate is set"),
            "cleartext with a certificate is the certificate's refusal: {why}"
        );
    }

    /// The door served over https from a loopback port, with the certificate the peer makes for itself: the manifest
    /// names https everywhere, `approve` reaches it pinned to that certificate, and any other certificate is refused.
    #[tokio::test]
    async fn the_door_serves_https_with_its_own_certificate_and_approve_pins_it() {
        let dir = tempfile::tempdir().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let listen = listener.local_addr().unwrap();
        let endpoint = format!("https://{listen}");
        let served = tls::serving(&Tls::Own, dir.path(), &tls::names_for(&endpoint, &listen))
            .unwrap()
            .unwrap();
        let (config, cert) = (served.config, served.certificate.as_str());
        let holdings = Arc::new(holdings::Holdings::default());
        let log = Arc::new(EventLog::ephemeral());
        let peer = peer(
            &endpoint,
            "engines.local",
            card(),
            Arc::new(best_peer_runtime::Fake::new(vec!["gpu-0".into()], vec![])),
            Arc::new(best_peer_engine::Fake::new()),
            log.clone(),
            Images::default(),
            Patience::default(),
            holdings.clone(),
            Confine::default(),
        )
        .await;
        let auth = Arc::new(Auth::ephemeral(
            &endpoint,
            Box::new(FakeApprover { proof: "ok".into() }),
        ));
        let data = tempfile::tempdir().unwrap();
        let workspaces = workspace::Workspaces::open(
            Arc::new(workspace::Context {
                endpoint: endpoint.clone(),
                service: SERVICE.into(),
                dir: data.path().into(),
                auth: auth.clone(),
                transport: Arc::new(Switchboard::default()),
                holdings,
                limits: Arc::new(Limits::default()),
                cleartext: Cleartext::Loopback,
            }),
            log,
        );
        let door = Arc::new(super::door(peer.clone(), workspaces.clone(), auth.clone()));
        let app = best_peer_door::router(door).merge(workspaces.router());
        let handle = axum_server::Handle::new();
        tokio::spawn(serve_on(listener, app, Some(config), handle.clone()));
        handle.listening().await;

        let get = |path: &str| {
            Request::get(path)
                .header(header::HOST, listen.to_string())
                .body(Body::empty())
                .unwrap()
        };
        let (status, manifest) = tls::call(listen, Some(cert), get("/.well-known/best")).await.unwrap();
        assert_eq!(status, StatusCode::OK);
        let auth_block = &manifest["best"]["authentication"];
        assert_eq!(auth_block["deviceAuthorizationUrl"], format!("{endpoint}/auth/device"));
        assert_eq!(auth_block["tokenUrl"], format!("{endpoint}/auth/token"));
        assert_eq!(manifest["best"]["services"][SERVICE]["http"]["endpoint"], endpoint);

        // The operator's side, as `best-peer approve` does it: the device flow's code approved over the pinned link.
        let form = |path: &str, pairs: &[(&str, &str)]| {
            Request::post(path)
                .header(header::HOST, listen.to_string())
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(serde_urlencoded::to_string(pairs).unwrap()))
                .unwrap()
        };
        let (status, asked) = tls::call(
            listen,
            Some(cert),
            form("/auth/device", &[("client_id", "agent"), ("connection", "box")]),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::OK, "{asked}");
        assert!(asked["verification_uri"].as_str().unwrap().starts_with("https://"));
        let code = asked["user_code"].as_str().unwrap();
        let (status, admitted) = tls::call(
            listen,
            Some(cert),
            form("/auth/approve", &[("user_code", code), ("proof", "ok")]),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::OK, "{admitted}");
        assert_eq!(admitted["admitted"]["client_id"], "agent");

        // Another certificate, even one made the same way, is not the peer's.
        let other = tempfile::tempdir().unwrap();
        let other_cert = tls::serving(&Tls::Own, other.path(), &tls::names_for(&endpoint, &listen))
            .unwrap()
            .unwrap()
            .certificate;
        let why = tls::call(listen, Some(&other_cert), get("/.well-known/best"))
            .await
            .unwrap_err();
        assert!(why.contains("does not serve the certificate"), "{why}");
        handle.shutdown();
    }

    #[tokio::test]
    async fn the_hardware_state_query_answers_from_the_gpu_abstraction() {
        let bed = fresh().await;
        let b = bed.query("get-hardware-state").await;
        assert_eq!(b["driver"], "fake 1.0");
        assert_eq!(b["devices"][0]["id"], "gpu-0");
        assert_eq!(b["devices"][0]["compute"][0]["api"], "cuda");
        assert_eq!(b["devices"][0]["memory"]["free_bytes"], 24 * GB);
    }

    #[tokio::test]
    async fn pull_image_runs_through_the_runtime_abstraction_and_tells_the_outcome_as_an_event() {
        let bed = fresh().await;
        let (s, _) = bed
            .send("c1", "PullImage", "pull-image", json!({ "image": "ollama/ollama:0.6" }))
            .await;
        assert_eq!(s, StatusCode::CREATED);
        let (s, _) = bed
            .send("c2", "PullImage", "pull-image", json!({ "image": "nobody/nothing:1" }))
            .await;
        assert_eq!(s, StatusCode::CREATED);
        let ok = bed.events_of("c1", "ImagePulled").await;
        assert_eq!(ok.last().unwrap().data["image"], "ollama/ollama:0.6");
        let failed = bed.events_of("c2", "ImagePullFailed").await;
        assert!(failed.last().unwrap().data["reason"]
            .as_str()
            .unwrap()
            .contains("nobody/nothing:1"));
    }

    #[tokio::test]
    async fn a_deploy_is_every_transition_on_the_stream_then_a_prompt_answered_and_an_undeploy_frees_the_device() {
        let bed = fresh().await;
        let (s, b) = bed.deploy("d1", "llama3.2:3b", "ollama", 8).await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        assert_eq!(b["correlationId"], "d1");
        let events = bed.events_of("d1", "DeploymentReady").await;
        assert_eq!(
            types(&events),
            vec![
                "ImagePulling",
                "ImagePulling",
                "ImagePulled",
                "DeploymentStarted",
                "WeightsLoading",
                "WeightsLoading",
                "DeploymentReady"
            ],
            "{events:#?}"
        );
        let started = &events[3].data;
        assert_eq!(started["device"], "gpu-0");
        assert_eq!(started["engine"], "ollama");
        assert_eq!(started["memory_bytes"], 8 * GB);
        assert!(started["deployment"].as_str().unwrap().starts_with("dep-"));
        assert_eq!(events[1].data["progress_pct"], 100, "a pull that completed is 100");
        assert_eq!(events[4].data["progress_pct"], 25);
        let ready = &events[6].data;
        assert_eq!(ready["engine"], "ollama");
        assert!(ready.get("endpoint").is_none(), "nothing of the engine is on the door");
        assert_eq!(ready["deployment"], started["deployment"]);
        assert!(events.iter().all(|e| e.dataschema.as_deref().unwrap().starts_with(EP)));
        // The container runs the recipe on the device, and the engine loaded the model at the base the event names.
        let container = ContainerId(started["container"].as_str().unwrap().into());
        let spec = bed.runtime.spec_of(&container).unwrap();
        assert_eq!(spec.image.0, "ollama/ollama");
        assert_eq!(spec.devices, vec!["gpu-0".into()]);
        assert_eq!(spec.ports, vec![11434]);
        assert_eq!(
            spec.confinement,
            Confinement::serving(),
            "an engine keeps its network and a writable root, with no capabilities and no new privileges"
        );
        assert_eq!(spec.confinement.network, Network::Default);
        assert!(spec.confinement.drop_capabilities && !spec.confinement.read_only_root);
        assert_eq!(
            bed.engine.loaded_at("http://engines.local:41434"),
            vec!["llama3.2:3b"],
            "the peer reaches the engine where its port is bound, not at the door's public host"
        );
        let w = bed.query("get-workloads").await;
        assert_eq!(w["deployments"][0]["phase"], "ready");
        assert!(w["deployments"][0].get("endpoint").is_none());

        let dep = started["deployment"].as_str().unwrap();
        // The one way to the model: a prompt command, answered as a fact.
        let (s, b) = bed
            .send(
                "p1",
                "Prompt",
                "prompt",
                json!({ "deployment": dep, "messages": [{ "role": "user", "content": "Say hello" }] }),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let answered = bed.events_of("p1", "PromptAnswered").await;
        assert_eq!(answered[0].data["content"], "fake answer to: Say hello");
        assert_eq!(bed.engine.prompted_at("http://engines.local:41434").len(), 1);

        let (s, b) = bed
            .send("u1", "UndeployModel", "undeploy-model", json!({ "deployment": dep }))
            .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let events = bed.events_of("u1", "Undeployed").await;
        assert_eq!(types(&events), vec!["Undeployed"]);
        assert_eq!(events[0].data["model"], "llama3.2:3b");
        assert_eq!(
            bed.engine.unloaded_at("http://engines.local:41434"),
            vec!["llama3.2:3b"],
            "the engine is asked to free the model before its container goes"
        );
        assert!(bed.runtime.running().await.unwrap().is_empty());
        assert!(bed.query("get-workloads").await["deployments"]
            .as_array()
            .unwrap()
            .is_empty());
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            types(&bed.log_of("d1")).last().unwrap(),
            "DeploymentReady",
            "the container's exit on undeploy is not an ending of its own"
        );
        // The memory is free again: a deploy of most of the card fits now.
        assert_eq!(
            bed.deploy("d2", "llama3.2:3b", "ollama", 20).await.0,
            StatusCode::CREATED
        );
        // And a deployment that is gone is refused by name.
        let (s, b) = bed
            .send("u2", "UndeployModel", "undeploy-model", json!({ "deployment": dep }))
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(b["error"]["code"], "NO_SUCH_DEPLOYMENT");
        assert!(b["error"]["message"].as_str().unwrap().contains("get-workloads"));
    }

    #[tokio::test]
    async fn a_deploy_the_device_cannot_hold_is_refused_with_what_holds_the_memory_and_what_to_do() {
        let bed = fresh().await;
        let dep = bed.deployed("d1", "big:70b", 20).await;
        // 4 GiB left of 24: the driver still says 24 free (the fake never moves it); the promise is what counts.
        let (s, b) = bed.deploy("d2", "small:3b", "ollama", 8).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        assert_eq!(b["error"]["code"], "INSUFFICIENT_MEMORY");
        let msg = b["error"]["message"].as_str().unwrap();
        assert!(msg.contains("UndeployModel"), "{msg}");
        assert!(msg.contains("gpu-0 (Card A)"), "{msg}");
        let device = &b["error"]["details"]["devices"][0];
        assert_eq!(device["promised_bytes"], 20 * GB);
        assert_eq!(device["room_bytes"], 4 * GB);
        assert_eq!(device["holders"][0]["deployment"], dep);
        assert!(bed.log_of("d2").is_empty(), "a refused deploy told nothing");
        // The driver's free memory counts too: when it says less than the promises leave, that is the room.
        bed.gpu.set_free(&"gpu-0".into(), 2 * GB).unwrap();
        let (s, b) = bed.deploy("d3", "tiny:1b", "ollama", 3).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        assert_eq!(b["error"]["details"]["devices"][0]["room_bytes"], 2 * GB);
        assert_eq!(bed.deploy("d4", "tiny:1b", "ollama", 2).await.0, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn a_prompt_is_a_command_on_the_door_and_nothing_of_the_engine_is() {
        let bed = fresh().await;
        let dep = bed.deployed("d1", "llama3.2:3b", 8).await;
        let ask = |content: &str| json!({ "deployment": dep, "messages": [{ "role": "system", "content": "be brief" }, { "role": "user", "content": content }] });
        // The prompt is accepted at ingest and answered as a fact under its own correlation id.
        let (s, b) = bed.send("p1", "Prompt", "prompt", ask("Say hello")).await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let events = bed.events_of("p1", "PromptAnswered").await;
        assert_eq!(types(&events), vec!["PromptAnswered"]);
        let answered = &events[0].data;
        assert_eq!(answered["deployment"], dep);
        assert_eq!(answered["model"], "llama3.2:3b");
        assert_eq!(answered["content"], "fake answer to: Say hello");
        assert_eq!(answered["finish"], "stop");
        assert_eq!(answered["prompt_tokens"], 4);
        // The engine was asked where its port is bound, with the whole conversation, and nowhere else.
        let asked = bed.engine.prompted_at("http://engines.local:41434");
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].0, "llama3.2:3b");
        assert_eq!(asked[0].1.len(), 2);
        assert_eq!(asked[0].1[1].content, "Say hello");
        // The door has no inference endpoint: nothing answers under the deployment, with or without the credential.
        for (path, key) in [
            (format!("/deployments/{dep}/v1/models"), Some(bed.key.as_str())),
            (
                format!("/deployments/{dep}/v1/chat/completions"),
                Some(bed.key.as_str()),
            ),
            (format!("/deployments/{dep}"), None),
        ] {
            let mut req = Request::get(&path);
            if let Some(k) = key {
                req = req.header("X-Api-Key", k);
            }
            let res = bed.app.clone().oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(res.status(), StatusCode::NOT_FOUND, "{path}");
        }
        // A prompt that does not fit the schema is refused with the field.
        let (s, b) = bed.send("p2", "Prompt", "prompt", json!({ "deployment": dep })).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(b["error"]["code"], "SCHEMA_VALIDATION");
        assert!(b["error"]["message"].as_str().unwrap().contains("messages"), "{b}");
        // A deployment nobody made, refused at ingest with what to do.
        let (s, b) = bed
            .send(
                "p3",
                "Prompt",
                "prompt",
                json!({ "deployment": "dep-nope", "messages": [{ "role": "user", "content": "hi" }] }),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(b["error"]["code"], "NO_SUCH_DEPLOYMENT");
        assert!(b["error"]["message"].as_str().unwrap().contains("deploy-model"), "{b}");
        // The scope: a credential approved to deploy and not to prompt is refused by name; one approved to prompt
        // alone cannot deploy.
        let deploys = key_with(&bed.app, Some("deploy"), None).await;
        let (s, b) = send_as(&bed.app, "", &deploys, "p4", "Prompt", "prompt", ask("hi")).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(b["error"]["code"], "FORBIDDEN");
        assert!(b["error"]["message"].as_str().unwrap().contains("prompt"), "{b}");
        let prompts = key_with(&bed.app, Some("prompt"), None).await;
        let (s, b) = send_as(
            &bed.app,
            "",
            &prompts,
            "d9",
            "DeployModel",
            "deploy-model",
            json!({ "model": "m", "engine": "ollama", "memory_bytes": GB }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(b["error"]["code"], "FORBIDDEN");
        // And another holder's deployment is not theirs to prompt.
        let (s, b) = send_as(&bed.app, "", &prompts, "p5", "Prompt", "prompt", ask("hi")).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(b["error"]["code"], "FORBIDDEN");
        assert!(
            b["error"]["message"].as_str().unwrap().contains("another credential"),
            "{b}"
        );
        // The answer is its holder's: another credential reading the prompt's correlation sees nothing of it.
        let (s, seen) = get_as(&bed.app, "", &prompts, "/events?correlationId=p1").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(seen["events"], json!([]), "{seen}");
        // A prompt over the door's body ceiling is refused at ingest, 413, and the fix names the messages.
        let (s, b) = bed.send("p7", "Prompt", "prompt", ask(&"x".repeat(2 << 20))).await;
        assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE, "{b}");
        assert!(b["error"]["message"].as_str().unwrap().contains("messages"), "{b}");
        // Once the deployment is gone, so is the thing to prompt.
        let (s, _) = bed
            .send("u1", "UndeployModel", "undeploy-model", json!({ "deployment": dep }))
            .await;
        assert_eq!(s, StatusCode::CREATED);
        bed.events_of("u1", "Undeployed").await;
        let (s, b) = bed.send("p6", "Prompt", "prompt", ask("hi")).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(b["error"]["code"], "NO_SUCH_DEPLOYMENT");
    }

    #[tokio::test]
    async fn a_deployment_that_is_starting_is_not_yet_to_prompt_and_says_what_to_follow() {
        let bed = fresh().await;
        // A deployment whose engine is still coming up, as the state holds it between DeploymentStarted and ready.
        let dep = "dep-starting".to_string();
        bed.peer.state.lock().unwrap().deployments.insert(
            dep.clone(),
            state::Deployment {
                id: dep.clone(),
                model: "llama3.2:3b".into(),
                engine: best_peer_engine::Kind::Ollama,
                device: "gpu-0".into(),
                memory_bytes: 8 * GB,
                container: ContainerId("c-starting".into()),
                port: 41434,
                ready: false,
                holder: String::new(),
                correlation: "d-starting".into(),
                phase: state::Phase::Starting,
                peer: None,
            },
        );
        let (s, b) = bed
            .send(
                "p1",
                "Prompt",
                "prompt",
                json!({ "deployment": dep, "messages": [{ "role": "user", "content": "hi" }] }),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        assert_eq!(b["error"]["code"], "DEPLOYMENT_NOT_READY");
        assert!(
            b["error"]["message"].as_str().unwrap().contains("DeploymentReady"),
            "{b}"
        );
        assert_eq!(b["error"]["details"]["deployment"], dep);
        // A prompt over the schema's bounds is refused naming the field, never accepted and lost.
        let (s, b) = bed
            .send(
                "p2",
                "Prompt",
                "prompt",
                json!({ "deployment": dep, "messages": [{ "role": "user", "content": "hi" }], "max_tokens": 5_000_000_000u64 }),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(b["error"]["code"], "SCHEMA_VALIDATION");
        assert!(b["error"]["message"].as_str().unwrap().contains("max_tokens"), "{b}");
    }

    #[tokio::test]
    async fn a_prompt_the_engine_does_not_answer_is_a_failed_prompt_with_the_fix() {
        let bed = fresh().await;
        let dep = bed.deployed("d1", "llama3.2:3b", 8).await;
        bed.engine.down("http://engines.local:41434");
        let (s, b) = bed
            .send(
                "p1",
                "Prompt",
                "prompt",
                json!({ "deployment": dep, "messages": [{ "role": "user", "content": "hi" }] }),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let events = bed.events_of("p1", "PromptFailed").await;
        assert_eq!(types(&events), vec!["PromptFailed"]);
        let failed = &events[0].data;
        assert_eq!(failed["deployment"], dep);
        assert!(
            failed["reason"].as_str().unwrap().contains("did not answer"),
            "{failed}"
        );
        assert_eq!(failed["fix"], "read the engine's logs on the host");
    }

    #[tokio::test]
    async fn engines_that_report_every_percent_are_told_at_steps_of_ten_and_the_last_is_a_hundred() {
        let bed = bed_with(
            card(),
            Arc::new(EventLog::ephemeral()),
            Arc::new(best_peer_runtime::Fake::new(vec!["gpu-0".into()], vec![]).reporting_every_percent()),
            Arc::new(best_peer_engine::Fake::new().reporting_every_percent()),
            "engines.local",
            None,
        )
        .await;
        let (s, b) = bed.deploy("d1", "llama3.2:3b", "ollama", 8).await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let events = bed.events_of("d1", "DeploymentReady").await;
        for kind in ["ImagePulling", "WeightsLoading"] {
            let pcts: Vec<u64> = events
                .iter()
                .filter(|e| e.r#type == kind)
                .map(|e| e.data["progress_pct"].as_u64().unwrap())
                .collect();
            assert_eq!(pcts, vec![0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100], "{kind}");
        }
        // Eleven of each, with ImagePulled, DeploymentStarted and DeploymentReady between: tens, not hundreds.
        assert_eq!(events.len(), 11 + 1 + 1 + 11 + 1, "{:?}", types(&events));
    }

    #[tokio::test]
    async fn a_pull_says_100_only_once_it_has_ended_whatever_the_engine_reported_on_the_way() {
        // The engine reaches 100 for the layers it knew of, learns of more and falls back, as Docker does.
        let bed = bed_with(
            card(),
            Arc::new(EventLog::ephemeral()),
            Arc::new(best_peer_runtime::Fake::new(vec!["gpu-0".into()], vec![]).reporting(&[0, 40, 100, 25, 60, 100])),
            Arc::new(best_peer_engine::Fake::new()),
            "engines.local",
            None,
        )
        .await;
        let (s, b) = bed.deploy("d1", "llama3.2:3b", "ollama", 8).await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let events = bed.events_of("d1", "DeploymentReady").await;
        let pulling: Vec<u64> = events
            .iter()
            .filter(|e| e.r#type == "ImagePulling")
            .map(|e| e.data["progress_pct"].as_u64().unwrap())
            .collect();
        assert_eq!(pulling, vec![0, 40, 99, 25, 60, 99, 100], "{:?}", types(&events));
        let last = events.iter().rposition(|e| e.r#type == "ImagePulling").unwrap();
        assert_eq!(
            events[last + 1].r#type,
            "ImagePulled",
            "the 100 comes with the end of the pull"
        );
    }

    #[test]
    fn a_span_of_time_reads_as_a_person_writes_it() {
        assert_eq!(parse_duration("8h").unwrap(), Duration::from_secs(8 * 3600));
        assert_eq!(parse_duration("30M").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_duration("2d").unwrap(), Duration::from_secs(2 * 86400));
        assert_eq!(parse_duration("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("3600").unwrap(), Duration::from_secs(3600));
        assert!(parse_duration("soon").unwrap_err().contains("8h"));
        assert!(parse_duration("4w").unwrap_err().contains("unit"));
        assert!(parse_duration("0").unwrap_err().contains("above zero"));
        assert_eq!(parse_duration("366d").unwrap(), Duration::from_secs(366 * 86400));
        assert!(parse_duration("367d").unwrap_err().contains("366d"));
        assert!(parse_duration("3000000000d").unwrap_err().contains("366d"));
    }

    #[test]
    fn an_amount_of_memory_reads_as_a_person_writes_it() {
        assert_eq!(parse_memory("40G").unwrap(), 40 << 30);
        assert_eq!(parse_memory("40GB").unwrap(), 40 << 30);
        assert_eq!(parse_memory("512m").unwrap(), 512 << 20);
        assert_eq!(parse_memory("1T").unwrap(), 1 << 40);
        assert_eq!(parse_memory("1073741824").unwrap(), 1 << 30);
        assert!(parse_memory("lots").unwrap_err().contains("40G"));
        assert!(parse_memory("4X").unwrap_err().contains("unit"));
    }

    /// The ids of the devices `key` is shown under `prefix`.
    async fn devices_shown(app: &axum::Router, prefix: &str, key: &str) -> Vec<String> {
        let (_, v) = get_as(app, prefix, key, "/queries/get-hardware-state").await;
        v["devices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["id"].as_str().unwrap().to_string())
            .collect()
    }

    #[tokio::test]
    async fn a_credential_held_to_the_accelerators_sees_and_uses_them_alone() {
        let gpu = Arc::new(
            best_peer_gpu::Fake::new()
                .with_driver("fake 1.0")
                .with_device(best_peer_gpu::Fake::cuda_card("gpu-0", "Card A", 24, "12.4"))
                .with_device(best_peer_gpu::Fake::host_cpu("cpu-0", 64)),
        );
        let bed = bed(
            gpu,
            Arc::new(EventLog::ephemeral()),
            Arc::new(best_peer_runtime::Fake::new(vec!["gpu-0".into()], vec![])),
        )
        .await;
        let held = key_held(&bed.app, Some("deploy,jobs"), Some(8 * GB), true).await;
        let shared = key_with(&bed.app, Some("deploy,jobs"), Some(8 * GB)).await;
        assert_eq!(devices_shown(&bed.app, "", &bed.key).await, vec!["cpu-0", "gpu-0"]);
        assert_eq!(devices_shown(&bed.app, "", &held).await, vec!["gpu-0"]);
        for (id, r#type, schema, data) in [
            (
                "t0",
                "DeployModel",
                "deploy-model",
                json!({ "model": "a:7b", "engine": "ollama", "memory_bytes": GB, "device": "cpu-0" }),
            ),
            (
                "t1",
                "RunJob",
                "run-job",
                json!({ "image": "busybox", "memory_bytes": GB, "device": "cpu-0" }),
            ),
        ] {
            let (s, b) = send_as(&bed.app, "", &held, id, r#type, schema, data).await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
            assert_eq!(b["error"]["code"], "ACCELERATORS_ONLY");
            assert_eq!(b["error"]["details"]["devices"], json!(["gpu-0"]));
            let message = b["error"]["message"].as_str().unwrap();
            assert!(message.starts_with("device cpu-0 offers the CPU alone"), "{message}");
            assert!(message.contains("name one of gpu-0, or leave device out"), "{message}");
        }
        let (s, b) = send_as(
            &bed.app,
            "",
            &held,
            "t2",
            "RunJob",
            "run-job",
            json!({ "image": "busybox", "memory_bytes": GB }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        // A share alone does not hide the CPU: that is the approver's separate word.
        assert_eq!(devices_shown(&bed.app, "", &shared).await, vec!["cpu-0", "gpu-0"]);
        let (s, b) = send_as(
            &bed.app,
            "",
            &shared,
            "s0",
            "DeployModel",
            "deploy-model",
            json!({ "model": "a:7b", "engine": "ollama", "memory_bytes": GB, "device": "cpu-0" }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
    }

    #[tokio::test]
    async fn a_credential_held_to_the_accelerators_on_a_door_with_none_is_told_why_it_runs_nothing() {
        let bed = bed(
            Arc::new(best_peer_gpu::Fake::new().with_device(best_peer_gpu::Fake::host_cpu("cpu-0", 64))),
            Arc::new(EventLog::ephemeral()),
            Arc::new(best_peer_runtime::Fake::new(vec![], vec![])),
        )
        .await;
        let held = key_held(&bed.app, Some("deploy"), Some(8 * GB), true).await;
        assert!(devices_shown(&bed.app, "", &held).await.is_empty());
        let (s, b) = send_as(
            &bed.app,
            "",
            &held,
            "t0",
            "DeployModel",
            "deploy-model",
            json!({ "model": "a:7b", "engine": "ollama", "memory_bytes": GB }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        assert_eq!(b["error"]["code"], "ACCELERATORS_ONLY");
        assert_eq!(b["error"]["details"]["devices"], json!([]));
        let message = b["error"]["message"].as_str().unwrap();
        assert!(message.starts_with("no device here is an accelerator"), "{message}");
        assert!(message.contains("not held to the accelerators"), "{message}");
    }

    #[tokio::test]
    async fn a_credential_held_to_the_accelerators_uses_a_cloud_s_alone() {
        let (a, _) = two_members().await;
        let host = bed(
            Arc::new(best_peer_gpu::Fake::new().with_device(best_peer_gpu::Fake::host_cpu("cpu-0", 64))),
            Arc::new(EventLog::ephemeral()),
            Arc::new(best_peer_runtime::Fake::new(vec![], vec![])),
        )
        .await;
        const C: &str = "https://c.test";
        let (key_a, key_c) = (a.key.clone(), host.key.clone());
        let site = site(vec![(A, a), (C, host)]).await;
        let ws = site.workspace("c1", "Research").await;
        site.cloud(&ws, "k1", "lab", &[("a", A, &key_a), ("c", C, &key_c)])
            .await;
        let bob = key_held(&site.app, Some("deploy,jobs"), Some(4 * GB), true).await;
        let (_, w) = get_as(&site.app, "", &bob, "/queries/get-workspaces").await;
        let bob_id = w["identity"].as_str().unwrap().to_string();
        let (s, _) = send_as(
            &site.app,
            "",
            &site.key,
            "i0",
            "InviteMember",
            "invite-member",
            json!({ "workspace": ws, "identity": bob_id }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        events_as(&site.app, "", &site.key, "i0", "MemberInvitedV1").await;
        let (s, _) = send_as(
            &site.app,
            "",
            &bob,
            "a0",
            "AcceptInvitation",
            "accept-invitation",
            json!({ "workspace": ws }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        events_as(&site.app, "", &bob, "a0", "MemberJoinedV1").await;
        let prefix = format!("/workspaces/{ws}");
        assert_eq!(devices_shown(&site.app, &prefix, &bob).await, vec!["lab/a/gpu-0"]);
        assert_eq!(devices_shown(&site.app, &prefix, &site.key).await.len(), 2);
        for (id, r#type, schema, data) in [
            (
                "bd0",
                "DeployModel",
                "deploy-model",
                json!({ "model": "m", "engine": "ollama", "memory_bytes": GB, "device": "lab/c/cpu-0" }),
            ),
            (
                "bj0",
                "RunJob",
                "run-job",
                json!({ "image": "busybox", "memory_bytes": GB, "device": "lab/c/cpu-0" }),
            ),
        ] {
            let (s, e) = send_as(&site.app, &prefix, &bob, id, r#type, schema, data).await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{e}");
            assert_eq!(e["error"]["code"], "ACCELERATORS_ONLY");
            assert!(e["error"]["message"]
                .as_str()
                .unwrap()
                .contains("name one of lab/a/gpu-0"));
        }
        let (s, b) = send_as(
            &site.app,
            &prefix,
            &bob,
            "bd1",
            "DeployModel",
            "deploy-model",
            json!({ "model": "m", "engine": "ollama", "memory_bytes": GB, "cloud": "lab" }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
    }

    /// What the log said while `f` ran, as plain lines.
    async fn logged_lines<F: std::future::Future<Output = ()>>(f: F) -> Vec<String> {
        #[derive(Clone, Default)]
        struct Lines(Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Lines {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let lines = Lines::default();
        let writer = lines.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        f.await;
        let text = String::from_utf8(lines.0.lock().unwrap().clone()).unwrap();
        text.lines()
            .filter(|l| l.contains(" request "))
            .map(str::to_string)
            .collect()
    }

    #[tokio::test]
    async fn a_request_the_client_gave_up_on_is_still_a_line() {
        let bed = fresh().await;
        let holder = bed.door.auth.authenticate(&bed.key).unwrap().holder();
        let app = logged(bed.app.clone());
        let lines = logged_lines(async {
            let never_ends = Request::post("/commands")
                .header("X-Api-Key", &bed.key)
                .header(header::CONTENT_TYPE, "application/cloudevents+json")
                .body(Body::from_stream(futures::stream::pending::<
                    Result<Vec<u8>, std::io::Error>,
                >()))
                .unwrap();
            let gave_up = tokio::time::timeout(Duration::from_millis(50), app.clone().oneshot(never_ends)).await;
            assert!(gave_up.is_err(), "the body never came, so no answer did");
        })
        .await;
        assert_eq!(lines.len(), 1, "{lines:#?}");
        for p in [
            "request abandoned",
            "method=POST",
            "path=/commands",
            "status=-",
            &format!("holder={holder}"),
        ] {
            assert!(lines[0].contains(p), "{p} in {}", lines[0]);
        }
    }

    #[tokio::test]
    async fn every_request_is_one_line_with_where_it_came_from_and_whose_it_was_never_the_key() {
        let bed = fresh().await;
        let team = key_with(&bed.app, Some("deploy"), None).await;
        let (s, b) = send_as(
            &bed.app,
            "",
            &bed.key,
            "w1",
            "CreateWorkspace",
            "create-workspace",
            json!({ "name": "Team" }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let ws = bed.events_of("w1", "WorkspaceCreatedV1").await[0].data["workspace"]
            .as_str()
            .unwrap()
            .to_string();
        let owner = bed.door.auth.authenticate(&bed.key).unwrap().holder();
        let holder = bed.door.auth.authenticate(&team).unwrap().holder();
        let app = logged(bed.app.clone()).layer(axum::extract::connect_info::MockConnectInfo(
            "203.0.113.9:40000".parse::<SocketAddr>().unwrap(),
        ));
        let (keys, ws_path) = ([bed.key.clone(), team.clone()], format!("/workspaces/{ws}/commands"));
        let lines = logged_lines(async {
            assert_eq!(get_as(&app, "", &team, "/commands").await.0, StatusCode::OK);
            assert_eq!(
                get_as(&app, &format!("/workspaces/{ws}"), &bed.key, "/commands")
                    .await
                    .0,
                StatusCode::OK
            );
            assert_eq!(
                get_as(&app, &format!("/workspaces/{ws}"), &team, "/commands").await.0,
                StatusCode::NOT_FOUND
            );
            let big = Request::post("/commands")
                .header("X-Api-Key", &team)
                .header(header::CONTENT_TYPE, "application/cloudevents+json")
                .body(Body::from(vec![b' '; 2 << 20]))
                .unwrap();
            assert_eq!(
                app.clone().oneshot(big).await.unwrap().status(),
                StatusCode::PAYLOAD_TOO_LARGE
            );
            assert_eq!(
                get_as(&app, "", "nope", "/commands?x=1").await.0,
                StatusCode::UNAUTHORIZED
            );
        })
        .await;
        assert_eq!(lines.len(), 5, "{lines:#?}");
        let has = |i: usize, parts: &[&str]| {
            for p in parts {
                assert!(lines[i].contains(p), "{p} in {}", lines[i]);
            }
        };
        has(
            0,
            &[
                "from=203.0.113.9:40000",
                "method=GET",
                "path=/commands",
                "status=200",
                &format!("holder={holder}"),
            ],
        );
        has(
            1,
            &[&format!("path={ws_path}"), "status=200", &format!("holder={owner}")],
        );
        has(
            2,
            &[&format!("path={ws_path}"), "status=404", &format!("holder={holder}")],
        );
        has(
            3,
            &[
                "method=POST",
                "path=/commands",
                "status=413",
                &format!("holder={holder}"),
            ],
        );
        has(4, &["path=/commands ", "status=401", "holder=-"]);
        for line in &lines {
            assert!(
                !keys.iter().any(|k| line.contains(k.as_str())) && !line.contains("x=1"),
                "{line}"
            );
        }
    }

    #[test]
    fn the_confinement_is_closed_and_the_operator_sets_only_its_ceilings() {
        let c = confine(None, None, None, None).unwrap();
        assert_eq!(c.job, Confinement::default());
        assert_eq!(c.engine, Confinement::serving());
        assert_eq!(c.job.network, Network::None);
        assert_eq!(c.job.memory_bytes, Some(4 << 30));
        assert_eq!(c.job.pids, Some(4096), "a training job's threads fit under the default");
        assert_eq!(c.engine.memory_bytes, None);
        assert_eq!(c.engine.pids, Some(4096));
        let c = confine(Some("8G"), Some("none"), Some("16G"), Some("100")).unwrap();
        assert_eq!(c.job.memory_bytes, Some(8 << 30));
        assert_eq!(c.job.pids, None);
        assert_eq!(c.engine.memory_bytes, Some(16 << 30));
        assert_eq!(c.engine.pids, Some(100));
        assert!(
            c.job.drop_capabilities
                && c.job.no_new_privileges
                && c.job.read_only_root
                && c.job.network == Network::None,
            "what is not a ceiling stays closed"
        );
        let c = confine(Some("none"), None, None, None).unwrap();
        assert_eq!(c.job.memory_bytes, None, "none is the one way to no ceiling");
        assert_eq!(
            confine(Some("6M"), None, None, None).unwrap().job.memory_bytes,
            Some(6 << 20)
        );
        for (why, args) in [
            ("BEST_PEER_JOB_MEMORY", (Some("lots"), None, None, None)),
            ("BEST_PEER_JOB_MEMORY", (Some("0"), None, None, None)),
            ("BEST_PEER_JOB_MEMORY", (Some("5M"), None, None, None)),
            ("BEST_PEER_JOB_MEMORY", (Some("9000000T"), None, None, None)),
            ("BEST_PEER_JOB_PIDS", (None, Some("0"), None, None)),
            ("BEST_PEER_ENGINE_MEMORY", (None, None, Some("4X"), None)),
            ("BEST_PEER_ENGINE_MEMORY", (None, None, Some("0"), None)),
            ("BEST_PEER_ENGINE_PIDS", (None, None, None, Some("many"))),
        ] {
            let err = confine(args.0, args.1, args.2, args.3).unwrap_err();
            assert!(err.contains(why), "{err}");
            assert!(err.contains("none"), "the refusal names the way to no ceiling: {err}");
        }
    }

    /// The strings and arrays in `schema` with no bound on their length, by path.
    fn unbounded(schema: &Value, at: &str, found: &mut Vec<String>) {
        match schema["type"].as_str() {
            Some("string") if schema.get("maxLength").is_none() && schema.get("enum").is_none() => {
                found.push(at.to_string())
            }
            Some("array") if schema.get("maxItems").is_none() => found.push(at.to_string()),
            _ => {}
        }
        if let Some(properties) = schema["properties"].as_object() {
            for (name, p) in properties {
                unbounded(p, &format!("{at}.{name}"), found);
            }
        }
        if schema.get("items").is_some() {
            unbounded(&schema["items"], &format!("{at}[]"), found);
        }
    }

    #[tokio::test]
    async fn every_string_and_collection_a_command_carries_is_bounded() {
        let (a, _) = two_members().await;
        let key_a = a.key.clone();
        let site = site(vec![(A, a)]).await;
        let ws = site.workspace("c1", "Research").await;
        site.cloud(&ws, "k1", "lab", &[("a", A, &key_a)]).await;
        let mut found = Vec::new();
        for prefix in [String::new(), format!("/workspaces/{ws}")] {
            let (_, c) = get_as(&site.app, &prefix, &site.key, "/commands").await;
            for entry in c["commands"].as_array().unwrap() {
                let path = format!(
                    "/commands/{}/{}",
                    entry["schema"].as_str().unwrap(),
                    entry["version"].as_str().unwrap()
                );
                let (s, doc) = get_as(&site.app, &prefix, &site.key, &path).await;
                assert_eq!(s, StatusCode::OK, "{doc}");
                unbounded(&doc, &format!("{prefix}{path}"), &mut found);
            }
        }
        assert!(found.is_empty(), "unbounded: {found:#?}");
        // A workspace's door takes a little less than the root's, so what its cloud took a member's door takes.
        let limit = best_peer_door::router::MAX_BODY - best_peer_door::router::TENANT_ROOM;
        let req = Request::post(format!("/workspaces/{ws}/commands"))
            .header("X-Api-Key", &site.key)
            .header(header::CONTENT_TYPE, "application/cloudevents+json")
            .body(Body::from("x".repeat(limit + 1)))
            .unwrap();
        let res = site.app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(body(res).await["error"]["details"]["limit_bytes"], limit);
    }

    #[tokio::test]
    async fn a_credential_with_a_share_runs_its_jobs_on_a_device_where_its_share_counts_them() {
        let bed = fresh().await;
        let team = key_with(&bed.app, Some("jobs"), Some(8 * GB)).await;
        let scoped = key_with(&bed.app, Some("jobs"), None).await;
        let (s, b) = send_as(
            &bed.app,
            "",
            &team,
            "t0",
            "RunJob",
            "run-job",
            json!({ "image": "busybox" }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        assert_eq!(b["error"]["code"], "JOB_NEEDS_DEVICE");
        assert_eq!(b["error"]["details"]["field"], "memory_bytes");
        assert!(
            b["error"]["message"].as_str().unwrap().contains("send memory_bytes"),
            "{b}"
        );
        let (s, b) = send_as(
            &bed.app,
            "",
            &team,
            "t1",
            "RunJob",
            "run-job",
            json!({ "image": "busybox", "memory_bytes": GB }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        // A key with no share is not held to a device, whatever its scopes.
        let (s, b) = send_as(
            &bed.app,
            "",
            &scoped,
            "s0",
            "RunJob",
            "run-job",
            json!({ "image": "busybox" }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
    }

    #[tokio::test]
    async fn a_credential_with_a_share_runs_its_jobs_on_a_device_in_a_cloud_too() {
        let (a, b) = two_members().await;
        let (key_a, key_b) = (a.key.clone(), b.key.clone());
        let site = site(vec![(A, a), (B, b)]).await;
        let ws = site.workspace("c1", "Research").await;
        site.cloud(&ws, "k1", "lab", &[("a", A, &key_a), ("b", B, &key_b)])
            .await;
        let bob = key_with(&site.app, Some("jobs"), Some(4 * GB)).await;
        let (_, w) = get_as(&site.app, "", &bob, "/queries/get-workspaces").await;
        let bob_id = w["identity"].as_str().unwrap().to_string();
        let (s, _) = send_as(
            &site.app,
            "",
            &site.key,
            "i0",
            "InviteMember",
            "invite-member",
            json!({ "workspace": ws, "identity": bob_id }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        events_as(&site.app, "", &site.key, "i0", "MemberInvitedV1").await;
        let (s, _) = send_as(
            &site.app,
            "",
            &bob,
            "a0",
            "AcceptInvitation",
            "accept-invitation",
            json!({ "workspace": ws }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        events_as(&site.app, "", &bob, "a0", "MemberJoinedV1").await;
        let prefix = format!("/workspaces/{ws}");
        let (s, e) = send_as(
            &site.app,
            &prefix,
            &bob,
            "bj0",
            "RunJob",
            "run-job",
            json!({ "image": "busybox", "cloud": "lab" }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{e}");
        assert_eq!(e["error"]["code"], "JOB_NEEDS_DEVICE");
        let (s, e) = send_as(
            &site.app,
            &prefix,
            &bob,
            "bj1",
            "RunJob",
            "run-job",
            json!({ "image": "busybox", "cloud": "lab", "memory_bytes": GB }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{e}");
    }

    /// The data of the last event of `until` with `correlation`, as `key` reads it at the root.
    async fn last_of(app: &axum::Router, key: &str, correlation: &str, until: &str) -> Value {
        let events = events_as(app, "", key, correlation, until).await;
        events.iter().rev().find(|e| e["type"] == until).unwrap()["data"].clone()
    }

    #[tokio::test]
    async fn a_credential_runs_as_many_workloads_at_once_as_its_approver_allows() {
        let log = Arc::new(EventLog::ephemeral());
        let runtime = Arc::new(best_peer_runtime::Fake::new(vec!["gpu-0".into()], vec![]));
        let engine = Arc::new(best_peer_engine::Fake::new());
        let bed = bed_with(
            card(),
            log.clone(),
            runtime.clone(),
            engine.clone(),
            "engines.local",
            None,
        )
        .await;
        let team = key_counted(&bed.app, Some("deploy,jobs"), Some(8 * GB), Some(1), Some(1)).await;
        let deploy = |id: &'static str, model: &'static str| {
            let (app, team) = (bed.app.clone(), team.clone());
            async move {
                send_as(
                    &app,
                    "",
                    &team,
                    id,
                    "DeployModel",
                    "deploy-model",
                    json!({ "model": model, "engine": "ollama", "memory_bytes": 1 }),
                )
                .await
            }
        };
        let run = |id: &'static str| {
            let (app, team) = (bed.app.clone(), team.clone());
            async move {
                send_as(
                    &app,
                    "",
                    &team,
                    id,
                    "RunJob",
                    "run-job",
                    json!({ "image": "busybox", "memory_bytes": 1 }),
                )
                .await
            }
        };
        // One deployment at a time, however small each claims to be; the owner, approved with no count, is not counted.
        let (s, b) = deploy("d1", "a:7b").await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let first = last_of(&bed.app, &team, "d1", "DeploymentReady").await["deployment"].clone();
        let (s, b) = deploy("d2", "b:7b").await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        assert_eq!(b["error"]["code"], "DEPLOYMENTS_EXCEEDED");
        assert_eq!(b["error"]["details"], json!({ "ceiling": 1, "running": 1 }));
        assert!(b["error"]["message"].as_str().unwrap().contains("undeploy one first"));
        bed.deployed("o1", "owner-a:7b", 1).await;
        bed.deployed("o2", "owner-b:7b", 1).await;
        // Room comes back when the deployment is undeployed, and when one fails.
        let (s, _) = send_as(
            &bed.app,
            "",
            &team,
            "u1",
            "UndeployModel",
            "undeploy-model",
            json!({ "deployment": first }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        events_as(&bed.app, "", &team, "u1", "Undeployed").await;
        engine.missing("gone:7b");
        let (s, b) = deploy("d3", "gone:7b").await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        last_of(&bed.app, &team, "d3", "DeploymentFailed").await;
        let (s, b) = deploy("d4", "b:7b").await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        last_of(&bed.app, &team, "d4", "DeploymentReady").await;
        // One job at a time: room comes back when it finishes and when it is stopped.
        let (s, b) = run("j1").await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let started = last_of(&bed.app, &team, "j1", "JobStarted").await;
        let (s, b) = run("j2").await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        assert_eq!(b["error"]["code"], "JOBS_EXCEEDED");
        assert_eq!(b["error"]["details"], json!({ "ceiling": 1, "running": 1 }));
        assert!(b["error"]["message"]
            .as_str()
            .unwrap()
            .contains("stop one or let one finish first"));
        runtime
            .stop(&ContainerId(started["container"].as_str().unwrap().into()))
            .await
            .unwrap();
        last_of(&bed.app, &team, "j1", "JobFinished").await;
        let (s, b) = run("j3").await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let started = last_of(&bed.app, &team, "j3", "JobStarted").await;
        let (s, _) = send_as(
            &bed.app,
            "",
            &team,
            "s3",
            "StopJob",
            "stop-job",
            json!({ "job": started["job"] }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        events_as(&bed.app, "", &team, "s3", "JobStopped").await;
        let (s, b) = run("j4").await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        last_of(&bed.app, &team, "j4", "JobStarted").await;
        // A restart counts again what still runs, from the log.
        bed.peer.halt();
        let credentials = bed.door.auth.clone();
        drop(bed);
        let again = bed_with(card(), log, runtime, engine, "engines.local", Some(credentials)).await;
        let (s, b) = send_as(
            &again.app,
            "",
            &team,
            "d5",
            "DeployModel",
            "deploy-model",
            json!({ "model": "c:7b", "engine": "ollama", "memory_bytes": 1 }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        assert_eq!(b["error"]["code"], "DEPLOYMENTS_EXCEEDED");
        let (s, b) = send_as(
            &again.app,
            "",
            &team,
            "j5",
            "RunJob",
            "run-job",
            json!({ "image": "busybox", "memory_bytes": 1 }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        assert_eq!(b["error"]["code"], "JOBS_EXCEEDED");
        // A share with no count runs as many as fit in it: the counts are the approver's word, never a default.
        let shared = key_with(&again.app, Some("deploy"), Some(8 * GB)).await;
        for (id, model) in [("x1", "x:7b"), ("x2", "y:7b"), ("x3", "z:7b")] {
            let (s, b) = send_as(
                &again.app,
                "",
                &shared,
                id,
                "DeployModel",
                "deploy-model",
                json!({ "model": model, "engine": "ollama", "memory_bytes": 1 }),
            )
            .await;
            assert_eq!(s, StatusCode::CREATED, "{b}");
        }
    }

    #[tokio::test]
    async fn a_credential_with_a_share_is_counted_across_the_door_every_workspace_included() {
        let (a, b) = two_members().await;
        let (key_a, key_b) = (a.key.clone(), b.key.clone());
        let site = site(vec![(A, a), (B, b)]).await;
        let ws1 = site.workspace("c1", "Research").await;
        let ws2 = site.workspace("c2", "Ops").await;
        site.cloud(&ws1, "k1", "lab", &[("a", A, &key_a)]).await;
        site.cloud(&ws2, "k2", "ops-pool", &[("b", B, &key_b)]).await;
        let bob = key_counted(&site.app, Some("deploy"), Some(4 * GB), Some(1), None).await;
        let (_, w) = get_as(&site.app, "", &bob, "/queries/get-workspaces").await;
        let bob_id = w["identity"].as_str().unwrap().to_string();
        for (n, ws) in [&ws1, &ws2].into_iter().enumerate() {
            let (s, _) = send_as(
                &site.app,
                "",
                &site.key,
                &format!("i{n}"),
                "InviteMember",
                "invite-member",
                json!({ "workspace": ws, "identity": bob_id }),
            )
            .await;
            assert_eq!(s, StatusCode::CREATED);
            events_as(&site.app, "", &site.key, &format!("i{n}"), "MemberInvitedV1").await;
            let (s, _) = send_as(
                &site.app,
                "",
                &bob,
                &format!("a{n}"),
                "AcceptInvitation",
                "accept-invitation",
                json!({ "workspace": ws }),
            )
            .await;
            assert_eq!(s, StatusCode::CREATED);
            events_as(&site.app, "", &bob, &format!("a{n}"), "MemberJoinedV1").await;
        }
        let (s, b) = send_as(
            &site.app,
            &format!("/workspaces/{ws1}"),
            &bob,
            "bd1",
            "DeployModel",
            "deploy-model",
            json!({ "model": "m", "engine": "ollama", "memory_bytes": GB, "cloud": "lab" }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let (s, e) = send_as(
            &site.app,
            &format!("/workspaces/{ws2}"),
            &bob,
            "bd2",
            "DeployModel",
            "deploy-model",
            json!({ "model": "m", "engine": "ollama", "memory_bytes": GB, "cloud": "ops-pool" }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{e}");
        assert_eq!(e["error"]["code"], "DEPLOYMENTS_EXCEEDED");
        assert_eq!(e["error"]["details"]["running"], 1);
        assert!(e["error"]["message"]
            .as_str()
            .unwrap()
            .contains("every workspace counted"));
    }

    #[tokio::test]
    async fn a_member_that_gave_the_cloud_a_count_counts_the_whole_cloud_as_one() {
        let (a, _) = two_members().await;
        let cloud_key = key_counted(&a.app, Some("deploy,jobs"), Some(16 * GB), Some(1), None).await;
        let site = site(vec![(A, a)]).await;
        let ws = site.workspace("c1", "Research").await;
        site.cloud(&ws, "k1", "lab", &[("a", A, &cloud_key)]).await;
        let (s, b) = site.deploy(&ws, "d1", Some("lab"), 4, None).await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        site.events(&ws, "d1", "DeploymentReady").await;
        // The owner of the workspace is not counted by the cloud, but the member counts the cloud as one holder.
        let (s, b) = site.deploy(&ws, "d2", Some("lab"), 4, None).await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let events = site.events(&ws, "d2", "DeploymentFailed").await;
        let failed = &events.last().unwrap()["data"];
        assert!(
            failed["reason"]
                .as_str()
                .unwrap()
                .contains("may run 1 deployment(s) at once"),
            "{failed}"
        );
    }

    #[tokio::test]
    async fn an_agent_revokes_its_own_credential_with_a_command_and_every_door_here_closes_to_it() {
        let bed = fresh().await;
        let team = key_with(&bed.app, Some("deploy"), None).await;
        let (s, b) = send_as(
            &bed.app,
            "",
            &team,
            "w1",
            "CreateWorkspace",
            "create-workspace",
            json!({ "name": "Team" }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let ws = bed.events_of("w1", "WorkspaceCreatedV1").await[0].data["workspace"]
            .as_str()
            .unwrap()
            .to_string();
        let at_ws = format!("/workspaces/{ws}");
        assert_eq!(get_as(&bed.app, &at_ws, &team, "/commands").await.0, StatusCode::OK);
        let res = bed
            .app
            .clone()
            .oneshot(
                Request::get("/events/stream")
                    .header("X-Api-Key", &team)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let mut stream = res.into_body().into_data_stream();
        // Any credential may revoke itself, whatever it was approved for, and nothing else is named.
        let (s, b) = send_as(&bed.app, "", &team, "r1", "RevokeAgent", "revoke-agent", json!({})).await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let told = tokio::time::timeout(Duration::from_secs(10), async {
            while let Some(frame) = stream.next().await {
                let frame = String::from_utf8_lossy(&frame.unwrap()).to_string();
                if frame.contains("AgentRevokedV1") {
                    return frame.contains("\"correlationid\":\"r1\"");
                }
            }
            false
        })
        .await;
        assert_eq!(
            told,
            Ok(true),
            "the stream it held open read the outcome of its own revoke"
        );
        let revoked = &bed.events_of("r1", "AgentRevokedV1").await[0].data;
        assert!(revoked["revoked_at"].is_string() && revoked["holder"].is_string());
        for prefix in ["", at_ws.as_str()] {
            let (s, b) = get_as(&bed.app, prefix, &team, "/commands").await;
            assert_eq!(s, StatusCode::UNAUTHORIZED, "{prefix}: {b}");
        }
        let (s, _) = send_as(&bed.app, "", &team, "r2", "RevokeAgent", "revoke-agent", json!({})).await;
        assert_eq!(
            s,
            StatusCode::UNAUTHORIZED,
            "a credential taken back sends nothing more"
        );
        assert_eq!(
            get_as(&bed.app, "", &bed.key, "/commands").await.0,
            StatusCode::OK,
            "the owner's is its own"
        );
        let (s, b) = send_as(
            &bed.app,
            "",
            &bed.key,
            "r3",
            "RevokeAgent",
            "revoke-agent",
            json!({ "holder": "x" }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "it names no one else: {b}");
    }

    #[tokio::test]
    async fn a_credential_with_a_share_holds_its_event_streams_across_the_root_and_every_workspace_together() {
        let site = site(Vec::new()).await;
        let bob = key_with(&site.app, None, Some(GB)).await;
        let (s, b) = send_as(
            &site.app,
            "",
            &bob,
            "w1",
            "CreateWorkspace",
            "create-workspace",
            json!({ "name": "Bob's" }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let ws = events_as(&site.app, "", &bob, "w1", "WorkspaceCreatedV1").await[0]["data"]["workspace"]
            .as_str()
            .unwrap()
            .to_string();
        let open = |prefix: String| {
            let (app, bob) = (site.app.clone(), bob.clone());
            async move {
                let res = app
                    .oneshot(
                        Request::get(format!("{prefix}/events/stream"))
                            .header("X-Api-Key", &bob)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(res.status(), StatusCode::OK);
                res.into_body().into_data_stream()
            }
        };
        let mut held = Vec::new();
        for n in 0..best_peer_door::streams::STREAMS_PER_CREDENTIAL {
            held.push(
                open(if n % 2 == 0 {
                    String::new()
                } else {
                    format!("/workspaces/{ws}")
                })
                .await,
            );
        }
        let _newest = open(format!("/workspaces/{ws}")).await;
        let oldest = &mut held[0];
        let ended = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(frame) = oldest.next().await {
                frame.unwrap();
            }
        })
        .await;
        assert!(ended.is_ok(), "the root's oldest gave way to the workspace's newest");
        assert_eq!(streams_per_credential(None).unwrap(), 4);
        assert_eq!(streams_per_credential(Some(" 8 ")).unwrap(), 8);
        assert!(streams_per_credential(Some("0")).unwrap_err().contains("1 or more"));
        assert!(streams_per_credential(Some("many")).unwrap_err().contains("many"));
    }

    #[tokio::test]
    async fn a_credential_with_a_share_is_paced_across_the_root_and_every_workspace_together() {
        let site = site_pacing(Vec::new(), Pace::per_minute(2)).await;
        let bob = key_with(&site.app, None, Some(GB)).await;
        let send = |prefix: String, id: &'static str, r#type: &'static str, schema: &'static str, data: Value| {
            let (app, bob) = (site.app.clone(), bob.clone());
            async move { send_as(&app, &prefix, &bob, id, r#type, schema, data).await }
        };
        let (s, b) = send(
            "".into(),
            "w1",
            "CreateWorkspace",
            "create-workspace",
            json!({ "name": "Bob's" }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let ws = events_as(&site.app, "", &bob, "w1", "WorkspaceCreatedV1").await[0]["data"]["workspace"]
            .as_str()
            .unwrap()
            .to_string();
        let at_ws = format!("/workspaces/{ws}");
        // A command its admission refuses gives back what it took.
        let (s, b) = send(
            at_ws.clone(),
            "c0",
            "ArchiveCloud",
            "archive-cloud",
            json!({ "cloud": "lab" }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        let (s, b) = send(
            "".into(),
            "w2",
            "CreateWorkspace",
            "create-workspace",
            json!({ "name": "Bob's other" }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let (s, b) = send(at_ws, "c1", "ArchiveCloud", "archive-cloud", json!({ "cloud": "lab" })).await;
        assert_eq!(
            s,
            StatusCode::TOO_MANY_REQUESTS,
            "the workspace counts what the root took: {b}"
        );
        assert_eq!(b["error"]["code"], "TOO_MANY_COMMANDS");
        // The owner's key, approved with nothing said, is not paced.
        for id in ["o1", "o2", "o3"] {
            let (s, b) = send_as(
                &site.app,
                "",
                &site.key,
                id,
                "CreateWorkspace",
                "create-workspace",
                json!({ "name": id }),
            )
            .await;
            assert_eq!(s, StatusCode::CREATED, "{b}");
        }
        assert_eq!(commands_per_minute(None).unwrap(), 60);
        assert_eq!(commands_per_minute(Some(" 120 ")).unwrap(), 120);
        assert!(commands_per_minute(Some("0")).unwrap_err().contains("1 or more"));
        assert!(commands_per_minute(Some("fast")).unwrap_err().contains("fast"));
    }

    #[tokio::test]
    async fn a_credential_does_what_it_was_approved_for_holds_its_share_and_ends_only_its_own() {
        let bed = fresh().await;
        // A team key: may deploy, 8 GiB of device memory at most, no jobs; nothing in the door changed for the
        // owner's own key, which was approved with nothing said.
        let team = key_with(&bed.app, Some("deploy"), Some(8 * GB)).await;
        let send = |key: String, id: &'static str, r#type: &'static str, schema: &'static str, data: Value| {
            let app = bed.app.clone();
            async move {
                let req = Request::post("/commands")
                    .header("X-Api-Key", &key)
                    .header(header::CONTENT_TYPE, "application/cloudevents+json")
                    .body(Body::from(
                        json!({
                            "specversion": "1.0", "id": id, "source": "https://team.test", "type": r#type,
                            "datacontenttype": "application/json", "dataschema": format!("{EP}/commands/{schema}/1.0"),
                            "time": "2026-10-13T10:30:00Z", "data": data
                        })
                        .to_string(),
                    ))
                    .unwrap();
                let res = app.oneshot(req).await.unwrap();
                let status = res.status();
                (status, body(res).await)
            }
        };
        let query = |key: String| {
            let app = bed.app.clone();
            async move {
                let req = Request::get("/queries/get-workloads")
                    .header("X-Api-Key", &key)
                    .body(Body::empty())
                    .unwrap();
                body(app.oneshot(req).await.unwrap()).await
            }
        };
        // The share: 6 of 8 GiB fits; 4 more does not, at ingest, with what is held and the room left.
        let (s, b) = send(
            team.clone(),
            "t1",
            "DeployModel",
            "deploy-model",
            json!({ "model": "a:7b", "engine": "ollama", "memory_bytes": 6 * GB }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let (s, b) = send(
            team.clone(),
            "t2",
            "DeployModel",
            "deploy-model",
            json!({ "model": "b:3b", "engine": "ollama", "memory_bytes": 4 * GB }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        assert_eq!(b["error"]["code"], "SHARE_EXCEEDED");
        assert_eq!(b["error"]["details"]["room_bytes"], 2 * GB);
        assert!(bed.log_of("t2").is_empty(), "a refused deploy told nothing");
        // The device had room (24 GiB): the share, not the hardware, said no.
        let (s, _) = send(
            team.clone(),
            "t3",
            "DeployModel",
            "deploy-model",
            json!({ "model": "c:1b", "engine": "ollama", "memory_bytes": 2 * GB }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        // No jobs for this key, said at ingest with what it was approved for; the command document says so too.
        let (s, b) = send(team.clone(), "t4", "RunJob", "run-job", json!({ "image": "busybox" })).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        assert_eq!(b["error"]["code"], "FORBIDDEN");
        assert!(
            b["error"]["message"].as_str().unwrap().contains("approved for deploy"),
            "{b}"
        );
        let doc = body(
            bed.app
                .clone()
                .oneshot(
                    Request::get("/commands/run-job/1.0")
                        .header("X-Api-Key", &team)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert!(doc["description"].as_str().unwrap().contains("jobs scope"), "{doc}");
        // The owner's key deploys too; the team key sees only its own, the owner's sees both with the holder.
        let owner_dep = bed.deployed("o1", "owner:7b", 4).await;
        let team_events = bed.events_of("t1", "DeploymentReady").await;
        let team_dep = team_events
            .iter()
            .find(|e| e.r#type == "DeploymentStarted")
            .unwrap()
            .data["deployment"]
            .as_str()
            .unwrap()
            .to_string();
        let mine = query(team.clone()).await;
        let ids: Vec<&str> = mine["deployments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["deployment"].as_str().unwrap())
            .collect();
        assert!(
            ids.contains(&team_dep.as_str()) && !ids.contains(&owner_dep.as_str()),
            "{ids:?}"
        );
        assert_eq!(mine["held_bytes"], 8 * GB);
        assert_eq!(mine["share_bytes"], 8 * GB);
        let all = query(bed.key.clone()).await;
        assert_eq!(all["deployments"].as_array().unwrap().len(), 3);
        assert_eq!(all["share_bytes"], Value::Null);
        assert!(all["deployments"]
            .as_array()
            .unwrap()
            .iter()
            .all(|d| d["holder"].as_str().is_some_and(|h| h.len() == 16)));
        // Another's deployment is refused by name; its own and, for the owner, anyone's, go.
        let (s, b) = send(
            team.clone(),
            "t5",
            "UndeployModel",
            "undeploy-model",
            json!({ "deployment": owner_dep }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        assert_eq!(b["error"]["code"], "FORBIDDEN");
        assert!(
            b["error"]["message"].as_str().unwrap().contains("another credential"),
            "{b}"
        );
        // Nor is it the team's to prompt, nor are its events or its name in a refusal: the team reads what is the
        // team's.
        let (s, b) = send_as(
            &bed.app,
            "",
            &team,
            "p-team",
            "Prompt",
            "prompt",
            json!({ "deployment": owner_dep, "messages": [{ "role": "user", "content": "hi" }] }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(b["error"]["code"], "FORBIDDEN");
        let events = |key: String, corr: &'static str| {
            let app = bed.app.clone();
            async move {
                let req = Request::get(format!("/events?correlationId={corr}"))
                    .header("X-Api-Key", &key)
                    .body(Body::empty())
                    .unwrap();
                body(app.oneshot(req).await.unwrap()).await["events"]
                    .as_array()
                    .unwrap()
                    .len()
            }
        };
        assert_eq!(
            events(team.clone(), "o1").await,
            0,
            "the owner's deploy is not the team's to read"
        );
        assert!(events(team.clone(), "t1").await > 0, "its own is");
        assert!(
            events(bed.key.clone(), "t1").await > 0,
            "and the owner reads everyone's"
        );
        let (s, b) = send(
            team.clone(),
            "t5b",
            "UndeployModel",
            "undeploy-model",
            json!({ "deployment": "dep-nope" }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        let live: Vec<&str> = b["error"]["details"]["live"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(
            !live.contains(&owner_dep.as_str()) && live.contains(&team_dep.as_str()),
            "{live:?}"
        );
        let (s, _) = send(
            team.clone(),
            "t6",
            "UndeployModel",
            "undeploy-model",
            json!({ "deployment": team_dep.clone() }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        bed.events_of("t6", "Undeployed").await;
        let (s, _) = send(
            bed.key.clone(),
            "o2",
            "UndeployModel",
            "undeploy-model",
            json!({ "deployment": owner_dep }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        // Freed memory is room again for the share.
        bed.events_of("o2", "Undeployed").await;
        let (s, b) = send(
            team.clone(),
            "t7",
            "DeployModel",
            "deploy-model",
            json!({ "model": "d:3b", "engine": "ollama", "memory_bytes": 5 * GB }),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        // A scope the door does not have is refused at the approval, by name.
        let a = body(
            bed.app
                .clone()
                .oneshot(
                    Request::post("/auth/device")
                        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                        .body(Body::from("client_id=test"))
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        let res = bed
            .app
            .clone()
            .oneshot(
                Request::post("/auth/approve")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(
                        serde_urlencoded::to_string([
                            ("user_code", a["user_code"].as_str().unwrap()),
                            ("proof", "ok"),
                            ("may", "deploy,admin"),
                        ])
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert!(body(res).await["error_description"].as_str().unwrap().contains("admin"));
        // The manifest lists what may be granted.
        let m = body(
            bed.app
                .clone()
                .oneshot(Request::get("/.well-known/best").body(Body::empty()).unwrap())
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            m["best"]["authentication"]["scopes"],
            json!(["deploy", "jobs", "prompt"])
        );
    }

    #[tokio::test]
    async fn a_job_on_a_runtime_that_runs_none_is_refused_at_ingest_with_the_fix_and_nothing_is_told() {
        let bed = bed(
            card(),
            Arc::new(EventLog::ephemeral()),
            Arc::new(best_peer_runtime::Fake::new(vec!["gpu-0".into()], vec![]).without_jobs()),
        )
        .await;
        let (s, b) = bed.send("j1", "RunJob", "run-job", json!({ "image": "busybox" })).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        assert_eq!(b["error"]["code"], "NO_CONTAINER_ENGINE");
        let msg = b["error"]["message"].as_str().unwrap();
        assert!(msg.contains("BEST_PEER_RUNTIME=docker"), "{msg}");
        assert!(bed.log_of("j1").is_empty(), "a refused job told nothing");
        // A deploy on the same runtime is still placed: only jobs are what it lacks.
        assert_eq!(
            bed.deploy("d1", "llama3.2:3b", "ollama", 8).await.0,
            StatusCode::CREATED
        );
    }

    #[tokio::test]
    async fn an_engine_no_device_can_run_and_a_device_that_is_not_here_are_refused_by_name() {
        let cpu = best_peer_gpu::Device {
            compute: vec![best_peer_gpu::Compute::Cpu],
            ..best_peer_gpu::Fake::cuda_card("cpu-0", "Host", 64, "0")
        };
        let bed = bed(
            Arc::new(best_peer_gpu::Fake::new().with_device(cpu)),
            Arc::new(EventLog::ephemeral()),
            Arc::new(best_peer_runtime::Fake::new(vec!["cpu-0".into()], vec![])),
        )
        .await;
        // vllm runs on cuda only; a host with only a cpu device cannot run it.
        let (s, b) = bed.deploy("v1", "Qwen/Qwen2.5-0.5B", "vllm", 1).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        assert_eq!(b["error"]["code"], "NO_DEVICE_FOR_ENGINE");
        assert_eq!(b["error"]["details"]["wanted"][0], "cuda");
        // ollama runs on cpu: placed there, with no device handed to the container.
        let (s, b) = bed.deploy("o1", "llama3.2:3b", "ollama", 1).await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let events = bed.events_of("o1", "DeploymentReady").await;
        assert_eq!(events[3].data["device"], "cpu-0");
        let container = ContainerId(events[3].data["container"].as_str().unwrap().into());
        assert!(bed.runtime.spec_of(&container).unwrap().devices.is_empty());
        let (s, b) = bed
            .send(
                "p1",
                "DeployModel",
                "deploy-model",
                json!({ "model": "m", "engine": "ollama", "memory_bytes": 1, "device": "gpu-9" }),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        assert_eq!(b["error"]["code"], "NO_SUCH_DEVICE");
        assert_eq!(b["error"]["details"]["devices"][0], "cpu-0");
    }

    #[tokio::test]
    async fn a_model_in_the_store_is_served_from_it_read_only_and_one_not_in_it_is_pulled() {
        let store = tempfile::tempdir().unwrap();
        let manifest = store.path().join("manifests/registry.ollama.ai/library/llama3.2/3b");
        std::fs::create_dir_all(manifest.parent().unwrap()).unwrap();
        std::fs::write(&manifest, "{}").unwrap();
        let at = store.path().to_str().unwrap().to_string();
        let images = Images {
            model_store: Some(at.clone()),
            ..Images::default()
        };
        let bed = bed_imaging(
            card(),
            Arc::new(EventLog::ephemeral()),
            Arc::new(best_peer_runtime::Fake::new(vec!["gpu-0".into()], vec![])),
            Arc::new(best_peer_engine::Fake::new()),
            "engines.local",
            None,
            images,
        )
        .await;
        let base_of = |id: &str, events: &[Envelope]| {
            let started = events.iter().find(|e| e.r#type == "DeploymentStarted").unwrap();
            assert_eq!(started.data["deployment"], id);
            format!("http://engines.local:{}", started.data["port"].as_u64().unwrap())
        };
        // In the store: mounted read-only, the engine pointed at it, nothing pulled.
        let dep = bed.deployed("d1", "llama3.2:3b", 8).await;
        let spec = bed.runtime.spec_of(&bed.container_of(&dep)).unwrap();
        assert_eq!(
            spec.mounts,
            vec![best_peer_runtime::Mount {
                host: at.clone(),
                container: best_peer_engine::STORE_PATH.into(),
                read_only: true
            }]
        );
        assert!(spec
            .env
            .contains(&("OLLAMA_MODELS".into(), best_peer_engine::STORE_PATH.into())));
        let base = base_of(&dep, &bed.events_of("d1", "DeploymentReady").await);
        assert_eq!(bed.engine.loaded_at(&base), vec!["llama3.2:3b"]);
        assert!(bed.engine.pulled_at(&base).is_empty(), "a store is never pulled into");
        // Not in the store: no mount, and pulled from the registry as before.
        let other = bed.deployed("d2", "qwen3:0.6b", 1).await;
        let spec = bed.runtime.spec_of(&bed.container_of(&other)).unwrap();
        assert!(spec.mounts.is_empty() && !spec.env.iter().any(|(k, _)| k == "OLLAMA_MODELS"));
        let base = base_of(&other, &bed.events_of("d2", "DeploymentReady").await);
        assert_eq!(bed.engine.pulled_at(&base), vec!["qwen3:0.6b"]);
        // vLLM is not served from a store: it pulls as before.
        let (s, b) = bed
            .send(
                "v1",
                "DeployModel",
                "deploy-model",
                json!({ "model": "Qwen/Qwen2.5-0.5B", "engine": "vllm", "memory_bytes": GB }),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let v = bed.events_of("v1", "DeploymentReady").await;
        let vdep = v.last().unwrap().data["deployment"].as_str().unwrap().to_string();
        let vspec = bed.runtime.spec_of(&bed.container_of(&vdep)).unwrap();
        assert!(vspec.mounts.is_empty(), "{vspec:?}");
        // A model the store holds only in part fails with a fix that names no path of the host's.
        bed.engine.missing("llama3.2:3b");
        let (s, _) = bed.deploy("d3", "llama3.2:3b", "ollama", 1).await;
        assert_eq!(s, StatusCode::CREATED);
        let failed = bed.events_of("d3", "DeploymentFailed").await;
        let why = &failed.last().unwrap().data;
        let fix = why["fix"].as_str().unwrap();
        assert!(
            fix.contains("the operator's model store") && !fix.contains(&at),
            "{why}"
        );
        // A job shares nothing of it.
        let (s, _) = bed.send("j1", "RunJob", "run-job", json!({ "image": "busybox" })).await;
        assert_eq!(s, StatusCode::CREATED);
        let started = bed.events_of("j1", "JobStarted").await;
        let container = ContainerId(started.last().unwrap().data["container"].as_str().unwrap().into());
        assert!(bed.runtime.spec_of(&container).unwrap().mounts.is_empty());
        // The store is read where the peer runs, and a container engine is what mounts it.
        assert_eq!(model_store(None, None).unwrap(), None);
        assert_eq!(model_store(Some(" "), None).unwrap(), None);
        assert_eq!(
            model_store(Some(&at), Some("docker")).unwrap().as_deref(),
            Some(at.as_str())
        );
        let missing = model_store(Some("/nowhere/models"), None).unwrap_err();
        assert!(
            missing.contains("cannot read") && missing.contains("same path"),
            "{missing}"
        );
        for runtime in ["native", "fake"] {
            let refused = model_store(Some(&at), Some(runtime)).unwrap_err();
            assert!(refused.contains(&format!("BEST_PEER_RUNTIME={runtime}")), "{refused}");
        }
    }

    #[test]
    fn a_model_is_looked_for_where_ollama_writes_its_manifest() {
        let store = tempfile::tempdir().unwrap();
        for path in [
            "registry.ollama.ai/library/qwen3/0.6b",
            "registry.ollama.ai/library/tiny/latest",
            "registry.ollama.ai/team/coder/7b",
            "hf.co/org/repo/Q4_K_M",
        ] {
            let m = store.path().join("manifests").join(path);
            std::fs::create_dir_all(m.parent().unwrap()).unwrap();
            std::fs::write(m, "{}").unwrap();
        }
        for model in ["qwen3:0.6b", "tiny", "team/coder:7b", "hf.co/org/repo:Q4_K_M"] {
            assert!(lifecycle::in_store(store.path(), model), "{model}");
        }
        for model in ["qwen3:8b", "qwen3", "other/coder:7b", "../manifests:x", "tiny:"] {
            assert!(!lifecycle::in_store(store.path(), model), "{model}");
        }
    }

    #[tokio::test]
    async fn a_deploy_that_fails_tells_why_and_what_to_do_and_leaves_nothing_running() {
        let bed = fresh().await;
        bed.engine.missing("nobody/none:1b");
        let (s, _) = bed.deploy("f1", "nobody/none:1b", "ollama", 1).await;
        assert_eq!(s, StatusCode::CREATED);
        let events = bed.events_of("f1", "DeploymentFailed").await;
        assert_eq!(
            types(&events),
            vec![
                "ImagePulling",
                "ImagePulling",
                "ImagePulled",
                "DeploymentStarted",
                "DeploymentFailed"
            ]
        );
        let failed = &events[4].data;
        assert!(failed["reason"].as_str().unwrap().contains("nobody/none:1b"));
        assert!(failed["fix"].as_str().unwrap().contains("check the name"));
        assert!(
            !failed["fix"].as_str().unwrap().contains("store"),
            "a peer with no store says nothing of one"
        );
        assert!(
            bed.runtime.running().await.unwrap().is_empty(),
            "the container is stopped"
        );
        assert!(bed.query("get-workloads").await["deployments"]
            .as_array()
            .unwrap()
            .is_empty());
        // The memory it was promised is free again: the whole card can be asked for.
        let dep = bed.deployed("f2", "llama3.2:3b", 24).await;
        let (s, _) = bed
            .send("u", "UndeployModel", "undeploy-model", json!({ "deployment": dep }))
            .await;
        assert_eq!(s, StatusCode::CREATED);
        bed.events_of("u", "Undeployed").await;
        // An engine that never comes up is a failure that says so.
        bed.engine.down("http://engines.local:41434");
        let (s, _) = bed.deploy("f3", "llama3.2:3b", "ollama", 1).await;
        assert_eq!(s, StatusCode::CREATED);
        let events = bed.events_of("f3", "DeploymentFailed").await;
        assert!(events.last().unwrap().data["reason"]
            .as_str()
            .unwrap()
            .contains("did not answer"));
        assert!(bed.runtime.running().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn what_the_engine_does_on_its_own_is_told_under_the_deploys_correlation() {
        let bed = fresh().await;
        let dep = bed.deployed("d1", "llama3.2:3b", 8).await;
        let dep2 = bed.deployed("d2", "llama3.2:3b", 8).await;
        bed.runtime.out_of_memory(&bed.container_of(&dep)).unwrap();
        let events = bed.events_of("d1", "OutOfMemory").await;
        let oom = &events.last().unwrap().data;
        assert_eq!(oom["deployment"], dep);
        assert_eq!(oom["device"], "gpu-0");
        assert!(oom["fix"].as_str().unwrap().contains("memory_bytes"));
        // Failed once it was ready: the deploy completed with DeploymentReady, so this is the deployment's end.
        bed.runtime.fail(&bed.container_of(&dep2), "exit 137").unwrap();
        let events = bed.events_of("d2", "DeploymentEnded").await;
        assert_eq!(events.last().unwrap().data["reason"], "exit 137");
        assert!(!events.iter().any(|e| e.r#type == "DeploymentFailed"));
        assert!(bed.query("get-workloads").await["deployments"]
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(
            bed.deploy("d3", "llama3.2:3b", "ollama", 24).await.0,
            StatusCode::CREATED,
            "all memory is free again"
        );
    }

    #[tokio::test]
    async fn by_default_a_tag_is_pulled_again_and_a_digest_the_peer_holds_is_not() {
        let tag = best_peer_runtime::ImageRef("team/trainer:1".into());
        let pinned = best_peer_runtime::ImageRef(format!("team/trainer@sha256:{}", "a".repeat(64)));
        let runtime = Arc::new(best_peer_runtime::Fake::new(
            vec!["gpu-0".into()],
            vec![tag.clone(), pinned.clone()],
        ));
        runtime.registry_has(tag.clone());
        let bed = bed(card(), Arc::new(EventLog::ephemeral()), runtime.clone()).await;
        let (s, b) = bed
            .send("t1", "RunJob", "run-job", json!({ "image": tag.0, "memory_bytes": GB }))
            .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        assert_eq!(
            bed.events_of("t1", "JobStarted")
                .await
                .iter()
                .find(|e| e.r#type == "ImagePulled")
                .unwrap()
                .data["held"],
            false
        );
        assert!(
            runtime.pulled().contains(&tag),
            "a tag may have moved: it is pulled again"
        );
        let (s, b) = bed
            .send(
                "t2",
                "RunJob",
                "run-job",
                json!({ "image": pinned.0, "memory_bytes": GB }),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        assert_eq!(
            bed.events_of("t2", "JobStarted")
                .await
                .iter()
                .find(|e| e.r#type == "ImagePulled")
                .unwrap()
                .data["held"],
            true
        );
        assert!(
            !runtime.pulled().contains(&pinned),
            "a digest names one image: held, it is not pulled"
        );
        assert_eq!(pull_rule(None).unwrap(), Pull::Tags);
        assert_eq!(pull_rule(Some(" missing ")).unwrap(), Pull::Missing);
        assert!(pull_rule(Some("never")).unwrap_err().contains("missing"));
    }

    #[tokio::test]
    async fn with_pull_missing_a_deploy_or_a_job_runs_what_the_peer_holds_without_a_registry_and_pull_image_always_pulls(
    ) {
        let held = best_peer_runtime::ImageRef("held/trainer:1".into());
        let runtime = Arc::new(best_peer_runtime::Fake::new(
            vec!["gpu-0".into()],
            vec![held.clone(), best_peer_runtime::ImageRef("ollama/ollama".into())],
        ));
        let bed = bed_imaging(
            card(),
            Arc::new(EventLog::ephemeral()),
            runtime.clone(),
            Arc::new(best_peer_engine::Fake::new()),
            "engines.local",
            None,
            Images {
                pull: Pull::Missing,
                ..Images::default()
            },
        )
        .await;
        // Held and in no registry, as on a host with no way out: the job runs, and nothing went to a registry.
        let (s, b) = bed
            .send(
                "h1",
                "RunJob",
                "run-job",
                json!({ "image": held.0, "memory_bytes": GB }),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let events = bed.events_of("h1", "JobStarted").await;
        assert_eq!(types(&events), vec!["ImagePulling", "ImagePulled", "JobStarted"]);
        assert_eq!(events[0].data["progress_pct"], 100);
        assert_eq!(events[1].data["held"], true);
        assert!(!runtime.pulled().contains(&held), "a held image is not pulled");
        // The engine's image, held, is not pulled for a deploy either.
        bed.deployed("h2", "llama3.2:3b", 4).await;
        assert_eq!(bed.log_of("h2")[1].data["held"], true);
        assert!(!runtime.pulled().iter().any(|i| i.0 == "ollama/ollama"));
        // Neither held nor in a registry: the job fails with the fix, after one pull.
        let (s, _) = bed
            .send("h3", "RunJob", "run-job", json!({ "image": "nobody/nothing:1" }))
            .await;
        assert_eq!(s, StatusCode::CREATED);
        let failed = bed.events_of("h3", "JobFailed").await;
        assert!(failed.last().unwrap().data["fix"]
            .as_str()
            .unwrap()
            .contains("check the name"));
        assert_eq!(runtime.pulled().iter().filter(|i| i.0 == "nobody/nothing:1").count(), 1);
        // pull-image always goes to the registry, held or not: the way a held image is refreshed.
        let (s, _) = bed
            .send("h4", "PullImage", "pull-image", json!({ "image": held.0 }))
            .await;
        assert_eq!(s, StatusCode::CREATED);
        bed.events_of("h4", "ImagePullFailed").await;
        assert!(runtime.pulled().contains(&held), "pull-image asked the registry");
        let (s, _) = bed
            .send("h5", "PullImage", "pull-image", json!({ "image": "busybox" }))
            .await;
        assert_eq!(s, StatusCode::CREATED);
        assert_eq!(
            bed.events_of("h5", "ImagePulled").await.last().unwrap().data["held"],
            false
        );
        let (s, _) = bed
            .send("h6", "PullImage", "pull-image", json!({ "image": "busybox" }))
            .await;
        assert_eq!(s, StatusCode::CREATED);
        bed.events_of("h6", "ImagePulled").await;
        assert_eq!(runtime.pulled().iter().filter(|i| i.0 == "busybox").count(), 2);
    }

    #[tokio::test]
    async fn a_job_runs_once_and_its_end_is_told_and_a_stop_ends_it_early() {
        let bed = fresh().await;
        let (s, b) = bed
            .send(
                "j1",
                "RunJob",
                "run-job",
                json!({ "image": "busybox", "args": ["echo", "hi"], "memory_bytes": 4 * GB }),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let events = bed.events_of("j1", "JobStarted").await;
        assert_eq!(
            types(&events),
            vec!["ImagePulling", "ImagePulling", "ImagePulled", "JobStarted"]
        );
        let started = &events[3].data;
        assert_eq!(started["device"], "gpu-0");
        let job = started["job"].as_str().unwrap().to_string();
        assert!(job.starts_with("job-"));
        let container = ContainerId(started["container"].as_str().unwrap().into());
        let spec = bed.runtime.spec_of(&container).unwrap();
        assert_eq!(spec.args, vec!["echo", "hi"]);
        // The owner's job, from a credential with no share, keeps the network, a writable filesystem and the host's
        // memory, as on 0.0.11, under the capability, privilege and task rules every container gets.
        assert_eq!(spec.confinement.network, Network::Default);
        assert!(
            spec.confinement.drop_capabilities
                && spec.confinement.no_new_privileges
                && !spec.confinement.read_only_root
                && spec.confinement.pids.is_some()
                && spec.confinement.memory_bytes.is_none()
        );
        assert_eq!(started["boxed"], false);
        assert_eq!(bed.query("get-workloads").await["jobs"][0]["phase"], "running");
        // A tenant's job, from a credential with a share, runs in the closed box, whatever the operator set.
        let tenant = key_with(&bed.app, Some("jobs"), Some(8 * GB)).await;
        let opened = key_opened(&bed.app, Some("jobs"), Some(8 * GB), true).await;
        let started_by = |key: String, id: &'static str| {
            let bed = &bed;
            async move {
                let (s, b) = send_as(
                    &bed.app,
                    "",
                    &key,
                    id,
                    "RunJob",
                    "run-job",
                    json!({ "image": "busybox", "memory_bytes": GB }),
                )
                .await;
                assert_eq!(s, StatusCode::CREATED, "{b}");
                bed.events_of(id, "JobStarted").await.last().unwrap().data.clone()
            }
        };
        let boxed = started_by(tenant.clone(), "b3").await;
        assert_eq!(boxed["boxed"], true);
        assert_eq!(boxed["host_memory_bytes"], 4u64 << 30);
        let spec = bed
            .runtime
            .spec_of(&ContainerId(boxed["container"].as_str().unwrap().into()))
            .unwrap();
        assert_eq!(spec.confinement, Confinement::default());
        assert_eq!(spec.confinement.network, Network::None);
        assert!(spec.confinement.read_only_root && spec.confinement.memory_bytes.is_some());
        // One approved with --open-jobs runs open: the approver's word, never the credential's.
        let open = started_by(opened, "b4").await;
        assert_eq!(open["boxed"], false);
        let spec = bed
            .runtime
            .spec_of(&ContainerId(open["container"].as_str().unwrap().into()))
            .unwrap();
        assert_eq!(spec.confinement.network, Network::Default);
        assert!(!spec.confinement.read_only_root && spec.confinement.memory_bytes.is_none());
        // The boxed job's host memory runs out: the fix is the host's ceiling, not the device memory it asked for.
        bed.runtime
            .out_of_memory(&ContainerId(boxed["container"].as_str().unwrap().into()))
            .unwrap();
        let events = bed.events_of("b3", "JobFailed").await;
        let failed = &events.last().unwrap().data;
        assert_eq!(failed["host_memory_bytes"], 4u64 << 30);
        assert!(failed["reason"].as_str().unwrap().contains("host memory"), "{failed}");
        assert!(failed["fix"].as_str().unwrap().contains("ceiling"), "{failed}");
        assert!(!failed["fix"].as_str().unwrap().contains("memory_bytes"), "{failed}");
        // An open job's runs out with the host's own memory, and no ceiling is named.
        bed.runtime
            .out_of_memory(&ContainerId(open["container"].as_str().unwrap().into()))
            .unwrap();
        let events = bed.events_of("b4", "JobFailed").await;
        let failed = &events.last().unwrap().data;
        assert!(failed["host_memory_bytes"].is_null(), "{failed}");
        assert!(!failed["fix"].as_str().unwrap().contains("ceiling"), "{failed}");
        // The engine ends it: the exit is told, and the memory is free.
        bed.runtime.stop(&container).await.unwrap();
        let events = bed.events_of("j1", "JobFinished").await;
        assert_eq!(events.last().unwrap().data["exit_code"], 0);
        assert!(bed.query("get-workloads").await["jobs"].as_array().unwrap().is_empty());
        let (s, b) = bed.send("s0", "StopJob", "stop-job", json!({ "job": job })).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        assert_eq!(b["error"]["code"], "NO_SUCH_JOB");

        // A job with no memory asked runs with no device, and a stop ends it on request: JobStopped, not JobFinished.
        let (s, _) = bed
            .send(
                "j2",
                "RunJob",
                "run-job",
                json!({ "image": "busybox", "args": ["sleep", "100"] }),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED);
        let events = bed.events_of("j2", "JobStarted").await;
        let started = &events.last().unwrap().data;
        assert!(started["device"].is_null());
        let container = ContainerId(started["container"].as_str().unwrap().into());
        assert!(bed.runtime.spec_of(&container).unwrap().devices.is_empty());
        let job = started["job"].as_str().unwrap();
        let (s, _) = bed.send("s1", "StopJob", "stop-job", json!({ "job": job })).await;
        assert_eq!(s, StatusCode::CREATED);
        let events = bed.events_of("s1", "JobStopped").await;
        assert_eq!(types(&events), vec!["JobStopped"]);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            types(&bed.log_of("j2")),
            vec!["ImagePulling", "ImagePulling", "ImagePulled", "JobStarted"],
            "no JobFinished for a stop"
        );
        // A device without the memory to place it by is refused, not ignored.
        let (s, b) = bed
            .send(
                "j4",
                "RunJob",
                "run-job",
                json!({ "image": "busybox", "device": "gpu-0" }),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        assert_eq!(b["error"]["code"], "DEVICE_NEEDS_MEMORY");
        assert_eq!(b["error"]["details"]["field"], "memory_bytes");
        // A missing image fails the job with the fix.
        let (s, _) = bed
            .send("j3", "RunJob", "run-job", json!({ "image": "nobody/nothing:1" }))
            .await;
        assert_eq!(s, StatusCode::CREATED);
        let events = bed.events_of("j3", "JobFailed").await;
        assert!(events.last().unwrap().data["fix"]
            .as_str()
            .unwrap()
            .contains("registry"));
    }

    #[tokio::test]
    async fn after_a_restart_the_state_is_the_logs_and_what_died_meanwhile_is_told() {
        let log = Arc::new(EventLog::ephemeral());
        let runtime = Arc::new(best_peer_runtime::Fake::new(vec!["gpu-0".into()], vec![]));
        let first = bed(card(), log.clone(), runtime.clone()).await;
        let kept = first.deployed("d1", "kept:1b", 4).await;
        let lost = first.deployed("d2", "lost:1b", 4).await;
        let (s, _) = first
            .send(
                "j1",
                "RunJob",
                "run-job",
                json!({ "image": "busybox", "memory_bytes": GB }),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED);
        let job_container = ContainerId(
            first.events_of("j1", "JobStarted").await.last().unwrap().data["container"]
                .as_str()
                .unwrap()
                .into(),
        );
        let lost_container = first.container_of(&lost);
        // A job that keeps running across the restart: its command is complete, and must not be run again.
        let (s, _) = first
            .send(
                "j2",
                "RunJob",
                "run-job",
                json!({ "image": "busybox", "args": ["sleep", "1000"] }),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED);
        first.events_of("j2", "JobStarted").await;
        // The peer dies. While it is down the engine loses one deployment and the job, and nobody hears.
        first.peer.halt();
        let credentials = first.door.auth.clone();
        drop(first);
        runtime.stop(&lost_container).await.unwrap();
        runtime.stop(&job_container).await.unwrap();
        // A new peer over the same log and the same engine.
        // The restart keeps the credentials, as a host's data directory does: the command accepted before it
        // is still its sender's.
        let again = bed_with(
            card(),
            log.clone(),
            runtime.clone(),
            Arc::new(best_peer_engine::Fake::new()),
            "engines.local",
            Some(credentials),
        )
        .await;
        let w = again.query("get-workloads").await;
        assert_eq!(w["deployments"].as_array().unwrap().len(), 1, "{w}");
        assert_eq!(w["deployments"][0]["deployment"], kept);
        assert_eq!(w["deployments"][0]["phase"], "ready");
        assert_eq!(w["jobs"].as_array().unwrap().len(), 1, "{w}");
        assert_eq!(w["jobs"][0]["phase"], "running");
        assert_eq!(
            types(&again.log_of("j2")).iter().filter(|t| *t == "JobStarted").count(),
            1,
            "the running job was not started a second time"
        );
        let ended = again.events_of("d2", "DeploymentEnded").await;
        assert!(ended.last().unwrap().data["reason"]
            .as_str()
            .unwrap()
            .contains("not observed"));
        assert_eq!(
            again.engine.unloaded_at("http://engines.local:41434"),
            vec!["lost:1b"],
            "an engine outside any container is asked to let the lost model go"
        );
        let failed = again.events_of("j1", "JobFailed").await;
        assert!(failed.last().unwrap().data["reason"]
            .as_str()
            .unwrap()
            .contains("not observed"));
        // A deploy accepted just before the crash, never run: it runs now, under its own correlation.
        let owed_log = log.clone();
        let envelope: Envelope = serde_json::from_value(json!({
            "specversion": "1.0", "id": "d9", "source": "https://agent.test", "type": "DeployModel",
            "datacontenttype": "application/json", "dataschema": format!("{EP}/commands/deploy-model/1.0"),
            "time": "2026-10-12T10:30:00Z", "data": { "model": "owed:1b", "engine": "ollama", "memory_bytes": GB }
        }))
        .unwrap();
        // Accepted from a live credential: a restart runs it as that credential, found again in the store.
        owed_log.accept_command(
            &best_peer_door::auth::hash_key(&again.key),
            "d9",
            &best_peer_door::payload_hash(&envelope),
            "d9",
            &envelope,
        );
        again.peer.halt();
        let credentials = again.door.auth.clone();
        drop(again);
        let third = bed_with(
            card(),
            log.clone(),
            runtime.clone(),
            Arc::new(best_peer_engine::Fake::new()),
            "engines.local",
            Some(credentials),
        )
        .await;
        let ready = third.events_of("d9", "DeploymentReady").await;
        assert_eq!(ready.last().unwrap().data["model"], "owed:1b");
        assert!(
            third.door.log.unfinished().is_empty(),
            "nothing is owed once it completed"
        );
        let again = third;
        // The kept deployment still holds its memory, and can still be undeployed.
        let (s, b) = again.deploy("d3", "more:1b", "ollama", 21).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        assert_eq!(
            b["error"]["details"]["devices"][0]["promised_bytes"],
            5 * GB,
            "the kept deployment and the one owed after the restart"
        );
        let (s, _) = again
            .send("u1", "UndeployModel", "undeploy-model", json!({ "deployment": kept }))
            .await;
        assert_eq!(s, StatusCode::CREATED);
        again.events_of("u1", "Undeployed").await;
        let still = runtime.running().await.unwrap();
        assert_eq!(
            still.len(),
            2,
            "the deployment owed after the restart and the running job"
        );
        assert_eq!(again.query("get-workloads").await["deployments"][0]["model"], "owed:1b");
    }
}
