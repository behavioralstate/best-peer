//! [`Runtime`] for engines that already run on the host, outside any container: Ollama installed as a service, a
//! vLLM started by hand. There is nothing to pull and nothing to start: a deploy's "container" is the engine's own
//! port on the host, and a stop ends the peer's claim on it, not the engine. Whether the engine answers there is the
//! `Engine` adapter's question, asked on readiness; whether anything still listens on a claimed port is this
//! runtime's, asked when the peer squares its state with what runs: an engine that stopped is gone, with its
//! deployment. A job needs a container engine and is refused with that fix. Thin; proven on a host by hand, never
//! unit-tested.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use best_peer_runtime::{
    ContainerId, Event, ImageRef, Isolation, Progress, Published, Runtime, RuntimeError, Spec, Started,
};
use tokio::sync::broadcast;

pub struct NativeRuntime {
    /// Where the engines' ports are reached from here.
    host: String,
    claimed: Mutex<BTreeMap<ContainerId, Spec>>,
    tx: Option<broadcast::Sender<Event>>,
}

impl NativeRuntime {
    pub fn new(host: &str) -> Self {
        let (tx, _) = broadcast::channel(16);
        Self {
            host: host.to_string(),
            claimed: Mutex::new(BTreeMap::new()),
            tx: Some(tx),
        }
    }

    fn tx(&self) -> &broadcast::Sender<Event> {
        self.tx.as_ref().expect("built with new")
    }
}

#[async_trait]
impl Runtime for NativeRuntime {
    async fn pull(&self, _image: &ImageRef, _progress: Progress) -> Result<(), RuntimeError> {
        Ok(())
    }

    async fn start(&self, spec: Spec) -> Result<Started, RuntimeError> {
        let Some(&port) = spec.ports.first() else {
            return Err(RuntimeError::Engine(
                "no container engine on this host: a job needs Docker (BEST_PEER_RUNTIME=docker)".into(),
            ));
        };
        let id = ContainerId(format!("native-{port}"));
        let mut claimed = self.claimed.lock().unwrap();
        if claimed.contains_key(&id) {
            return Err(RuntimeError::Engine(format!(
                "the engine on port {port} already serves a deployment: undeploy it first"
            )));
        }
        claimed.insert(id.clone(), spec);
        let ports = vec![Published {
            container: port,
            host: port,
        }];
        let _ = self.tx().send(Event::Started {
            id: id.clone(),
            ports: ports.clone(),
        });
        Ok(Started { id, ports })
    }

    async fn stop(&self, id: &ContainerId) -> Result<(), RuntimeError> {
        self.claimed
            .lock()
            .unwrap()
            .remove(id)
            .ok_or_else(|| RuntimeError::NoSuchContainer(id.0.clone()))?;
        let _ = self.tx().send(Event::Exited {
            id: id.clone(),
            code: 0,
            last_words: None,
        });
        Ok(())
    }

    /// A claimed port with something listening on it. One nobody listens on any more is the engine gone: the claim
    /// is dropped, so the port can be claimed again once the engine is back.
    async fn running(&self) -> Result<Vec<ContainerId>, RuntimeError> {
        let claimed: Vec<(ContainerId, u16)> = self
            .claimed
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(id, spec)| spec.ports.first().map(|&port| (id.clone(), port)))
            .collect();
        let mut alive = Vec::new();
        for (id, port) in claimed {
            let listening = tokio::time::timeout(
                Duration::from_secs(2),
                tokio::net::TcpStream::connect((self.host.as_str(), port)),
            )
            .await
            .is_ok_and(|r| r.is_ok());
            if listening {
                alive.push(id);
            } else {
                self.claimed.lock().unwrap().remove(&id);
            }
        }
        Ok(alive)
    }

    fn events(&self) -> broadcast::Receiver<Event> {
        self.tx().subscribe()
    }

    /// A job needs a container engine; this runtime has none, so the door refuses the job at ingest.
    fn runs_jobs(&self) -> bool {
        false
    }

    /// An engine installed on the host runs its models as its own processes: nothing of the peer's stands between.
    async fn isolation(&self) -> Isolation {
        Isolation::Process
    }
}
