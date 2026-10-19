//! The BEST surface of a peer, written from the spec text (behavioralstate.io, SPEC.md) and from nothing else.
//!
//! A [`Door`] is what a peer offers through the protocol: a [`Catalogue`] of commands, queries and events with their
//! schemas and handlers, an [`EventLog`] every fact is appended to and streamed from, and an [`Auth`] that admits
//! agents through the device flow and checks their credential on every call. [`router`] turns a door into the HTTP
//! routes the spec names; [`manifest`] describes it at `/.well-known/best`.
//!
//! What the door does not know: which hardware or engine stands behind the handlers, and who approves a sign-in. The
//! first two are the peer's abstractions; the last is an [`Approver`] the peer chooses.
//!
//! A door may host tenants (SPEC.md, Multi-Tenancy): the root door declares the URI template of their manifests, and
//! each tenant is a [`Door`] of its own, with its endpoint under the root's and its own log, served through
//! [`tenant_router`] where the host mounts it. The root serves the tenant manifests; the host decides which tenant a
//! credential opens.

pub mod auth;
pub mod catalogue;
pub mod envelope;
pub mod error;
pub mod guidance;
pub mod log;
pub mod manifest;
pub mod router;

pub use auth::{Approver, Auth, FakeApprover, LocalApprover};
pub use catalogue::{AdmitHook, Catalogue, CommandDef, Emitter, EventDef, QueryDef};
pub use envelope::Envelope;
pub use error::BestError;
pub use log::{Accept, EventLog, Filter, Stored, Unfinished};

/// What a credential may read of an event, beyond the door's own rule: `Some(visible)` decides, `None` leaves it to
/// the rule (a credential that acts for every holder reads everything; another reads the events under its own
/// commands). The host sets one where a log carries facts addressed to identities (SPEC.md, Security
/// Requirements: tenant context derives from the credential, streams are isolated per tenant).
pub type Partition = Arc<dyn Fn(&auth::Credential, &Stored) -> Option<bool> + Send + Sync>;
pub use router::{payload_hash, resume, router, tenant_router};

use std::collections::HashMap;
use std::sync::Arc;

/// The BEST spec version this surface is written against.
pub const BEST_VERSION: &str = "0.9.17";

/// Everything the routes need. Built once by the peer, shared by every handler.
pub struct Door {
    /// The consumer-facing base URL every capability path is appended to.
    pub endpoint: String,
    /// The service key in the manifest (`services`), and the `source` of every event the door emits.
    pub service: String,
    /// What the service is, in a sentence, for the manifest.
    pub description: String,
    pub catalogue: Catalogue,
    pub log: Arc<EventLog>,
    pub auth: Arc<Auth>,
    /// Event type → absolute dataschema URI, for every event the catalogue declares.
    pub event_dataschemas: Arc<HashMap<String, String>>,
    /// Commands between their duplicate check and their record, by sender and id: a second copy of one in flight
    /// is the same command, answered as such, never admitted twice.
    pub inflight: std::sync::Mutex<HashMap<(String, String), (String, String)>>,
    /// Command type to the event types that complete it.
    pub completions: Arc<HashMap<String, std::collections::HashSet<String>>>,
    /// The URI template of the tenant manifests this door hosts (`{tenantId}` the one variable), when it hosts
    /// tenants: the manifest's `tenants` block, and the root service then declares its own authentication, so
    /// its capabilities read as the root's, not a tenant's.
    pub tenants: Option<String>,
    /// What a credential may read of this log's events, when the door's own rule is not the whole answer.
    pub partition: Option<Partition>,
}

impl Door {
    pub fn new(
        endpoint: &str,
        service: &str,
        description: &str,
        catalogue: Catalogue,
        log: Arc<EventLog>,
        auth: Arc<Auth>,
    ) -> Self {
        let endpoint = endpoint.trim_end_matches('/').to_string();
        let event_dataschemas = Arc::new(catalogue.event_dataschemas(&endpoint));
        let completions = Arc::new(catalogue.completions());
        Self {
            endpoint,
            service: service.into(),
            description: description.into(),
            catalogue,
            log,
            auth,
            event_dataschemas,
            inflight: std::sync::Mutex::new(HashMap::new()),
            completions,
            tenants: None,
            partition: None,
        }
    }

    /// Decides what a credential reads beyond the door's own rule.
    pub fn with_partition(mut self, partition: Partition) -> Self {
        self.partition = Some(partition);
        self
    }

    /// Whether `who` reads the event `s`: the partition's word when it has one, else the door's rule, under which a
    /// credential that acts for every holder reads everything and another reads the events under the correlations
    /// it owns, the ones its commands used first.
    pub fn visible_to(&self, who: &auth::Credential, s: &Stored) -> bool {
        if let Some(decided) = self.partition.as_ref().and_then(|p| p(who, s)) {
            return decided;
        }
        let only = (!who.grant.is_all()).then_some(who.hash.as_str());
        self.log.visible_to(only, s)
    }

    /// Declares the tenant manifests this door hosts: their URI template, with `{tenantId}` where the tenant's id
    /// goes.
    pub fn with_tenants(mut self, template: &str) -> Self {
        self.tenants = Some(template.into());
        self
    }

    /// The absolute `dataschema` URI of a command, query or event schema document on this door.
    pub fn schema_url(&self, kind: &str, schema: &str, version: &str) -> String {
        format!("{}/{kind}/{schema}/{version}", self.endpoint)
    }

    /// An emitter for the handler of a command with this correlation id.
    pub fn emitter(&self, correlation: &str) -> Emitter {
        Emitter::new(
            self.log.clone(),
            &self.service,
            correlation,
            self.event_dataschemas.clone(),
        )
        .with_completions(self.completions.clone())
    }
}
