//! What this peer offers through its door: the hardware and the workloads as queries, the model lifecycle as
//! commands, each outcome as events; and the workspaces it hosts, the BEST tenants, each with its clouds. The schemas
//! and descriptions here are everything an agent gets. The behaviour is in [`crate::lifecycle`] for the machine's own
//! hardware at the root, in [`crate::workspace`] for the workspaces and their clouds, and in [`crate::cloud`] for a
//! cloud placing across the peers it fronts.
//!
//! Two surfaces, one vocabulary. The root is the machine: its devices, its workloads, the commands that place on it,
//! and the workspaces an identity creates, is invited into, accepts or leaves. A workspace is a tenant with its own
//! endpoint, log and catalogue: its clouds (configured and archived), its devices named `cloud/peer/device`, its
//! workloads with the cloud and the peer on every row, and the same lifecycle commands taking the cloud they place
//! in.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use best_peer_door::auth::{holder_of_hash, Credential};
use best_peer_door::{Auth, BestError, Catalogue, CommandDef, Emitter, Envelope, EventDef, QueryDef};
use best_peer_gpu::Host;
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// What stands behind the lifecycle surface: the handlers of its two queries and five commands, with the checks that
/// admit each command before it is recorded.
#[async_trait]
pub trait Service: Send + Sync + 'static {
    async fn hardware_state(&self, who: &Credential) -> Result<Value, BestError>;
    fn workloads(&self, who: &Credential) -> Result<Value, BestError>;
    fn admit_pull(&self, cmd: Envelope, who: &Credential) -> Result<(), BestError>;
    async fn pull_image(self: Arc<Self>, cmd: Envelope, em: Emitter);
    async fn admit_deploy(&self, cmd: Envelope, who: Credential, key: String) -> Result<(), BestError>;
    async fn deploy(self: Arc<Self>, cmd: Envelope, em: Emitter);
    fn admit_undeploy(&self, cmd: Envelope, who: &Credential) -> Result<(), BestError>;
    async fn undeploy(self: Arc<Self>, cmd: Envelope, em: Emitter);
    async fn admit_run_job(&self, cmd: Envelope, who: Credential, key: String) -> Result<(), BestError>;
    async fn run_job(self: Arc<Self>, cmd: Envelope, em: Emitter);
    fn admit_stop_job(&self, cmd: Envelope, who: &Credential) -> Result<(), BestError>;
    async fn stop_job(self: Arc<Self>, cmd: Envelope, em: Emitter);
    fn admit_prompt(&self, cmd: Envelope, who: &Credential) -> Result<(), BestError>;
    async fn prompt(self: Arc<Self>, cmd: Envelope, em: Emitter);
}

/// What a workspace adds to the lifecycle surface: its clouds, configured and archived.
#[async_trait]
pub trait Clouds: Service {
    fn clouds(&self) -> Result<Value, BestError>;
    fn admit_configure(&self, cmd: Envelope, who: &Credential) -> Result<(), BestError>;
    async fn configure(self: Arc<Self>, cmd: Envelope, em: Emitter);
    fn admit_archive(&self, cmd: Envelope, who: &Credential) -> Result<(), BestError>;
    async fn archive(self: Arc<Self>, cmd: Envelope, em: Emitter);
}

/// What the root knows of its workspaces: which exist, who is in each, and the four commands that change that.
#[async_trait]
pub trait Membership: Send + Sync + 'static {
    fn workspaces(&self, who: &Credential) -> Result<Value, BestError>;
    fn admit_create(&self, cmd: Envelope, who: &Credential) -> Result<(), BestError>;
    async fn create(self: Arc<Self>, cmd: Envelope, em: Emitter);
    fn admit_invite(&self, cmd: Envelope, who: &Credential) -> Result<(), BestError>;
    async fn invite(self: Arc<Self>, cmd: Envelope, em: Emitter);
    fn admit_accept(&self, cmd: Envelope, who: &Credential) -> Result<(), BestError>;
    async fn accept(self: Arc<Self>, cmd: Envelope, em: Emitter);
    fn admit_leave(&self, cmd: Envelope, who: &Credential) -> Result<(), BestError>;
    async fn leave(self: Arc<Self>, cmd: Envelope, em: Emitter);
}

/// Which surface a schema is written for: the machine's own devices at the root, or a workspace's clouds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Where {
    Root,
    Workspace,
}

/// The root door's catalogue: the machine's own hardware and lifecycle, and the workspaces it hosts.
pub fn catalogue(svc: Arc<dyn Service>, membership: Arc<dyn Membership>, auth: Arc<Auth>) -> Catalogue {
    let mut c = lifecycle(Catalogue::new(), svc, Where::Root)
        .query(workspaces_query(membership.clone()))
        .command(create_workspace(membership.clone()))
        .command(invite_member(membership.clone()))
        .command(accept_invitation(membership.clone()))
        .command(leave_workspace(membership))
        .command(revoke_agent(auth));
    for e in event_defs()
        .into_iter()
        .chain(membership_event_defs())
        .chain(credential_event_defs())
    {
        c = c.event(e);
    }
    c
}

/// A workspace door's catalogue: its clouds, the lifecycle placed in them, and the facts about its own membership,
/// which its stream carries too.
pub fn workspace_catalogue(ws: Arc<dyn Clouds>) -> Catalogue {
    let mut c = lifecycle(Catalogue::new(), ws.clone(), Where::Workspace)
        .query(clouds_query(ws.clone()))
        .command(configure_cloud(ws.clone()))
        .command(archive_cloud(ws));
    for e in event_defs()
        .into_iter()
        .chain(cloud_event_defs())
        .chain(membership_event_defs())
    {
        c = c.event(e);
    }
    c
}

fn lifecycle(c: Catalogue, svc: Arc<dyn Service>, at: Where) -> Catalogue {
    c.query(hardware_query(svc.clone(), at))
        .query(workloads_query(svc.clone(), at))
        .command(pull_image(svc.clone(), at))
        .command(deploy_model(svc.clone(), at))
        .command(undeploy_model(svc.clone()))
        .command(run_job(svc.clone(), at))
        .command(stop_job(svc.clone()))
        .command(prompt(svc, at))
}

/// What completes each command: the events after which its outcome is known, so a consumer stops waiting for the
/// command and a restart does not run it again. What the command made then has a life of its own, told under the
/// same correlation id (a deployment's end, a job's end). `CommandFailed` completes any command.
pub fn completions() -> HashMap<String, HashSet<String>> {
    let set = |types: &[&str]| types.iter().map(|t| t.to_string()).collect::<HashSet<_>>();
    HashMap::from([
        ("PullImage".to_string(), set(&["ImagePulled", "ImagePullFailed"])),
        (
            "DeployModel".to_string(),
            set(&["DeploymentReady", "DeploymentFailed", "DeploymentEnded", "OutOfMemory"]),
        ),
        ("UndeployModel".to_string(), set(&["Undeployed"])),
        // JobStopped: on a workspace's door, an order stopped before it started.
        ("RunJob".to_string(), set(&["JobStarted", "JobFailed", "JobStopped"])),
        ("StopJob".to_string(), set(&["JobStopped"])),
        ("Prompt".to_string(), set(&["PromptAnswered", "PromptFailed"])),
        ("CreateWorkspace".to_string(), set(&["WorkspaceCreatedV1"])),
        ("InviteMember".to_string(), set(&["MemberInvitedV1"])),
        ("AcceptInvitation".to_string(), set(&["MemberJoinedV1"])),
        ("LeaveWorkspace".to_string(), set(&["MemberLeftV1"])),
        ("ConfigureCloud".to_string(), set(&["CloudConfiguredV1"])),
        ("ArchiveCloud".to_string(), set(&["CloudArchivedV1"])),
        ("RevokeAgent".to_string(), set(&["AgentRevokedV1"])),
    ])
}

fn completes(command_type: &str) -> Vec<String> {
    let mut v: Vec<String> = completions()
        .remove(command_type)
        .unwrap_or_default()
        .into_iter()
        .collect();
    v.sort();
    v
}

/// Event type to absolute dataschema URI for the root's emitters: the lifecycle, the membership facts and the
/// credentials'.
pub fn event_dataschemas(endpoint: &str) -> HashMap<String, String> {
    let mut c = Catalogue::new();
    for e in event_defs()
        .into_iter()
        .chain(membership_event_defs())
        .chain(credential_event_defs())
    {
        c = c.event(e);
    }
    c.event_dataschemas(endpoint)
}

/// Event type to dataschema URI for a workspace's emitters: the lifecycle, the cloud and the membership facts, on
/// the workspace's endpoint.
pub fn workspace_event_dataschemas(endpoint: &str) -> HashMap<String, String> {
    let mut c = Catalogue::new();
    for e in event_defs()
        .into_iter()
        .chain(cloud_event_defs())
        .chain(membership_event_defs())
    {
        c = c.event(e);
    }
    c.event_dataschemas(endpoint)
}

/// The facts about a workspace's membership, told at the root under the command that made each and again on the
/// workspace's own stream, for its members.
pub const MEMBERSHIP_EVENTS: &[&str] = &[
    "WorkspaceCreatedV1",
    "MemberInvitedV1",
    "MemberJoinedV1",
    "MemberLeftV1",
];

/// The commands that change a workspace's membership, whose failures are their sender's alone to read.
pub const MEMBERSHIP_COMMANDS: &[&str] = &["CreateWorkspace", "InviteMember", "AcceptInvitation", "LeaveWorkspace"];

/// The facts that are a workspace's own, which every member of it reads whatever their grant: its membership, its
/// clouds and its peers. What a workload's holder alone reads stays the lifecycle's rule.
pub const WORKSPACE_EVENTS: &[&str] = &[
    "WorkspaceCreatedV1",
    "MemberInvitedV1",
    "MemberJoinedV1",
    "MemberLeftV1",
    "CloudConfiguredV1",
    "CloudArchivedV1",
    "PeerJoined",
    "PeerLost",
];

/// What a credential may be approved for: `deploy` models (pull, deploy, undeploy), run `jobs` (run, stop), `prompt`
/// a ready deployment; `all` is every scope and every holder's workloads, what a credential approved with nothing
/// said is. Reading the hardware and its own workloads and events is every credential's, as is creating a workspace
/// and acting in the ones it belongs to.
pub const SCOPES: &[&str] = &["deploy", "jobs", "prompt"];

/// `^[a-z0-9][a-z0-9-]{0,63}$`: the shape of a cloud's name and a peer's name in a cloud, so that each composes
/// into a device id (`cloud/peer/device`) and into the connection name a cloud signs in to its members under.
pub fn is_name(s: &str) -> bool {
    best_peer_door::auth::is_connection_name(s)
}

/// What a refusal says about a name of another shape.
pub const NAME_SHAPE: &str =
    "one word of lowercase letters, digits and hyphens, 1 to 64 characters, starting with a letter or digit; no slash, since it composes into ids as cloud/peer/device";

fn hardware_query(svc: Arc<dyn Service>, at: Where) -> QueryDef {
    let description = match at {
        Where::Root => "The accelerators on this host right now: each device's compute APIs with their versions, its memory total and free, temperature, power and utilisation, and the driver. Read it before deploying: a model needs an API the device offers and memory it has free; get-workloads says what already holds memory.",
        Where::Workspace => "The accelerators of this workspace's clouds right now: every device of every peer that answers in a cloud that is not archived, named cloud/peer/device, with the cloud and the peer on each, its compute APIs with their versions, its memory total and free (less what the peer has promised), temperature, power and utilisation; and peers, every member of every cloud with whether it answers (up), has not admitted the cloud yet (joining) or does not answer (unreachable). Read it before deploying: a model needs an API a device offers and memory it has free; get-workloads says what already holds memory.",
    };
    let mut device_properties = json!({
        "id": { "type": "string", "description": "Stable device id, the value a command names a device by" },
        "vendor": { "description": "Who made it; informative, never what a workload asks for" },
        "name": { "type": "string" },
        "memory": { "type": "object", "properties": { "total_bytes": { "type": "integer" }, "free_bytes": { "type": "integer" } } },
        "compute": { "type": "array", "description": "The compute APIs the device offers, with versions: what a workload asks for", "items": { "type": "object", "properties": { "api": { "type": "string" }, "version": { "type": "string" } } } },
        "temperature_c": { "type": ["number", "null"] },
        "power_w": { "type": ["number", "null"] },
        "utilisation_pct": { "type": ["integer", "null"] }
    });
    let mut properties = json!({
        "driver": { "type": ["string", "null"], "description": "The accelerator driver's version, when there is one" },
        "observed_at": { "type": "string", "format": "date-time" }
    });
    if at == Where::Workspace {
        device_properties["id"]["description"] =
            json!("Stable device id, the value a command names a device by: cloud/peer/device");
        device_properties["cloud"] = json!({ "type": "string", "description": "The cloud the device is in" });
        device_properties["peer"] = json!({ "type": "string", "description": "The member peer the device is on" });
        properties["peers"] = json!({
            "type": "array",
            "description": "Every member of every cloud of this workspace and whether it answers",
            "items": { "type": "object", "required": ["cloud", "peer", "endpoint", "state"], "properties": {
                "cloud": { "type": "string" }, "peer": { "type": "string" }, "endpoint": { "type": "string", "description": "The member's own door" },
                "state": { "type": "string", "enum": ["up", "joining", "unreachable"], "description": "up answers; joining has not admitted this cloud yet (its owner approves the code in the door's log); unreachable did not answer" },
                "driver": { "type": ["string", "null"] }, "reason": { "type": "string", "description": "What the cloud saw, when unreachable" }
            } }
        });
    }
    properties["devices"] = json!({
        "type": "array",
        "items": { "type": "object", "required": ["id", "vendor", "name", "memory", "compute"], "properties": device_properties }
    });
    QueryDef {
        schema: "get-hardware-state".into(),
        version: "1.0".into(),
        description: description.into(),
        parameters: None,
        response: json!({ "type": "object", "required": ["devices", "observed_at"], "properties": properties }),
        handler: Arc::new(move |who, _params| {
            let svc = svc.clone();
            Box::pin(async move { svc.hardware_state(&who).await })
        }),
    }
}

fn workloads_query(peer: Arc<dyn Service>, at: Where) -> QueryDef {
    let description = match at {
        Where::Root => "What this peer runs for you now: each deployment with its model, engine, device, the memory promised to it, its phase (starting, ready, ending); each job with its image, device and phase (running, stopping); and held_bytes, the device memory your workloads hold together on this door, against share_bytes, the most your credential may hold (null when no share was set). A credential approved for all sees every holder's workloads, with the holder. The ids here are what undeploy-model and stop-job name.",
        Where::Workspace => "What this workspace runs for you now, across its clouds: each deployment with its cloud, the peer it is on, its model, engine, device (cloud/peer/device), the memory promised to it, its phase (starting, ready, ending); each job with its cloud, peer, image, device and phase (running, stopping); queued, the orders not started yet, oldest first, each with its id (what stop-job names while it waits), its cloud, image and memory, whether it waits or the peer it was sent to, its attempt and when it was queued; and held_bytes, the device memory your workloads hold together on this door, every workspace counted, orders that wait included, against share_bytes, the most your credential may hold (null when no share was set). A credential approved for all sees every holder's workloads, with the holder. The ids here are what undeploy-model and stop-job name.",
    };
    let mut deployment = json!({
        "deployment": { "type": "string" }, "model": { "type": "string" }, "engine": { "type": "string", "enum": ["ollama", "vllm"] },
        "device": { "type": "string" }, "memory_bytes": { "type": "integer" }, "holder": { "type": "string", "description": "The credential that deployed it, an opaque id" },
        "phase": { "type": "string", "enum": ["starting", "ready", "ending"] }
    });
    let mut job = json!({
        "job": { "type": "string" }, "image": { "type": "string" }, "device": { "type": ["string", "null"] },
        "memory_bytes": { "type": "integer" }, "holder": { "type": "string" }, "phase": { "type": "string", "enum": ["running", "stopping"] }
    });
    let mut required_deployment = vec!["deployment", "model", "engine", "device", "memory_bytes", "phase"];
    let mut required_job = vec!["job", "image", "phase"];
    if at == Where::Workspace {
        for row in [&mut deployment, &mut job] {
            row["cloud"] = json!({ "type": "string", "description": "The cloud it was placed in" });
            row["peer"] = json!({ "type": "string", "description": "The member peer it runs on" });
        }
        required_deployment.extend(["cloud", "peer"]);
        required_job.extend(["cloud", "peer"]);
    }
    let mut response = json!({
        "type": "object",
        "required": ["deployments", "jobs"],
        "properties": {
            "deployments": { "type": "array", "items": { "type": "object", "required": required_deployment, "properties": deployment } },
            "jobs": { "type": "array", "items": { "type": "object", "required": required_job, "properties": job } },
            "held_bytes": { "type": "integer", "description": "The device memory your workloads hold together on this door, admitted ones included" },
            "share_bytes": { "type": ["integer", "null"], "description": "The most your credential may hold; null when no share was set" }
        }
    });
    if at == Where::Workspace {
        response["required"] = json!(["deployments", "jobs", "queued"]);
        response["properties"]["queued"] = json!({
            "type": "array",
            "description": "The orders not started yet, oldest first",
            "items": {
                "type": "object",
                "required": ["job", "cloud", "image", "attempt", "queued_at", "waiting"],
                "properties": {
                    "job": { "type": "string", "description": "The order's id, what stop-job names" },
                    "cloud": { "type": "string", "description": "The cloud that took it" },
                    "image": { "type": "string" },
                    "memory_bytes": { "type": ["integer", "null"] },
                    "device": { "type": ["string", "null"], "description": "The device it pinned, cloud/peer/device" },
                    "holder": { "type": "string", "description": "The credential that ordered it, an opaque id" },
                    "attempt": { "type": "integer", "description": "1; 2 once queued again after a member peer was lost under it" },
                    "queued_at": { "type": "string", "description": "When this attempt was queued, as JobQueued told it" },
                    "queue_seconds": { "type": ["integer", "null"], "description": "How long it may wait from then" },
                    "waiting": { "type": "boolean", "description": "True while no member peer has taken it; false once sent to the peer named" },
                    "peer": { "type": ["string", "null"], "description": "The member peer it was sent to, once sent" }
                }
            }
        });
    }
    QueryDef {
        schema: "get-workloads".into(),
        version: "1.0".into(),
        description: description.into(),
        parameters: None,
        response,
        handler: Arc::new(move |who, _params| {
            let peer = peer.clone();
            Box::pin(async move { peer.workloads(&who) })
        }),
    }
}

/// The `cloud` a workspace's placing commands take.
fn cloud_property(what: &str) -> Value {
    json!({ "type": "string", "maxLength": 64, "description": format!("The cloud of this workspace {what}; get-clouds lists them") })
}

fn prompt(peer: Arc<dyn Service>, at: Where) -> CommandDef {
    let admit = peer.clone();
    let description = match at {
        Where::Root => "Asks a ready deployment on this peer to answer a conversation, whole. The messages are the conversation so far, each with its role (system, user, assistant) and content; max_tokens, temperature and stop are the engine's knobs, and are left to the engine when not given. Refused at once, with the reason and what to do, when the deployment is not there, not ready yet, ending, or another credential's. Otherwise PromptAnswered follows on the stream with this command's correlation id, carrying the answer and the token counts the engine reports, or PromptFailed with the reason and the fix; either completes the command. Nothing of the engine is reachable any other way: this command is the one data path. Needs the prompt scope.",
        Where::Workspace => "Asks a ready deployment in a cloud of this workspace to answer a conversation, whole; the deployment names its cloud and peer. The messages are the conversation so far, each with its role (system, user, assistant) and content; max_tokens, temperature and stop are the engine's knobs, and are left to the engine when not given. Refused at once, with the reason and what to do, when the deployment is not this workspace's, not ready yet, ending, or another credential's. Otherwise PromptAnswered follows on this workspace's stream with this command's correlation id, the cloud and the peer named, carrying the answer and the token counts the engine reports, or PromptFailed with the reason and the fix; either completes the command. Needs the prompt scope.",
    };
    CommandDef {
        schema: "prompt".into(),
        version: "1.0".into(),
        command_type: "Prompt".into(),
        description: description.into(),
        data_schema: json!({
            "type": "object",
            "required": ["deployment", "messages"],
            "properties": {
                "deployment": { "type": "string", "minLength": 1, "maxLength": 128, "description": "The deployment to ask, as DeploymentReady and get-workloads name it; it must be ready" },
                "messages": {
                    "type": "array", "minItems": 1, "maxItems": 1024,
                    "description": "The conversation so far, oldest first; the last is what the model answers",
                    "items": {
                        "type": "object", "required": ["role", "content"], "additionalProperties": false,
                        "properties": {
                            "role": { "type": "string", "enum": ["system", "user", "assistant"] },
                            "content": { "type": "string", "maxLength": 131072 }
                        }
                    }
                },
                "max_tokens": { "type": "integer", "minimum": 1, "maximum": 1048576, "description": "The most tokens the answer may have; the engine's default when not given" },
                "temperature": { "type": "number", "minimum": 0, "maximum": 2, "description": "The sampling temperature; the engine's default when not given" },
                "stop": { "type": "array", "items": { "type": "string", "minLength": 1, "maxLength": 256 }, "maxItems": 4, "description": "Strings at which the answer stops" }
            },
            "additionalProperties": false
        }),
        produces: vec!["PromptAnswered".into(), "PromptFailed".into()],
        completes: completes("Prompt"),
        impact: None,
        admit: Some(Arc::new(move |cmd, who, _key| {
            let peer = admit.clone();
            Box::pin(async move { peer.admit_prompt(cmd, &who) })
        })),
        handler: Arc::new(move |cmd, emitter| {
            let peer = peer.clone();
            Box::pin(async move { peer.prompt(cmd, emitter).await })
        }),
    }
}

fn pull_image(peer: Arc<dyn Service>, at: Where) -> CommandDef {
    let admit = peer.clone();
    let (description, mut properties, required) = match at {
        Where::Root => (
            "Pulls a container image from its registry onto this peer, whether or not the peer holds it already, so a later deploy or job can start at once: how a held image is refreshed where a deploy or a job runs what the peer holds as it is. The outcome is an ImagePulled or ImagePullFailed event with this command's correlation id. Needs the deploy scope.",
            json!({}),
            vec!["image"],
        ),
        Where::Workspace => (
            "Pulls a container image from its registry onto every peer of the cloud named, whether or not a peer holds it already, so a later deploy or job there can start at once: how a held image is refreshed where a deploy or a job runs what a peer holds as it is. Progress is told per peer as ImagePulling with the peer named; the outcome is one ImagePulled once every peer has it, or ImagePullFailed naming the peers that failed, with this command's correlation id. Refused at once when the cloud is not this workspace's or is archived. Needs the deploy scope.",
            json!({ "cloud": cloud_property("to pull on") }),
            vec!["image", "cloud"],
        ),
    };
    properties["image"] = json!({ "type": "string", "minLength": 1, "maxLength": 512, "description": "The image reference as the container engine understands it, name and tag" });
    CommandDef {
        schema: "pull-image".into(),
        version: "1.0".into(),
        command_type: "PullImage".into(),
        description: description.into(),
        data_schema: json!({ "type": "object", "required": required, "properties": properties, "additionalProperties": false }),
        produces: vec!["ImagePulling".into(), "ImagePulled".into(), "ImagePullFailed".into()],
        completes: completes("PullImage"),
        impact: None,
        admit: Some(Arc::new(move |cmd, who, _key| {
            let peer = admit.clone();
            Box::pin(async move { peer.admit_pull(cmd, &who) })
        })),
        handler: Arc::new(move |cmd, emitter| {
            let peer = peer.clone();
            Box::pin(async move { peer.pull_image(cmd, emitter).await })
        }),
    }
}

fn deploy_model(peer: Arc<dyn Service>, at: Where) -> CommandDef {
    let admit = peer.clone();
    let (description, mut properties) = match at {
        Where::Root => (
            "Serves a model on this peer with the engine named, on a device that offers an API the engine runs on and has the memory asked for free. Refused at once, with the reason and what to do, when no device fits, or when the credential already runs as many deployments across this door as its approver allowed (DEPLOYMENTS_EXCEEDED); a credential held to the accelerators runs on those get-hardware-state shows it, never on a host's CPU (ACCELERATORS_ONLY). Otherwise the facts follow on the stream with this command's correlation id: ImagePulling and ImagePulled (an image the peer holds is used as it is, not pulled again, when it is pinned by digest or the operator pulls only what is missing; one named by tag is otherwise pulled each time), DeploymentStarted, WeightsLoading, then DeploymentReady, after which prompt commands naming the deployment are answered, or DeploymentFailed, which complete it. Later, OutOfMemory or DeploymentEnded if the engine ends it or stops on its own, under the same correlation id. Needs the deploy scope, and room in the credential's share when one was set.",
            json!({
                "device": { "type": "string", "maxLength": 256, "description": "A device id from get-hardware-state, to pin the placement; otherwise the fitting device with the most room" }
            }),
        ),
        Where::Workspace => (
            "Serves a model in a cloud of this workspace with the engine named, on the member peer whose device offers an API the engine runs on and has the memory asked for free; name the cloud, or a device (cloud/peer/device) to pin the placement, which names the cloud too. Refused at once, with the reason and what to do, when the cloud is not this workspace's, is archived, or no device in it fits, or when the credential already runs as many deployments across this door as its approver allowed (DEPLOYMENTS_EXCEEDED); a credential held to the accelerators runs on those get-hardware-state shows it, never on a host's CPU (ACCELERATORS_ONLY). Otherwise the facts follow on this workspace's stream with this command's correlation id, each with the cloud and the peer named: ImagePulling and ImagePulled (an image the peer holds is used as it is, not pulled again, when it is pinned by digest or the operator pulls only what is missing; one named by tag is otherwise pulled each time), DeploymentStarted with the device as cloud/peer/device, WeightsLoading, then DeploymentReady, after which prompt commands naming the deployment are answered on this workspace's door, or DeploymentFailed, which complete it. Later, OutOfMemory or DeploymentEnded if the engine ends it, the peer stops on its own, or the peer is lost, under the same correlation id. Needs the deploy scope, and room in the credential's share when one was set.",
            json!({
                "cloud": cloud_property("to place in; may be left out when device names it"),
                "device": { "type": "string", "maxLength": 256, "description": "A device id from this workspace's get-hardware-state, cloud/peer/device, to pin the placement; otherwise the fitting device of the cloud with the most room" }
            }),
        ),
    };
    properties["model"] = json!({ "type": "string", "minLength": 1, "maxLength": 256, "description": "The model as the engine names it: the name in the engine's own library or registry, tag included where the engine uses one" });
    properties["engine"] = json!({ "type": "string", "enum": ["ollama", "vllm"], "description": "ollama runs on cuda, rocm or cpu; vllm on cuda" });
    properties["memory_bytes"] = json!({ "type": "integer", "minimum": 1, "description": "The device memory the model needs; the deploy is placed where that much is free after what is already promised" });
    CommandDef {
        schema: "deploy-model".into(),
        version: "1.0".into(),
        command_type: "DeployModel".into(),
        description: description.into(),
        data_schema: json!({
            "type": "object",
            "required": ["model", "engine", "memory_bytes"],
            "properties": properties,
            "additionalProperties": false
        }),
        produces: vec![
            "ImagePulling".into(),
            "ImagePulled".into(),
            "DeploymentStarted".into(),
            "WeightsLoading".into(),
            "DeploymentReady".into(),
            "DeploymentFailed".into(),
            "OutOfMemory".into(),
            "DeploymentEnded".into(),
        ],
        completes: completes("DeployModel"),
        impact: None,
        admit: Some(Arc::new(move |cmd, who, key| {
            let peer = admit.clone();
            Box::pin(async move { peer.admit_deploy(cmd, who, key).await })
        })),
        handler: Arc::new(move |cmd, emitter| {
            let peer = peer.clone();
            Box::pin(async move { peer.deploy(cmd, emitter).await })
        }),
    }
}

fn undeploy_model(peer: Arc<dyn Service>) -> CommandDef {
    let admit = peer.clone();
    CommandDef {
        schema: "undeploy-model".into(),
        version: "1.0".into(),
        command_type: "UndeployModel".into(),
        description: "Stops a deployment and frees its device memory. Refused when no such deployment is live, or when another credential deployed it. The outcome is an Undeployed event with this command's correlation id. Needs the deploy scope.".into(),
        data_schema: json!({
            "type": "object",
            "required": ["deployment"],
            "properties": {
                "deployment": { "type": "string", "minLength": 1, "maxLength": 128, "description": "The deployment id from DeploymentStarted or get-workloads" }
            },
            "additionalProperties": false
        }),
        produces: vec!["Undeployed".into(), "CommandFailed".into()],
        completes: completes("UndeployModel"),
        impact: None,
        admit: Some(Arc::new(move |cmd, who, _key| {
            let peer = admit.clone();
            Box::pin(async move { peer.admit_undeploy(cmd, &who) })
        })),
        handler: Arc::new(move |cmd, emitter| {
            let peer = peer.clone();
            Box::pin(async move { peer.undeploy(cmd, emitter).await })
        }),
    }
}

fn run_job(peer: Arc<dyn Service>, at: Where) -> CommandDef {
    let admit = peer.clone();
    let (description, mut properties) = match at {
        Where::Root => (
            "Runs an image once, with the arguments given, and tells its end. With memory_bytes the job is placed on a device with that much room and handed that device; without, it runs with no device. The facts follow with this command's correlation id: ImagePulling and ImagePulled (an image the peer holds is used as it is, not pulled again, when it is pinned by digest or the operator pulls only what is missing; one named by tag is otherwise pulled each time), then JobStarted or JobFailed, which complete the command; the job's own end follows as JobFinished with the exit code, or JobFailed. No container gets a capability or a new privilege, and each has a ceiling on tasks (threads count). The job of a credential with a share runs in a closed box besides: no network, a read-only filesystem with a private /tmp of 1 GiB, and a ceiling on host memory that whoever runs the peer sets, unless its approver opened its jobs; JobStarted says boxed. An image that needs the network fails inside the box, not at the door, and a boxed job that reaches the host memory ceiling ends in JobFailed naming it, whatever memory_bytes it asked for, since memory_bytes is device memory. Needs the jobs scope, and room in the credential's share when one was set and memory_bytes is given; a credential with a share sends memory_bytes, since its jobs run on a device where the share counts them (JOB_NEEDS_DEVICE without); refused when the credential already runs as many jobs across this door as its approver allowed (JOBS_EXCEEDED); one held to the accelerators names no device offering the CPU alone (ACCELERATORS_ONLY).",
            json!({
                "device": { "type": "string", "maxLength": 256, "description": "A device id from get-hardware-state, to pin the placement; refused without memory_bytes" }
            }),
        ),
        Where::Workspace => (
            "Orders an image run once in a cloud of this workspace, with the arguments given, and tells its end. With memory_bytes the job is placed on a member peer's device with that much room and handed that device; without, it runs on the first peer of the cloud that answers, with no device. Name the cloud, or a device (cloud/peer/device) to pin the placement, which names the cloud too. Refused at once when the cloud is not this workspace's or is archived, and when no device of the cloud's members that answer could ever hold it (INSUFFICIENT_MEMORY, NO_DEVICE_FOR_ENGINE, NO_SUCH_DEVICE, with the devices); a cloud with no room now takes the order and it waits its turn. JobQueued follows first, with the order's id as job and waiting true when it waits; the cloud places its orders first come, first served, as soon as a member has the memory free, and an order that does not fit yet holds back none that does. JobPlaced names the member peer it was sent to. queue_seconds bounds the wait: an order not placed within it ends in JobFailed saying it was never placed. deadline_seconds bounds the run from JobStarted: a job still running past it is stopped, and JobStopped says why. stop-job names a waiting order by its id, which ends it in JobStopped before it started. A member peer lost under an order queues it again once, JobQueued telling attempt 2, and fails it the second time. The facts follow on this workspace's stream with this command's correlation id, each with the cloud and the peer named: ImagePulling and ImagePulled (an image the peer holds is used as it is, not pulled again, when it is pinned by digest or the operator pulls only what is missing; one named by tag is otherwise pulled each time), then JobStarted or JobFailed, which complete the command; the job's own end follows as JobFinished with the exit code, or JobFailed. No container gets a capability or a new privilege, and each has a ceiling on tasks (threads count). The job of a credential with a share runs in a closed box besides: no network, a read-only filesystem with a private /tmp of 1 GiB, and a ceiling on host memory that whoever runs that peer sets, unless its approver opened its jobs; JobStarted says boxed. An image that needs the network fails inside the box, not at the door, and a boxed job that reaches the host memory ceiling ends in JobFailed naming it, whatever memory_bytes it asked for, since memory_bytes is device memory. Needs the jobs scope, and room in the credential's share when one was set and memory_bytes is given; a credential with a share sends memory_bytes, since its jobs run on a device where the share counts them (JOB_NEEDS_DEVICE without); refused when the credential already runs as many jobs across this door as its approver allowed (JOBS_EXCEEDED); one held to the accelerators names no device offering the CPU alone (ACCELERATORS_ONLY).",
            json!({
                "cloud": cloud_property("to run in; may be left out when device names it"),
                "device": { "type": "string", "maxLength": 256, "description": "A device id from this workspace's get-hardware-state, cloud/peer/device, to pin the placement; refused without memory_bytes" },
                "queue_seconds": { "type": "integer", "minimum": 1, "maximum": 604800, "description": "How long the order may wait for room before it ends unplaced, counted from JobQueued; at most seven days; without it the order waits until it is placed or stopped" },
                "deadline_seconds": { "type": "integer", "minimum": 1, "maximum": 2592000, "description": "How long the job may run before it is stopped, counted from JobStarted; at most thirty days; without it the job runs to its end" }
            }),
        ),
    };
    let produces: Vec<String> = match at {
        Where::Root => vec!["ImagePulling", "ImagePulled", "JobStarted", "JobFinished", "JobFailed"],
        Where::Workspace => vec![
            "JobQueued",
            "JobPlaced",
            "ImagePulling",
            "ImagePulled",
            "JobStarted",
            "JobFinished",
            "JobFailed",
            "JobStopped",
        ],
    }
    .into_iter()
    .map(String::from)
    .collect();
    properties["image"] = json!({ "type": "string", "minLength": 1, "maxLength": 512, "description": "The image to run, as the container engine understands it" });
    properties["args"] = json!({ "type": "array", "maxItems": 256, "items": { "type": "string", "maxLength": 4096 }, "description": "The command line passed to the image's entrypoint" });
    properties["memory_bytes"] = json!({ "type": "integer", "minimum": 1, "description": "Device memory the job needs; omit to run it with no device" });
    CommandDef {
        schema: "run-job".into(),
        version: "1.0".into(),
        command_type: "RunJob".into(),
        description: description.into(),
        data_schema: json!({
            "type": "object",
            "required": ["image"],
            "properties": properties,
            "additionalProperties": false
        }),
        // An order stopped before it started is a workspace's alone; the root's run-job never tells JobStopped.
        completes: completes("RunJob")
            .into_iter()
            .filter(|t| produces.contains(t))
            .collect(),
        produces,
        impact: None,
        admit: Some(Arc::new(move |cmd, who, key| {
            let peer = admit.clone();
            Box::pin(async move { peer.admit_run_job(cmd, who, key).await })
        })),
        handler: Arc::new(move |cmd, emitter| {
            let peer = peer.clone();
            Box::pin(async move { peer.run_job(cmd, emitter).await })
        }),
    }
}

fn stop_job(peer: Arc<dyn Service>) -> CommandDef {
    let admit = peer.clone();
    CommandDef {
        schema: "stop-job".into(),
        version: "1.0".into(),
        command_type: "StopJob".into(),
        description: "Stops a running job; on a workspace's door, also an order that waits or is not yet started, named by the id JobQueued gave it, which ends before it started: JobStopped under the order's own correlation id too. Refused when no such job or order is there, or when another credential started it. The outcome is a JobStopped event with this command's correlation id. Needs the jobs scope.".into(),
        data_schema: json!({
            "type": "object",
            "required": ["job"],
            "properties": {
                "job": { "type": "string", "minLength": 1, "maxLength": 128, "description": "The job id from JobStarted or get-workloads; on a workspace's door, or an order's id from JobQueued" }
            },
            "additionalProperties": false
        }),
        produces: vec!["JobStopped".into(), "CommandFailed".into()],
        completes: completes("StopJob"),
        impact: None,
        admit: Some(Arc::new(move |cmd, who, _key| {
            let peer = admit.clone();
            Box::pin(async move { peer.admit_stop_job(cmd, &who) })
        })),
        handler: Arc::new(move |cmd, emitter| {
            let peer = peer.clone();
            Box::pin(async move { peer.stop_job(cmd, emitter).await })
        }),
    }
}

// ----- the workspaces, at the root ----------------------------------------------------------------------------------

fn workspaces_query(m: Arc<dyn Membership>) -> QueryDef {
    QueryDef {
        schema: "get-workspaces".into(),
        version: "1.0".into(),
        description: "Who you are on this door and where you belong: identity, the opaque id of your credential, which an owner names to invite you; workspaces, every workspace you own or are a member of, each with its id, name, your role, its members, and the endpoint and manifest of its own door, where its clouds, devices, workloads, commands and events are; and invitations, the workspaces you were invited into and have not accepted, which accept-invitation takes. Nothing of a workspace you do not belong to is listed, here or on this door's events: the root tells you the facts addressed to you (the workspaces you made or joined, the invitations you received) and the workspace's own stream tells its members the rest.".into(),
        parameters: None,
        response: json!({
            "type": "object",
            "required": ["identity", "workspaces", "invitations"],
            "properties": {
                "identity": { "type": "string", "description": "Your identity on this door: an opaque id of your credential, the value invite-member names" },
                "workspaces": { "type": "array", "items": { "type": "object", "required": ["workspace", "name", "role", "endpoint", "manifest", "members"], "properties": {
                    "workspace": { "type": "string", "description": "The workspace id: the tenant id, what the other commands name" },
                    "name": { "type": "string" },
                    "role": { "type": "string", "enum": ["owner", "member"] },
                    "endpoint": { "type": "string", "description": "The workspace's own door: its commands, queries and events are under it" },
                    "manifest": { "type": "string", "description": "The workspace's manifest, the one document an agent needs to act in it" },
                    "members": { "type": "array", "items": { "type": "object", "required": ["identity", "role"], "properties": { "identity": { "type": "string" }, "role": { "type": "string", "enum": ["owner", "member"] } } } }
                } } },
                "invitations": { "type": "array", "items": { "type": "object", "required": ["workspace", "name"], "properties": {
                    "workspace": { "type": "string", "description": "What accept-invitation names" }, "name": { "type": "string" }, "invited_by": { "type": "string", "description": "The identity that invited you" }
                } } }
            }
        }),
        handler: Arc::new(move |who, _params| {
            let m = m.clone();
            Box::pin(async move { m.workspaces(&who) })
        }),
    }
}

fn clouds_query(ws: Arc<dyn Clouds>) -> QueryDef {
    QueryDef {
        schema: "get-clouds".into(),
        version: "1.0".into(),
        description: "The clouds of this workspace: each named pool of machines with its member peers (name and endpoint) and whether each answers (up), has not admitted the cloud yet (joining) or does not answer (unreachable), and whether the cloud is archived. The cloud's name is what deploy-model, run-job, pull-image and archive-cloud take, and the first part of every device id (cloud/peer/device). configure-cloud makes a cloud or changes its members.".into(),
        parameters: None,
        response: json!({
            "type": "object",
            "required": ["clouds"],
            "properties": {
                "clouds": { "type": "array", "items": { "type": "object", "required": ["cloud", "archived", "peers"], "properties": {
                    "cloud": { "type": "string" },
                    "archived": { "type": "boolean", "description": "An archived cloud places nothing and answers no device; configure-cloud with its name brings it back" },
                    "peers": { "type": "array", "items": { "type": "object", "required": ["peer", "endpoint", "state"], "properties": {
                        "peer": { "type": "string" }, "endpoint": { "type": "string" },
                        "state": { "type": "string", "enum": ["up", "joining", "unreachable", "archived"] }
                    } } }
                } } }
            }
        }),
        handler: Arc::new(move |_who, _params| {
            let ws = ws.clone();
            Box::pin(async move { ws.clouds() })
        }),
    }
}

fn create_workspace(m: Arc<dyn Membership>) -> CommandDef {
    let admit = m.clone();
    CommandDef {
        schema: "create-workspace".into(),
        version: "1.0".into(),
        command_type: "CreateWorkspace".into(),
        description: "Makes a workspace, the organization or team that holds clouds and admits the identities who may use them, with you as its owner. The outcome is a WorkspaceCreatedV1 event with this command's correlation id, naming the new workspace's id; get-workspaces then lists it with the endpoint of its own door, where configure-cloud makes its first cloud. Any credential may create a workspace.".into(),
        data_schema: json!({
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": { "type": "string", "minLength": 1, "maxLength": 100, "description": "What the workspace is called, for people; the id is the door's" }
            },
            "additionalProperties": false
        }),
        produces: vec!["WorkspaceCreatedV1".into(), "CommandFailed".into()],
        completes: completes("CreateWorkspace"),
        impact: None,
        admit: Some(Arc::new(move |cmd, who, _key| {
            let m = admit.clone();
            Box::pin(async move { m.admit_create(cmd, &who) })
        })),
        handler: Arc::new(move |cmd, emitter| {
            let m = m.clone();
            Box::pin(async move { m.create(cmd, emitter).await })
        }),
    }
}

fn invite_member(m: Arc<dyn Membership>) -> CommandDef {
    let admit = m.clone();
    CommandDef {
        schema: "invite-member".into(),
        version: "1.0".into(),
        command_type: "InviteMember".into(),
        description: "Invites an identity into a workspace you own, as a member. The identity is the value get-workspaces shows that person or agent as identity, on this door, after they signed in; ask them for it. The outcome is a MemberInvitedV1 event with this command's correlation id; the invitation shows in their get-workspaces until they accept it with accept-invitation. Refused when the workspace is not yours to invite into, or the identity is already a member or already invited.".into(),
        data_schema: json!({
            "type": "object",
            "required": ["workspace", "identity"],
            "properties": {
                "workspace": { "type": "string", "minLength": 1, "maxLength": 128, "description": "The workspace id from get-workspaces" },
                "identity": { "type": "string", "maxLength": 16, "pattern": "^[0-9a-f]{16}$", "description": "The invitee's identity on this door, as their get-workspaces shows it" }
            },
            "additionalProperties": false
        }),
        produces: vec!["MemberInvitedV1".into(), "CommandFailed".into()],
        completes: completes("InviteMember"),
        impact: None,
        admit: Some(Arc::new(move |cmd, who, _key| {
            let m = admit.clone();
            Box::pin(async move { m.admit_invite(cmd, &who) })
        })),
        handler: Arc::new(move |cmd, emitter| {
            let m = m.clone();
            Box::pin(async move { m.invite(cmd, emitter).await })
        }),
    }
}

fn accept_invitation(m: Arc<dyn Membership>) -> CommandDef {
    let admit = m.clone();
    CommandDef {
        schema: "accept-invitation".into(),
        version: "1.0".into(),
        command_type: "AcceptInvitation".into(),
        description: "Accepts an invitation into a workspace, making you a member of it: from then its door opens to your credential, and get-workspaces lists it with the endpoint. The invitations you may accept are in get-workspaces. The outcome is a MemberJoinedV1 event with this command's correlation id. Refused when no invitation into that workspace stands for your identity.".into(),
        data_schema: json!({
            "type": "object",
            "required": ["workspace"],
            "properties": {
                "workspace": { "type": "string", "minLength": 1, "maxLength": 128, "description": "The workspace id, from the invitations in get-workspaces" }
            },
            "additionalProperties": false
        }),
        produces: vec!["MemberJoinedV1".into(), "CommandFailed".into()],
        completes: completes("AcceptInvitation"),
        impact: None,
        admit: Some(Arc::new(move |cmd, who, _key| {
            let m = admit.clone();
            Box::pin(async move { m.admit_accept(cmd, &who) })
        })),
        handler: Arc::new(move |cmd, emitter| {
            let m = m.clone();
            Box::pin(async move { m.accept(cmd, emitter).await })
        }),
    }
}

fn leave_workspace(m: Arc<dyn Membership>) -> CommandDef {
    let admit = m.clone();
    CommandDef {
        schema: "leave-workspace".into(),
        version: "1.0".into(),
        command_type: "LeaveWorkspace".into(),
        description: "Leaves a workspace you are a member of: its door closes to your credential, an event stream you hold open there ends, and get-workspaces no longer lists it. The outcome is a MemberLeftV1 event with this command's correlation id. Refused when you are not a member; when you are the owner, since a workspace keeps its owner; or while you still hold a workload there (undeploy or stop it first: its get-workloads lists them).".into(),
        data_schema: json!({
            "type": "object",
            "required": ["workspace"],
            "properties": {
                "workspace": { "type": "string", "minLength": 1, "maxLength": 128, "description": "The workspace id from get-workspaces" }
            },
            "additionalProperties": false
        }),
        produces: vec!["MemberLeftV1".into(), "CommandFailed".into()],
        completes: completes("LeaveWorkspace"),
        impact: None,
        admit: Some(Arc::new(move |cmd, who, _key| {
            let m = admit.clone();
            Box::pin(async move { m.admit_leave(cmd, &who) })
        })),
        handler: Arc::new(move |cmd, emitter| {
            let m = m.clone();
            Box::pin(async move { m.leave(cmd, emitter).await })
        }),
    }
}

/// Revoke agent (SPEC.md, Agent Registration): the agent takes back the credential it sends this under. Any
/// credential may; the door is the root's, and a workspace's door closes with it, since they share the credentials.
fn revoke_agent(auth: Arc<Auth>) -> CommandDef {
    CommandDef {
        schema: "revoke-agent".into(),
        version: "1.0".into(),
        command_type: "RevokeAgent".into(),
        description: "Takes back the credential this command is sent under, at once and for good: from then on every request carrying it is refused with 401, on this door and every workspace door here, and an event stream open under it ends within seconds. What it left running stays, for the owner to end. The outcome is an AgentRevokedV1 event with this command's correlation id: an event stream open under the credential delivers it, then ends, and nothing else under it reads it after; the way back is to sign in again, from the manifest. Any credential may revoke itself, and only itself.".into(),
        data_schema: json!({ "type": "object", "properties": {}, "additionalProperties": false }),
        produces: vec!["AgentRevokedV1".into(), "CommandFailed".into()],
        completes: completes("RevokeAgent"),
        impact: None,
        admit: None,
        handler: Arc::new(move |cmd, em: Emitter| {
            let auth = auth.clone();
            Box::pin(async move {
                let hash = em
                    .command_key()
                    .split_once(':')
                    .map(|(sender, _)| sender.to_string())
                    .unwrap_or_default();
                match auth.revoke_own(&hash) {
                    Ok(c) => em.emit(
                        "AgentRevokedV1",
                        json!({ "holder": holder_of_hash(&c.hash), "name": c.name, "revoked_at": c.revoked_at }),
                    ),
                    Err(why) => em.emit(
                        "CommandFailed",
                        json!({ "type": cmd.r#type, "reason": format!("{why}; ask whoever runs this peer to run best-peer revoke {}", holder_of_hash(&hash)) }),
                    ),
                };
            })
        }),
    }
}

/// What the door tells about its credentials.
pub fn credential_event_defs() -> Vec<EventDef> {
    let s = |d: &str| json!({ "type": "string", "description": d });
    vec![event(
        "agent-revoked",
        "AgentRevokedV1",
        "A credential was taken back by the agent that held it: it opens nothing from now on.",
        &["holder", "name", "revoked_at"],
        json!({ "holder": s("The opaque id of the credential taken back, as its workloads' events name it"), "name": s("The connection name it signed in under"), "revoked_at": s("When, RFC 3339") }),
    )]
}

// ----- the clouds, in a workspace ------------------------------------------------------------------------------------

fn configure_cloud(ws: Arc<dyn Clouds>) -> CommandDef {
    let admit = ws.clone();
    CommandDef {
        schema: "configure-cloud".into(),
        version: "1.0".into(),
        command_type: "ConfigureCloud".into(),
        description: format!("Makes a cloud of this workspace, a named pool of machines, or changes the members of one that exists; an archived cloud of that name comes back. Each member is a peer by name and the base URL of its door; its devices appear as cloud/peer/device once its owner admits this cloud: the door's log shows the code to approve on that machine (best-peer approve <code>), and get-clouds shows the peer as joining until then, then up. The outcome is a CloudConfiguredV1 event with this command's correlation id. Refused when a name is not {NAME_SHAPE}; when a member's endpoint is already in another cloud of this workspace (a machine serves one cloud per workspace); when a member's endpoint is http:// off loopback (CLEARTEXT_MEMBER: the cloud's credential would travel in the clear; name its https:// endpoint, as its manifest advertises it); or when a peer being removed still holds a workload here (end it first, or keep the peer). Only the workspace's owner may configure its clouds."),
        data_schema: json!({
            "type": "object",
            "required": ["cloud", "members"],
            "properties": {
                "cloud": { "type": "string", "minLength": 1, "maxLength": 64, "description": "The cloud's name, one word: what deploy-model names and the first part of its device ids" },
                "members": {
                    "type": "array", "minItems": 1, "maxItems": 64,
                    "description": "The machines in the cloud: each a peer's name, one word, and the base URL of its door",
                    "items": { "type": "object", "required": ["peer", "endpoint"], "properties": {
                        "peer": { "type": "string", "minLength": 1, "maxLength": 64, "description": "The name this cloud knows the machine by: the middle part of its device ids, and what every fact about a workload there carries as peer" },
                        "endpoint": { "type": "string", "maxLength": 2048, "pattern": "^https?://", "description": "The base URL of the peer's door, as its manifest advertises it" }
                    }, "additionalProperties": false }
                }
            },
            "additionalProperties": false
        }),
        produces: vec!["CloudConfiguredV1".into(), "CommandFailed".into()],
        completes: completes("ConfigureCloud"),
        impact: None,
        admit: Some(Arc::new(move |cmd, who, _key| {
            let ws = admit.clone();
            Box::pin(async move { ws.admit_configure(cmd, &who) })
        })),
        handler: Arc::new(move |cmd, emitter| {
            let ws = ws.clone();
            Box::pin(async move { ws.configure(cmd, emitter).await })
        }),
    }
}

fn archive_cloud(ws: Arc<dyn Clouds>) -> CommandDef {
    let admit = ws.clone();
    CommandDef {
        schema: "archive-cloud".into(),
        version: "1.0".into(),
        command_type: "ArchiveCloud".into(),
        description: "Archives a cloud of this workspace: it places nothing, answers no device, and its members are no longer followed; get-clouds lists it as archived, and configure-cloud with its name brings it back. The outcome is a CloudArchivedV1 event with this command's correlation id. Refused when the cloud is not this workspace's, is already archived, or still holds a workload (undeploy or stop it first; get-workloads lists them). Only the workspace's owner may archive its clouds.".into(),
        data_schema: json!({
            "type": "object",
            "required": ["cloud"],
            "properties": {
                "cloud": { "type": "string", "minLength": 1, "maxLength": 64, "description": "The cloud's name from get-clouds" }
            },
            "additionalProperties": false
        }),
        produces: vec!["CloudArchivedV1".into(), "CommandFailed".into()],
        completes: completes("ArchiveCloud"),
        impact: None,
        admit: Some(Arc::new(move |cmd, who, _key| {
            let ws = admit.clone();
            Box::pin(async move { ws.admit_archive(cmd, &who) })
        })),
        handler: Arc::new(move |cmd, emitter| {
            let ws = ws.clone();
            Box::pin(async move { ws.archive(cmd, emitter).await })
        }),
    }
}

fn event(schema: &str, event_type: &str, description: &str, required: &[&str], properties: Value) -> EventDef {
    EventDef {
        schema: schema.into(),
        version: "1.0".into(),
        event_type: event_type.into(),
        description: description.into(),
        data_schema: json!({ "type": "object", "required": required, "properties": properties }),
    }
}

/// Every lifecycle event this peer tells, with its schema. The stream is the only channel for progress and outcomes.
/// On a workspace's door each carries `cloud` and `peer` too, the cloud the workload is in and the member peer it is
/// on, and its device is `cloud/peer/device`.
pub fn event_defs() -> Vec<EventDef> {
    let s = |d: &str| json!({ "type": "string", "description": d });
    let n = |d: &str| json!({ "type": "integer", "description": d });
    let placed = |mut v: Value| {
        v["cloud"] = s("On a workspace's door, the cloud the workload is in");
        v["peer"] = s("On a workspace's door, the member peer the workload is on");
        v
    };
    vec![
        event(
            "image-pulling",
            "ImagePulling",
            "The image is being pulled; progress in percent where the engine says. On a workspace's door, per peer, with the peer named.",
            &["image"],
            placed(json!({ "image": s("The image being pulled"), "progress_pct": { "type": ["integer", "null"] } })),
        ),
        event(
            "image-pulled",
            "ImagePulled",
            "The image is present on the peer; on a workspace's door, on every peer of the cloud.",
            &["image"],
            placed(json!({ "image": s("The image now present"), "held": { "type": "boolean", "description": "True when the peer already held it and nothing was downloaded, as a deploy or a job finds it; false when it was pulled from the registry, as pull-image always does. Absent on a workspace's door, which tells the cloud as a whole" } })),
        ),
        event(
            "image-pull-failed",
            "ImagePullFailed",
            "The image could not be made present; the reason says why, and on a workspace's door names the peers that failed.",
            &["image", "reason"],
            placed(json!({ "image": s("The image asked for"), "reason": s("What the engine said"), "fix": s("What to do") })),
        ),
        event(
            "deployment-started",
            "DeploymentStarted",
            "The engine's container runs on the device named; the model is not yet served.",
            &["deployment", "model", "engine", "device", "memory_bytes", "container"],
            placed(json!({ "deployment": s("The id later commands name"), "holder": s("The credential that deployed it, an opaque id: what get-workloads shows as holder; absent for one deployed before holders were told"), "model": s("The model"), "engine": s("ollama or vllm"), "device": s("The device it was placed on; on a workspace's door, cloud/peer/device"), "memory_bytes": n("The memory promised to it"), "container": s("The engine's container id"), "port": n("The host port the engine is reached at") })),
        ),
        event(
            "weights-loading",
            "WeightsLoading",
            "The engine is making the model present; progress in percent where it says.",
            &["deployment", "model"],
            placed(json!({ "deployment": s("The deployment"), "model": s("The model"), "progress_pct": { "type": ["integer", "null"] } })),
        ),
        event(
            "deployment-ready",
            "DeploymentReady",
            "The model is loaded and answers: send prompt commands naming this deployment, and each is answered with PromptAnswered under its own correlation id. Nothing of the engine is on the door; the command is the one way to the model.",
            &["deployment", "model", "engine"],
            placed(json!({ "deployment": s("The deployment to name in prompt"), "model": s("The model"), "engine": s("ollama or vllm") })),
        ),
        event(
            "prompt-answered",
            "PromptAnswered",
            "The model's answer to a prompt, whole, under the prompt's correlation id; the counts are what the engine reported, null where it did not.",
            &["deployment", "model", "content"],
            placed(json!({ "deployment": s("The deployment that answered"), "model": s("The model that answered, as the engine names it"), "content": s("The answer"), "finish": { "type": ["string", "null"], "description": "Why the answer stopped, as the engine says: stop, length, or its own word" }, "prompt_tokens": { "type": ["integer", "null"] }, "completion_tokens": { "type": ["integer", "null"] } })),
        ),
        event(
            "prompt-failed",
            "PromptFailed",
            "The prompt was accepted and not answered: the deployment ended meanwhile, or the engine failed or did not answer in time. The reason says what happened and the fix what to do.",
            &["deployment", "reason", "fix"],
            placed(json!({ "deployment": s("The deployment asked"), "reason": s("What happened"), "fix": s("What to do") })),
        ),
        event(
            "deployment-failed",
            "DeploymentFailed",
            "The deployment did not reach ready, or failed after; its container is stopped. The reason says what happened and the fix what to do.",
            &["deployment", "model", "reason", "fix"],
            placed(json!({ "deployment": s("The deployment"), "model": s("The model"), "reason": s("What happened"), "fix": s("What to do") })),
        ),
        event(
            "deployment-ended",
            "DeploymentEnded",
            "The engine ended the deployment on its own: its container exited; or, on a workspace's door, the peer it ran on was lost.",
            &["deployment", "model", "reason"],
            placed(json!({ "deployment": s("The deployment"), "model": s("The model"), "exit_code": { "type": ["integer", "null"] }, "reason": s("What happened") })),
        ),
        event(
            "undeployed",
            "Undeployed",
            "The deployment is stopped and its memory free.",
            &["deployment"],
            placed(json!({ "deployment": s("The deployment"), "model": s("The model it served") })),
        ),
        event(
            "out-of-memory",
            "OutOfMemory",
            "The device ran out of memory under the deployment; the engine ended it.",
            &["deployment", "model", "device", "memory_bytes", "fix"],
            placed(json!({ "deployment": s("The deployment"), "model": s("The model"), "device": s("The device"), "memory_bytes": n("What was promised to it"), "fix": s("What to do") })),
        ),
        event(
            "job-started",
            "JobStarted",
            "The job's container runs.",
            &["job", "image", "container"],
            placed(json!({ "job": s("The id stop-job names"), "order": s("On a workspace's door, the order it ran for: the id JobQueued gave it"), "holder": s("The credential that ran it, an opaque id; absent for one run before holders were told"), "image": s("The image"), "device": { "type": ["string", "null"] }, "memory_bytes": n("The memory promised to it"), "container": s("The engine's container id"), "boxed": { "type": "boolean", "description": "True when the job runs in the closed box a credential with a share gets: no network, a read-only filesystem, a ceiling on host memory" }, "host_memory_bytes": { "type": ["integer", "null"], "description": "The most host memory its container may hold; null for no ceiling" } })),
        ),
        event(
            "job-finished",
            "JobFinished",
            "The job's container exited; the exit code is the engine's.",
            &["job", "exit_code"],
            placed(json!({ "job": s("The job"), "exit_code": n("The container's exit code") })),
        ),
        event(
            "job-failed",
            "JobFailed",
            "The job did not start, or the engine ended it, or, on a workspace's door, the peer it ran on was lost; the reason says what happened and the fix what to do.",
            &["job", "reason", "fix"],
            placed(json!({ "job": s("The job"), "image": s("The image"), "reason": s("What happened"), "fix": s("What to do") })),
        ),
        event(
            "job-stopped",
            "JobStopped",
            "The job was stopped on request; on a workspace's door also an order stopped before it started, or a job stopped by the door when it ran past its deadline_seconds, which the reason says.",
            &["job"],
            placed(json!({ "job": s("The job, or the order"), "reason": s("Why, when the door stopped it rather than a stop-job: its deadline, or before it started") })),
        ),
        event(
            "command-failed",
            "CommandFailed",
            "A command that was accepted could not be carried out; the reason says why. The state is as it was.",
            &["type", "reason"],
            json!({ "type": s("The command's type"), "reason": s("What happened") }),
        ),
    ]
}

/// What the root tells about its workspaces: made, and who joined, was invited, left.
pub fn membership_event_defs() -> Vec<EventDef> {
    let s = |d: &str| json!({ "type": "string", "description": d });
    let role = json!({ "type": "string", "enum": ["owner", "member"] });
    vec![
        event(
            "workspace-created",
            "WorkspaceCreatedV1",
            "A workspace exists, with its owner as its one member; its own door is open to the owner's credential, and configure-cloud there makes its first cloud.",
            &["workspace", "name", "owner"],
            json!({ "workspace": s("The workspace id: the tenant id, what the other commands name"), "name": s("What it is called"), "owner": s("The identity that created it, an opaque id of their credential"), "endpoint": s("The workspace's own door"), "manifest": s("The workspace's manifest") }),
        ),
        event(
            "member-invited",
            "MemberInvitedV1",
            "An identity was invited into a workspace by its owner; the invitation stands until accepted with accept-invitation.",
            &["workspace", "identity", "invited_by"],
            json!({ "workspace": s("The workspace"), "identity": s("The invitee's identity"), "invited_by": s("The owner's identity") }),
        ),
        event(
            "member-joined",
            "MemberJoinedV1",
            "An identity accepted its invitation and is a member of the workspace: its door opens to their credential.",
            &["workspace", "identity", "role"],
            json!({ "workspace": s("The workspace"), "identity": s("The member's identity"), "role": role }),
        ),
        event(
            "member-left",
            "MemberLeftV1",
            "An identity left a workspace: its door closes to their credential.",
            &["workspace", "identity"],
            json!({ "workspace": s("The workspace"), "identity": s("The identity that left") }),
        ),
    ]
}

/// What a workspace tells about its clouds: configured and archived, and each member peer answering or lost.
pub fn cloud_event_defs() -> Vec<EventDef> {
    let s = |d: &str| json!({ "type": "string", "description": d });
    vec![
        event(
            "cloud-configured",
            "CloudConfiguredV1",
            "A cloud of this workspace exists with the members listed: made, changed, or brought back from archived. Each member's devices appear in get-hardware-state once its owner admits the cloud; get-clouds says which have.",
            &["workspace", "cloud", "members"],
            json!({ "workspace": s("The workspace"), "cloud": s("The cloud's name"), "members": { "type": "array", "description": "The peers in the cloud now", "items": { "type": "object", "required": ["peer", "endpoint"], "properties": { "peer": s("The peer's name in this cloud"), "endpoint": s("The peer's own door") } } } }),
        ),
        event(
            "cloud-archived",
            "CloudArchivedV1",
            "A cloud of this workspace is archived: it places nothing and answers no device until configure-cloud brings it back.",
            &["workspace", "cloud"],
            json!({ "workspace": s("The workspace"), "cloud": s("The cloud's name") }),
        ),
        event(
            "job-queued",
            "JobQueued",
            "A cloud took a run-job order: the order whole, as it is placed. waiting is true when no member peer has the room now; the cloud places it as soon as one does, first come, first served. attempt 2 says a member peer was lost under it and it was queued again, once.",
            &["job", "image", "attempt", "waiting", "cloud"],
            json!({
                "job": s("The order's id, what stop-job names while it waits"),
                "image": s("The image"),
                "args": { "type": "array", "items": { "type": "string" }, "description": "The command line passed to the image's entrypoint" },
                "memory_bytes": { "type": ["integer", "null"], "description": "Device memory the order needs; null for none" },
                "device": { "type": ["string", "null"], "description": "The device the order pinned, cloud/peer/device" },
                "queue_seconds": { "type": ["integer", "null"], "description": "How long it may wait, from this event" },
                "deadline_seconds": { "type": ["integer", "null"], "description": "How long its job may run, from JobStarted" },
                "holder": s("The credential that ordered it, an opaque id"),
                "accelerators_only": { "type": "boolean", "description": "True when its credential runs on the accelerators alone" },
                "attempt": { "type": "integer", "description": "1; 2 once queued again after a member peer was lost under it" },
                "waiting": { "type": "boolean", "description": "True when no member peer has the room now" },
                "reason": s("Why it waits, or why it was queued again"),
                "instead_of": s("Queued again: the job the lost member peer was running for it"),
                "cloud": s("The cloud that took it")
            }),
        ),
        event(
            "job-placed",
            "JobPlaced",
            "An order was sent to a member peer, which pulls the image and starts it: JobStarted follows, naming the order.",
            &["job", "peer", "cloud"],
            json!({ "job": s("The order's id"), "peer": s("The member peer it was sent to"), "device": { "type": ["string", "null"], "description": "The device there, cloud/peer/device; null for a job with no device" }, "cloud": s("The cloud") }),
        ),
        event(
            "peer-joined",
            "PeerJoined",
            "A member peer admitted this cloud and answers: its devices are in get-hardware-state as cloud/peer/device and workloads can be placed on it.",
            &["cloud", "peer", "endpoint"],
            json!({ "cloud": s("The cloud the peer is a member of"), "peer": s("The member's name, the value device ids and events carry as peer"), "endpoint": s("The member's own door") }),
        ),
        event(
            "peer-lost",
            "PeerLost",
            "A member peer stopped answering; every workload it held is told as ended under its own correlation id, and nothing is placed there until it answers again, which PeerJoined tells.",
            &["cloud", "peer", "endpoint", "reason"],
            json!({ "cloud": s("The cloud the peer is a member of"), "peer": s("The member's name"), "endpoint": s("The member's own door"), "reason": s("What the cloud saw") }),
        ),
    ]
}

/// `get-hardware-state`'s body for a host as the accelerator abstraction reports it.
pub fn host_state(host: &Host) -> Value {
    let observed = OffsetDateTime::from(host.observed_at)
        .format(&Rfc3339)
        .unwrap_or_default();
    let devices: Vec<Value> = host
        .devices
        .iter()
        .map(|d| {
            json!({
                "id": d.id.0,
                "vendor": d.vendor,
                "name": d.name,
                "memory": { "total_bytes": d.memory.total_bytes, "free_bytes": d.memory.free_bytes },
                "compute": d.compute,
                "temperature_c": d.temperature_c,
                "power_w": d.power_w,
                "utilisation_pct": d.utilisation_pct
            })
        })
        .collect();
    json!({ "driver": host.driver, "observed_at": observed, "devices": devices })
}
