//! Workspaces: the organizations or teams this door hosts, each the BEST tenant with its own endpoint, log, catalogue,
//! stream and correlation space, and inside each the clouds, named pools of machines. An identity (a credential
//! signed in by the device flow) creates a workspace and owns it, invites other identities, who accept and become
//! members, and may leave; an identity belongs to as many workspaces as it creates or is invited into. Machines join
//! a cloud another way: their owner approves the cloud's door at the console, as they admit any agent.
//!
//! [`Workspaces`] is the fold of the root log's membership facts and the registry of the live [`Workspace`] doors;
//! it serves the root's four membership commands and `get-workspaces`, and dispatches `/workspaces/{id}/...` to the
//! workspace's own door once the credential is a member's. A [`Workspace`] is the fold of its own log's cloud facts,
//! the [`Cloud`] behind each name that is not archived, and the lifecycle surface that places in the cloud a
//! command names.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::{Path as UrlPath, Request, State};
use axum::http::Uri;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use best_peer_door::auth::Credential;
use best_peer_door::{Auth, BestError, Door, Emitter, Envelope, EventLog, Limits, Partition, Stored};
use futures::StreamExt;
use serde::Deserialize;
use serde_json::{json, Value};
use tower::ServiceExt;

use crate::cloud::Cloud;
use crate::domain::{
    self, Clouds, Membership, Service, MEMBERSHIP_COMMANDS, MEMBERSHIP_EVENTS, NAME_SHAPE, WORKSPACE_EVENTS,
};
use crate::holdings::Holdings;
use crate::lifecycle::{list, new_id, require};
use crate::menu::{Menu, Size};
use crate::transport::{Cleartext, Transport};

/// Where the workspaces' doors are under the root: `/workspaces/<id>`.
pub const PREFIX: &str = "/workspaces/";

/// What every workspace door is built with: the root it hangs under and what the root shares with it.
pub struct Context {
    /// The root door's endpoint, what a workspace's endpoint is under.
    pub endpoint: String,
    /// The service key, and the `source` of every event.
    pub service: String,
    /// The data directory; a workspace keeps its log and its clouds' credentials under `workspaces/<id>`.
    pub dir: PathBuf,
    /// The door's credentials: one sign-in opens every workspace the identity belongs to.
    pub auth: Arc<Auth>,
    /// How the clouds reach their members.
    pub transport: Arc<dyn Transport>,
    /// What a credential holds across the door, for its share.
    pub holdings: Arc<Holdings>,
    /// Where a cloud may reach a member in cleartext: on loopback alone, unless the operator said a VPN carries it.
    pub cleartext: Cleartext,
    /// What a credential with a share may do at once, counted across the root and every workspace.
    pub limits: Arc<Limits>,
}

impl Context {
    fn workspace_endpoint(&self, id: &str) -> String {
        format!("{}{PREFIX}{id}", self.endpoint)
    }

    fn workspace_manifest(&self, id: &str) -> String {
        format!("{}/.well-known/best/{id}", self.endpoint)
    }

    /// The template of the workspace manifests, the root manifest's `tenants.manifest`.
    pub fn manifest_template(&self) -> String {
        self.workspace_manifest("{tenantId}")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Member,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Member => "member",
        }
    }
}

/// A workspace as the root knows it: its name, who is in it and who is invited.
#[derive(Clone, Debug, Default)]
struct Record {
    name: String,
    members: BTreeMap<String, Role>,
    /// Invitee to the identity that invited.
    invited: BTreeMap<String, String>,
}

impl Record {
    fn owner(&self) -> Option<&str> {
        self.members
            .iter()
            .find(|(_, r)| **r == Role::Owner)
            .map(|(id, _)| id.as_str())
    }
}

/// The registry and the fold: every workspace this door hosts, who is in each, and the live door of each. The
/// membership facts are told on the root log, by the emitter of the command that makes each.
pub struct Workspaces {
    pub ctx: Arc<Context>,
    records: Mutex<BTreeMap<String, Record>>,
    live: Mutex<BTreeMap<String, Arc<Workspace>>>,
}

impl Workspaces {
    /// The workspaces the root log says exist, each opened over its own log with its clouds built, none following
    /// its members yet: [`Workspaces::start`] does that, after each door's unfinished commands are resumed.
    pub fn open(ctx: Arc<Context>, log: Arc<EventLog>) -> Arc<Self> {
        let me = Arc::new(Self {
            ctx,
            records: Mutex::new(BTreeMap::new()),
            live: Mutex::new(BTreeMap::new()),
        });
        let mut facts = Vec::new();
        log.replay(|e| facts.push(e.clone()));
        for e in &facts {
            me.apply(e);
        }
        // A fact the root told that its workspace did not hear (the door stopped in between) is heard now.
        for e in facts.iter().filter(|e| MEMBERSHIP_EVENTS.contains(&e.r#type.as_str())) {
            if let Some(ws) = e.data["workspace"].as_str().and_then(|id| me.get(id)) {
                ws.hear(e);
            }
        }
        me
    }

    /// Every live workspace, for the root to resume and start.
    pub fn all(&self) -> Vec<Arc<Workspace>> {
        self.live.lock().unwrap().values().cloned().collect()
    }

    pub fn get(&self, id: &str) -> Option<Arc<Workspace>> {
        self.live.lock().unwrap().get(id).cloned()
    }

    /// The members of a live cloud whose recorded endpoint this peer's cleartext rule refuses, as
    /// `(workspace, cloud, peer, endpoint)`: recorded before the rule, or while `BEST_PEER_CLEARTEXT=vpn` was set.
    pub fn cleartext_members(&self) -> Vec<(String, String, String, String)> {
        let mut out = Vec::new();
        for ws in self.all() {
            for (cloud, r) in ws.clouds.lock().unwrap().iter().filter(|(_, r)| !r.archived) {
                for (peer, endpoint) in r.members.iter().filter(|(_, e)| !self.ctx.cleartext.allows(e)) {
                    out.push((ws.id.clone(), cloud.clone(), peer.clone(), endpoint.clone()));
                }
            }
        }
        out
    }

    /// Follows every cloud's members, and from here on a workspace or a cloud made later starts at once.
    pub async fn start(&self) {
        for ws in self.all() {
            best_peer_door::resume(ws.door()).await;
            ws.start();
        }
    }

    /// Tells a membership fact: appended at the root under the command that made it, folded, and told again on the
    /// workspace's own stream, where its members hear it.
    fn tell(&self, em: &Emitter, r#type: &str, data: Value) -> Envelope {
        let e = em.emit(r#type, data);
        self.apply(&e);
        if let Some(ws) = e.data["workspace"].as_str().and_then(|id| self.get(id)) {
            ws.hear(&e);
        }
        e
    }

    /// What a credential reads of the root log: the door's own facts under the door's rule, and of the membership
    /// facts those addressed to it by identity (the workspace it made, the invitation it received or sent, its own
    /// join or leave) and nothing else, whatever its grant and whatever correlation it names; the failure of a
    /// membership command is its sender's alone (SPEC.md, Security Requirements: tenant context derives from the
    /// credential, streams are isolated per tenant).
    pub fn root_partition(log: Arc<EventLog>) -> Partition {
        Arc::new(move |who: &Credential, s: &Stored| {
            let e = &s.envelope;
            if MEMBERSHIP_EVENTS.contains(&e.r#type.as_str()) {
                let me = who.holder();
                let names = |field: &str| e.data[field].as_str() == Some(me.as_str());
                return Some(names("identity") || names("owner") || names("invited_by"));
            }
            let failed_membership = e.r#type == "CommandFailed"
                && MEMBERSHIP_COMMANDS.contains(&e.data["type"].as_str().unwrap_or_default());
            failed_membership.then(|| log.visible_to(Some(&who.hash), s))
        })
    }

    /// What a member reads of a workspace's log: the workspace's own facts (its membership, its clouds, its peers)
    /// whatever its grant, and of the lifecycle what the door's rule gives it.
    fn workspace_partition() -> Partition {
        Arc::new(|_who: &Credential, s: &Stored| WORKSPACE_EVENTS.contains(&s.envelope.r#type.as_str()).then_some(true))
    }

    /// Folds one fact in, live and on replay: the record, the member list the workspace's door checks, and the
    /// workspace itself when it is made. A fact about a workspace the fold does not know changes nothing.
    fn apply(&self, e: &Envelope) {
        let d = &e.data;
        let text = |k: &str| d[k].as_str().unwrap_or_default().to_string();
        let id = text("workspace");
        match e.r#type.as_str() {
            "WorkspaceCreatedV1" => {
                let owner = text("owner");
                if self.records.lock().unwrap().contains_key(&id) {
                    return;
                }
                let mut r = Record {
                    name: text("name"),
                    ..Default::default()
                };
                r.members.insert(owner, Role::Owner);
                // The door is opened before anything is recorded, and outside the locks: one that cannot be opened
                // leaves no record, so the fact is in the log and the workspace is not, which the log line says.
                match Workspace::open(self.ctx.clone(), &id, r.members.clone()) {
                    Ok(ws) => {
                        self.records.lock().unwrap().insert(id.clone(), r);
                        self.live.lock().unwrap().insert(id, ws);
                    }
                    Err(why) => {
                        tracing::error!(workspace = %id, %why, "the workspace's door cannot be opened; it is not served")
                    }
                }
            }
            "MemberInvitedV1" => {
                let mut records = self.records.lock().unwrap();
                if let Some(r) = records.get_mut(&id) {
                    r.invited.insert(text("identity"), text("invited_by"));
                }
            }
            "MemberJoinedV1" => {
                let mut records = self.records.lock().unwrap();
                if let Some(r) = records.get_mut(&id) {
                    let who = text("identity");
                    r.invited.remove(&who);
                    let role = serde_json::from_value(d["role"].clone()).unwrap_or(Role::Member);
                    r.members.insert(who, role);
                    if let Some(ws) = self.live.lock().unwrap().get(&id) {
                        ws.set_members(r.members.clone());
                    }
                }
            }
            "MemberLeftV1" => {
                let mut records = self.records.lock().unwrap();
                if let Some(r) = records.get_mut(&id) {
                    r.members.remove(&text("identity"));
                    if let Some(ws) = self.live.lock().unwrap().get(&id) {
                        ws.set_members(r.members.clone());
                    }
                }
            }
            _ => {}
        }
    }

    /// The record of `id` when `who` may act in it as `at_least`; else the refusal, which names only what the
    /// credential may see: a workspace that is not theirs is one that does not exist for them.
    fn record_for(&self, id: &str, who: &Credential, at_least: Role) -> Result<Record, BestError> {
        let records = self.records.lock().unwrap();
        let holder = who.holder();
        let known = records.get(id).filter(|r| r.members.contains_key(&holder));
        let Some(r) = known else {
            let mine: Vec<&String> = records
                .iter()
                .filter(|(_, r)| r.members.contains_key(&holder))
                .map(|(id, _)| id)
                .collect();
            return Err(BestError::bad_request(
                "NO_SUCH_WORKSPACE",
                format!(
                    "no workspace {id} of yours: yours are {}; get-workspaces lists them, create-workspace makes one",
                    list(mine.iter())
                ),
            )
            .with_details(json!({ "workspace": id, "workspaces": mine })));
        };
        if at_least == Role::Owner && r.members.get(&holder) != Some(&Role::Owner) {
            return Err(BestError::bad_request(
                "FORBIDDEN",
                format!(
                    "workspace {id} is not yours to change: you are a member, and its owner is {}; ask them",
                    r.owner().unwrap_or("nobody")
                ),
            )
            .with_details(json!({ "workspace": id, "role": "member" })));
        }
        Ok(r.clone())
    }

    /// The routes the root mounts for its workspaces: each workspace's manifest, public like the root's, and its
    /// door under `/workspaces/<id>`, open to a member's credential and to no one else.
    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/.well-known/best/:workspace", get(tenant_manifest))
            .route("/workspaces/:workspace", any(dispatch))
            .route("/workspaces/:workspace/", any(dispatch))
            .route("/workspaces/:workspace/*rest", any(dispatch))
            .with_state(self.clone())
    }
}

async fn tenant_manifest(State(reg): State<Arc<Workspaces>>, UrlPath(id): UrlPath<String>) -> Response {
    match reg.get(&id) {
        Some(ws) => (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            Json(best_peer_door::manifest::manifest(ws.door())),
        )
            .into_response(),
        None => BestError::not_found(
            "NO_SUCH_WORKSPACE",
            format!(
                "no workspace {id} on this door. A credential opens the workspaces it belongs to: sign in at the root manifest's deviceAuthorizationUrl, then get-workspaces at the root lists yours with each one's manifest, and create-workspace makes one"
            ),
        )
        .into_response(),
    }
}

/// A request under a workspace's endpoint goes to that workspace's door, with the path below the endpoint, once
/// the credential is a member's. Without a credential the answer is the door's 401; with one that is no member's,
/// or for a workspace that does not exist, the same 404: a workspace one does not belong to is not there for them.
async fn dispatch(
    State(reg): State<Arc<Workspaces>>,
    UrlPath(params): UrlPath<HashMap<String, String>>,
    req: Request,
) -> Response {
    let id = params.get("workspace").cloned().unwrap_or_default();
    let key = req
        .headers()
        .get(best_peer_door::auth::AUTH_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .unwrap_or("");
    let Some(who) = (!key.is_empty()).then(|| reg.ctx.auth.authenticate(key)).flatten() else {
        return BestError::unauthorized().into_response();
    };
    best_peer_door::router::Answered::record(&req, &who);
    let ws = reg.get(&id).filter(|ws| ws.is_member(&who.holder()));
    let Some(ws) = ws else {
        return BestError::not_found(
            "NO_SUCH_WORKSPACE",
            format!("no workspace {id} opens to this credential: get-workspaces at the root lists yours, and accept-invitation joins one you were invited into"),
        )
        .with_details(json!({ "workspace": id }))
        .into_response();
    };
    let (mut parts, body) = req.into_parts();
    let sent = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".into());
    let below = sent
        .strip_prefix(PREFIX)
        .and_then(|s| s.strip_prefix(id.as_str()))
        .unwrap_or("");
    let rest = match below {
        "" => "/".to_string(),
        r if r.starts_with('?') => format!("/{r}"),
        r => r.to_string(),
    };
    let Ok(uri) = rest.parse::<Uri>() else {
        return BestError::bad_request("BAD_REQUEST", "the path cannot be read").into_response();
    };
    parts.uri = uri;
    // What the root's router matched (its path parameters) is not the workspace's door's to read.
    parts.extensions.clear();
    let streaming = rest.starts_with("/events/stream");
    let req = Request::from_parts(parts, body);
    let res = match ws.router().clone().oneshot(req).await {
        Ok(res) => res,
        Err(never) => match never {},
    };
    if !streaming {
        return res;
    }
    // An open stream is a door held open: it closes at the next frame once the credential is no member's.
    let holder = who.holder();
    let (parts, body) = res.into_parts();
    let frames = body
        .into_data_stream()
        .take_while(move |_| futures::future::ready(ws.is_member(&holder)));
    Response::from_parts(parts, Body::from_stream(frames))
}

#[async_trait]
impl Membership for Workspaces {
    fn workspaces(&self, who: &Credential) -> Result<Value, BestError> {
        let holder = who.holder();
        let records = self.records.lock().unwrap();
        let workspaces: Vec<Value> = records
            .iter()
            .filter_map(|(id, r)| {
                let role = r.members.get(&holder)?;
                let members: Vec<Value> = r
                    .members
                    .iter()
                    .map(|(i, role)| json!({ "identity": i, "role": role.as_str() }))
                    .collect();
                Some(json!({
                    "workspace": id, "name": r.name, "role": role.as_str(),
                    "endpoint": self.ctx.workspace_endpoint(id), "manifest": self.ctx.workspace_manifest(id),
                    "members": members
                }))
            })
            .collect();
        let invitations: Vec<Value> = records
            .iter()
            .filter_map(|(id, r)| {
                let by = r.invited.get(&holder)?;
                Some(json!({ "workspace": id, "name": r.name, "invited_by": by }))
            })
            .collect();
        Ok(json!({ "identity": holder, "workspaces": workspaces, "invitations": invitations }))
    }

    fn admit_create(&self, _cmd: Envelope, _who: &Credential) -> Result<(), BestError> {
        Ok(())
    }

    async fn create(self: Arc<Self>, cmd: Envelope, em: Emitter) {
        let id = new_id("ws");
        let owner = em
            .command_key()
            .split_once(':')
            .map(|(sender, _)| best_peer_door::auth::holder_of_hash(sender))
            .unwrap_or_default();
        // The workspace's place on disk is made before the fact is told: a fact told is a workspace that exists.
        if let Err(e) = EventLog::open(&Workspace::dir(&self.ctx, &id)) {
            em.emit(
                "CommandFailed",
                json!({ "type": cmd.r#type, "reason": format!("the workspace's log cannot be kept under the data directory: {e}; fix the directory and send it again") }),
            );
            return;
        }
        self.tell(
            &em,
            "WorkspaceCreatedV1",
            json!({
                "workspace": id, "name": cmd.data["name"], "owner": owner,
                "endpoint": self.ctx.workspace_endpoint(&id), "manifest": self.ctx.workspace_manifest(&id)
            }),
        );
        if let Some(ws) = self.get(&id) {
            ws.start();
        }
    }

    fn admit_invite(&self, cmd: Envelope, who: &Credential) -> Result<(), BestError> {
        let id = cmd.data["workspace"].as_str().unwrap_or_default();
        let identity = cmd.data["identity"].as_str().unwrap_or_default();
        let r = self.record_for(id, who, Role::Owner)?;
        if r.members.contains_key(identity) {
            return Err(BestError::bad_request(
                "ALREADY_A_MEMBER",
                format!("{identity} is already a member of workspace {id}: nothing to invite"),
            )
            .with_details(json!({ "workspace": id, "identity": identity })));
        }
        if r.invited.contains_key(identity) {
            return Err(BestError::bad_request(
                "ALREADY_INVITED",
                format!("{identity} is already invited into workspace {id}: they accept with accept-invitation"),
            )
            .with_details(json!({ "workspace": id, "identity": identity })));
        }
        Ok(())
    }

    async fn invite(self: Arc<Self>, cmd: Envelope, em: Emitter) {
        let by = em
            .command_key()
            .split_once(':')
            .map(|(sender, _)| best_peer_door::auth::holder_of_hash(sender))
            .unwrap_or_default();
        self.tell(
            &em,
            "MemberInvitedV1",
            json!({ "workspace": cmd.data["workspace"], "identity": cmd.data["identity"], "invited_by": by }),
        );
    }

    fn admit_accept(&self, cmd: Envelope, who: &Credential) -> Result<(), BestError> {
        let id = cmd.data["workspace"].as_str().unwrap_or_default();
        let records = self.records.lock().unwrap();
        let holder = who.holder();
        match records.get(id) {
            Some(r) if r.invited.contains_key(&holder) => Ok(()),
            Some(r) if r.members.contains_key(&holder) => Err(BestError::bad_request(
                "ALREADY_A_MEMBER",
                format!("you are already a member of workspace {id}: its door is open to you"),
            )
            .with_details(json!({ "workspace": id }))),
            _ => {
                let open: Vec<&String> = records
                    .iter()
                    .filter(|(_, r)| r.invited.contains_key(&holder))
                    .map(|(id, _)| id)
                    .collect();
                Err(BestError::bad_request(
                    "NOT_INVITED",
                    format!(
                        "no invitation into workspace {id} stands for your identity {holder}: the ones that do are {}; get-workspaces lists them, and the workspace's owner invites with invite-member",
                        list(open.iter())
                    ),
                )
                .with_details(json!({ "workspace": id, "identity": holder, "invitations": open })))
            }
        }
    }

    async fn accept(self: Arc<Self>, cmd: Envelope, em: Emitter) {
        let who = em
            .command_key()
            .split_once(':')
            .map(|(sender, _)| best_peer_door::auth::holder_of_hash(sender))
            .unwrap_or_default();
        self.tell(
            &em,
            "MemberJoinedV1",
            json!({ "workspace": cmd.data["workspace"], "identity": who, "role": "member" }),
        );
    }

    fn admit_leave(&self, cmd: Envelope, who: &Credential) -> Result<(), BestError> {
        let id = cmd.data["workspace"].as_str().unwrap_or_default();
        let r = self.record_for(id, who, Role::Member)?;
        if r.members.get(&who.holder()) == Some(&Role::Owner) {
            return Err(BestError::bad_request(
                "OWNER_STAYS",
                format!("you own workspace {id} and a workspace keeps its owner: it cannot be left"),
            )
            .with_details(json!({ "workspace": id, "role": "owner" })));
        }
        // What one holds in a workspace counts against one's share and is one's to end: it goes before one does.
        let holds: Vec<Value> = self.get(id).map(|ws| ws.held_by(&who.holder())).unwrap_or_default();
        if !holds.is_empty() {
            return Err(BestError::bad_request(
                "HOLDS_WORKLOADS",
                format!(
                    "you still hold {} workload(s) in workspace {id}: undeploy or stop them first (its get-workloads lists them), then leave",
                    holds.len()
                ),
            )
            .with_details(json!({ "workspace": id, "holds": holds })));
        }
        Ok(())
    }

    async fn leave(self: Arc<Self>, cmd: Envelope, em: Emitter) {
        let who = em
            .command_key()
            .split_once(':')
            .map(|(sender, _)| best_peer_door::auth::holder_of_hash(sender))
            .unwrap_or_default();
        self.tell(
            &em,
            "MemberLeftV1",
            json!({ "workspace": cmd.data["workspace"], "identity": who }),
        );
    }
}

// ----- one workspace --------------------------------------------------------------------------------------------------

/// A cloud as the workspace's log says it stands: its members, whether it is archived, and the live cloud behind
/// it when it is not.
#[derive(Clone, Default)]
struct CloudRecord {
    members: Vec<(String, String)>,
    archived: bool,
    live: Option<Arc<Cloud>>,
    /// The sizes it sells by, as `set-menu` last set them; none until then, or once set with no sizes.
    menu: Option<Menu>,
}

pub struct Workspace {
    pub id: String,
    ctx: Arc<Context>,
    /// The workspace's own door: `<root>/workspaces/<id>`.
    pub endpoint: String,
    pub log: Arc<EventLog>,
    dir: PathBuf,
    dataschemas: Arc<HashMap<String, String>>,
    completions: Arc<HashMap<String, HashSet<String>>>,
    members: Mutex<BTreeMap<String, Role>>,
    clouds: Mutex<BTreeMap<String, CloudRecord>>,
    door: OnceLock<Arc<Door>>,
    router: OnceLock<Router>,
    started: std::sync::atomic::AtomicBool,
}

#[derive(Deserialize)]
struct ConfigureData {
    cloud: String,
    members: Vec<MemberData>,
}

#[derive(Deserialize)]
struct SetMenuData {
    cloud: String,
    currency: String,
    sizes: Vec<Size>,
}

#[derive(Deserialize)]
struct MemberData {
    peer: String,
    endpoint: String,
}

impl Workspace {
    /// Where the workspace `id` keeps its log and its clouds' credentials.
    fn dir(ctx: &Context, id: &str) -> PathBuf {
        ctx.dir.join("workspaces").join(id)
    }

    /// The workspace `id` over its own log under the data directory, its clouds built from the log, none following
    /// yet; `members` is who may enter. A log that cannot be opened is the error, never a panic.
    fn open(ctx: Arc<Context>, id: &str, members: BTreeMap<String, Role>) -> Result<Arc<Self>, String> {
        let dir = Self::dir(&ctx, id);
        let log = Arc::new(
            EventLog::open(&dir)
                .map_err(|e| format!("cannot keep the log of workspace {id} in {}: {e}", dir.display()))?,
        );
        let endpoint = ctx.workspace_endpoint(id);
        let me = Arc::new(Self {
            id: id.into(),
            dataschemas: Arc::new(domain::workspace_event_dataschemas(&endpoint)),
            completions: Arc::new(domain::completions()),
            endpoint,
            log: log.clone(),
            dir,
            ctx: ctx.clone(),
            members: Mutex::new(members),
            clouds: Mutex::new(BTreeMap::new()),
            door: OnceLock::new(),
            router: OnceLock::new(),
            started: std::sync::atomic::AtomicBool::new(false),
        });
        let mut facts = Vec::new();
        log.replay(|e| facts.push(e.clone()));
        for e in &facts {
            me.fold(e);
        }
        me.materialise();
        let door = Arc::new(
            Door::new(
                &me.endpoint,
                &ctx.service,
                "A workspace: the clouds of one organization or team, each a pool of GPU peers, and the models and jobs its members place on them, told as events with the cloud and the peer named.",
                domain::workspace_catalogue(me.clone()),
                log,
                ctx.auth.clone(),
            )
            .with_partition(Workspaces::workspace_partition())
            .with_limits(ctx.limits.clone()),
        );
        let router = best_peer_door::tenant_router(door.clone());
        let _ = me.door.set(door);
        let _ = me.router.set(router);
        Ok(me)
    }

    /// What `holder` holds in this workspace, across its clouds, by name: deployments, jobs and admitted commands.
    fn held_by(&self, holder: &str) -> Vec<Value> {
        self.live_clouds().iter().flat_map(|c| c.holds_of(holder)).collect()
    }

    pub fn door(&self) -> &Arc<Door> {
        self.door.get().expect("the door is set at open")
    }

    /// A membership fact about this workspace, told at the root, told again on this workspace's own stream: the same
    /// fact, with the same id, correlation and time, under the workspace's schema, so its members hear who joined,
    /// was invited or left. A fact already on this log, by its id, is not told twice, so the start's repair of what a
    /// stop left untold and a live telling agree.
    fn hear(&self, e: &Envelope) {
        if self.log.contains_id(&e.id) {
            return;
        }
        self.log.append(Envelope {
            dataschema: self.dataschemas.get(&e.r#type).cloned(),
            source: self.ctx.service.clone(),
            ..e.clone()
        });
    }

    pub fn router(&self) -> &Router {
        self.router.get().expect("the router is set at open")
    }

    fn set_members(&self, members: BTreeMap<String, Role>) {
        *self.members.lock().unwrap() = members;
    }

    pub fn is_member(&self, holder: &str) -> bool {
        self.members.lock().unwrap().contains_key(holder)
    }

    fn is_owner(&self, holder: &str) -> bool {
        self.members.lock().unwrap().get(holder) == Some(&Role::Owner)
    }

    /// Follows every live cloud's members; a cloud made from here on follows at once.
    pub fn start(&self) {
        self.started.store(true, std::sync::atomic::Ordering::SeqCst);
        for c in self.live_clouds() {
            c.follow();
        }
    }

    fn live_clouds(&self) -> Vec<Arc<Cloud>> {
        self.clouds
            .lock()
            .unwrap()
            .values()
            .filter_map(|r| r.live.clone())
            .collect()
    }

    /// The live cloud named, or why not: an archived one and an unknown one are refused with what to do.
    fn cloud(&self, name: &str) -> Result<Arc<Cloud>, BestError> {
        let clouds = self.clouds.lock().unwrap();
        let live: Vec<&String> = clouds.iter().filter(|(_, r)| !r.archived).map(|(n, _)| n).collect();
        match clouds.get(name) {
            Some(r) if r.archived => Err(BestError::bad_request(
                "CLOUD_ARCHIVED",
                format!(
                    "cloud {name} is archived: the live ones are {}; configure-cloud with its name brings it back",
                    list(live.iter())
                ),
            )
            .with_details(json!({ "cloud": name, "clouds": live }))),
            Some(CloudRecord { live: Some(c), .. }) => Ok(c.clone()),
            _ => Err(BestError::bad_request(
                "NO_SUCH_CLOUD",
                format!(
                    "no cloud {name} in this workspace: the live ones are {}; get-clouds lists them, configure-cloud makes one",
                    list(live.iter())
                ),
            )
            .with_details(json!({ "cloud": name, "clouds": live }))),
        }
    }

    /// The cloud a placing command names: `cloud`, or the first part of `device` (`cloud/peer/device`); both when
    /// they agree.
    fn cloud_for(&self, data: &Value) -> Result<Arc<Cloud>, BestError> {
        let named = data["cloud"].as_str();
        if let Some(d) = data["device"].as_str().filter(|d| !d.contains('/')) {
            return Err(BestError::bad_request(
                "INVALID_DEVICE",
                format!("device {d} names no cloud: a device here is cloud/peer/device, as this workspace's get-hardware-state lists them"),
            )
            .with_details(json!({ "device": d })));
        }
        let from_device = data["device"].as_str().and_then(|d| d.split('/').next());
        let name = match (named, from_device) {
            (Some(c), Some(d)) if c != d => {
                return Err(BestError::bad_request(
                    "CLOUD_MISMATCH",
                    format!("cloud is {c} but device {} is in cloud {d}: name one cloud, or leave cloud out and let the device say", data["device"]),
                )
                .with_details(json!({ "cloud": c, "device": data["device"] })));
            }
            (Some(c), _) | (None, Some(c)) => c,
            (None, None) => {
                let clouds = self.clouds.lock().unwrap();
                let live: Vec<&String> = clouds.iter().filter(|(_, r)| !r.archived).map(|(n, _)| n).collect();
                return Err(BestError::bad_request(
                    "NO_CLOUD",
                    format!(
                        "name the cloud to place in: this workspace's are {}; get-clouds lists them, or name a device as cloud/peer/device",
                        list(live.iter())
                    ),
                )
                .with_details(json!({ "clouds": live })));
            }
        };
        self.cloud(name)
    }

    /// The live cloud named, for a test that squares its state by hand.
    #[cfg(test)]
    pub fn cloud_for_test(&self, name: &str) -> Arc<Cloud> {
        self.cloud(name).expect("a live cloud")
    }

    /// The live cloud holding the workload `id`.
    fn cloud_of(&self, id: &str) -> Option<Arc<Cloud>> {
        self.live_clouds().into_iter().find(|c| c.holds_workload(id))
    }

    fn members_file(&self, cloud: &str) -> PathBuf {
        self.dir.join("clouds").join(cloud).join("members.json")
    }

    /// Tells a cloud fact: appended, then folded, then made so.
    fn tell(&self, em: &Emitter, r#type: &str, data: Value) -> Envelope {
        let e = em.emit(r#type, data);
        self.fold(&e);
        self.materialise();
        e
    }

    /// Folds one cloud fact into the records; the live clouds are made to match by [`Workspace::materialise`].
    fn fold(&self, e: &Envelope) {
        let d = &e.data;
        let name = d["cloud"].as_str().unwrap_or_default().to_string();
        match e.r#type.as_str() {
            "CloudConfiguredV1" => {
                let members: Vec<(String, String)> = d["members"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|m| Some((m["peer"].as_str()?.to_string(), m["endpoint"].as_str()?.to_string())))
                    .collect();
                let mut clouds = self.clouds.lock().unwrap();
                let r = clouds.entry(name).or_default();
                r.members = members;
                r.archived = false;
            }
            "CloudArchivedV1" => {
                let mut clouds = self.clouds.lock().unwrap();
                if let Some(r) = clouds.get_mut(&name) {
                    r.archived = true;
                }
            }
            "MenuSetV1" => {
                let menu = serde_json::from_value::<SetMenuData>(d.clone())
                    .ok()
                    .filter(|m| !m.sizes.is_empty())
                    .map(|m| Menu {
                        currency: m.currency,
                        sizes: m.sizes,
                    });
                if let Some(r) = self.clouds.lock().unwrap().get_mut(&name) {
                    r.menu = menu;
                }
            }
            _ => {}
        }
    }

    /// Makes the live clouds match the records: one archived is halted and dropped, one configured is made (and
    /// followed, once the workspace started) or has its members changed.
    fn materialise(&self) {
        let mut clouds = self.clouds.lock().unwrap();
        for (name, r) in clouds.iter_mut() {
            match (&r.live, r.archived) {
                (Some(c), true) => {
                    c.halt();
                    r.live = None;
                }
                (Some(c), false) => {
                    c.reconfigure(&r.members);
                    c.set_menu(r.menu.clone());
                }
                (None, false) => {
                    let c = Cloud::new(
                        name,
                        &self.id,
                        &self.endpoint,
                        &self.ctx.service,
                        self.log.clone(),
                        self.dataschemas.clone(),
                        self.completions.clone(),
                        &r.members,
                        Some(self.members_file(name)),
                        self.ctx.transport.clone(),
                        self.ctx.holdings.clone(),
                    );
                    c.set_menu(r.menu.clone());
                    c.rebuild();
                    if self.started.load(std::sync::atomic::Ordering::SeqCst) {
                        c.follow();
                    }
                    r.live = Some(c);
                }
                (None, true) => {}
            }
        }
    }
}

#[async_trait]
impl Clouds for Workspace {
    fn clouds(&self) -> Result<Value, BestError> {
        let clouds = self.clouds.lock().unwrap();
        let rows: Vec<Value> = clouds
            .iter()
            .map(|(name, r)| {
                let peers: Vec<Value> = match &r.live {
                    Some(c) => c.peers(),
                    None => r
                        .members
                        .iter()
                        .map(|(p, e)| json!({ "peer": p, "endpoint": e, "state": "archived" }))
                        .collect(),
                };
                json!({ "cloud": name, "archived": r.archived, "peers": peers })
            })
            .collect();
        Ok(json!({ "clouds": rows }))
    }

    fn admit_configure(&self, cmd: Envelope, who: &Credential) -> Result<(), BestError> {
        if !self.is_owner(&who.holder()) {
            return Err(BestError::bad_request(
                "FORBIDDEN",
                "only the workspace's owner configures its clouds: ask them, or create a workspace of your own",
            )
            .with_details(json!({ "workspace": self.id, "role": "member" })));
        }
        let data: ConfigureData = crate::lifecycle::parse(&cmd.data)?;
        let bad_name = |field: &str, value: &str| {
            BestError::bad_request("INVALID_NAME", format!("{field} {value:?} must be {NAME_SHAPE}"))
                .with_details(json!({ "field": field, "value": value }))
        };
        if !domain::is_name(&data.cloud) {
            return Err(bad_name("cloud", &data.cloud));
        }
        let mut seen_names = HashSet::new();
        let mut seen_endpoints = HashSet::new();
        for m in &data.members {
            if !domain::is_name(&m.peer) {
                return Err(bad_name("peer", &m.peer));
            }
            let endpoint = m.endpoint.trim_end_matches('/').to_string();
            if !seen_names.insert(m.peer.clone()) {
                return Err(BestError::bad_request(
                    "DUPLICATE_MEMBER",
                    format!("peer {} is listed twice: give each member its own name", m.peer),
                )
                .with_details(json!({ "peer": m.peer })));
            }
            if !self.ctx.cleartext.allows(&endpoint) {
                return Err(BestError::bad_request(
                    "CLEARTEXT_MEMBER",
                    format!(
                        "endpoint {endpoint} is cleartext off loopback: the cloud's credential would travel unencrypted to peer {}; name it by its https:// endpoint, as its manifest advertises it, or have this door's operator set BEST_PEER_CLEARTEXT=vpn when a VPN carries it",
                        m.peer
                    ),
                )
                .with_details(json!({ "field": "members", "peer": m.peer, "endpoint": endpoint })));
            }
            if !seen_endpoints.insert(endpoint.clone()) {
                return Err(BestError::bad_request(
                    "DUPLICATE_MEMBER",
                    format!("endpoint {endpoint} is listed twice: a machine is one member"),
                )
                .with_details(json!({ "endpoint": endpoint })));
            }
        }
        let clouds = self.clouds.lock().unwrap();
        for (other, r) in clouds.iter().filter(|(n, r)| **n != data.cloud && !r.archived) {
            for m in &data.members {
                let endpoint = m.endpoint.trim_end_matches('/');
                if r.members.iter().any(|(_, e)| e.trim_end_matches('/') == endpoint) {
                    return Err(BestError::bad_request(
                        "ENDPOINT_IN_ANOTHER_CLOUD",
                        format!(
                            "endpoint {endpoint} is a member of cloud {other} of this workspace: a machine serves one cloud per workspace; remove it there with configure-cloud, or archive {other}"
                        ),
                    )
                    .with_details(json!({ "endpoint": endpoint, "cloud": other })));
                }
            }
        }
        if let Some(CloudRecord { live: Some(c), .. }) = clouds.get(&data.cloud) {
            for m in c.members() {
                let kept = data
                    .members
                    .iter()
                    .any(|n| n.endpoint.trim_end_matches('/') == m.endpoint && n.peer == m.name);
                if kept {
                    continue;
                }
                let holds = c.holds(Some(&m.name));
                if !holds.is_empty() {
                    return Err(BestError::bad_request(
                        "PEER_HOLDS_WORKLOADS",
                        format!(
                            "peer {} of cloud {} still holds {} workload(s): undeploy or stop them first (get-workloads lists them), or keep the peer",
                            m.name, data.cloud, holds.len()
                        ),
                    )
                    .with_details(json!({ "cloud": data.cloud, "peer": m.name, "holds": holds })));
                }
            }
        }
        Ok(())
    }

    async fn configure(self: Arc<Self>, cmd: Envelope, em: Emitter) {
        let Ok(data) = crate::lifecycle::parse::<ConfigureData>(&cmd.data) else {
            return;
        };
        let members: Vec<Value> = data
            .members
            .iter()
            .map(|m| json!({ "peer": m.peer, "endpoint": m.endpoint.trim_end_matches('/') }))
            .collect();
        self.tell(
            &em,
            "CloudConfiguredV1",
            json!({ "workspace": self.id, "cloud": data.cloud, "members": members }),
        );
    }

    async fn menus(&self) -> Result<Value, BestError> {
        let live: Vec<(String, Arc<Cloud>)> = self
            .clouds
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(n, r)| r.live.clone().map(|c| (n.clone(), c)))
            .collect();
        let mut menus = Vec::new();
        for (name, c) in live {
            menus.push(
                c.menu_view()
                    .await
                    .unwrap_or_else(|| json!({ "cloud": name, "currency": null, "sizes": [] })),
            );
        }
        Ok(json!({ "menus": menus }))
    }

    fn admit_set_menu(&self, cmd: Envelope, who: &Credential) -> Result<(), BestError> {
        if !self.is_owner(&who.holder()) {
            return Err(BestError::bad_request(
                "FORBIDDEN",
                "only the workspace's owner sets a cloud's menu: ask them",
            )
            .with_details(json!({ "workspace": self.id, "role": "member" })));
        }
        let data: SetMenuData = crate::lifecycle::parse(&cmd.data)?;
        self.cloud(&data.cloud)?;
        Menu {
            currency: data.currency,
            sizes: data.sizes,
        }
        .check()
    }

    async fn set_menu(self: Arc<Self>, cmd: Envelope, em: Emitter) {
        let Ok(data) = crate::lifecycle::parse::<SetMenuData>(&cmd.data) else {
            return;
        };
        self.tell(
            &em,
            "MenuSetV1",
            json!({ "workspace": self.id, "cloud": data.cloud, "currency": data.currency, "sizes": data.sizes }),
        );
    }

    fn admit_archive(&self, cmd: Envelope, who: &Credential) -> Result<(), BestError> {
        if !self.is_owner(&who.holder()) {
            return Err(BestError::bad_request(
                "FORBIDDEN",
                "only the workspace's owner archives its clouds: ask them",
            )
            .with_details(json!({ "workspace": self.id, "role": "member" })));
        }
        let name = cmd.data["cloud"].as_str().unwrap_or_default();
        let cloud = self.cloud(name)?;
        let holds = cloud.holds(None);
        if !holds.is_empty() {
            return Err(BestError::bad_request(
                "CLOUD_HOLDS_WORKLOADS",
                format!(
                    "cloud {name} still holds {} workload(s): undeploy or stop them first; get-workloads lists them",
                    holds.len()
                ),
            )
            .with_details(json!({ "cloud": name, "holds": holds })));
        }
        Ok(())
    }

    async fn archive(self: Arc<Self>, cmd: Envelope, em: Emitter) {
        self.tell(
            &em,
            "CloudArchivedV1",
            json!({ "workspace": self.id, "cloud": cmd.data["cloud"] }),
        );
    }
}

#[async_trait]
impl Service for Workspace {
    async fn hardware_state(&self, who: &Credential) -> Result<Value, BestError> {
        let mut devices = Vec::new();
        let mut peers = Vec::new();
        for c in self.live_clouds() {
            let mut v = c.hardware_state(who).await?;
            if let Some(d) = v["devices"].as_array_mut() {
                devices.append(d);
            }
            if let Some(p) = v["peers"].as_array_mut() {
                peers.append(p);
            }
        }
        Ok(json!({
            "driver": null,
            "observed_at": best_peer_door::envelope::now_rfc3339(),
            "devices": devices,
            "peers": peers
        }))
    }

    fn workloads(&self, who: &Credential) -> Result<Value, BestError> {
        let mut deployments = Vec::new();
        let mut jobs = Vec::new();
        let mut queued = Vec::new();
        for c in self.live_clouds() {
            let mut v = c.workloads(who)?;
            if let Some(d) = v["deployments"].as_array_mut() {
                deployments.append(d);
            }
            if let Some(j) = v["jobs"].as_array_mut() {
                jobs.append(j);
            }
            if let Some(q) = v["queued"].as_array_mut() {
                queued.append(q);
            }
        }
        Ok(json!({
            "deployments": deployments, "jobs": jobs, "queued": queued,
            "held_bytes": self.ctx.holdings.held_by(&who.holder()), "share_bytes": who.grant.memory_bytes
        }))
    }

    fn admit_pull(&self, cmd: Envelope, who: &Credential) -> Result<(), BestError> {
        require(who, "deploy")?;
        self.cloud_for(&cmd.data)?.admit_pull(cmd, who)
    }

    async fn pull_image(self: Arc<Self>, cmd: Envelope, em: Emitter) {
        match self.cloud_for(&cmd.data) {
            Ok(c) => c.pull_image(cmd, em).await,
            Err(e) => {
                em.emit(
                    "ImagePullFailed",
                    json!({ "image": cmd.data["image"], "reason": e.message, "fix": "get-clouds lists the clouds; pull again on one of them" }),
                );
            }
        }
    }

    async fn admit_deploy(&self, cmd: Envelope, who: Credential, key: String) -> Result<(), BestError> {
        require(&who, "deploy")?;
        self.cloud_for(&cmd.data)?.admit_deploy(cmd, who, key).await
    }

    async fn deploy(self: Arc<Self>, cmd: Envelope, em: Emitter) {
        match self.cloud_for(&cmd.data) {
            Ok(c) => c.deploy(cmd, em).await,
            Err(e) => {
                em.emit(
                    "CommandFailed",
                    json!({ "type": cmd.r#type, "reason": format!("{}; the command was accepted and its cloud is gone", e.message) }),
                );
            }
        }
    }

    fn admit_undeploy(&self, cmd: Envelope, who: &Credential) -> Result<(), BestError> {
        require(who, "deploy")?;
        let id = cmd.data["deployment"].as_str().unwrap_or_default();
        match self.cloud_of(id) {
            Some(c) => c.admit_undeploy(cmd, who),
            None => {
                let live: Vec<String> = self
                    .live_clouds()
                    .iter()
                    .flat_map(|c| {
                        let s = c.state.lock().unwrap();
                        s.deployments
                            .values()
                            .filter(|d| who.grant.is_all() || d.holder == who.holder())
                            .map(|d| d.id.clone())
                            .collect::<Vec<_>>()
                    })
                    .collect();
                Err(BestError::bad_request(
                    "NO_SUCH_DEPLOYMENT",
                    format!(
                        "no deployment {id} in this workspace: the live ones are {}; get-workloads lists them",
                        list(live.iter())
                    ),
                )
                .with_details(json!({ "deployment": id, "live": live })))
            }
        }
    }

    async fn undeploy(self: Arc<Self>, cmd: Envelope, em: Emitter) {
        let id = cmd.data["deployment"].as_str().unwrap_or_default().to_string();
        match self.cloud_of(&id) {
            Some(c) => c.undeploy(cmd, em).await,
            // Ended by itself between admission and now: it is not deployed, and that is what was asked.
            None => {
                em.emit("Undeployed", json!({ "deployment": id, "model": null }));
            }
        }
    }

    async fn admit_run_job(&self, cmd: Envelope, who: Credential, key: String) -> Result<(), BestError> {
        require(&who, "jobs")?;
        self.cloud_for(&cmd.data)?.admit_run_job(cmd, who, key).await
    }

    async fn run_job(self: Arc<Self>, cmd: Envelope, em: Emitter) {
        match self.cloud_for(&cmd.data) {
            Ok(c) => c.run_job(cmd, em).await,
            Err(e) => {
                em.emit(
                    "CommandFailed",
                    json!({ "type": cmd.r#type, "reason": format!("{}; the command was accepted and its cloud is gone", e.message) }),
                );
            }
        }
    }

    fn admit_stop_job(&self, cmd: Envelope, who: &Credential) -> Result<(), BestError> {
        require(who, "jobs")?;
        let id = cmd.data["job"].as_str().unwrap_or_default();
        match self.cloud_of(id) {
            Some(c) => c.admit_stop_job(cmd, who),
            None => {
                let running: Vec<String> = self
                    .live_clouds()
                    .iter()
                    .flat_map(|c| {
                        let s = c.state.lock().unwrap();
                        s.jobs
                            .values()
                            .filter(|j| who.grant.is_all() || j.holder == who.holder())
                            .map(|j| j.id.clone())
                            .collect::<Vec<_>>()
                    })
                    .collect();
                Err(BestError::bad_request(
                    "NO_SUCH_JOB",
                    format!(
                        "no job {id} is running in this workspace: the running ones are {}; get-workloads lists them",
                        list(running.iter())
                    ),
                )
                .with_details(json!({ "job": id, "running": running })))
            }
        }
    }

    async fn stop_job(self: Arc<Self>, cmd: Envelope, em: Emitter) {
        let id = cmd.data["job"].as_str().unwrap_or_default().to_string();
        match self.cloud_of(&id) {
            Some(c) => c.stop_job(cmd, em).await,
            None => {
                em.emit("JobStopped", json!({ "job": id }));
            }
        }
    }

    fn admit_prompt(&self, cmd: Envelope, who: &Credential) -> Result<(), BestError> {
        require(who, "prompt")?;
        let id = cmd.data["deployment"].as_str().unwrap_or_default();
        match self.cloud_of(id) {
            Some(c) => c.admit_prompt(cmd, who),
            None => Err(BestError::bad_request(
                "NO_SUCH_DEPLOYMENT",
                format!("no deployment {id} in this workspace: get-workloads lists what it runs for you, and deploy-model starts one"),
            )
            .with_details(json!({ "deployment": id }))),
        }
    }

    fn admit_forget(&self, cmd: Envelope, who: &Credential) -> Result<(), BestError> {
        crate::forget::admit(&self.log, &cmd, who).map(|_| ())
    }

    /// Forgets on this workspace's door, then asks the member peer that answered each forgotten prompt to forget its
    /// copy, under the member's own correlation of it.
    async fn forget(self: Arc<Self>, cmd: Envelope, em: Emitter) {
        let Ok(scope) = crate::forget::scope_of(&cmd) else {
            return;
        };
        let sender = crate::forget::sender_of(&em);
        let forgot = match crate::forget::forget(&self.log, &sender, &scope) {
            Ok(f) => f,
            Err(why) => {
                em.emit(
                    "CommandFailed",
                    json!({ "type": cmd.r#type, "reason": format!("the content is gone from what this door serves, but its files could not all be rewritten: {why}; send forget again") }),
                );
                return;
            }
        };
        // Each member that answered is asked for each prompt it holds, a few at a time, and told of once.
        let mut peers = Vec::new();
        for ((cloud, peer), prompts) in crate::forget::answered_on(&forgot) {
            let c = self.cloud(&cloud).ok();
            let asks: Vec<(Option<Arc<Cloud>>, String, String)> = prompts
                .iter()
                .map(|prompt| {
                    let on_member =
                        crate::cloud::member_correlation(&format!("{sender}:{}", prompt.id), &prompt.data, None);
                    (c.clone(), peer.clone(), on_member)
                })
                .collect();
            let asks = asks.into_iter().map(|(c, peer, on_member)| async move {
                match c {
                    Some(c) => c.forget_on_member(&peer, &on_member).await,
                    None => Err("its cloud is no longer live".to_string()),
                }
            });
            let told: Vec<Result<(), String>> = futures::stream::iter(asks).buffer_unordered(8).collect().await;
            let refused: Vec<&String> = told.iter().filter_map(|t| t.as_ref().err()).collect();
            let mut row = json!({ "cloud": cloud, "peer": peer, "prompts": told.len(), "asked": told.len() - refused.len(), "refused": refused.len() });
            if let Some(why) = refused.last() {
                row["reason"] = json!(why);
            }
            peers.push(row);
        }
        crate::forget::tell_forgotten(&em, &scope, &forgot, Some(json!(peers)));
    }

    async fn prompt(self: Arc<Self>, cmd: Envelope, em: Emitter) {
        let id = cmd.data["deployment"].as_str().unwrap_or_default().to_string();
        match self.cloud_of(&id) {
            Some(c) => c.prompt(cmd, em).await,
            None => {
                em.emit(
                    "PromptFailed",
                    json!({ "deployment": id, "reason": "the deployment ended between the prompt's admission and now", "fix": "deploy the model again, then prompt it" }),
                );
            }
        }
    }
}

/// A door started with `BEST_PEER_MEMBERS` set is refused, with the commands that configure a cloud.
pub fn members_variable_replaced(value: &str) -> String {
    format!(
        "BEST_PEER_MEMBERS is set ({value}) and no longer read: a cloud is configured through the door, not the process. Start the peer without it, sign in, then create-workspace at the root and configure-cloud in the workspace with the same members as name=endpoint; the README's \"More than one machine\" has the steps"
    )
}
