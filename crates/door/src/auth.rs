//! Sign-in as the spec defines it (SPEC.md, Agent Registration): RFC 8628 on the agent's side, unchanged, with the
//! three BEST request parameters, the three token-answer members, the credential block and the sign-in guidance
//! verbatim. Who approves is not the spec's business and not this module's either: an [`Approver`] the peer chooses
//! turns a pending registration into an admitted agent, and takes a credential back. The credential is a secret the
//! door generates, kept hashed, shown once, until it expires or is revoked.

use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::net::{IpAddr, Ipv6Addr};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::envelope::now_rfc3339;
use crate::guidance;

/// The header a credential travels in.
pub const AUTH_HEADER: &str = "X-Api-Key";
/// What a key looks like, so a leak is recognisable in a transcript.
const KEY_PREFIX: &str = "bp_";
/// How long an agent has to get the person to approve.
const DEVICE_CODE_TTL: Duration = Duration::from_secs(600);
/// How long after that an expired code is still remembered, so a late poll is told `expired_token` rather than
/// `invalid_grant` (RFC 8628 §3.5 tells them apart).
const EXPIRED_GRACE: Duration = Duration::from_secs(3600);
const POLL_INTERVAL: Duration = Duration::from_secs(5);
const SESSION_LIFETIME: Duration = Duration::from_secs(8 * 3600);
/// Registrations that may be pending at once, in all; the device endpoint is public, so it has a ceiling.
const MAX_PENDING: usize = 64;
/// The longest a person may bound a credential to at the approval: a year and a day.
pub const MAX_EXPIRES: Duration = Duration::from_secs(366 * 24 * 3600);
/// Registrations one client may have pending at once.
const MAX_PENDING_PER_CLIENT: usize = 5;
/// Registrations one address may have pending at once, whatever clients it names: a client names itself, an address
/// is what it has. A quarter of the door's, so no one address fills it. Loopback is not counted: what comes from it
/// is this machine's own, or a proxy in front of the door that every caller shares.
const MAX_PENDING_PER_ADDRESS: usize = 16;
const MAX_CLIENT_ID: usize = 100;
const MAX_AGENT_LABEL: usize = 200;
/// Letters and digits a person can read back without ambiguity.
const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ23456789";

/// An error the two OAuth endpoints answer with (RFC 6749 §5.2): never the BEST error format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthError {
    pub status: u16,
    pub error: &'static str,
    pub description: String,
}

impl OAuthError {
    pub fn invalid_request(description: impl Into<String>) -> Self {
        Self {
            status: 400,
            error: "invalid_request",
            description: description.into(),
        }
    }

    fn grant(error: &'static str, description: impl Into<String>) -> Self {
        Self {
            status: 400,
            error,
            description: description.into(),
        }
    }

    pub fn body(&self) -> Value {
        json!({ "error": self.error, "error_description": self.description })
    }
}

/// An admitted agent's credential, as the door keeps it: the hash, never the key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Credential {
    /// The connection's name, the person's label for this sign-in.
    pub name: String,
    pub hash: String,
    pub client_id: String,
    pub agent_label: Option<String>,
    pub issued_at: String,
    /// Absent for a durable credential.
    pub expires_at: Option<String>,
    /// When the person took it back; a revoked credential opens nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    /// What the credential may do and how much it may hold, as the person set it at the approval.
    #[serde(default, flatten)]
    pub grant: Grant,
}

impl Credential {
    /// Who holds a workload, as the events name it: an opaque id derived from the credential, never the key.
    pub fn holder(&self) -> String {
        holder_of_hash(&self.hash)
    }
}

/// The holder id of a credential hash: its first sixteen hex characters, what a command key's sender part also
/// yields, so a handler that has only the key names the same holder the admit saw.
pub fn holder_of_hash(hash: &str) -> String {
    hash.chars().take(16).collect()
}

/// Whether a credential opens the door at `now`: not taken back, and not past its end.
fn is_live(c: &Credential, now: OffsetDateTime) -> bool {
    c.revoked_at.is_none()
        && match &c.expires_at {
            None => true,
            Some(e) => OffsetDateTime::parse(e, &Rfc3339).is_ok_and(|e| e > now),
        }
}

/// What a credential may do and how much of the machine it may hold, decided by the person at the approval. A
/// credential approved with nothing said is `all`: what every credential was before scopes existed, the owner's
/// own box.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Grant {
    /// The scopes the credential may use, from the service's own list (`scopes` in the manifest's authentication
    /// block); absent means every scope and every holder's workloads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    /// The most device memory the credential's workloads may hold together; absent means no share is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_bytes: Option<u64>,
    /// The most deployments the credential may run at once across the door; absent means no count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployments: Option<u32>,
    /// The most jobs the credential may run at once across the door; absent means no count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jobs: Option<u32>,
    /// Whether the jobs of a credential with a share leave the closed box a tenant's job gets: the network and the
    /// host's memory, as the owner's own jobs have. The approver's word alone; a credential cannot ask for it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub open_jobs: bool,
}

impl Grant {
    /// Whether the credential may use `scope`: every scope when none was set or when `all` was.
    pub fn allows(&self, scope: &str) -> bool {
        match &self.scopes {
            None => true,
            Some(s) => s.iter().any(|x| x == "all" || x == scope),
        }
    }

    /// Whether the credential acts for every holder: it was approved with nothing said, or with `all`.
    pub fn is_all(&self) -> bool {
        self.scopes.as_ref().is_none_or(|s| s.iter().any(|x| x == "all"))
    }

    /// What was granted, for a refusal to say.
    pub fn said(&self) -> String {
        match &self.scopes {
            None => "all".into(),
            Some(s) => s.join(","),
        }
    }
}

/// `durable` (default) or `session` (SPEC.md: a consumer that cannot keep a secret out of a conversation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lifetime {
    Durable,
    Session,
}

impl Lifetime {
    fn as_str(self) -> &'static str {
        match self {
            Lifetime::Durable => "durable",
            Lifetime::Session => "session",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Pending {
    pub device_code: String,
    pub user_code: String,
    pub client_id: String,
    pub connection: Option<String>,
    pub agent_label: Option<String>,
    pub lifetime: Lifetime,
    /// Where it is counted: what `counted_as` made of the address it came from.
    from: Option<IpAddr>,
    created: Instant,
    last_poll: Option<Instant>,
    approved: bool,
    /// What the approval granted, once it happened.
    grant: Grant,
    /// How long the credential lasts, when the person said at the approval: sooner than the lifetime the agent
    /// asked for, never later.
    expires: Option<Duration>,
}

impl Pending {
    fn expired(&self) -> bool {
        self.created.elapsed() >= DEVICE_CODE_TTL
    }

    fn expires_in(&self) -> Duration {
        DEVICE_CODE_TTL.saturating_sub(self.created.elapsed())
    }
}

/// What was admitted, for whoever approved to read back.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Admitted {
    pub user_code: String,
    pub client_id: String,
    pub connection: Option<String>,
    pub agent_label: Option<String>,
    pub lifetime: &'static str,
    pub grant: Grant,
    /// Seconds until the credential ends, when it does.
    pub expires_in: Option<u64>,
}

/// The device authorization answer (RFC 8628 §3.2) plus BEST's `note`.
#[derive(Clone, Debug, Serialize)]
pub struct DeviceAnswer {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: u64,
    pub interval: u64,
    pub note: String,
}

/// The device request's parameters, form-encoded by the agent.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct DeviceRequest {
    pub client_id: Option<String>,
    pub connection: Option<String>,
    pub agent_label: Option<String>,
    pub credential_lifetime: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct TokenRequest {
    pub grant_type: Option<String>,
    pub device_code: Option<String>,
    pub client_id: Option<String>,
}

/// The authority that admits an agent. The spec leaves the person's side of sign-in to the platform; a peer is one
/// person's machine, so the default authority is whoever controls that machine. Another approver (an identity
/// provider, any of them) is an adapter behind this trait; the door never knows which.
#[async_trait]
pub trait Approver: Send + Sync {
    /// What the verification page tells the person to do for this user code.
    fn instructions(&self, user_code: &str) -> String;
    /// Whether `proof` is the authority's: asked before anything else on an approval, so a caller without it learns
    /// nothing of the door, and before taking a credential back.
    async fn attest(&self, proof: &str) -> Result<(), OAuthError>;
    /// Admits the registration `user_code` names, once `attest` has said the proof is the authority's: an error says
    /// why not.
    async fn admit(&self, user_code: &str, proof: &str) -> Result<(), OAuthError>;
}

/// Approval by whoever controls the machine: a token the peer wrote to its data directory, which only that person
/// can read, presented back through `best-peer approve <code>`.
pub struct LocalApprover {
    token: String,
}

impl LocalApprover {
    /// Reads the admin token in `dir`, writing a fresh one first when there is none. The file is created readable
    /// by its owner only, and an existing one is tightened to that.
    pub fn open(dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("admin-token");
        let token = match std::fs::read_to_string(&path) {
            Ok(t) if !t.trim().is_empty() => {
                restrict(&path)?;
                t.trim().to_string()
            }
            Ok(_) => Self::write_fresh(&path)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::write_fresh(&path)?,
            Err(e) => return Err(e),
        };
        Ok(Self { token })
    }

    fn write_fresh(path: &Path) -> std::io::Result<String> {
        let token = random_token(32);
        let mut options = OpenOptions::new();
        options.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut f = options.open(path)?;
        f.write_all(token.as_bytes())?;
        f.flush()?;
        restrict(path)?;
        Ok(token)
    }

    pub fn from_token(token: &str) -> Self {
        Self { token: token.into() }
    }
}

#[cfg(unix)]
fn restrict(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[async_trait]
impl Approver for LocalApprover {
    fn instructions(&self, user_code: &str) -> String {
        format!(
            "This peer admits agents on the word of whoever controls the machine it runs on. On that machine, run: best-peer approve {user_code}"
        )
    }

    async fn admit(&self, _user_code: &str, proof: &str) -> Result<(), OAuthError> {
        self.attest(proof).await
    }

    async fn attest(&self, proof: &str) -> Result<(), OAuthError> {
        if bool::from(proof.as_bytes().ct_eq(self.token.as_bytes())) {
            Ok(())
        } else {
            Err(OAuthError {
                status: 403,
                error: "access_denied",
                description: "the proof is not this peer's admin token".into(),
            })
        }
    }
}

/// For tests: admits any code when the proof is the one it was built with.
pub struct FakeApprover {
    pub proof: String,
}

#[async_trait]
impl Approver for FakeApprover {
    fn instructions(&self, user_code: &str) -> String {
        format!("fake approver: approve {user_code}")
    }

    async fn admit(&self, _user_code: &str, proof: &str) -> Result<(), OAuthError> {
        self.attest(proof).await
    }

    async fn attest(&self, proof: &str) -> Result<(), OAuthError> {
        if proof == self.proof {
            Ok(())
        } else {
            Err(OAuthError {
                status: 403,
                error: "access_denied",
                description: "wrong proof".into(),
            })
        }
    }
}

pub struct Auth {
    endpoint: String,
    approver: Box<dyn Approver>,
    credentials: Mutex<Vec<Credential>>,
    credentials_file: Mutex<Option<std::fs::File>>,
    /// Credentials taken back whose new line did not reach the disk: closed now, open again after a restart until a
    /// revoke writes them, so a revoke takes them again.
    unwritten: Mutex<HashSet<String>>,
    /// How many times a credential was taken back: what an open stream looks at before it looks for its own.
    revocations: AtomicU64,
    pending: Mutex<HashMap<String, Pending>>,
    /// The scopes this door has, named by the service: what an approval may grant.
    scopes: Vec<String>,
}

/// Where a registration from `from` is counted: an IPv4 address alone, an IPv6 address by its /64 (one client holds
/// a whole /64), every registration whose address the transport did not name in one place together, and loopback,
/// this machine or a proxy on it, nowhere.
fn counted_as(from: Option<IpAddr>) -> Option<IpAddr> {
    match from.map(|a| a.to_canonical()) {
        None => Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
        Some(a) if a.is_loopback() => None,
        Some(IpAddr::V6(a)) => Some(IpAddr::V6(Ipv6Addr::from(u128::from(a) & !(u128::MAX >> 64)))),
        Some(a) => Some(a),
    }
}

impl Auth {
    /// Credentials kept only in memory; for tests and for a peer run without a data directory.
    pub fn ephemeral(endpoint: &str, approver: Box<dyn Approver>) -> Self {
        Self {
            endpoint: endpoint.trim_end_matches('/').into(),
            approver,
            credentials: Mutex::new(Vec::new()),
            credentials_file: Mutex::new(None),
            unwritten: Mutex::new(HashSet::new()),
            revocations: AtomicU64::new(0),
            pending: Mutex::new(HashMap::new()),
            scopes: Vec::new(),
        }
    }

    /// The scopes this door has, as the service names them: what an approval may grant, and what the manifest's
    /// authentication block lists.
    pub fn with_scopes(mut self, scopes: &[&str]) -> Self {
        self.scopes = scopes.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// The live credential with this hash, for a command accepted before a restart: gone when it expired, was
    /// taken back, or was never this door's.
    pub fn credential_by_hash(&self, hash: &str) -> Option<Credential> {
        let now = OffsetDateTime::now_utc();
        self.credentials
            .lock()
            .unwrap()
            .iter()
            .find(|c| c.hash == hash)
            .filter(|c| is_live(c, now))
            .cloned()
    }

    /// Credentials kept in `dir/credentials.jsonl`, hashes only, one line per credential and one more each time it
    /// changed (taken back), the last line for a hash being the credential as it stands. A line that cannot be read
    /// (a torn write) is skipped, never fatal.
    pub fn open(dir: &Path, endpoint: &str, approver: Box<dyn Approver>) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let auth = Self::ephemeral(endpoint, approver);
        let path = dir.join("credentials.jsonl");
        if path.exists() {
            let text = String::from_utf8_lossy(&std::fs::read(&path)?).into_owned();
            let mut credentials = auth.credentials.lock().unwrap();
            for line in text.lines() {
                match serde_json::from_str::<Credential>(line) {
                    Ok(c) => match credentials.iter_mut().find(|known| known.hash == c.hash) {
                        Some(known) => *known = c,
                        None => credentials.push(c),
                    },
                    Err(e) if !line.trim().is_empty() => {
                        tracing::warn!(error = %e, "a credential line could not be read and is skipped")
                    }
                    Err(_) => {}
                }
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        restrict(&path)?;
        *auth.credentials_file.lock().unwrap() = Some(file);
        Ok(auth)
    }

    pub fn device_authorization_url(&self) -> String {
        format!("{}/auth/device", self.endpoint)
    }

    pub fn token_url(&self) -> String {
        format!("{}/auth/token", self.endpoint)
    }

    pub fn verification_uri(&self) -> String {
        format!("{}/auth/verify", self.endpoint)
    }

    /// The credential the key opens, if it is one this door issued and it has neither expired nor been taken back.
    pub fn authenticate(&self, key: &str) -> Option<Credential> {
        let hash = hash_key(key);
        let now = OffsetDateTime::now_utc();
        self.credentials
            .lock()
            .unwrap()
            .iter()
            .find(|c| bool::from(c.hash.as_bytes().ct_eq(hash.as_bytes())))
            .filter(|c| is_live(c, now))
            .cloned()
    }

    /// Takes back every live credential `name` names, by its connection name or its holder id, on the authority's
    /// word: each is written again with `revoked_at` set, so a restart reads it back taken, and opens nothing from
    /// now on. No live credential by that name is refused with the live names; one the disk did not take is closed
    /// now and said so (500), and a revoke again writes it.
    pub async fn revoke(&self, name: &str, proof: &str) -> Result<Vec<Credential>, OAuthError> {
        self.approver.attest(proof).await?;
        let name = name.trim();
        self.take_back(|c| c.name == name || holder_of_hash(&c.hash) == name)
            .map_err(|why| match why {
                TakeBack::NoneLive(live) => OAuthError::invalid_request(format!(
                    "no live credential is named {name}: the live ones are {}",
                    if live.is_empty() {
                        "none".to_string()
                    } else {
                        live.join(", ")
                    }
                )),
                TakeBack::Unwritten(e) => OAuthError {
                    status: 500,
                    error: "server_error",
                    description: format!(
                        "{name} is taken back now, but the line that keeps it taken was not written ({e}): it would open again after a restart; free the disk and revoke {name} again"
                    ),
                },
            })
    }

    /// Takes back the credential with this hash, on its own word (the agent's revoke-agent command).
    pub fn revoke_own(&self, hash: &str) -> Result<Credential, String> {
        match self.take_back(|c| c.hash == hash) {
            Ok(mut taken) => Ok(taken.remove(0)),
            Err(TakeBack::NoneLive(_)) => Err("this credential is not live".into()),
            Err(TakeBack::Unwritten(e)) => Err(format!(
                "taken back now, but the line that keeps it taken was not written ({e}): it would open again after a restart until its owner revokes it again"
            )),
        }
    }

    /// How many times a credential was taken back since the door started: an open stream looks for its own
    /// credential again only when this moved.
    pub fn revocations(&self) -> u64 {
        self.revocations.load(Ordering::SeqCst)
    }

    /// Marks every live credential `select` picks taken back, in memory first, so it opens nothing at once, then on
    /// disk, a line each; one whose line did not reach the disk stays pickable, so the next revoke writes it.
    fn take_back(&self, select: impl Fn(&Credential) -> bool) -> Result<Vec<Credential>, TakeBack> {
        let now = OffsetDateTime::now_utc();
        let taken: Vec<Credential> = {
            let mut credentials = self.credentials.lock().unwrap();
            let unwritten = self.unwritten.lock().unwrap();
            let mut taken = Vec::new();
            for c in credentials
                .iter_mut()
                .filter(|c| select(c) && (is_live(c, now) || unwritten.contains(&c.hash)))
            {
                if c.revoked_at.is_none() {
                    c.revoked_at = Some(now_rfc3339());
                }
                taken.push(c.clone());
            }
            if taken.is_empty() {
                return Err(TakeBack::NoneLive(
                    credentials
                        .iter()
                        .filter(|c| is_live(c, now))
                        .map(|c| format!("{} ({})", c.name, holder_of_hash(&c.hash)))
                        .collect(),
                ));
            }
            taken
        };
        self.revocations.fetch_add(1, Ordering::SeqCst);
        let mut failed = None;
        for c in &taken {
            match self.write(c) {
                Ok(()) => {
                    self.unwritten.lock().unwrap().remove(&c.hash);
                }
                Err(e) => {
                    tracing::error!(holder = %holder_of_hash(&c.hash), error = %e, "a credential taken back could not be written to disk: it is closed until the peer restarts");
                    self.unwritten.lock().unwrap().insert(c.hash.clone());
                    failed = Some(e.to_string());
                }
            }
        }
        match failed {
            None => Ok(taken),
            Some(e) => Err(TakeBack::Unwritten(e)),
        }
    }

    /// RFC 8628 §3.1–3.2 with BEST's parameters: a `connection` of another shape is refused with the shape.
    pub fn start_device(&self, req: DeviceRequest) -> Result<DeviceAnswer, OAuthError> {
        self.start_device_from(req, None)
    }

    /// The same, from the address the transport named: one address has its own ceiling on registrations pending at
    /// once, whatever clients it names (SPEC.md security: rate-limited per client). Loopback is not counted.
    pub fn start_device_from(&self, req: DeviceRequest, from: Option<IpAddr>) -> Result<DeviceAnswer, OAuthError> {
        let from = counted_as(from);
        let client_id = match req.client_id.as_deref().map(str::trim) {
            Some(c) if !c.is_empty() && c.len() <= MAX_CLIENT_ID => c.to_string(),
            Some(_) => {
                return Err(OAuthError::invalid_request(format!(
                    "client_id must be the name of the consumer software, at most {MAX_CLIENT_ID} characters"
                )))
            }
            None => {
                return Err(OAuthError::invalid_request(
                    "client_id is required: the name of the consumer software",
                ))
            }
        };
        if let Some(c) = &req.connection {
            if !is_connection_name(c) {
                return Err(OAuthError::invalid_request(
                    "connection must be one word of lowercase letters, digits and hyphens, 1 to 64 characters, starting with a letter or digit (acme-payroll-dev)",
                ));
            }
        }
        if req.agent_label.as_ref().is_some_and(|l| l.len() > MAX_AGENT_LABEL) {
            return Err(OAuthError::invalid_request(format!(
                "agent_label must be at most {MAX_AGENT_LABEL} characters: what the approver reads"
            )));
        }
        let lifetime = match req.credential_lifetime.as_deref() {
            None | Some("durable") => Lifetime::Durable,
            Some("session") => Lifetime::Session,
            Some(other) => {
                return Err(OAuthError::invalid_request(format!(
                    "credential_lifetime must be durable or session, not {other:?}"
                )))
            }
        };
        self.expire_pending();
        let mut pending = self.pending.lock().unwrap();
        let waiting: Vec<&Pending> = pending.values().filter(|p| !p.expired() && !p.approved).collect();
        let mine: Vec<&Pending> = waiting.iter().copied().filter(|p| p.client_id == client_id).collect();
        let here: Vec<&Pending> = match from {
            Some(a) => waiting.iter().copied().filter(|p| p.from == Some(a)).collect(),
            None => Vec::new(),
        };
        let full = [
            (waiting.len() >= MAX_PENDING, &waiting),
            (mine.len() >= MAX_PENDING_PER_CLIENT, &mine),
            (here.len() >= MAX_PENDING_PER_ADDRESS, &here),
        ];
        if full.iter().any(|(hit, _)| *hit) {
            let wait = full
                .iter()
                .filter(|(hit, _)| *hit)
                .filter_map(|(_, group)| group.iter().map(|p| p.expires_in()).min())
                .max()
                .unwrap_or(DEVICE_CODE_TTL)
                .as_secs()
                + 1;
            return Err(OAuthError {
                status: 503,
                error: "temporarily_unavailable",
                description: format!(
                    "too many registrations are waiting for approval: {} from client {client_id} (at most {MAX_PENDING_PER_CLIENT}), {} from your address (at most {MAX_PENDING_PER_ADDRESS}), {} in all (at most {MAX_PENDING}); have one of yours approved, or ask again in {wait} s, when the oldest expires",
                    mine.len(),
                    here.len(),
                    waiting.len()
                ),
            });
        }
        let device_code = random_token(32);
        let user_code = random_user_code();
        pending.insert(
            device_code.clone(),
            Pending {
                device_code: device_code.clone(),
                user_code: user_code.clone(),
                client_id,
                connection: req.connection,
                agent_label: req.agent_label,
                lifetime,
                from,
                grant: Grant::default(),
                expires: None,
                created: Instant::now(),
                last_poll: None,
                approved: false,
            },
        );
        Ok(DeviceAnswer {
            device_code,
            user_code: user_code.clone(),
            verification_uri: self.verification_uri(),
            verification_uri_complete: format!("{}?user_code={user_code}", self.verification_uri()),
            expires_in: DEVICE_CODE_TTL.as_secs(),
            interval: POLL_INTERVAL.as_secs(),
            note: guidance::DEVICE_TEXT.into(),
        })
    }

    /// The page the person opens: the code, who is asking, what they would get, and what to do.
    pub fn verification_page(&self, user_code: Option<&str>) -> String {
        let code = user_code.map(normalise_user_code).unwrap_or_default();
        let asking = self
            .pending
            .lock()
            .unwrap()
            .values()
            .find(|p| p.user_code == code && !p.approved && !p.expired())
            .cloned();
        let body = if code.is_empty() {
            "<p>Enter the code your agent showed you in the address: <code>?user_code=XXXX-XXXX</code>.</p>".to_string()
        } else if let Some(p) = asking {
            let who = match &p.agent_label {
                Some(l) => format!("{} ({})", html_escape(l), html_escape(&p.client_id)),
                None => html_escape(&p.client_id),
            };
            let connection = p
                .connection
                .as_deref()
                .map(html_escape)
                .unwrap_or_else(|| host_of(&self.endpoint));
            format!(
                "<p>An agent asks to be admitted with code <code>{}</code>.</p><dl><dt>Who</dt><dd>{who}</dd><dt>Connection name</dt><dd>{connection}</dd><dt>Credential</dt><dd>{}</dd></dl><p>{}</p>",
                html_escape(&code),
                p.lifetime.as_str(),
                html_escape(&self.approver.instructions(&code))
            )
        } else {
            format!(
                "<p>Code <code>{}</code> is unknown, already used, or expired. Ask your agent to start again.</p>",
                html_escape(&code)
            )
        };
        format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>best-peer: admit an agent</title></head><body style=\"font-family:system-ui;max-width:40em;margin:3em auto\"><h1>Admit an agent</h1>{body}</body></html>"
        )
    }

    /// Admits the registration `user_code` names, with `grant` as what the credential may do and `expires` as how
    /// long it lasts when the person said (sooner than the lifetime the agent asked for, never later), once
    /// `proof` is the authority's. A scope the service does not have is refused by name, so a typo cannot admit
    /// more or less than the person meant.
    pub async fn approve(
        &self,
        user_code: &str,
        proof: &str,
        grant: Grant,
        expires: Option<Duration>,
    ) -> Result<Admitted, OAuthError> {
        self.approver.attest(proof).await?;
        if expires.is_some_and(|d| d.is_zero() || d > MAX_EXPIRES) {
            return Err(OAuthError::invalid_request(format!(
                "expires_in must be seconds above zero and {} at most (366 days): how long the credential lasts, or leave it out",
                MAX_EXPIRES.as_secs()
            )));
        }
        if let Some(scopes) = &grant.scopes {
            if scopes.is_empty() {
                return Err(OAuthError::invalid_request(
                    "may names no scope: say which, or leave it out for all",
                ));
            }
            if let Some(unknown) = scopes
                .iter()
                .find(|s| *s != "all" && !self.scopes.iter().any(|k| k == *s))
            {
                return Err(OAuthError::invalid_request(format!(
                    "no such scope {unknown}: this door has {}, and all",
                    self.scopes.join(", ")
                )));
            }
        }
        self.expire_pending();
        let code = normalise_user_code(user_code);
        let lifetime = self
            .pending
            .lock()
            .unwrap()
            .values()
            .find(|p| p.user_code == code && !p.approved && !p.expired())
            .map(|p| p.lifetime);
        let Some(lifetime) = lifetime else {
            return Err(OAuthError::invalid_request(format!(
                "no pending registration has the code {code}: it is unknown, already approved, or older than {} s",
                DEVICE_CODE_TTL.as_secs()
            )));
        };
        if lifetime == Lifetime::Session && expires.is_some_and(|d| d > SESSION_LIFETIME) {
            return Err(OAuthError::invalid_request(format!(
                "the agent asked for a session credential, which lasts {} s (8 hours) at most: approve it with expires_in of that or less, or leave it out",
                SESSION_LIFETIME.as_secs()
            )));
        }
        self.approver.admit(&code, proof).await?;
        let mut pending = self.pending.lock().unwrap();
        let p = pending
            .values_mut()
            .find(|p| p.user_code == code && !p.approved && !p.expired())
            .ok_or_else(|| {
                OAuthError::invalid_request(format!("the registration {code} expired while being approved"))
            })?;
        p.approved = true;
        p.grant = grant.clone();
        p.expires = expires;
        Ok(Admitted {
            user_code: code,
            client_id: p.client_id.clone(),
            connection: p.connection.clone(),
            agent_label: p.agent_label.clone(),
            lifetime: p.lifetime.as_str(),
            grant,
            expires_in: lasts(p.lifetime, expires).map(|d| d.as_secs()),
        })
    }

    /// RFC 8628 §3.4–3.5: the token answer once approved, `authorization_pending` or `slow_down` until then,
    /// `expired_token` for a code whose time ran out, `invalid_grant` for one this door never issued or already
    /// redeemed. A `device_code` is redeemed once, by the client that started it.
    pub fn token(&self, req: TokenRequest) -> Result<Value, OAuthError> {
        if req.grant_type.as_deref() != Some("urn:ietf:params:oauth:grant-type:device_code") {
            return Err(OAuthError {
                status: 400,
                error: "unsupported_grant_type",
                description: "grant_type must be urn:ietf:params:oauth:grant-type:device_code".into(),
            });
        }
        let Some(device_code) = req.device_code.filter(|d| !d.is_empty()) else {
            return Err(OAuthError::invalid_request("device_code is required"));
        };
        let Some(client_id) = req.client_id.filter(|c| !c.trim().is_empty()) else {
            return Err(OAuthError::invalid_request(
                "client_id is required: the name the registration was started with",
            ));
        };
        self.expire_pending();
        let mut pending = self.pending.lock().unwrap();
        let Some(p) = pending.get_mut(&device_code) else {
            return Err(OAuthError::grant("invalid_grant", "unknown device_code"));
        };
        if p.expired() {
            pending.remove(&device_code);
            return Err(OAuthError::grant(
                "expired_token",
                format!(
                    "the registration expired after {} s; start again",
                    DEVICE_CODE_TTL.as_secs()
                ),
            ));
        }
        if client_id != p.client_id {
            return Err(OAuthError::grant(
                "invalid_grant",
                "client_id is not the one that started this registration",
            ));
        }
        if p.last_poll.is_some_and(|t| t.elapsed() < POLL_INTERVAL) {
            p.last_poll = Some(Instant::now());
            return Err(OAuthError::grant(
                "slow_down",
                format!("poll no faster than every {} seconds", POLL_INTERVAL.as_secs()),
            ));
        }
        p.last_poll = Some(Instant::now());
        if !p.approved {
            return Err(OAuthError::grant(
                "authorization_pending",
                "the person has not approved yet",
            ));
        }
        let p = pending.remove(&device_code).expect("just found");
        drop(pending);
        let key = format!("{KEY_PREFIX}{}", random_token(32));
        let name = p.connection.clone().unwrap_or_else(|| host_of(&self.endpoint));
        let expires_in = lasts(p.lifetime, p.expires);
        let expires_at = expires_in.map(rfc3339_in);
        let credential = Credential {
            name: name.clone(),
            hash: hash_key(&key),
            client_id: p.client_id,
            agent_label: p.agent_label,
            issued_at: now_rfc3339(),
            expires_at: expires_at.clone(),
            revoked_at: None,
            grant: p.grant,
        };
        self.store(&credential);
        let mut answer = json!({
            "access_token": key,
            "token_type": "apikey",
            "auth_header": AUTH_HEADER,
            "name": name,
            "tenant_id": host_of(&self.endpoint),
            "note": format!("{} This peer admitted you on the word of whoever controls the machine it runs on.", guidance::TOKEN_TEXT),
            "endpoint": self.endpoint,
            "manifest": format!("{}/.well-known/best", self.endpoint),
            "ready_check": format!("{}/queries", self.endpoint),
            "mcp": {
                name: {
                    "command": "npx",
                    "args": ["-y", "@behavioralstate/best-mcp"],
                    "env": {
                        "BEST_ENDPOINT": self.endpoint,
                        "BEST_API_KEY": key,
                        "BEST_AUTH_TYPE": "apikey",
                        "BEST_AUTH_HEADER": AUTH_HEADER
                    }
                }
            },
            "http": {
                "header": format!("{AUTH_HEADER}: <access_token>"),
                "commands": format!("{}/commands", self.endpoint),
                "queries": format!("{}/queries", self.endpoint),
                "events": format!("{}/events", self.endpoint)
            }
        });
        if let (Some(d), Some(e)) = (expires_in, expires_at) {
            answer["expires_in"] = json!(d.as_secs());
            answer["expires_at"] = json!(e);
        }
        Ok(answer)
    }

    pub fn credentials(&self) -> Vec<Credential> {
        self.credentials.lock().unwrap().clone()
    }

    /// Keeps a credential, in memory and, when there is a file, on disk.
    fn store(&self, c: &Credential) {
        if let Err(e) = self.write(c) {
            tracing::error!(error = %e, "a credential could not be written to disk; it lasts until restart");
        }
        self.credentials.lock().unwrap().push(c.clone());
    }

    /// Writes a credential as it stands, when there is a file: one line, one write, on the disk before it returns.
    fn write(&self, c: &Credential) -> std::io::Result<()> {
        if let Some(f) = self.credentials_file.lock().unwrap().as_mut() {
            let mut line = serde_json::to_string(c).expect("a credential serialises");
            line.push('\n');
            f.write_all(line.as_bytes())?;
            f.flush()?;
            f.sync_data()?;
        }
        Ok(())
    }

    /// Forgets registrations that expired longer ago than the grace period keeps them for `expired_token`.
    fn expire_pending(&self) {
        self.pending
            .lock()
            .unwrap()
            .retain(|_, p| p.created.elapsed() < DEVICE_CODE_TTL + EXPIRED_GRACE);
    }

    #[cfg(test)]
    fn age(&self, device_code: &str, by: Duration) {
        if let Some(p) = self.pending.lock().unwrap().get_mut(device_code) {
            p.created = p.created.checked_sub(by).expect("a test ages within Instant's range");
            p.last_poll = None;
        }
    }
}

/// `^[a-z0-9][a-z0-9-]{0,63}$`
pub fn is_connection_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

pub fn hash_key(key: &str) -> String {
    hex::encode(Sha256::digest(key.as_bytes()))
}

/// A person types the code as they read it: case and spacing do not matter.
fn normalise_user_code(s: &str) -> String {
    s.trim().to_ascii_uppercase()
}

fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

fn random_user_code() -> String {
    let mut buf = [0u8; 8];
    rand::rng().fill_bytes(&mut buf);
    let chars: Vec<char> = buf
        .iter()
        .map(|b| USER_CODE_ALPHABET[(*b as usize) % USER_CODE_ALPHABET.len()] as char)
        .collect();
    format!(
        "{}-{}",
        chars[..4].iter().collect::<String>(),
        chars[4..].iter().collect::<String>()
    )
}

fn host_of(endpoint: &str) -> String {
    endpoint
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(endpoint)
        .to_string()
}

fn rfc3339_in(d: Duration) -> String {
    (OffsetDateTime::now_utc() + d).format(&Rfc3339).expect("rfc3339")
}

/// Why nothing, or not all, was taken back.
enum TakeBack {
    /// No live credential was picked; the live ones, by name and holder.
    NoneLive(Vec<String>),
    /// Taken in memory, not written: the disk's error.
    Unwritten(String),
}

/// How long a credential lasts: what the person said at the approval, which the approval held to the session
/// lifetime for a session credential, else that lifetime, and for ever for a durable one nobody bounded.
fn lasts(lifetime: Lifetime, said: Option<Duration>) -> Option<Duration> {
    match (lifetime, said) {
        (_, Some(d)) => Some(d),
        (Lifetime::Durable, None) => None,
        (Lifetime::Session, None) => Some(SESSION_LIFETIME),
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> Auth {
        Auth::ephemeral("http://peer.test", Box::new(FakeApprover { proof: "ok".into() }))
    }

    fn start(auth: &Auth, connection: Option<&str>) -> DeviceAnswer {
        auth.start_device(DeviceRequest {
            client_id: Some("best-validate".into()),
            connection: connection.map(String::from),
            agent_label: Some("a test".into()),
            credential_lifetime: None,
        })
        .unwrap()
    }

    fn poll(auth: &Auth, device_code: &str) -> Result<Value, OAuthError> {
        auth.token(TokenRequest {
            grant_type: Some("urn:ietf:params:oauth:grant-type:device_code".into()),
            device_code: Some(device_code.into()),
            client_id: Some("best-validate".into()),
        })
    }

    #[test]
    fn the_device_answer_is_rfc_8628_with_a_service_generated_code_and_the_spec_words() {
        let a = start(&auth(), Some("my-peer"));
        assert!(a.device_code.len() >= 20);
        assert_ne!(a.device_code, a.user_code);
        assert_eq!(a.user_code.len(), 9);
        assert!(!a.verification_uri_complete.contains(&a.device_code));
        assert!(a
            .verification_uri_complete
            .ends_with(&format!("user_code={}", a.user_code)));
        assert_eq!(a.note, guidance::DEVICE_TEXT);
        assert_eq!(a.interval, 5);
    }

    #[test]
    fn a_request_of_another_shape_is_refused_with_the_shape() {
        let a = auth();
        let err = a
            .start_device(DeviceRequest {
                client_id: Some("x".into()),
                connection: Some("Not One Word".into()),
                ..Default::default()
            })
            .unwrap_err();
        assert_eq!(err.error, "invalid_request");
        assert!(
            err.description.contains("lowercase letters, digits and hyphens"),
            "{}",
            err.description
        );
        let long = a
            .start_device(DeviceRequest {
                client_id: Some("x".into()),
                agent_label: Some("l".repeat(201)),
                ..Default::default()
            })
            .unwrap_err();
        assert!(long.description.contains("agent_label"), "{}", long.description);
        assert!(is_connection_name("acme-payroll-dev"));
        assert!(!is_connection_name("-x"));
        assert!(!is_connection_name(""));
    }

    #[tokio::test]
    async fn pending_then_approved_then_a_credential_that_opens_the_door_once() {
        let auth = auth();
        let a = start(&auth, Some("my-peer"));
        assert_eq!(poll(&auth, &a.device_code).unwrap_err().error, "authorization_pending");
        assert_eq!(poll(&auth, &a.device_code).unwrap_err().error, "slow_down");
        assert_eq!(
            auth.approve(&a.user_code, "wrong", Grant::default(), None)
                .await
                .unwrap_err()
                .error,
            "access_denied"
        );
        let admitted = auth
            .approve(&a.user_code.to_ascii_lowercase(), "ok", Grant::default(), None)
            .await
            .unwrap();
        assert_eq!(admitted.connection.as_deref(), Some("my-peer"));
        assert_eq!(admitted.agent_label.as_deref(), Some("a test"));
        assert_eq!(admitted.lifetime, "durable");
        auth.age(&a.device_code, Duration::ZERO);
        let answer = poll(&auth, &a.device_code).unwrap();
        let key = answer["access_token"].as_str().unwrap().to_string();
        assert!(key.starts_with("bp_"));
        assert_eq!(answer["name"], "my-peer");
        assert_eq!(answer["auth_header"], "X-Api-Key");
        assert!(answer["note"].as_str().unwrap().starts_with(guidance::TOKEN_TEXT));
        assert!(
            !answer["note"].as_str().unwrap().contains("revoke"),
            "no promise the peer cannot keep"
        );
        assert_eq!(answer["mcp"]["my-peer"]["env"]["BEST_API_KEY"], key);
        assert!(
            !answer["http"].to_string().contains(&key),
            "the key appears only in access_token and mcp"
        );
        assert!(answer.get("expires_in").is_none(), "durable");
        let who = auth.authenticate(&key).unwrap();
        assert_eq!(who.name, "my-peer");
        assert_eq!(who.hash, hash_key(&key));
        assert!(auth.authenticate("bp_nope").is_none());
        assert_eq!(
            poll(&auth, &a.device_code).unwrap_err().error,
            "invalid_grant",
            "redeemed once"
        );
    }

    #[test]
    fn the_token_is_redeemed_only_by_the_client_that_started_and_only_in_time() {
        let auth = auth();
        let a = start(&auth, None);
        let other = auth.token(TokenRequest {
            grant_type: Some("urn:ietf:params:oauth:grant-type:device_code".into()),
            device_code: Some(a.device_code.clone()),
            client_id: Some("someone-else".into()),
        });
        assert_eq!(other.unwrap_err().error, "invalid_grant");
        let none = auth.token(TokenRequest {
            grant_type: Some("urn:ietf:params:oauth:grant-type:device_code".into()),
            device_code: Some(a.device_code.clone()),
            client_id: None,
        });
        assert_eq!(none.unwrap_err().error, "invalid_request");
        auth.age(&a.device_code, DEVICE_CODE_TTL + Duration::from_secs(1));
        assert_eq!(poll(&auth, &a.device_code).unwrap_err().error, "expired_token");
        assert_eq!(
            poll(&auth, &a.device_code).unwrap_err().error,
            "invalid_grant",
            "told once, then forgotten"
        );
    }

    #[tokio::test]
    async fn an_expired_registration_cannot_be_approved_and_the_page_says_so() {
        let auth = auth();
        let a = start(&auth, None);
        auth.age(&a.device_code, DEVICE_CODE_TTL + Duration::from_secs(1));
        assert!(auth.verification_page(Some(&a.user_code)).contains("unknown"));
        assert_eq!(
            auth.approve(&a.user_code, "ok", Grant::default(), None)
                .await
                .unwrap_err()
                .error,
            "invalid_request"
        );
    }

    #[tokio::test]
    async fn a_session_credential_expires_and_a_missing_connection_is_named_after_the_host() {
        let auth = auth();
        let a = auth
            .start_device(DeviceRequest {
                client_id: Some("best-validate".into()),
                credential_lifetime: Some("session".into()),
                ..Default::default()
            })
            .unwrap();
        auth.approve(&a.user_code, "ok", Grant::default(), None).await.unwrap();
        let answer = poll(&auth, &a.device_code).unwrap();
        assert_eq!(answer["name"], "peer.test");
        assert_eq!(answer["expires_in"], 8 * 3600);
        let key = answer["access_token"].as_str().unwrap();
        assert!(auth.authenticate(key).is_some(), "live for eight hours");
        auth.store(&Credential {
            name: "stale".into(),
            hash: hash_key("bp_stale"),
            client_id: "x".into(),
            agent_label: None,
            issued_at: "2020-01-01T00:00:00Z".into(),
            expires_at: Some("2020-01-01T08:00:00.5Z".into()),
            revoked_at: None,
            grant: Grant::default(),
        });
        assert!(
            auth.authenticate("bp_stale").is_none(),
            "an expired credential opens nothing"
        );
    }

    #[test]
    fn an_unknown_code_is_invalid_grant_and_the_wrong_grant_type_is_named() {
        let auth = auth();
        assert_eq!(poll(&auth, "best-validate-unknown").unwrap_err().error, "invalid_grant");
        let err = auth
            .token(TokenRequest {
                grant_type: Some("password".into()),
                ..Default::default()
            })
            .unwrap_err();
        assert_eq!(err.error, "unsupported_grant_type");
    }

    #[test]
    fn the_verification_page_says_who_asks_what_they_get_and_escapes_what_it_shows() {
        let auth = auth();
        let a = auth
            .start_device(DeviceRequest {
                client_id: Some("claude".into()),
                connection: Some("my-peer".into()),
                agent_label: Some("Claude on <Ada's> phone".into()),
                credential_lifetime: Some("session".into()),
            })
            .unwrap();
        let page = auth.verification_page(Some(&a.user_code));
        assert!(page.contains(&a.user_code));
        assert!(page.contains("Claude on &lt;Ada's&gt; phone (claude)"), "{page}");
        assert!(page.contains("<dd>my-peer</dd>"));
        assert!(page.contains("<dd>session</dd>"));
        assert!(page.contains("fake approver: approve"));
        let hostile = auth.verification_page(Some("<script>x</script>"));
        assert!(!hostile.contains("<script>"), "{hostile}");
        assert!(hostile.contains("unknown"));
    }

    #[tokio::test]
    async fn a_credential_taken_back_opens_nothing_at_once_nor_after_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let auth = Auth::open(
            dir.path(),
            "http://peer.test",
            Box::new(FakeApprover { proof: "ok".into() }),
        )
        .unwrap();
        let a = start(&auth, Some("team"));
        auth.approve(&a.user_code, "ok", Grant::default(), None).await.unwrap();
        let key = poll(&auth, &a.device_code).unwrap()["access_token"]
            .as_str()
            .unwrap()
            .to_string();
        let b = start(&auth, Some("other"));
        auth.approve(&b.user_code, "ok", Grant::default(), None).await.unwrap();
        let other = poll(&auth, &b.device_code).unwrap()["access_token"]
            .as_str()
            .unwrap()
            .to_string();
        let holder = auth.authenticate(&key).unwrap().holder();
        // The authority's word, or nothing happens.
        assert_eq!(auth.revoke("team", "wrong").await.unwrap_err().error, "access_denied");
        assert!(auth.authenticate(&key).is_some());
        // By name: taken at once, and the other is untouched.
        let taken = auth.revoke("team", "ok").await.unwrap();
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].name, "team");
        assert!(taken[0].revoked_at.is_some());
        assert!(auth.authenticate(&key).is_none(), "taken back");
        assert!(
            auth.credential_by_hash(&hash_key(&key)).is_none(),
            "nor for a command owed after a restart"
        );
        assert!(auth.authenticate(&other).is_some());
        // A name with no live credential is refused with the live ones, and a taken one is not live.
        let err = auth.revoke("team", "ok").await.unwrap_err();
        assert_eq!(err.error, "invalid_request");
        assert!(
            err.description.contains("other (") && !err.description.contains("team ("),
            "{}",
            err.description
        );
        // By holder id too.
        let other_holder = auth.authenticate(&other).unwrap().holder();
        assert_ne!(other_holder, holder);
        assert_eq!(auth.revoke(&other_holder, "ok").await.unwrap().len(), 1);
        assert!(auth.authenticate(&other).is_none());
        // On disk as one more line each, read back taken.
        let file = std::fs::read_to_string(dir.path().join("credentials.jsonl")).unwrap();
        assert_eq!(file.lines().count(), 4);
        assert!(!file.contains(&key) && !file.contains(&other));
        drop(auth);
        let again = Auth::open(
            dir.path(),
            "http://peer.test",
            Box::new(FakeApprover { proof: "ok".into() }),
        )
        .unwrap();
        assert!(again.authenticate(&key).is_none() && again.authenticate(&other).is_none());
        assert_eq!(again.credentials().len(), 2, "one record per credential, as it stands");
        assert_eq!(again.revoke("team", "ok").await.unwrap_err().error, "invalid_request");
    }

    #[tokio::test]
    async fn a_revocation_the_disk_did_not_take_is_said_closes_at_once_and_is_written_by_the_next() {
        let dir = tempfile::tempdir().unwrap();
        let open = || {
            Auth::open(
                dir.path(),
                "http://peer.test",
                Box::new(FakeApprover { proof: "ok".into() }),
            )
            .unwrap()
        };
        let auth = open();
        let a = start(&auth, Some("team"));
        auth.approve(&a.user_code, "ok", Grant::default(), None).await.unwrap();
        let key = poll(&auth, &a.device_code).unwrap()["access_token"]
            .as_str()
            .unwrap()
            .to_string();
        let before = auth.revocations();
        // The disk refuses the line: the revoke says so, and the key is closed now all the same.
        let file = dir.path().join("credentials.jsonl");
        let writable = auth
            .credentials_file
            .lock()
            .unwrap()
            .replace(std::fs::File::open(&file).unwrap());
        let err = auth.revoke("team", "ok").await.unwrap_err();
        assert_eq!((err.status, err.error), (500, "server_error"));
        assert!(err.description.contains("revoke team again"), "{}", err.description);
        assert!(auth.authenticate(&key).is_none(), "closed at once");
        assert!(auth.revocations() > before, "an open stream looks again");
        // Read back from what the disk holds, it would open again: that is what the 500 said.
        assert!(open().authenticate(&key).is_some());
        // The disk takes lines again: the same revoke writes it, though it is no longer live.
        *auth.credentials_file.lock().unwrap() = writable;
        assert_eq!(auth.revoke("team", "ok").await.unwrap().len(), 1);
        assert!(open().authenticate(&key).is_none(), "taken for good");
        assert_eq!(auth.revoke("team", "ok").await.unwrap_err().error, "invalid_request");
        // The agent's own revoke: by the hash alone.
        let b = start(&auth, Some("own"));
        auth.approve(&b.user_code, "ok", Grant::default(), None).await.unwrap();
        let own = poll(&auth, &b.device_code).unwrap()["access_token"]
            .as_str()
            .unwrap()
            .to_string();
        let taken = auth.revoke_own(&hash_key(&own)).unwrap();
        assert_eq!(taken.name, "own");
        assert!(auth.authenticate(&own).is_none() && open().authenticate(&own).is_none());
        assert!(auth.revoke_own(&hash_key(&own)).is_err());
    }

    #[tokio::test]
    async fn without_the_proof_approve_tells_nothing_of_the_door() {
        let auth = auth().with_scopes(&["deploy"]);
        let a = start(&auth, Some("my-peer"));
        let session = auth
            .start_device(DeviceRequest {
                client_id: Some("best-validate".into()),
                credential_lifetime: Some("session".into()),
                ..Default::default()
            })
            .unwrap();
        let bogus = Grant {
            scopes: Some(vec!["bogus".into()]),
            ..Grant::default()
        };
        let day = Some(Duration::from_secs(24 * 3600));
        for (code, grant, expires) in [
            (a.user_code.as_str(), bogus.clone(), None),
            ("NOPE-CODE", Grant::default(), None),
            ("NOPE-CODE", bogus.clone(), None),
            (session.user_code.as_str(), Grant::default(), day),
            (a.user_code.as_str(), Grant::default(), Some(Duration::ZERO)),
            (a.user_code.as_str(), Grant::default(), Some(Duration::MAX)),
        ] {
            let refused = auth.approve(code, "wrong", grant, expires).await.unwrap_err();
            assert_eq!((refused.status, refused.error), (403, "access_denied"));
            for told in ["deploy", "pending", "session", "28800", "expires_in"] {
                assert!(!refused.description.contains(told), "{}", refused.description);
            }
        }
        let unknown = auth.approve(&a.user_code, "ok", bogus, None).await.unwrap_err();
        assert!(
            unknown.description.contains("no such scope bogus"),
            "{}",
            unknown.description
        );
        let missing = auth
            .approve("NOPE-CODE", "ok", Grant::default(), None)
            .await
            .unwrap_err();
        assert!(
            missing.description.contains("no pending registration"),
            "{}",
            missing.description
        );
        let long = auth
            .approve(&session.user_code, "ok", Grant::default(), day)
            .await
            .unwrap_err();
        assert!(long.description.contains("28800"), "{}", long.description);
    }

    #[tokio::test]
    async fn the_person_bounds_how_long_a_credential_lasts_whatever_the_agent_asked() {
        let auth = auth();
        // A durable credential bounded to a minute.
        let a = start(&auth, Some("short"));
        let admitted = auth
            .approve(&a.user_code, "ok", Grant::default(), Some(Duration::from_secs(60)))
            .await
            .unwrap();
        assert_eq!(admitted.expires_in, Some(60));
        let answer = poll(&auth, &a.device_code).unwrap();
        assert_eq!(answer["expires_in"], 60);
        let ends = OffsetDateTime::parse(answer["expires_at"].as_str().unwrap(), &Rfc3339).unwrap();
        assert!(ends > OffsetDateTime::now_utc() && ends < OffsetDateTime::now_utc() + Duration::from_secs(61));
        assert!(auth.authenticate(answer["access_token"].as_str().unwrap()).is_some());
        // A session credential bounded past its eight hours is refused, nothing cut silently; bounded to an hour, it
        // gets the hour.
        let s = auth
            .start_device(DeviceRequest {
                client_id: Some("best-validate".into()),
                credential_lifetime: Some("session".into()),
                ..Default::default()
            })
            .unwrap();
        let err = auth
            .approve(
                &s.user_code,
                "ok",
                Grant::default(),
                Some(Duration::from_secs(24 * 3600)),
            )
            .await
            .unwrap_err();
        assert!(
            err.description.contains("session") && err.description.contains("28800"),
            "{}",
            err.description
        );
        assert_eq!(poll(&auth, &s.device_code).unwrap_err().error, "authorization_pending");
        let s = auth
            .start_device(DeviceRequest {
                client_id: Some("best-validate".into()),
                credential_lifetime: Some("session".into()),
                ..Default::default()
            })
            .unwrap();
        auth.approve(&s.user_code, "ok", Grant::default(), Some(Duration::from_secs(3600)))
            .await
            .unwrap();
        assert_eq!(poll(&auth, &s.device_code).unwrap()["expires_in"], 3600);
        // Zero is not a bound, nor is more than a year and a day: refused before anything is admitted.
        let z = start(&auth, Some("zero"));
        for bad in [Duration::ZERO, MAX_EXPIRES + Duration::from_secs(1), Duration::MAX] {
            let err = auth
                .approve(&z.user_code, "ok", Grant::default(), Some(bad))
                .await
                .unwrap_err();
            assert!(
                err.description.contains("expires_in") && err.description.contains("31622400"),
                "{}",
                err.description
            );
        }
        let admitted = auth
            .approve(&z.user_code, "ok", Grant::default(), Some(MAX_EXPIRES))
            .await
            .unwrap();
        assert_eq!(admitted.expires_in, Some(MAX_EXPIRES.as_secs()));
        assert_eq!(
            poll(&auth, &z.device_code).unwrap()["expires_in"],
            MAX_EXPIRES.as_secs()
        );
        assert_eq!(lasts(Lifetime::Durable, None), None);
    }

    #[test]
    fn the_device_endpoint_has_a_ceiling_per_client_and_in_all() {
        let auth = auth();
        for _ in 0..MAX_PENDING_PER_CLIENT {
            start(&auth, None);
        }
        let err = auth
            .start_device(DeviceRequest {
                client_id: Some("best-validate".into()),
                ..Default::default()
            })
            .unwrap_err();
        assert_eq!(err.error, "temporarily_unavailable");
        assert_eq!(err.status, 503);
        auth.start_device(DeviceRequest {
            client_id: Some("another".into()),
            ..Default::default()
        })
        .unwrap();
    }

    #[tokio::test]
    async fn the_device_endpoint_has_a_ceiling_per_address_that_loopback_and_approved_ones_do_not_count_against() {
        let auth = auth();
        let from = |client: &str, ip: &str| {
            auth.start_device_from(
                DeviceRequest {
                    client_id: Some(client.into()),
                    ..Default::default()
                },
                Some(ip.parse().unwrap()),
            )
        };
        // Clients naming themselves anew each time, from one address: the ceiling is the address's.
        let mut first = None;
        for i in 0..MAX_PENDING_PER_ADDRESS {
            let a = from(&format!("client-{i}"), "203.0.113.9").unwrap();
            first.get_or_insert(a);
        }
        let err = from("client-new", "203.0.113.9").unwrap_err();
        assert_eq!((err.status, err.error), (503, "temporarily_unavailable"));
        assert!(
            err.description.contains("16 from your address") && err.description.contains("ask again in"),
            "{}",
            err.description
        );
        let wait: u64 = err
            .description
            .split("ask again in ")
            .nth(1)
            .and_then(|r| r.split(' ').next())
            .and_then(|n| n.parse().ok())
            .unwrap();
        assert!(wait > 0 && wait <= DEVICE_CODE_TTL.as_secs() + 1, "{wait}");
        assert!(
            from("client-new", "::ffff:203.0.113.9").is_err(),
            "an IPv4 address mapped into IPv6 is the same address"
        );
        // Another address is another count, and loopback is not counted: a proxy or this machine is everyone's.
        from("client-new", "203.0.113.10").unwrap();
        for i in 0..MAX_PENDING_PER_ADDRESS + 2 {
            from(&format!("local-{i}"), "127.0.0.1").unwrap();
        }
        // One approved is no longer waiting: the address has room again.
        let first = first.unwrap();
        auth.approve(&first.user_code, "ok", Grant::default(), None)
            .await
            .unwrap();
        from("client-after", "203.0.113.9").unwrap();
    }

    #[test]
    fn an_ipv6_client_is_counted_by_its_64_and_an_address_not_named_is_counted_too() {
        let auth = auth();
        let from = |client: &str, ip: &str| {
            auth.start_device_from(
                DeviceRequest {
                    client_id: Some(client.into()),
                    ..Default::default()
                },
                Some(ip.parse().unwrap()),
            )
        };
        // An IPv6 client is counted by its /64, which it holds whole.
        for i in 0..MAX_PENDING_PER_ADDRESS {
            from(&format!("v6-{i}"), &format!("2001:db8:1:2::{:x}", i + 1)).unwrap();
        }
        assert!(from("v6-new", "2001:db8:1:2:ffff::1").is_err(), "the same /64");
        from("v6-new", "2001:db8:1:3::1").unwrap();
        // Registrations whose address the transport did not name are counted together, not let through.
        for i in 0..MAX_PENDING_PER_ADDRESS {
            auth.start_device_from(
                DeviceRequest {
                    client_id: Some(format!("nameless-{i}")),
                    ..Default::default()
                },
                None,
            )
            .unwrap();
        }
        let nameless = auth
            .start_device_from(
                DeviceRequest {
                    client_id: Some("nameless-new".into()),
                    ..Default::default()
                },
                None,
            )
            .unwrap_err();
        assert_eq!(nameless.error, "temporarily_unavailable");
    }

    #[tokio::test]
    async fn credentials_survive_a_restart_as_hashes_only_and_a_torn_line_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let first = Auth::open(
            dir.path(),
            "http://peer.test",
            Box::new(FakeApprover { proof: "ok".into() }),
        )
        .unwrap();
        let a = start(&first, Some("kept"));
        first.approve(&a.user_code, "ok", Grant::default(), None).await.unwrap();
        let key = poll(&first, &a.device_code).unwrap()["access_token"]
            .as_str()
            .unwrap()
            .to_string();
        drop(first);
        let path = dir.path().join("credentials.jsonl");
        let file = std::fs::read_to_string(&path).unwrap();
        assert!(!file.contains(&key), "the key is never written");
        std::fs::write(&path, format!("{file}{{\"name\":\"torn")).unwrap();
        let again = Auth::open(
            dir.path(),
            "http://peer.test",
            Box::new(FakeApprover { proof: "ok".into() }),
        )
        .unwrap();
        assert_eq!(again.authenticate(&key).unwrap().name, "kept");
        assert_eq!(again.credentials().len(), 1);
    }

    #[test]
    fn the_local_approver_keeps_its_token_in_the_data_directory_and_reads_it_back() {
        let dir = tempfile::tempdir().unwrap();
        let a = LocalApprover::open(dir.path()).unwrap();
        let b = LocalApprover::open(dir.path()).unwrap();
        assert_eq!(a.token, b.token);
        assert!(a.token.len() >= 40);
        assert!(a.instructions("ABCD-EFGH").contains("best-peer approve ABCD-EFGH"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join("admin-token"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
