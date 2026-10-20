//! A holder's right to forget (behavioralstate/spec#68): `forget` removes the content of the holder's prompts, the
//! messages it sent and the answers and engines' words it got, and keeps every event's envelope, so the fold, who
//! owns which correlation, and what a prompt used are unchanged. What it names is one correlation, a deployment's
//! prompts, or the holder's answers told before a time (with a prompt's messages when every answer under its
//! correlation came before it); nothing else is touched, and nothing of another
//! holder's: a correlation the sender does not own is refused as a read of it is.

use best_peer_door::auth::Credential;
use std::collections::{BTreeMap, HashMap};

use best_peer_door::{BestError, Emitter, Envelope, EventLog, Redacted, Stored};
use serde::Deserialize;
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// The events whose data carries what a prompt said or got: what `forget` strips.
const CONTENT_EVENTS: &[&str] = &["PromptAnswered", "PromptFailed"];

/// What is taken out of a forgotten event's or command's data; everything else stays.
const CONTENT_FIELDS: &[&str] = &["messages", "content", "reason", "stop"];

#[derive(Deserialize)]
struct ForgetData {
    #[serde(default)]
    correlation: Option<String>,
    #[serde(default)]
    deployment: Option<String>,
    #[serde(default)]
    before: Option<String>,
}

/// What a `forget` names.
#[derive(Clone, Debug)]
pub enum Scope {
    Correlation(String),
    Deployment(String),
    Before(OffsetDateTime),
}

impl Scope {
    fn holds(&self, correlation: Option<&str>, data: &Value, time: &str) -> bool {
        match self {
            Scope::Correlation(c) => correlation == Some(c.as_str()),
            Scope::Deployment(d) => data["deployment"].as_str() == Some(d.as_str()),
            Scope::Before(t) => OffsetDateTime::parse(time, &Rfc3339).is_ok_and(|told| told < *t),
        }
    }

    fn named(&self) -> Value {
        match self {
            Scope::Correlation(c) => json!({ "correlation": c }),
            Scope::Deployment(d) => json!({ "deployment": d }),
            Scope::Before(t) => json!({ "before": t.format(&Rfc3339).unwrap_or_default() }),
        }
    }
}

/// Reads what a `forget` names, refusing one that names nothing, more than one thing, or a correlation the sender
/// does not own.
pub fn admit(log: &EventLog, cmd: &Envelope, who: &Credential) -> Result<Scope, BestError> {
    let scope = scope_of(cmd)?;
    if let Scope::Correlation(c) = &scope {
        if log.owner_of_correlation(c).as_deref() != Some(who.hash.as_str()) {
            return Err(BestError::bad_request(
                "NO_SUCH_CORRELATION",
                format!("no command of yours used correlation {c}: a credential forgets what it was told under its own correlations, as it reads them"),
            )
            .with_details(json!({ "correlation": c })));
        }
    }
    Ok(scope)
}

/// What a `forget` names, read from its data.
pub fn scope_of(cmd: &Envelope) -> Result<Scope, BestError> {
    let data: ForgetData = crate::lifecycle::parse(&cmd.data)?;
    let scope = match (data.correlation, data.deployment, data.before) {
        (Some(c), None, None) => Scope::Correlation(c),
        (None, Some(d), None) => Scope::Deployment(d),
        (None, None, Some(b)) => Scope::Before(OffsetDateTime::parse(&b, &Rfc3339).map_err(|_| {
            BestError::bad_request(
                "INVALID_TIME",
                format!("before {b:?} is not a time: send it as RFC 3339, such as 2026-10-20T00:00:00Z"),
            )
            .with_details(json!({ "field": "before" }))
        })?),
        _ => {
            return Err(BestError::bad_request(
                "FORGET_NAMES_ONE",
                "name one of correlation (one command's prompts), deployment (every prompt of yours to it) or before (the answers told before that time, and a prompt's messages when every answer under its correlation came before it)",
            )
            .with_details(json!({ "fields": ["correlation", "deployment", "before"] })))
        }
    };
    Ok(scope)
}

/// The sender of the command an emitter speaks for: the hash its key starts with.
pub fn sender_of(em: &Emitter) -> String {
    em.command_key()
        .split_once(':')
        .map(|(s, _)| s.to_string())
        .unwrap_or_default()
}

/// What a `forget` found in one log: the events and commands of the scope, as they are now (without content), and
/// how many of the sender's prompts in the scope were still in flight, which keep their content until they end.
pub struct Forgot {
    pub events: Vec<Stored>,
    pub commands: Vec<Redacted>,
    pub in_flight: usize,
    /// For a time: the correlations some of whose outcomes came after it, whose prompts keep their messages.
    pub held_back: Vec<String>,
}

/// Removes, from `log`, the content of `sender`'s prompts that `scope` names: the answers and failures told under
/// its correlations, and the prompts whose answer or failure that was. What is already forgotten is taken again,
/// so a forget that failed partway, on disk or at a member, is done by the next. A prompt is judged by the log's
/// own time on its outcome, never the time its sender wrote on it.
pub fn forget(log: &EventLog, sender: &str, scope: &Scope) -> Result<Forgot, String> {
    let events = log.redact(
        |s: &Stored| {
            let e = &s.envelope;
            CONTENT_EVENTS.contains(&e.r#type.as_str())
                && scope.holds(e.correlationid.as_deref(), &e.data, &e.time)
                && log.visible_to(Some(sender), s)
        },
        strip,
    )?;
    // One credential may send several prompts under one correlation: a prompt is taken by its own deployment, or,
    // for a time, only when every outcome under its correlation was told before it, so nothing not named is lost.
    let mut picked: HashMap<String, usize> = HashMap::new();
    for s in &events {
        if let Some(c) = &s.envelope.correlationid {
            *picked.entry(c.clone()).or_default() += 1;
        }
    }
    let mut told: HashMap<String, usize> = HashMap::new();
    log.replay(|e| {
        if let Some(c) = e.correlationid.as_ref().filter(|c| picked.contains_key(*c)) {
            if CONTENT_EVENTS.contains(&e.r#type.as_str()) {
                *told.entry(c.clone()).or_default() += 1;
            }
        }
    });
    let commands = log.redact_commands(
        |who, correlation, e| {
            who == sender
                && e.r#type == "Prompt"
                && match scope {
                    Scope::Correlation(c) => correlation == c,
                    Scope::Deployment(d) => {
                        picked.contains_key(correlation) && e.data["deployment"].as_str() == Some(d.as_str())
                    }
                    Scope::Before(_) => picked
                        .get(correlation)
                        .is_some_and(|n| told.get(correlation) == Some(n)),
                }
        },
        strip,
    )?;
    let in_flight = log
        .unfinished()
        .iter()
        .filter(|u| u.sender == sender && u.envelope.r#type == "Prompt")
        .filter(|u| {
            let e = &u.envelope;
            let correlation = e.correlationid.as_deref().unwrap_or(&e.id);
            scope.holds(Some(correlation), &e.data, &e.time)
        })
        .count();
    // Only a time holds a prompt back: a deployment leaves a sibling under the same correlation because it was not
    // named, which forgetting by correlation would take unasked.
    let mut held_back: Vec<String> = match scope {
        Scope::Before(_) => picked
            .iter()
            .filter(|(c, n)| told.get(*c).is_some_and(|t| t > *n))
            .map(|(c, _)| c.clone())
            .collect(),
        Scope::Correlation(_) | Scope::Deployment(_) => Vec::new(),
    };
    held_back.sort();
    Ok(Forgot {
        events,
        commands,
        in_flight,
        held_back,
    })
}

/// The member peer that answered each forgotten prompt on a workspace, as its outcome names it, by `(cloud, peer)`,
/// with the prompts' command ids and data.
pub fn answered_on(forgot: &Forgot) -> BTreeMap<(String, String), Vec<&Redacted>> {
    let mut on: BTreeMap<(String, String), Vec<&Redacted>> = BTreeMap::new();
    for prompt in &forgot.commands {
        // Its own outcome: under its correlation, from the deployment it asked, which one member holds.
        let outcome = forgot.events.iter().find(|s| {
            s.envelope.correlationid.as_deref() == Some(prompt.correlation.as_str())
                && s.envelope.data["deployment"] == prompt.data["deployment"]
        });
        let Some(d) = outcome.map(|s| &s.envelope.data) else {
            continue;
        };
        if let (Some(cloud), Some(peer)) = (d["cloud"].as_str(), d["peer"].as_str()) {
            on.entry((cloud.to_string(), peer.to_string()))
                .or_default()
                .push(prompt);
        }
    }
    on
}

/// Takes a forgotten event's or command's data down to what stays, and marks it forgotten.
fn strip(data: &mut Value) {
    if let Some(o) = data.as_object_mut() {
        for field in CONTENT_FIELDS {
            o.remove(*field);
        }
        o.insert("forgotten".into(), json!(true));
    }
}

/// Tells `Forgotten` for `scope`: what was removed, what stays, and on a workspace the member peers asked to forget
/// their copies.
pub fn tell_forgotten(em: &Emitter, scope: &Scope, forgot: &Forgot, peers: Option<Value>) -> Envelope {
    let mut data = json!({
        "scope": scope.named(),
        "events": forgot.events.len(),
        "commands": forgot.commands.len(),
        "in_flight": forgot.in_flight,
        "removed": "the messages of your prompts, the answers' content, and what an engine said when a prompt failed; a prompt still in flight keeps its content until it ends, and a forget sent then removes it",
        "kept": "every event and command as an envelope (its id, type, time and correlation) with its deployment, model, token counts, holder, cloud and peer: that a prompt happened and what it used",
    });
    if !forgot.held_back.is_empty() {
        data["held_back"] = json!(forgot.held_back);
    }
    if let Some(p) = peers {
        data["peers"] = p;
    }
    em.emit("Forgotten", data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prompt(id: &str, deployment: &str, time: &str) -> Envelope {
        let mut e = Envelope::event(
            "io.best.agents",
            "Prompt",
            json!({ "deployment": deployment, "messages": [{ "role": "user", "content": "secret" }] }),
            Some(id.into()),
            None,
        );
        e.id = id.into();
        e.time = time.into();
        e
    }

    fn answer(correlation: &str, deployment: &str, time: &str) -> Envelope {
        let mut e = Envelope::event(
            "io.best.agents",
            "PromptAnswered",
            json!({ "deployment": deployment, "model": "m", "content": "secret answer" }),
            Some(correlation.into()),
            None,
        );
        e.time = time.into();
        e
    }

    #[test]
    fn a_prompt_in_flight_is_counted_and_kept_and_before_reads_the_logs_time_not_the_senders() {
        let log = EventLog::ephemeral();
        // p1 was answered at 10:00, though its sender's clock wrote 11:00 on it; p2 is still in flight.
        log.accept_command("alice", "p1", "h", "p1", &prompt("p1", "dep-1", "2026-10-20T11:00:00Z"));
        log.append(answer("p1", "dep-1", "2026-10-20T10:00:00Z"));
        log.finish_command("alice", "p1");
        log.accept_command("alice", "p2", "h", "p2", &prompt("p2", "dep-1", "2026-10-20T10:01:00Z"));
        let before = OffsetDateTime::parse("2026-10-20T10:30:00Z", &Rfc3339).unwrap();
        let forgot = forget(&log, "alice", &Scope::Before(before)).unwrap();
        assert_eq!(forgot.events.len(), 1);
        assert_eq!(forgot.in_flight, 1, "p2 has no answer yet");
        let (page, _) = log.list(&best_peer_door::Filter::default());
        assert!(page[0].data.get("content").is_none());
        let still = log.unfinished();
        assert_eq!(still.len(), 1);
        assert_eq!(
            still[0].envelope.data["messages"][0]["content"], "secret",
            "a prompt in flight is left alone"
        );
        // Another sender's forget takes nothing of alice's.
        let none = forget(&log, "bob", &Scope::Deployment("dep-1".into())).unwrap();
        assert!(none.events.is_empty() && none.commands.is_empty());
    }

    #[test]
    fn a_scope_holds_its_correlation_its_deployment_or_what_was_told_before_its_time() {
        let data = json!({ "deployment": "dep-1" });
        assert!(Scope::Correlation("c1".into()).holds(Some("c1"), &data, ""));
        assert!(!Scope::Correlation("c1".into()).holds(Some("c2"), &data, ""));
        assert!(Scope::Deployment("dep-1".into()).holds(None, &data, ""));
        assert!(!Scope::Deployment("dep-2".into()).holds(None, &data, ""));
        let t = OffsetDateTime::parse("2026-10-20T00:00:00Z", &Rfc3339).unwrap();
        assert!(Scope::Before(t).holds(None, &data, "2026-10-19T23:59:59Z"));
        assert!(!Scope::Before(t).holds(None, &data, "2026-10-20T00:00:00Z"));
        assert!(!Scope::Before(t).holds(None, &data, "not a time"));
        let mut d = json!({ "deployment": "dep-1", "content": "x", "messages": [], "reason": "y", "prompt_tokens": 4 });
        strip(&mut d);
        assert_eq!(
            d,
            json!({ "deployment": "dep-1", "prompt_tokens": 4, "forgotten": true })
        );
    }
}
