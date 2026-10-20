//! A holder's right to forget (behavioralstate/spec#68): `forget` removes the content of the holder's prompts, the
//! messages it sent and the answers and engines' words it got, and keeps every event's envelope, so the fold, who
//! owns which correlation, and what a prompt used are unchanged. What it names is one correlation, a deployment's
//! prompts, or everything of the holder's told before a time; nothing else is touched, and nothing of another
//! holder's: a correlation the sender does not own is refused as a read of it is.

use best_peer_door::auth::Credential;
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
                "name one of correlation (one command's prompts), deployment (every prompt of yours to it) or before (every prompt of yours told before that time)",
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

/// What a `forget` removed from one log: how many events and commands, and the commands as they are now.
pub struct Forgot {
    pub events: usize,
    pub commands: Vec<Redacted>,
}

/// Removes, from `log`, the content of `sender`'s prompts that `scope` names: the answers and failures told under
/// its correlations, and the prompts it sent.
pub fn forget(log: &EventLog, sender: &str, scope: &Scope) -> Result<Forgot, String> {
    let events = log.redact(
        |s: &Stored| {
            let e = &s.envelope;
            CONTENT_EVENTS.contains(&e.r#type.as_str())
                && e.data["forgotten"] != true
                && scope.holds(e.correlationid.as_deref(), &e.data, &e.time)
                && log.visible_to(Some(sender), s)
        },
        strip,
    )?;
    let commands = log.redact_commands(
        |who, correlation, e| {
            who == sender
                && e.r#type == "Prompt"
                && e.data["forgotten"] != true
                && scope.holds(Some(correlation), &e.data, &e.time)
        },
        strip,
    )?;
    Ok(Forgot {
        events: events.len(),
        commands,
    })
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
        "events": forgot.events,
        "commands": forgot.commands.len(),
        "removed": "the messages of your prompts, the answers' content, and what an engine said when a prompt failed",
        "kept": "every event and command as an envelope (its id, type, time and correlation) with its deployment, model, token counts, holder, cloud and peer: that a prompt happened and what it used",
    });
    if let Some(p) = peers {
        data["peers"] = p;
    }
    em.emit("Forgotten", data)
}

#[cfg(test)]
mod tests {
    use super::*;

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
