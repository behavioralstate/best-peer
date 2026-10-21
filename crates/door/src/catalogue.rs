//! The catalogue: every command, query and event the door offers, with its schema compiled once, its description an
//! agent can act on, and the handler the peer plugs in. The catalogue is the source of every `dataschema`; a caller's
//! `dataschema` is never fetched (SPEC.md, Ingestion Semantics).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use futures::future::BoxFuture;
use serde_json::{json, Value};

use crate::auth::Credential;
use crate::envelope::Envelope;
use crate::error::BestError;
use crate::log::EventLog;

/// What a command handler gets to tell the world: every event it emits carries the command's correlation id and this
/// door's `source`, so any consumer can match it to the submission.
#[derive(Clone)]
pub struct Emitter {
    log: Arc<EventLog>,
    source: String,
    correlation: String,
    /// The command's own key, the sender and the envelope id: what a handler files its own state under, since the
    /// correlation id is the client's and may be shared across commands.
    key: String,
    /// The event types that complete the command; telling one marks the command finished in the log.
    completes: Arc<HashSet<String>>,
    /// Command type to the event types that complete it, for an emitter that speaks for no command of its own
    /// (a fact the engine told later): it finishes whatever command with its correlation the fact completes.
    completions: Arc<HashMap<String, HashSet<String>>>,
    dataschemas: Arc<HashMap<String, String>>,
}

impl Emitter {
    pub fn new(log: Arc<EventLog>, source: &str, correlation: &str, dataschemas: Arc<HashMap<String, String>>) -> Self {
        Self {
            log,
            source: source.into(),
            correlation: correlation.into(),
            key: String::new(),
            completes: Arc::new(HashSet::new()),
            completions: Arc::new(HashMap::new()),
            dataschemas,
        }
    }

    pub fn with_completions(mut self, completions: Arc<HashMap<String, HashSet<String>>>) -> Self {
        self.completions = completions;
        self
    }

    pub fn with_key(mut self, key: &str) -> Self {
        self.key = key.into();
        self
    }

    pub fn with_completes(mut self, completes: &[String]) -> Self {
        self.completes = Arc::new(completes.iter().cloned().collect());
        self
    }

    pub fn command_key(&self) -> &str {
        &self.key
    }

    /// Appends an event of `r#type` with `data`. A type the catalogue declares gets its `dataschema`; another is
    /// untyped, which the spec allows. A type that completes the command (one of its `completes`, or the door's
    /// own `CommandFailed`) marks the command finished, so a restart does not run it again.
    pub fn emit(&self, r#type: &str, data: Value) -> Envelope {
        let dataschema = self.dataschemas.get(r#type).cloned();
        let event = Envelope::event(&self.source, r#type, data, Some(self.correlation.clone()), dataschema);
        self.log.append(event.clone());
        if !self.key.is_empty() && (r#type == "CommandFailed" || self.completes.contains(r#type)) {
            if let Some((sender, id)) = self.key.split_once(':') {
                self.log.finish_command(sender, id);
            }
        }
        event
    }

    /// Records that this emitter's command made the workload `workload`, so a fact about it told later, by an
    /// emitter that speaks for no command, can complete the command.
    pub fn bind_workload(&self, workload: &str) {
        if let Some((sender, id)) = self.key.split_once(':') {
            self.log.bind_workload(sender, id, workload);
        }
    }

    /// For an emitter that speaks for no command: the fact just told about `workload` completes the command that
    /// made it when that command's type lists the fact's type among its `completes`.
    pub fn completes_workload(&self, workload: &str, r#type: &str) {
        if !self.key.is_empty() {
            return;
        }
        self.log.finish_by_workload(workload, |command_type| {
            self.completions.get(command_type).is_some_and(|c| c.contains(r#type))
        });
    }

    pub fn correlation(&self) -> &str {
        &self.correlation
    }
}

/// A command handler runs after the command is durably recorded; its outcome is events, never a return value
/// (SPEC.md: BEST defines no synchronous command response). A failure is an event too.
pub type CommandHandler = Arc<dyn Fn(Envelope, Emitter) -> BoxFuture<'static, ()> + Send + Sync>;

/// What a command may ask before it is accepted: a check against the door's current state, run after the schema
/// and before the command is recorded, so a command the peer cannot honour now (no device has the memory, the thing
/// it names does not exist) is refused with the reason and the fix instead of being accepted and failed later. A
/// refused command was never accepted: its `id` is free for the corrected retry. The check may reserve what the
/// handler will use, filed under the command's key (the second argument, the same the handler's emitter carries);
/// the handler runs next, or never, if the peer dies in between.
pub type AdmitHook =
    Arc<dyn Fn(Envelope, Credential, String) -> BoxFuture<'static, Result<(), BestError>> + Send + Sync>;

/// A query handler answers now, from current state, with the result body or a refusal, knowing who asks: what
/// a credential may read is the service's to decide (SPEC.md: context derives from the credential).
pub type QueryHandler =
    Arc<dyn Fn(Credential, HashMap<String, String>) -> BoxFuture<'static, Result<Value, BestError>> + Send + Sync>;

pub struct CommandDef {
    /// Kebab-case schema name: the `{schema}` path segment.
    pub schema: String,
    pub version: String,
    /// The envelope `type` to send, PascalCase.
    pub command_type: String,
    pub description: String,
    /// JSON Schema (draft 2020-12) for `data`.
    pub data_schema: Value,
    /// PascalCase event types this command can raise, failures included.
    pub produces: Vec<String>,
    /// The subset of `produces` that completes the command: once one of these is told, nothing more follows for
    /// it and a consumer stops waiting. The others are progress. `CommandFailed` completes any command.
    pub completes: Vec<String>,
    /// The spec's high-impact annotation, when the command deserves one.
    pub impact: Option<Value>,
    /// The state-dependent check, when the command has one.
    pub admit: Option<AdmitHook>,
    pub handler: CommandHandler,
}

pub struct QueryDef {
    pub schema: String,
    pub version: String,
    pub description: String,
    /// JSON Schema for the accepted query-string parameters; none when the query takes none.
    pub parameters: Option<Value>,
    /// JSON Schema for the result body.
    pub response: Value,
    pub handler: QueryHandler,
}

pub struct EventDef {
    pub schema: String,
    pub version: String,
    pub event_type: String,
    pub description: String,
    pub data_schema: Value,
}

struct Compiled {
    def: CommandDef,
    validator: jsonschema::Validator,
}

#[derive(Default)]
pub struct Catalogue {
    commands: Vec<Compiled>,
    queries: Vec<QueryDef>,
    /// The compiled `parameters` schema of each query that declares one, by schema name.
    query_parameters: HashMap<String, jsonschema::Validator>,
    events: Vec<EventDef>,
}

impl Catalogue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a command. Its data schema is compiled here, once; a schema that is not valid JSON Schema is a
    /// programming error and is refused at startup, not at the first command.
    pub fn command(mut self, def: CommandDef) -> Self {
        let validator = jsonschema::validator_for(&def.data_schema)
            .unwrap_or_else(|e| panic!("command {}/{}: data schema is not valid: {e}", def.schema, def.version));
        if let Some(stray) = def.completes.iter().find(|c| !def.produces.contains(c)) {
            panic!(
                "command {}/{}: {stray} completes it but is not among what it produces",
                def.schema, def.version
            );
        }
        self.commands.push(Compiled { def, validator });
        self
    }

    /// Adds a query. Its `parameters` schema, when it has one, is compiled here, once.
    pub fn query(mut self, def: QueryDef) -> Self {
        if let Some(p) = &def.parameters {
            let validator = jsonschema::validator_for(p).unwrap_or_else(|e| {
                panic!(
                    "query {}/{}: parameters schema is not valid: {e}",
                    def.schema, def.version
                )
            });
            self.query_parameters.insert(def.schema.clone(), validator);
        }
        self.queries.push(def);
        self
    }

    /// Validates a query's string parameters against its declared `parameters` schema; a query that declares none
    /// takes whatever it is given. Every violation is reported with the parameter it concerns.
    pub fn validate_params(&self, schema: &str, params: &HashMap<String, String>) -> Result<(), BestError> {
        let Some(validator) = self.query_parameters.get(schema) else {
            return Ok(());
        };
        let instance = Value::Object(
            params
                .iter()
                .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                .collect(),
        );
        let errors: Vec<Value> = validator
            .iter_errors(&instance)
            .map(|e| {
                let path = e.instance_path().to_string();
                let parameter = path.trim_start_matches('/').to_string();
                json!({ "parameter": if parameter.is_empty() { schema.to_string() } else { parameter }, "message": e.to_string() })
            })
            .collect();
        if errors.is_empty() {
            return Ok(());
        }
        Err(BestError::bad_request(
            "INVALID_PARAMETER",
            format!(
                "{}: {}. Read the parameters at GET /queries/{schema}/<version> and send what they ask.",
                errors[0]["parameter"].as_str().unwrap_or(schema),
                errors[0]["message"].as_str().unwrap_or("")
            ),
        )
        .with_details(json!({ "errors": errors })))
    }

    pub fn event(mut self, def: EventDef) -> Self {
        self.events.push(def);
        self
    }

    pub fn command_by_type(&self, r#type: &str) -> Option<&CommandDef> {
        self.commands
            .iter()
            .find(|c| c.def.command_type == r#type)
            .map(|c| &c.def)
    }

    pub fn command_by_schema(&self, schema: &str, version: &str) -> Option<&CommandDef> {
        self.commands
            .iter()
            .find(|c| c.def.schema == schema && c.def.version == version)
            .map(|c| &c.def)
    }

    pub fn query_by_schema(&self, schema: &str) -> Option<&QueryDef> {
        self.queries.iter().find(|q| q.schema == schema)
    }

    pub fn event_by_schema(&self, schema: &str, version: &str) -> Option<&EventDef> {
        self.events.iter().find(|e| e.schema == schema && e.version == version)
    }

    /// Command type to the event types that complete it.
    pub fn completions(&self) -> HashMap<String, HashSet<String>> {
        self.commands
            .iter()
            .map(|c| (c.def.command_type.clone(), c.def.completes.iter().cloned().collect()))
            .collect()
    }

    pub fn command_types(&self) -> Vec<&str> {
        self.commands.iter().map(|c| c.def.command_type.as_str()).collect()
    }

    pub fn has_commands(&self) -> bool {
        !self.commands.is_empty()
    }

    pub fn has_queries(&self) -> bool {
        !self.queries.is_empty()
    }

    /// Validates a command's `data` against the catalogue's schema for its type. Every violation is reported, with
    /// its path, so a caller fixes them all at once.
    /// The command `envelope` as the door records it: its data without the fields its schema marks `writeOnly`, a
    /// secret its admission has taken and kept where it belongs, which no log, replay or handler ever sees again.
    pub fn as_recorded(&self, envelope: &Envelope) -> Envelope {
        let Some(c) = self.commands.iter().find(|c| c.def.command_type == envelope.r#type) else {
            return envelope.clone();
        };
        let mut recorded = envelope.clone();
        if let (Some(fields), Some(data)) = (
            c.def.data_schema["properties"].as_object(),
            recorded.data.as_object_mut(),
        ) {
            for (name, schema) in fields {
                if schema["writeOnly"] == true {
                    data.remove(name);
                }
            }
        }
        recorded
    }

    /// Whether commands of `type` may carry a field the door never records: one whose stored copy is then not the
    /// command that was sent, and cannot be run again after a restart.
    pub fn carries_write_only(&self, r#type: &str) -> bool {
        self.commands
            .iter()
            .find(|c| c.def.command_type == r#type)
            .and_then(|c| c.def.data_schema["properties"].as_object())
            .is_some_and(|fields| fields.values().any(|f| f["writeOnly"] == true))
    }

    pub fn validate_data(&self, r#type: &str, data: &Value) -> Result<(), BestError> {
        let c = self
            .commands
            .iter()
            .find(|c| c.def.command_type == r#type)
            .expect("looked up by caller");
        let errors: Vec<Value> = c
            .validator
            .iter_errors(data)
            .map(|e| {
                let path = e.instance_path().to_string();
                json!({ "path": if path.is_empty() { "data".to_string() } else { format!("data{path}") }, "message": e.to_string() })
            })
            .collect();
        if errors.is_empty() {
            return Ok(());
        }
        let first = errors[0]["path"].as_str().unwrap_or("data").to_string();
        Err(BestError::bad_request(
            "SCHEMA_VALIDATION",
            format!(
                "{first}: {}. Read the schema at the catalogue's dataschema for {} and send what it asks.",
                errors[0]["message"].as_str().unwrap_or(""),
                c.def.schema
            ),
        )
        .with_details(json!({ "errors": errors })))
    }

    /// Event type → absolute dataschema URI, for the emitter.
    pub fn event_dataschemas(&self, endpoint: &str) -> HashMap<String, String> {
        self.events
            .iter()
            .map(|e| {
                (
                    e.event_type.clone(),
                    format!("{endpoint}/events/{}/{}", e.schema, e.version),
                )
            })
            .collect()
    }

    /// `GET /commands`
    pub fn command_catalogue(&self, endpoint: &str) -> Value {
        let commands: Vec<Value> = self
            .commands
            .iter()
            .map(|c| {
                let d = &c.def;
                let mut entry = json!({
                    "schema": d.schema,
                    "version": d.version,
                    "commandType": d.command_type,
                    "dataschema": format!("{endpoint}/commands/{}/{}", d.schema, d.version),
                    "description": d.description,
                });
                if let Some(impact) = &d.impact {
                    entry["impact"] = impact.clone();
                }
                entry
            })
            .collect();
        json!({ "commands": commands })
    }

    /// `GET /commands/{schema}/{version}`: the data schema with the spec's top-level members beside it.
    pub fn command_document(&self, endpoint: &str, def: &CommandDef) -> Value {
        let mut doc = def.data_schema.clone();
        let o = doc.as_object_mut().expect("a schema is an object");
        o.insert("$schema".into(), json!("https://json-schema.org/draft/2020-12/schema"));
        o.insert(
            "$id".into(),
            json!(format!("{endpoint}/commands/{}/{}", def.schema, def.version)),
        );
        o.entry("title").or_insert(json!(def.command_type));
        o.entry("description").or_insert(json!(def.description));
        o.insert("commandType".into(), json!(def.command_type));
        if !def.produces.is_empty() {
            o.insert("produces".into(), json!(def.produces));
        }
        if !def.completes.is_empty() {
            o.insert("completes".into(), json!(def.completes));
        }
        if let Some(impact) = &def.impact {
            o.insert("impact".into(), impact.clone());
        }
        doc
    }

    /// `GET /queries`
    pub fn query_catalogue(&self, endpoint: &str) -> Value {
        let queries: Vec<Value> = self
            .queries
            .iter()
            .map(|q| {
                json!({
                    "schema": q.schema,
                    "version": q.version,
                    "dataschema": format!("{endpoint}/queries/{}/{}", q.schema, q.version),
                    "description": q.description,
                })
            })
            .collect();
        json!({ "queries": queries })
    }

    /// `GET /queries/{schema}/{version}`
    pub fn query_document(&self, def: &QueryDef) -> Value {
        let mut doc = json!({ "description": def.description, "response": def.response });
        if let Some(p) = &def.parameters {
            doc["parameters"] = p.clone();
        }
        doc
    }

    /// The catalogue entries `GET /events` may carry beside the log.
    pub fn event_catalogue(&self, endpoint: &str) -> Vec<Value> {
        self.events
            .iter()
            .map(|e| {
                json!({
                    "schema": e.schema,
                    "version": e.version,
                    "dataschema": format!("{endpoint}/events/{}/{}", e.schema, e.version),
                    "description": e.description,
                })
            })
            .collect()
    }

    pub fn event_document(&self, endpoint: &str, def: &EventDef) -> Value {
        let mut doc = def.data_schema.clone();
        let o = doc.as_object_mut().expect("a schema is an object");
        o.insert("$schema".into(), json!("https://json-schema.org/draft/2020-12/schema"));
        o.insert(
            "$id".into(),
            json!(format!("{endpoint}/events/{}/{}", def.schema, def.version)),
        );
        o.entry("title").or_insert(json!(def.event_type));
        o.entry("description").or_insert(json!(def.description));
        doc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noop() -> CommandHandler {
        Arc::new(|_, _| Box::pin(async {}))
    }

    fn pull_image() -> CommandDef {
        CommandDef {
            schema: "pull-image".into(),
            version: "1.0".into(),
            command_type: "PullImage".into(),
            description: "Makes an image present on the peer.".into(),
            data_schema: json!({
                "type": "object",
                "required": ["image"],
                "properties": { "image": { "type": "string", "minLength": 1 } },
                "additionalProperties": false
            }),
            produces: vec!["ImagePulled".into(), "ImagePullFailed".into()],
            completes: vec!["ImagePulled".into(), "ImagePullFailed".into()],
            impact: None,
            admit: None,
            handler: noop(),
        }
    }

    #[test]
    fn a_field_marked_write_only_is_not_recorded() {
        let mut def = pull_image();
        def.command_type = "SetStore".into();
        def.data_schema = json!({
            "type": "object",
            "properties": { "bucket": { "type": "string" }, "secret": { "type": "string", "writeOnly": true } }
        });
        let c = Catalogue::new().command(def);
        let sent = Envelope::event(
            "s",
            "SetStore",
            json!({ "bucket": "b", "secret": "s3cr3t" }),
            None,
            None,
        );
        let recorded = c.as_recorded(&sent);
        assert_eq!(recorded.data, json!({ "bucket": "b" }));
        assert_eq!((recorded.id, recorded.r#type), (sent.id, sent.r#type));
        // A command with no such field is recorded as it came.
        let other = Envelope::event("s", "PullImage", json!({ "image": "x" }), None, None);
        assert_eq!(c.as_recorded(&other).data, other.data);
        assert!(c.carries_write_only("SetStore"));
        assert!(!c.carries_write_only("PullImage") && !c.carries_write_only("Unknown"));
    }

    #[test]
    fn validation_reports_every_violation_with_its_path_and_says_where_the_schema_is() {
        let c = Catalogue::new().command(pull_image());
        c.validate_data("PullImage", &json!({"image": "ollama/ollama:0.6"}))
            .unwrap();
        let err = c
            .validate_data("PullImage", &json!({"imag": "x", "image": ""}))
            .unwrap_err();
        assert_eq!(err.code, "SCHEMA_VALIDATION");
        let errors = err.details["errors"].as_array().unwrap();
        assert_eq!(errors.len(), 2, "{errors:?}");
        assert!(errors.iter().any(|e| e["path"] == "data/image"), "{errors:?}");
        assert!(err.message.contains("pull-image"), "{}", err.message);
    }

    #[test]
    fn the_catalogue_entry_and_the_schema_document_carry_the_same_members() {
        let c = Catalogue::new().command(pull_image());
        let cat = c.command_catalogue("http://peer.test");
        let entry = &cat["commands"][0];
        assert_eq!(entry["dataschema"], "http://peer.test/commands/pull-image/1.0");
        assert_eq!(entry["commandType"], "PullImage");
        let doc = c.command_document("http://peer.test", c.command_by_schema("pull-image", "1.0").unwrap());
        assert_eq!(doc["commandType"], "PullImage");
        assert_eq!(doc["$id"], entry["dataschema"]);
        assert_eq!(doc["produces"][1], "ImagePullFailed");
        assert_eq!(doc["completes"], json!(["ImagePulled", "ImagePullFailed"]));
        assert_eq!(doc["required"][0], "image");
    }

    #[test]
    #[should_panic(expected = "completes it but is not among what it produces")]
    fn a_completion_the_command_does_not_produce_is_refused_at_startup() {
        let mut d = pull_image();
        d.completes = vec!["Elsewhere".into()];
        let _ = Catalogue::new().command(d);
    }

    #[test]
    #[should_panic(expected = "data schema is not valid")]
    fn an_invalid_schema_is_refused_at_startup() {
        let mut d = pull_image();
        d.data_schema = json!({ "type": 12 });
        let _ = Catalogue::new().command(d);
    }
}
