//! The event log: every fact the door has told, in order, kept on disk and streamed live. `GET /events` reads it,
//! `GET /events/stream` follows it, and a reconnecting client replays from `Last-Event-ID`. The log also keeps the
//! commands it accepted, per sender, so an envelope `id` is an idempotency key across restarts.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::broadcast;

use crate::envelope::Envelope;

/// An event with its position in the log; the position is the stream's order and the pagination cursor.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Stored {
    pub seq: u64,
    pub envelope: Envelope,
}

/// What `GET /events` and the stream filter on (SPEC.md, Query Parameters).
#[derive(Clone, Debug, Default)]
pub struct Filter {
    pub r#type: Option<String>,
    pub correlation_id: Option<String>,
    pub source: Option<String>,
    pub from: Option<OffsetDateTime>,
    pub to: Option<OffsetDateTime>,
    pub limit: Option<usize>,
    /// The cursor from a previous page: the `seq` after which to read.
    pub after: Option<u64>,
}

/// The most events one page carries; a larger `limit` is refused, never clamped.
pub const MAX_PAGE: usize = 200;

impl Filter {
    pub fn matches(&self, s: &Stored) -> bool {
        let e = &s.envelope;
        if self.r#type.as_ref().is_some_and(|t| &e.r#type != t) {
            return false;
        }
        if self
            .correlation_id
            .as_ref()
            .is_some_and(|c| e.correlationid.as_ref() != Some(c))
        {
            return false;
        }
        if self.source.as_ref().is_some_and(|src| &e.source != src) {
            return false;
        }
        if self.from.is_some() || self.to.is_some() {
            let Ok(t) = OffsetDateTime::parse(&e.time, &Rfc3339) else {
                return false;
            };
            if self.from.is_some_and(|f| t < f) || self.to.is_some_and(|to| t > to) {
                return false;
            }
        }
        true
    }
}

/// The verdict on a command's `id` from one sender (SPEC.md, Ingestion Semantics: duplicates are ignored, a reused
/// id with a different payload is a conflict). A duplicate carries the correlation the original was given, so the
/// answer to a retry points at the same events.
#[derive(Debug, PartialEq, Eq)]
pub enum Accept {
    New,
    Duplicate { correlation: String },
    Conflict,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AcceptedLine {
    sender: String,
    id: String,
    hash: String,
    correlation: String,
    /// The command itself, so one the peer died before running can be run after the restart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    envelope: Option<Envelope>,
    /// Told by a line with the same sender and id once a completing event was emitted.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    finished: bool,
    /// The workload the command made (a deployment or job id), told by a later line, so a fact about the workload
    /// that completes the command finds it without the correlation id, which clients may share.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    workload: Option<String>,
    /// The order of acceptance: the file's order, never the client's clock.
    #[serde(skip)]
    order: u64,
}

/// An accepted command the door has not seen through to a completing event.
#[derive(Clone, Debug)]
pub struct Unfinished {
    pub sender: String,
    pub envelope: Envelope,
}

pub struct EventLog {
    events: Mutex<Vec<Stored>>,
    accepted: Mutex<HashMap<(String, String), AcceptedLine>>,
    /// Who owns each correlation id: the sender whose accepted command first carried it, with that command's order.
    owners: Mutex<HashMap<String, (u64, String)>>,
    /// How many commands were ever accepted: the next one's order.
    accepted_count: Mutex<u64>,
    events_file: Mutex<Option<File>>,
    accepted_file: Mutex<Option<File>>,
    tx: broadcast::Sender<Stored>,
}

impl EventLog {
    /// An in-memory log that forgets everything on restart; for tests and for a peer run without a data directory.
    pub fn ephemeral() -> Self {
        let (tx, _) = broadcast::channel(1024);
        Self {
            events: Mutex::new(Vec::new()),
            accepted: Mutex::new(HashMap::new()),
            owners: Mutex::new(HashMap::new()),
            accepted_count: Mutex::new(0),
            events_file: Mutex::new(None),
            accepted_file: Mutex::new(None),
            tx,
        }
    }

    /// A log kept in `dir` (`events.jsonl`, `accepted.jsonl`), loaded now and appended to from here on. A line that
    /// cannot be read (a torn write) is skipped and logged, never fatal.
    pub fn open(dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let log = Self::ephemeral();
        let events_path = dir.join("events.jsonl");
        let accepted_path = dir.join("accepted.jsonl");
        for line in read_lines(&events_path)? {
            match serde_json::from_str::<Stored>(&line) {
                Ok(s) => log.events.lock().unwrap().push(s),
                Err(e) => tracing::warn!(error = %e, "an event line could not be read and is skipped"),
            }
        }
        for line in read_lines(&accepted_path)? {
            match serde_json::from_str::<AcceptedLine>(&line) {
                Ok(mut a) => {
                    let mut accepted = log.accepted.lock().unwrap();
                    match accepted.get_mut(&(a.sender.clone(), a.id.clone())) {
                        // A later line for a known command only ever says it finished, or what it made.
                        Some(known) => {
                            known.finished |= a.finished;
                            if known.finished {
                                known.envelope = None;
                            }
                            if a.workload.is_some() {
                                known.workload = a.workload;
                            }
                        }
                        None => {
                            let mut count = log.accepted_count.lock().unwrap();
                            a.order = *count;
                            *count += 1;
                            log.own(&a);
                            accepted.insert((a.sender.clone(), a.id.clone()), a);
                        }
                    }
                }
                Err(e) => tracing::warn!(error = %e, "an accepted-command line could not be read and is skipped"),
            }
        }
        // A correlation two senders used before it belonged to one: the first keeps it, the other reads none of
        // its facts under it. The facts stay as told; the operator is told where.
        {
            let accepted = log.accepted.lock().unwrap();
            let owners = log.owners.lock().unwrap();
            for a in accepted.values() {
                if owners.get(&a.correlation).is_some_and(|(_, owner)| *owner != a.sender) {
                    tracing::warn!(correlation = %a.correlation, command = %a.id, "a correlation id another credential used first was also used by this command's sender, who reads nothing under it now");
                }
            }
        }
        *log.events_file.lock().unwrap() = Some(append_to(&events_path)?);
        *log.accepted_file.lock().unwrap() = Some(append_to(&accepted_path)?);
        Ok(log)
    }

    /// Appends an event and tells every subscriber, in the order of the log. The write to disk happens before anyone
    /// hears of it; a disk error is logged and the event still reaches subscribers, since a fact told cannot be
    /// untold.
    pub fn append(&self, envelope: Envelope) -> Stored {
        let mut events = self.events.lock().unwrap();
        let seq = events.last().map(|s| s.seq + 1).unwrap_or(1);
        let stored = Stored { seq, envelope };
        write_line(&self.events_file, &stored, "event");
        events.push(stored.clone());
        let _ = self.tx.send(stored.clone());
        drop(events);
        stored
    }

    /// What the log already knows of `sender`'s command `id` with payload hash `hash`: a duplicate, a conflict, or
    /// nothing. Nothing is recorded; a command is recorded by [`EventLog::accept_command`] once admitted.
    pub fn known_command(&self, sender: &str, id: &str, hash: &str) -> Option<Accept> {
        let accepted = self.accepted.lock().unwrap();
        match accepted.get(&(sender.to_string(), id.to_string())) {
            Some(a) if a.hash == hash => Some(Accept::Duplicate {
                correlation: a.correlation.clone(),
            }),
            Some(_) => Some(Accept::Conflict),
            None => None,
        }
    }

    /// Every event the log holds, oldest first, for a peer rebuilding its state from the facts it told.
    pub fn replay(&self, mut f: impl FnMut(&Envelope)) {
        let events = self.events.lock().unwrap();
        for s in events.iter() {
            f(&s.envelope);
        }
    }

    /// Records that `sender` sent a command with `id`, payload hash `hash` and correlation `correlation`, or says
    /// why it is not new. One sender's ids are theirs alone: another sender's identical id is a different command.
    pub fn accept_command(&self, sender: &str, id: &str, hash: &str, correlation: &str, envelope: &Envelope) -> Accept {
        let mut accepted = self.accepted.lock().unwrap();
        let key = (sender.to_string(), id.to_string());
        match accepted.get(&key) {
            Some(a) if a.hash == hash => Accept::Duplicate {
                correlation: a.correlation.clone(),
            },
            Some(_) => Accept::Conflict,
            None => {
                let order = {
                    let mut count = self.accepted_count.lock().unwrap();
                    *count += 1;
                    *count - 1
                };
                let line = AcceptedLine {
                    sender: sender.into(),
                    id: id.into(),
                    hash: hash.into(),
                    correlation: correlation.into(),
                    envelope: Some(envelope.clone()),
                    finished: false,
                    workload: None,
                    order,
                };
                write_line(&self.accepted_file, &line, "accepted command");
                self.own(&line);
                accepted.insert(key, line);
                Accept::New
            }
        }
    }

    /// Binds the correlation of an accepted command to its sender, unless an earlier command bound it already.
    fn own(&self, a: &AcceptedLine) {
        let mut owners = self.owners.lock().unwrap();
        let earlier = owners.get(&a.correlation).is_some_and(|(order, _)| *order < a.order);
        if !earlier {
            owners.insert(a.correlation.clone(), (a.order, a.sender.clone()));
        }
    }

    /// Records that `sender`'s command `id` reached a completing event: it is not run again after a restart.
    pub fn finish_command(&self, sender: &str, id: &str) {
        let mut accepted = self.accepted.lock().unwrap();
        let Some(a) = accepted.get_mut(&(sender.to_string(), id.to_string())) else {
            return;
        };
        if a.finished {
            return;
        }
        a.finished = true;
        a.envelope = None;
        let line = AcceptedLine {
            sender: sender.into(),
            id: id.into(),
            hash: a.hash.clone(),
            correlation: a.correlation.clone(),
            envelope: None,
            finished: true,
            workload: None,
            order: a.order,
        };
        write_line(&self.accepted_file, &line, "finished command");
    }

    /// Records that `sender`'s command `id` made the workload `workload`, so a later fact about the workload can
    /// complete the command.
    pub fn bind_workload(&self, sender: &str, id: &str, workload: &str) {
        let mut accepted = self.accepted.lock().unwrap();
        let Some(a) = accepted.get_mut(&(sender.to_string(), id.to_string())) else {
            return;
        };
        if a.workload.as_deref() == Some(workload) {
            return;
        }
        a.workload = Some(workload.into());
        let line = AcceptedLine {
            sender: sender.into(),
            id: id.into(),
            hash: a.hash.clone(),
            correlation: a.correlation.clone(),
            envelope: None,
            finished: false,
            workload: Some(workload.into()),
            order: a.order,
        };
        write_line(&self.accepted_file, &line, "bound command");
    }

    /// The workload `sender`'s command `id` made, when it bound one: what a restart finds already running.
    pub fn workload_of(&self, sender: &str, id: &str) -> Option<String> {
        self.accepted
            .lock()
            .unwrap()
            .get(&(sender.to_string(), id.to_string()))
            .and_then(|a| a.workload.clone())
    }

    /// The stored hash of `sender`'s command `id`, for a restart to check the stored envelope against.
    pub fn hash_of(&self, sender: &str, id: &str) -> Option<String> {
        self.accepted
            .lock()
            .unwrap()
            .get(&(sender.to_string(), id.to_string()))
            .map(|a| a.hash.clone())
    }

    /// Records that the unfinished command that made `workload`, when its type `completes` says the event told
    /// completes it, is finished: for a fact told later by the engine about the workload, not by the command's
    /// own handler. Precise: a workload id is the peer's, never shared.
    pub fn finish_by_workload(&self, workload: &str, completes: impl Fn(&str) -> bool) {
        let owed: Vec<(String, String)> = {
            let accepted = self.accepted.lock().unwrap();
            accepted
                .values()
                .filter(|a| !a.finished && a.workload.as_deref() == Some(workload))
                .filter(|a| a.envelope.as_ref().is_some_and(|e| completes(&e.r#type)))
                .map(|a| (a.sender.clone(), a.id.clone()))
                .collect()
        };
        for (sender, id) in owed {
            self.finish_command(&sender, &id);
        }
    }

    /// How many accepted commands are kept whole in memory.
    #[cfg(test)]
    fn kept_whole(&self) -> usize {
        self.accepted
            .lock()
            .unwrap()
            .values()
            .filter(|a| a.envelope.is_some())
            .count()
    }

    /// The accepted commands no completing event was told for, oldest first by acceptance: what a restart owes.
    /// A command accepted before envelopes were kept cannot be run again and is not listed.
    pub fn unfinished(&self) -> Vec<Unfinished> {
        let accepted = self.accepted.lock().unwrap();
        struct Owed {
            order: u64,
            unfinished: Unfinished,
        }
        let mut u: Vec<Owed> = accepted
            .values()
            .filter(|a| !a.finished)
            .filter_map(|a| {
                a.envelope.as_ref().map(|e| Owed {
                    order: a.order,
                    unfinished: Unfinished {
                        sender: a.sender.clone(),
                        envelope: e.clone(),
                    },
                })
            })
            .collect();
        u.sort_by_key(|x| x.order);
        u.into_iter().map(|x| x.unfinished).collect()
    }

    /// A page of the log, oldest first, and the cursor for the next page when there is one. `limit` is what the
    /// caller asked for and already checked (1 to [`MAX_PAGE`]); the default is 50.
    pub fn list(&self, filter: &Filter) -> (Vec<Envelope>, Option<String>) {
        self.list_for(filter, None)
    }

    /// The page `filter` selects, and when `sender` is given only the events under the correlations that sender
    /// owns: what a credential that does not act for every holder may read.
    pub fn list_for(&self, filter: &Filter, sender: Option<&str>) -> (Vec<Envelope>, Option<String>) {
        self.list_where(filter, |s| self.visible_to(sender, s))
    }

    /// The page `filter` selects among the events `visible` admits: the reader's rule, whatever it is. `visible`
    /// may read this log's own records; no lock but the events' is held while it runs.
    pub fn list_where(&self, filter: &Filter, visible: impl Fn(&Stored) -> bool) -> (Vec<Envelope>, Option<String>) {
        let limit = filter.limit.unwrap_or(50).clamp(1, MAX_PAGE);
        let events = self.events.lock().unwrap();
        let mut page: Vec<&Stored> = events
            .iter()
            .filter(|s| filter.after.is_none_or(|a| s.seq > a))
            .filter(|s| filter.matches(s))
            .filter(|s| visible(s))
            .take(limit + 1)
            .collect();
        let next = if page.len() > limit {
            page.truncate(limit);
            page.last().map(|s| s.seq.to_string())
        } else {
            None
        };
        (page.into_iter().map(|s| s.envelope.clone()).collect(), next)
    }

    /// The sender a correlation id belongs to: the one whose accepted command first carried it on this door. A
    /// correlation id is an identifier, never proof, so it is the first use that binds it, and a later command from
    /// another sender naming it is refused at ingest.
    pub fn owner_of_correlation(&self, corr: &str) -> Option<String> {
        self.owners.lock().unwrap().get(corr).map(|(_, s)| s.clone())
    }

    /// Whether `s` is under a correlation `sender` owns: every fact about a workload is told under the correlation
    /// id of the command that made it, so a sender's events are the events under the correlations its commands
    /// used first. An event under no correlation is nobody's and is read by a credential that acts for every holder
    /// only.
    fn is_senders(owners: &HashMap<String, (u64, String)>, sender: &str, s: &Stored) -> bool {
        let Some(corr) = s.envelope.correlationid.as_deref() else {
            return false;
        };
        owners.get(corr).is_some_and(|(_, owner)| owner == sender)
    }

    /// Whether `sender` reads `s`: everything when no sender is given (a credential that acts for every holder),
    /// else what is under the correlations it owns. Holds no lock across events.
    pub fn visible_to(&self, sender: Option<&str>, s: &Stored) -> bool {
        match sender {
            None => true,
            Some(who) => Self::is_senders(&self.owners.lock().unwrap(), who, s),
        }
    }

    /// Whether an event with this id is in the log: a fact told on two logs is the same fact, by its id.
    pub fn contains_id(&self, id: &str) -> bool {
        self.events.lock().unwrap().iter().any(|s| s.envelope.id == id)
    }

    pub fn since_id(&self, id: &str) -> Vec<Stored> {
        let events = self.events.lock().unwrap();
        match events.iter().position(|s| s.envelope.id == id) {
            Some(i) => events[i + 1..].to_vec(),
            None => Vec::new(),
        }
    }

    /// The live feed, with the position of the last event already in the log, so a subscriber that also replays can
    /// skip what it has seen: subscribe first, then read, and the two never overlap or miss.
    pub fn subscribe(&self) -> (broadcast::Receiver<Stored>, u64) {
        let events = self.events.lock().unwrap();
        (self.tx.subscribe(), events.last().map(|s| s.seq).unwrap_or(0))
    }

    pub fn len(&self) -> usize {
        self.events.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// One record, one line, one write; a failure is logged, never a panic that would poison the log for everyone.
fn write_line<T: Serialize>(file: &Mutex<Option<File>>, record: &T, what: &str) {
    if let Some(f) = file.lock().unwrap().as_mut() {
        let mut line = serde_json::to_string(record).expect("a record serialises");
        line.push('\n');
        if let Err(e) = f.write_all(line.as_bytes()).and_then(|_| f.flush()) {
            tracing::error!(error = %e, "{what} could not be written to disk; it lasts until restart");
        }
    }
}

fn read_lines(path: &Path) -> std::io::Result<Vec<String>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = String::from_utf8_lossy(&std::fs::read(path)?).into_owned();
    Ok(text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_string)
        .collect())
}

/// Opens the file for appending. A file whose last line was torn (the process died mid-write) gets a newline first,
/// so the next record starts on its own line and only the torn one is lost.
fn append_to(path: &Path) -> std::io::Result<File> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let bytes = std::fs::read(path)?;
    if bytes.last().is_some_and(|b| *b != b'\n') {
        file.write_all(b"\n")?;
        file.flush()?;
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ev(r#type: &str, corr: &str) -> Envelope {
        Envelope::event("io.best.agents", r#type, json!({}), Some(corr.into()), None)
    }

    #[test]
    fn events_are_numbered_in_order_and_paged_with_a_cursor() {
        let log = EventLog::ephemeral();
        for i in 0..5 {
            log.append(ev("Ticked", &format!("c{i}")));
        }
        let (page, next) = log.list(&Filter {
            limit: Some(2),
            ..Default::default()
        });
        assert_eq!(page.len(), 2);
        assert_eq!(next.as_deref(), Some("2"));
        let (page2, next2) = log.list(&Filter {
            limit: Some(2),
            after: Some(2),
            ..Default::default()
        });
        assert_eq!(page2[0].correlationid.as_deref(), Some("c2"));
        assert_eq!(next2.as_deref(), Some("4"));
        let (last, none) = log.list(&Filter {
            limit: Some(2),
            after: Some(4),
            ..Default::default()
        });
        assert_eq!(last.len(), 1);
        assert!(none.is_none());
    }

    #[test]
    fn filters_narrow_by_type_correlation_and_source() {
        let log = EventLog::ephemeral();
        log.append(ev("ImagePulled", "a"));
        log.append(ev("ImagePullFailed", "a"));
        log.append(ev("ImagePulled", "b"));
        let (by_corr, _) = log.list(&Filter {
            correlation_id: Some("a".into()),
            ..Default::default()
        });
        assert_eq!(by_corr.len(), 2);
        let (by_type, _) = log.list(&Filter {
            r#type: Some("ImagePulled".into()),
            ..Default::default()
        });
        assert_eq!(by_type.len(), 2);
        let (none, _) = log.list(&Filter {
            source: Some("elsewhere".into()),
            ..Default::default()
        });
        assert!(none.is_empty());
    }

    #[test]
    fn an_id_is_an_idempotency_key_per_sender_and_a_different_payload_is_a_conflict() {
        let log = EventLog::ephemeral();
        let cmd = ev("PullImage", "corr-1");
        assert_eq!(log.accept_command("alice", "x", "h1", "corr-1", &cmd), Accept::New);
        assert_eq!(
            log.accept_command("alice", "x", "h1", "corr-2", &cmd),
            Accept::Duplicate {
                correlation: "corr-1".into()
            },
            "the retry is told the original correlation"
        );
        assert_eq!(log.accept_command("alice", "x", "h2", "corr-3", &cmd), Accept::Conflict);
        assert_eq!(
            log.accept_command("bob", "x", "h1", "corr-4", &cmd),
            Accept::New,
            "another sender's id is their own"
        );
        assert_eq!(log.unfinished().len(), 2, "both accepted commands are owed");
        log.finish_command("alice", "x");
        let owed = log.unfinished();
        assert_eq!(owed.len(), 1);
        assert_eq!(owed[0].sender, "bob");
    }

    #[test]
    fn a_reconnect_replays_what_came_after_the_last_seen_id() {
        let log = EventLog::ephemeral();
        let a = log.append(ev("A", "c"));
        let _ = log.append(ev("B", "c"));
        let _ = log.append(ev("C", "c"));
        let after = log.since_id(&a.envelope.id);
        assert_eq!(
            after.iter().map(|s| s.envelope.r#type.as_str()).collect::<Vec<_>>(),
            vec!["B", "C"]
        );
        assert_eq!(
            log.since_id("never-seen").len(),
            0,
            "an id the log never told replays nothing"
        );
    }

    #[test]
    fn a_finished_command_is_kept_as_a_line_and_stays_so_after_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let first = EventLog::open(dir.path()).unwrap();
        let cmd = ev("PullImage", "c");
        assert_eq!(first.accept_command("alice", "cmd-1", "h", "c", &cmd), Accept::New);
        assert_eq!(first.accept_command("alice", "cmd-2", "h", "c", &cmd), Accept::New);
        assert_eq!(first.kept_whole(), 2);
        first.finish_command("alice", "cmd-2");
        assert_eq!(first.kept_whole(), 1, "the finished command is not kept whole");
        drop(first);
        let again = EventLog::open(dir.path()).unwrap();
        assert_eq!(again.kept_whole(), 1, "nor after a restart");
        assert_eq!(
            again.accept_command("alice", "cmd-2", "h", "c", &cmd),
            Accept::Duplicate {
                correlation: "c".into()
            },
            "its retry is still answered as it was"
        );
        assert_eq!(
            again.accept_command("alice", "cmd-2", "other", "c", &cmd),
            Accept::Conflict
        );
    }

    #[test]
    fn the_log_survives_a_restart_with_its_order_and_its_accepted_ids_and_skips_a_torn_line() {
        let dir = tempfile::tempdir().unwrap();
        let first = EventLog::open(dir.path()).unwrap();
        first.append(ev("A", "c"));
        first.append(ev("B", "c"));
        let cmd = ev("PullImage", "c");
        assert_eq!(first.accept_command("alice", "cmd-1", "h", "c", &cmd), Accept::New);
        assert_eq!(first.accept_command("alice", "cmd-2", "h", "c", &cmd), Accept::New);
        first.finish_command("alice", "cmd-2");
        drop(first);
        let path = dir.path().join("events.jsonl");
        let mut torn = std::fs::read_to_string(&path).unwrap();
        torn.push_str("{\"seq\":3,\"envelope\":{\"specversion");
        std::fs::write(&path, torn).unwrap();
        let again = EventLog::open(dir.path()).unwrap();
        let (events, _) = again.list(&Filter::default());
        assert_eq!(
            events.iter().map(|e| e.r#type.as_str()).collect::<Vec<_>>(),
            vec!["A", "B"]
        );
        assert_eq!(
            again.accept_command("alice", "cmd-1", "h", "c", &cmd),
            Accept::Duplicate {
                correlation: "c".into()
            }
        );
        let owed = again.unfinished();
        assert_eq!(owed.len(), 1, "the finished one is not owed after the restart");
        assert_eq!(owed[0].envelope.id, cmd.id);
        let c = again.append(ev("C", "c"));
        assert_eq!(c.seq, 3);
        // The record written after the torn line starts on its own line: a third open reads A, B and C.
        drop(again);
        let third = EventLog::open(dir.path()).unwrap();
        let (events, _) = third.list(&Filter::default());
        assert_eq!(
            events.iter().map(|e| e.r#type.as_str()).collect::<Vec<_>>(),
            vec!["A", "B", "C"]
        );
    }

    #[test]
    fn a_correlation_belongs_to_the_sender_that_first_used_it_through_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let first = EventLog::open(dir.path()).unwrap();
        let cmd = ev("PullImage", "c");
        assert_eq!(first.accept_command("alice", "a1", "h", "c", &cmd), Accept::New);
        // Accepted before the rule bound a correlation to its first sender: the log keeps the fact.
        assert_eq!(first.accept_command("bob", "b1", "h", "c", &cmd), Accept::New);
        assert_eq!(first.owner_of_correlation("c").as_deref(), Some("alice"));
        let fact = first.append(ev("ImagePulled", "c"));
        assert!(first.visible_to(Some("alice"), &fact));
        assert!(
            !first.visible_to(Some("bob"), &fact),
            "the second sender reads nothing under it"
        );
        assert!(first.visible_to(None, &fact));
        drop(first);
        let again = EventLog::open(dir.path()).unwrap();
        assert_eq!(
            again.owner_of_correlation("c").as_deref(),
            Some("alice"),
            "the file's order decides"
        );
        assert_eq!(again.owner_of_correlation("never"), None);
    }

    #[test]
    fn a_restart_owes_commands_in_the_order_they_were_accepted_and_finishes_by_the_workload_made() {
        let log = EventLog::ephemeral();
        let mut late = ev("DeployModel", "wf");
        late.time = "2020-01-01T00:00:00Z".into();
        let early = ev("DeployModel", "wf");
        assert_eq!(log.accept_command("a", "first", "h", "wf", &early), Accept::New);
        assert_eq!(log.accept_command("a", "second", "h", "wf", &late), Accept::New);
        let owed: Vec<String> = log.unfinished().iter().map(|u| u.envelope.id.clone()).collect();
        assert_eq!(
            owed,
            vec![early.id.clone(), late.id.clone()],
            "acceptance order, not the client's clock"
        );
        // The first made dep-1; a fact about dep-1 completes it and leaves the second, which shares the correlation.
        log.bind_workload("a", "first", "dep-1");
        log.finish_by_workload("dep-1", |t| t == "DeployModel");
        let owed: Vec<String> = log.unfinished().iter().map(|u| u.envelope.id.clone()).collect();
        assert_eq!(owed, vec![late.id.clone()]);
        assert_eq!(log.hash_of("a", "second").as_deref(), Some("h"));
    }

    #[tokio::test]
    async fn a_subscriber_hears_what_is_appended_after_it_subscribed_and_knows_where_the_log_was() {
        let log = EventLog::ephemeral();
        log.append(ev("Before", "c"));
        let (mut rx, last) = log.subscribe();
        assert_eq!(last, 1);
        log.append(ev("After", "c"));
        let got = rx.recv().await.unwrap();
        assert_eq!(got.envelope.r#type, "After");
        assert_eq!(got.seq, 2);
    }
}
