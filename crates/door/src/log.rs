//! The event log: every fact the door has told, in order, kept on disk and streamed live. `GET /events` reads it,
//! `GET /events/stream` follows it, and a reconnecting client replays from `Last-Event-ID`. The log also keeps the
//! commands it accepted, per sender, so an envelope `id` is an idempotency key across restarts.
//!
//! On disk the events are a file per UTC day, `events/<YYYY-MM-DD>.jsonl`, so a day can be copied, kept or forgotten
//! on its own. An event goes to the file of its own `time`, except that the log never goes back to an earlier file
//! (a fact told late with an old time, as a workspace hears a root fact again at start, joins the file being
//! written) and never opens a file for a day that has not come (a time ahead of the clock joins today's): so the
//! files in name order, each line by line, are the log in its order. An `events.jsonl` left by an older peer is read
//! before them and never written again.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{Date, OffsetDateTime, UtcOffset};
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
    /// Where events are written, for a log kept on disk.
    segments: Mutex<Option<Segments>>,
    accepted_file: Mutex<Option<File>>,
    /// Where the accepted commands are kept, for a log on disk: what a redaction rewrites.
    accepted_path: Mutex<Option<PathBuf>>,
    tx: broadcast::Sender<Stored>,
}

/// A command the log accepted, as `redact_commands` found it: its id, its correlation, and its data as it is now.
#[derive(Clone, Debug)]
pub struct Redacted {
    pub id: String,
    pub correlation: String,
    pub data: Value,
}

/// The day files of a log on disk, and the one being written.
struct Segments {
    dir: PathBuf,
    open: Option<(Date, File)>,
}

impl Segments {
    /// Writes `stored` to its day's file, opening that file when it is not the one being written. A day's file that
    /// cannot be opened loses that event on disk, as any failed write does: it is in memory and was told, and after a
    /// restart its `seq` is a gap. The file being written stays open, and the next event tries the day again.
    fn write(&mut self, stored: &Stored) {
        let current = self.open.as_ref().map(|(day, _)| *day);
        let day = segment_day(&stored.envelope.time, OffsetDateTime::now_utc().date(), current);
        if current != Some(day) {
            let path = self.dir.join(segment_name(day));
            match append_to(&path) {
                Ok(file) => self.open = Some((day, file)),
                Err(e) => {
                    tracing::error!(error = %e, file = %path.display(), "the day's event file could not be opened; the event lasts until restart");
                    return;
                }
            }
        }
        if let Some((_, file)) = self.open.as_mut() {
            write_record(file, stored, "event");
        }
    }
}

/// The day an event with `time` is written under: its own UTC day, never after `today` and never before the file
/// being written (`current`), so the files in name order keep the log's order whatever the clocks did. A time that
/// does not parse joins the file being written, or today's.
fn segment_day(time: &str, today: Date, current: Option<Date>) -> Date {
    let told = OffsetDateTime::parse(time, &Rfc3339)
        .map(|t| t.to_offset(UtcOffset::UTC).date())
        .unwrap_or(current.unwrap_or(today));
    let day = told.min(today);
    current.map_or(day, |c| day.max(c))
}

/// The path of `day`'s file under `dir`.
fn self_day_path(dir: &Path, day: Date) -> PathBuf {
    dir.join(segment_name(day))
}

/// Rewrites `path` line by line: `change` answers the new line for one it changes and nothing for one it keeps. The
/// new file is written beside it and renamed over it, so a crash leaves the old file or the new one, never half.
fn rewrite(path: &Path, mut change: impl FnMut(&str) -> Option<String>) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    let text = std::fs::read(path).map_err(|e| format!("{} could not be read: {e}", path.display()))?;
    let text = String::from_utf8_lossy(&text);
    let mut out = String::with_capacity(text.len());
    let mut changed = false;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        match change(line) {
            Some(new) => {
                out.push_str(&new);
                changed = true;
            }
            None => out.push_str(line),
        }
        out.push('\n');
    }
    if !changed {
        return Ok(());
    }
    let tmp = path.with_extension("jsonl.rewrite");
    let written = File::create(&tmp)
        .and_then(|mut f| f.write_all(out.as_bytes()).and_then(|_| f.sync_all()))
        .and_then(|_| std::fs::rename(&tmp, path));
    written.map_err(|e| format!("{} could not be rewritten: {e}", path.display()))
}

/// `2026-10-19.jsonl`: the date first, its fields widest first at a fixed width, so the names sort as the days do.
fn segment_name(day: Date) -> String {
    format!("{:04}-{:02}-{:02}.jsonl", day.year(), u8::from(day.month()), day.day())
}

/// The day files under `dir`, oldest first. A file whose name is not a day is left alone, and said so.
fn day_files(dir: &Path) -> std::io::Result<Vec<(Date, PathBuf)>> {
    let mut days = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let day = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(".jsonl"))
            .and_then(|stem| Date::parse(stem, format_description!("[year]-[month]-[day]")).ok());
        match day.filter(|_| path.is_file()) {
            Some(day) => days.push((day, path)),
            None => {
                tracing::warn!(file = %path.display(), "a file in the events folder is not a day's file and is not read")
            }
        }
    }
    days.sort_by_key(|(day, _)| *day);
    Ok(days)
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
            segments: Mutex::new(None),
            accepted_file: Mutex::new(None),
            accepted_path: Mutex::new(None),
            tx,
        }
    }

    /// A log kept in `dir` (the day files under `events/`, `accepted.jsonl`), loaded now and appended to from here
    /// on. An `events.jsonl` an older peer left is read first and never written again. A line that cannot be read (a
    /// torn write) is skipped and logged, never fatal.
    pub fn open(dir: &Path) -> std::io::Result<Self> {
        let events_dir = dir.join("events");
        std::fs::create_dir_all(&events_dir)?;
        let log = Self::ephemeral();
        let accepted_path = dir.join("accepted.jsonl");
        let days = day_files(&events_dir)?;
        let files = std::iter::once(dir.join("events.jsonl")).chain(days.iter().map(|(_, p)| p.clone()));
        for path in files {
            for line in read_lines(&path)? {
                match serde_json::from_str::<Stored>(&line) {
                    Ok(s) => {
                        let mut events = log.events.lock().unwrap();
                        if events.last().is_some_and(|last| last.seq >= s.seq) {
                            tracing::warn!(file = %path.display(), seq = s.seq, "an event is out of the log's order: an older peer wrote events.jsonl after this one wrote day files, or the files were changed by hand");
                        }
                        events.push(s);
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, file = %path.display(), "an event line could not be read and is skipped")
                    }
                }
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
        // The last day's file is the one being written: reopened, its torn line ended, so a restart appends to it.
        let open = match days.last() {
            Some((day, path)) => Some((*day, append_to(path)?)),
            None => None,
        };
        *log.segments.lock().unwrap() = Some(Segments { dir: events_dir, open });
        *log.accepted_file.lock().unwrap() = Some(append_to(&accepted_path)?);
        *log.accepted_path.lock().unwrap() = Some(accepted_path);
        Ok(log)
    }

    /// Appends an event and tells every subscriber, in the order of the log. The write to disk happens before anyone
    /// hears of it; a disk error is logged and the event still reaches subscribers, since a fact told cannot be
    /// untold.
    pub fn append(&self, envelope: Envelope) -> Stored {
        let mut events = self.events.lock().unwrap();
        let seq = events.last().map(|s| s.seq + 1).unwrap_or(1);
        let stored = Stored { seq, envelope };
        if let Some(segments) = self.segments.lock().unwrap().as_mut() {
            segments.write(&stored);
        }
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

    /// The key (`sender:id`) of the first accepted command `matches` says yes to, given the sender, the id and the
    /// workload it made: what a restart uses to find the command behind a workload or an order it rebuilt.
    pub fn command_where(&self, matches: impl Fn(&str, &str, Option<&str>) -> bool) -> Option<String> {
        let accepted = self.accepted.lock().unwrap();
        let mut found: Vec<&AcceptedLine> = accepted
            .values()
            .filter(|a| matches(&a.sender, &a.id, a.workload.as_deref()))
            .collect();
        found.sort_by_key(|a| a.order);
        found.first().map(|a| format!("{}:{}", a.sender, a.id))
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

    /// Removes the content of the events `pick` chooses, keeping each one's envelope: `strip` takes its data down to
    /// what stays. They are rewritten in memory and in the files they were written to, so a page, a replay of the
    /// stream and a restart serve them as they are now; a subscriber that heard one before heard it before. `strip`
    /// is applied to what is already stripped as well, so a redaction that failed on disk is done again by the
    /// next. Answers the events picked, as they are now, or what could not be rewritten on disk (memory is redacted
    /// either way).
    pub fn redact(&self, pick: impl Fn(&Stored) -> bool, strip: impl Fn(&mut Value)) -> Result<Vec<Stored>, String> {
        let mut events = self.events.lock().unwrap();
        // By the event's id: two files of one folder may hold the same seq (an older peer's file beside day files).
        let mut changed: HashMap<String, Stored> = HashMap::new();
        for stored in events.iter_mut().filter(|s| pick(s)) {
            strip(&mut stored.envelope.data);
            changed.insert(stored.envelope.id.clone(), stored.clone());
        }
        let picked: Vec<Stored> = changed.values().cloned().collect();
        if changed.is_empty() {
            return Ok(picked);
        }
        let mut segments = self.segments.lock().unwrap();
        if let Some(segments) = segments.as_mut() {
            let legacy = segments.dir.parent().map(|d| d.join("events.jsonl"));
            let days = day_files(&segments.dir).map_err(|e| format!("the events folder could not be read: {e}"))?;
            let paths = legacy.into_iter().chain(days.iter().map(|(_, p)| p.clone()));
            for path in paths {
                let open = segments
                    .open
                    .as_ref()
                    .map(|(day, _)| self_day_path(&segments.dir, *day));
                // The file being written is closed for the rewrite and reopened after, so nothing is lost or torn.
                let reopen = open.as_ref() == Some(&path);
                let day = segments.open.as_ref().map(|(d, _)| *d);
                if reopen {
                    segments.open = None;
                }
                let rewritten = rewrite(&path, |line| {
                    let s = serde_json::from_str::<Stored>(line).ok()?;
                    let now = changed.get(&s.envelope.id)?;
                    serde_json::to_string(now).ok()
                });
                if let (true, Some(day)) = (reopen, day) {
                    let file =
                        append_to(&path).map_err(|e| format!("{} could not be opened again: {e}", path.display()))?;
                    segments.open = Some((day, file));
                }
                rewritten?;
            }
        }
        drop(events);
        Ok(picked)
    }

    /// Removes the content of the finished commands `pick` chooses (by sender, correlation and the command as accepted), keeping
    /// each one's record: `strip` takes its data down to what stays. A finished command's data is held only in the
    /// file of accepted commands, which is rewritten. Answers the commands redacted, or what could not be rewritten.
    pub fn redact_commands(
        &self,
        pick: impl Fn(&str, &str, &Envelope) -> bool,
        strip: impl Fn(&mut Value),
    ) -> Result<Vec<Redacted>, String> {
        let accepted = self.accepted.lock().unwrap();
        let mut file = self.accepted_file.lock().unwrap();
        let Some(path) = self.accepted_path.lock().unwrap().clone() else {
            return Ok(Vec::new());
        };
        let finished = |sender: &str, id: &str| {
            accepted
                .get(&(sender.to_string(), id.to_string()))
                .is_some_and(|a| a.finished)
        };
        let mut done: Vec<Redacted> = Vec::new();
        let had = file.take();
        drop(had);
        let rewritten = rewrite(&path, |line| {
            let mut a = serde_json::from_str::<AcceptedLine>(line).ok()?;
            let envelope = a.envelope.as_mut()?;
            if !finished(&a.sender, &a.id) || !pick(&a.sender, &a.correlation, envelope) {
                return None;
            }
            strip(&mut envelope.data);
            if !done.iter().any(|d| d.id == a.id) {
                done.push(Redacted {
                    id: a.id.clone(),
                    correlation: a.correlation.clone(),
                    data: envelope.data.clone(),
                });
            }
            serde_json::to_string(&a).ok()
        });
        *file = Some(append_to(&path).map_err(|e| format!("{} could not be opened again: {e}", path.display()))?);
        rewritten?;
        Ok(done)
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
        write_record(f, record, what);
    }
}

fn write_record<T: Serialize>(f: &mut File, record: &T, what: &str) {
    let mut line = serde_json::to_string(record).expect("a record serialises");
    line.push('\n');
    if let Err(e) = f.write_all(line.as_bytes()).and_then(|_| f.flush()) {
        tracing::error!(error = %e, "{what} could not be written to disk; it lasts until restart");
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

    /// An event told at `time`, as a fact relayed or heard again keeps the time it was first told.
    fn ev_at(r#type: &str, time: &str) -> Envelope {
        let mut e = ev(r#type, "c");
        e.time = time.into();
        e
    }

    fn types(log: &EventLog) -> Vec<String> {
        log.list(&Filter {
            limit: Some(MAX_PAGE),
            ..Default::default()
        })
        .0
        .into_iter()
        .map(|e| e.r#type)
        .collect()
    }

    fn lines(path: &Path) -> usize {
        read_lines(path).unwrap().len()
    }

    fn day(text: &str) -> Date {
        Date::parse(text, format_description!("[year]-[month]-[day]")).unwrap()
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
    fn a_redacted_event_and_command_keep_their_envelope_on_disk_through_a_restart_and_the_log_goes_on() {
        let dir = tempfile::tempdir().unwrap();
        let first = EventLog::open(dir.path()).unwrap();
        let mut said = ev("PromptAnswered", "c1");
        said.data = json!({ "deployment": "dep-1", "content": "the secret answer", "completion_tokens": 3 });
        first.append(said);
        first.append(ev("DeploymentReady", "c1"));
        let mut asked = ev("Prompt", "c1");
        asked.data =
            json!({ "deployment": "dep-1", "messages": [{ "role": "user", "content": "the secret question" }] });
        first.accept_command("alice", "p1", "h", "c1", &asked);
        first.finish_command("alice", "p1");
        let strip = |d: &mut Value| {
            if let Some(o) = d.as_object_mut() {
                o.remove("content");
                o.remove("messages");
                o.insert("forgotten".into(), json!(true));
            }
        };
        let picked = first.redact(|s| s.envelope.r#type == "PromptAnswered", strip).unwrap();
        assert_eq!(picked.len(), 1);
        let done = first
            .redact_commands(|sender, _, e| sender == "alice" && e.r#type == "Prompt", strip)
            .unwrap();
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].correlation, "c1");
        assert_eq!(done[0].data["deployment"], "dep-1");
        // The log goes on: the file being written was reopened, and the next event lands after the others.
        first.append(ev("After", "c1"));
        drop(first);
        let text = std::fs::read_to_string(dir.path().join("accepted.jsonl")).unwrap()
            + &std::fs::read_dir(dir.path().join("events"))
                .unwrap()
                .map(|f| std::fs::read_to_string(f.unwrap().path()).unwrap())
                .collect::<String>();
        assert!(
            !text.contains("secret"),
            "nothing of the content is left on disk: {text}"
        );
        let again = EventLog::open(dir.path()).unwrap();
        assert_eq!(types(&again), ["PromptAnswered", "DeploymentReady", "After"]);
        let (page, _) = again.list(&Filter::default());
        assert_eq!(
            page[0].data,
            json!({ "deployment": "dep-1", "completion_tokens": 3, "forgotten": true })
        );
        // A command's retry is still answered as before: the record of it stays.
        assert_eq!(
            again.accept_command("alice", "p1", "h", "c1", &asked),
            Accept::Duplicate {
                correlation: "c1".into()
            }
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
        first.append(ev_at("A", "2020-01-01T10:00:00Z"));
        first.append(ev_at("B", "2020-01-01T11:00:00Z"));
        let cmd = ev("PullImage", "c");
        assert_eq!(first.accept_command("alice", "cmd-1", "h", "c", &cmd), Accept::New);
        assert_eq!(first.accept_command("alice", "cmd-2", "h", "c", &cmd), Accept::New);
        first.finish_command("alice", "cmd-2");
        drop(first);
        let path = dir.path().join("events").join("2020-01-01.jsonl");
        let mut torn = std::fs::read_to_string(&path).unwrap();
        torn.push_str("{\"seq\":3,\"envelope\":{\"specversion");
        std::fs::write(&path, torn).unwrap();
        let again = EventLog::open(dir.path()).unwrap();
        assert_eq!(types(&again), vec!["A", "B"]);
        assert_eq!(
            again.accept_command("alice", "cmd-1", "h", "c", &cmd),
            Accept::Duplicate {
                correlation: "c".into()
            }
        );
        let owed = again.unfinished();
        assert_eq!(owed.len(), 1, "the finished one is not owed after the restart");
        assert_eq!(owed[0].envelope.id, cmd.id);
        let c = again.append(ev_at("C", "2020-01-01T12:00:00Z"));
        assert_eq!(c.seq, 3);
        // The restart reopened the day's file and appended to it, the record after the torn line on its own line:
        // a third open reads A, B and C, and the day is still one file.
        drop(again);
        let third = EventLog::open(dir.path()).unwrap();
        assert_eq!(types(&third), vec!["A", "B", "C"]);
        assert_eq!(std::fs::read_dir(dir.path().join("events")).unwrap().count(), 1);
    }

    #[test]
    fn events_go_to_the_file_of_their_own_day_and_read_back_in_order_across_days() {
        let dir = tempfile::tempdir().unwrap();
        let first = EventLog::open(dir.path()).unwrap();
        let a = first.append(ev_at("A", "2020-01-01T23:59:59Z"));
        first.append(ev_at("B", "2020-01-02T00:00:01Z"));
        // A time with an offset is a UTC day: 01:00 at +02:00 is the 2nd at 23:00 UTC.
        first.append(ev_at("C", "2020-01-03T01:00:00+02:00"));
        let events = dir.path().join("events");
        assert_eq!(lines(&events.join("2020-01-01.jsonl")), 1);
        assert_eq!(lines(&events.join("2020-01-02.jsonl")), 2);
        assert!(!events.join("2020-01-03.jsonl").exists());
        assert!(!dir.path().join("events.jsonl").exists(), "no single file is made");
        drop(first);
        let again = EventLog::open(dir.path()).unwrap();
        assert_eq!(types(&again), vec!["A", "B", "C"]);
        assert_eq!(
            again
                .since_id(&a.envelope.id)
                .iter()
                .map(|s| (s.seq, s.envelope.r#type.as_str()))
                .collect::<Vec<_>>(),
            vec![(2, "B"), (3, "C")],
            "a reconnect replays across the day's boundary"
        );
        assert_eq!(again.subscribe().1, 3);
        assert_eq!(
            again.append(ev("D", "c")).seq,
            4,
            "the order goes on from the last day's file"
        );
    }

    #[test]
    fn a_fact_told_late_with_an_old_time_joins_the_file_being_written() {
        // As a workspace hears a root fact again at start, keeping the time it was first told.
        let dir = tempfile::tempdir().unwrap();
        let first = EventLog::open(dir.path()).unwrap();
        first.append(ev_at("A", "2020-01-02T10:00:00Z"));
        first.append(ev_at("Heard", "2020-01-01T09:00:00Z"));
        let events = dir.path().join("events");
        assert!(
            !events.join("2020-01-01.jsonl").exists(),
            "the log never goes back to an earlier day"
        );
        assert_eq!(lines(&events.join("2020-01-02.jsonl")), 2);
        drop(first);
        let again = EventLog::open(dir.path()).unwrap();
        assert_eq!(types(&again), vec!["A", "Heard"], "replayed in the order it was told");
    }

    #[test]
    fn the_day_is_the_events_own_bounded_by_today_and_by_the_file_being_written() {
        let today = day("2026-10-19");
        assert_eq!(segment_day("2026-10-18T12:00:00Z", today, None), day("2026-10-18"));
        assert_eq!(
            segment_day("2026-10-18T12:00:00Z", today, Some(day("2026-10-19"))),
            day("2026-10-19"),
            "never back to an earlier file"
        );
        assert_eq!(
            segment_day("2031-01-01T00:00:00Z", today, Some(day("2026-10-18"))),
            today,
            "never a day that has not come"
        );
        assert_eq!(
            segment_day("not a time", today, Some(day("2026-10-17"))),
            day("2026-10-17"),
            "a time that does not parse joins the file being written"
        );
        assert_eq!(segment_day("not a time", today, None), today);
        assert_eq!(segment_name(day("2026-01-09")), "2026-01-09.jsonl");
    }

    #[test]
    fn the_single_file_an_older_peer_left_is_read_first_and_never_written_again() {
        let dir = tempfile::tempdir().unwrap();
        let old: String = [
            ev_at("Old1", "2020-01-01T10:00:00Z"),
            ev_at("Old2", "2020-01-05T10:00:00Z"),
        ]
        .into_iter()
        .enumerate()
        .map(|(i, envelope)| {
            serde_json::to_string(&Stored {
                seq: i as u64 + 1,
                envelope,
            })
            .unwrap()
                + "\n"
        })
        .collect();
        let legacy = dir.path().join("events.jsonl");
        std::fs::write(&legacy, &old).unwrap();
        let first = EventLog::open(dir.path()).unwrap();
        assert_eq!(types(&first), vec!["Old1", "Old2"]);
        // An earlier day than the old file's last: it still comes after, since the old file is read first.
        assert_eq!(first.append(ev_at("New", "2020-01-03T10:00:00Z")).seq, 3);
        drop(first);
        assert_eq!(
            std::fs::read_to_string(&legacy).unwrap(),
            old,
            "the old file is not written"
        );
        assert!(dir.path().join("events").join("2020-01-03.jsonl").exists());
        let again = EventLog::open(dir.path()).unwrap();
        assert_eq!(types(&again), vec!["Old1", "Old2", "New"]);
    }

    #[test]
    fn a_day_file_that_cannot_be_opened_loses_that_event_on_disk_and_nothing_after_it() {
        let dir = tempfile::tempdir().unwrap();
        let first = EventLog::open(dir.path()).unwrap();
        first.append(ev_at("A", "2020-01-01T10:00:00Z"));
        // A directory where the next day's file would go: the file cannot be opened.
        let blocked = dir.path().join("events").join("2020-01-02.jsonl");
        std::fs::create_dir(&blocked).unwrap();
        assert_eq!(first.append(ev_at("Lost", "2020-01-02T10:00:00Z")).seq, 2);
        assert_eq!(types(&first), vec!["A", "Lost"], "in memory and told");
        assert_eq!(first.append(ev_at("Late", "2020-01-01T11:00:00Z")).seq, 3);
        drop(first);
        let again = EventLog::open(dir.path()).unwrap();
        assert_eq!(
            types(&again),
            vec!["A", "Late"],
            "what reached disk, in its order; the lost one is a gap"
        );
        assert_eq!(again.append(ev_at("B", "2020-01-01T12:00:00Z")).seq, 4);
    }

    #[test]
    fn an_older_peer_writing_its_single_file_after_day_files_leaves_both_read_and_the_order_going_on() {
        // A peer from before day files, started over a folder this one wrote, appends to events.jsonl with seq values
        // the day files already hold. Both are read, the old file first, with a warning; nothing is lost or refused.
        let dir = tempfile::tempdir().unwrap();
        let first = EventLog::open(dir.path()).unwrap();
        first.append(ev_at("New", "2020-01-02T10:00:00Z"));
        drop(first);
        let back = serde_json::to_string(&Stored {
            seq: 1,
            envelope: ev_at("FromOlderPeer", "2020-01-03T10:00:00Z"),
        })
        .unwrap();
        std::fs::write(dir.path().join("events.jsonl"), back + "\n").unwrap();
        let again = EventLog::open(dir.path()).unwrap();
        assert_eq!(types(&again), vec!["FromOlderPeer", "New"]);
        assert_eq!(
            again.append(ev("Next", "c")).seq,
            2,
            "the order goes on from the last event read"
        );
    }

    #[test]
    fn a_redaction_finds_its_event_by_id_where_two_files_hold_the_same_seq() {
        let dir = tempfile::tempdir().unwrap();
        let first = EventLog::open(dir.path()).unwrap();
        let mut said = ev_at("PromptAnswered", "2020-01-02T10:00:00Z");
        said.data = serde_json::json!({ "content": "secret" });
        first.append(said);
        drop(first);
        let back = serde_json::to_string(&Stored {
            seq: 1,
            envelope: ev_at("FromOlderPeer", "2020-01-03T10:00:00Z"),
        })
        .unwrap();
        std::fs::write(dir.path().join("events.jsonl"), back + "\n").unwrap();
        let again = EventLog::open(dir.path()).unwrap();
        again
            .redact(
                |s| s.envelope.r#type == "PromptAnswered",
                |d| {
                    d.as_object_mut().unwrap().remove("content");
                },
            )
            .unwrap();
        let legacy = std::fs::read_to_string(dir.path().join("events.jsonl")).unwrap();
        assert!(
            legacy.contains("FromOlderPeer"),
            "the older peer's event is left as it was: {legacy}"
        );
        drop(again);
        let reopened = EventLog::open(dir.path()).unwrap();
        assert_eq!(types(&reopened), vec!["FromOlderPeer", "PromptAnswered"]);
        let (page, _) = reopened.list(&Filter::default());
        assert!(page[1].data.get("content").is_none());
    }

    #[test]
    fn a_file_in_the_events_folder_that_is_not_a_day_is_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let first = EventLog::open(dir.path()).unwrap();
        first.append(ev_at("A", "2020-01-01T10:00:00Z"));
        drop(first);
        let stray = serde_json::to_string(&Stored {
            seq: 9,
            envelope: ev_at("Stray", "2020-01-01T10:00:00Z"),
        })
        .unwrap();
        std::fs::write(dir.path().join("events").join("notes.jsonl"), stray).unwrap();
        let again = EventLog::open(dir.path()).unwrap();
        assert_eq!(types(&again), vec!["A"]);
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
