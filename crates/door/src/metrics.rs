//! The door's telemetry: how the machine moves, as time series, beside the BEST surface and never on it
//! (behavioralstate/spec#47). Facts stay BEST; a reading that changes every second is a series a collector scrapes
//! from `/metrics`, in the open text format every collector reads: the Prometheus exposition format, or OpenMetrics
//! when the scraper asks for it (`Accept: application/openmetrics-text`). The door keeps no history and charts
//! nothing.
//!
//! What a credential reads here is what it may read elsewhere, and no more. The service's own series come from a
//! [`MetricsSource`] the host gives the door, asked with the credential, so a device it may not see or a workload
//! of another holder is not in its answer. The door adds the series of the whole door (commands, events, streams)
//! for a credential approved for all or for [`METRICS_SCOPE`], the read-only scope a collector is approved for.
//!
//! Every series is named `best_peer_…`, in base units (`_bytes`, `_celsius`, `_watts`, `_ratio` from 0 to 1), with
//! the labels it has; names say what is measured, never which vendor's tool measured it.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use futures::future::BoxFuture;

use crate::auth::Credential;

/// The scope that reads the whole door's series and nothing else: what a collector is approved for
/// (`best-peer approve <code> --may metrics`), so it holds no right to deploy, run or prompt.
pub const METRICS_SCOPE: &str = "metrics";

/// Whether a credential was approved to read metrics and nothing else: it sends no command.
pub fn reads_only(grant: &crate::auth::Grant) -> bool {
    grant
        .scopes
        .as_ref()
        .is_some_and(|s| !s.is_empty() && s.iter().all(|x| x == METRICS_SCOPE))
}

/// The content type of the Prometheus text format.
pub const PROMETHEUS_TEXT: &str = "text/plain; version=0.0.4; charset=utf-8";
/// The content type of OpenMetrics text.
pub const OPENMETRICS_TEXT: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// What a series measures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A value that goes up and down.
    Gauge,
    /// A count that only goes up, from when it started; its samples end in `_total`.
    Counter,
    /// A value of 1 that carries its labels: what something is, not how much.
    Info,
}

/// One series family: its name, what it measures, its unit, and its samples.
#[derive(Clone, Debug, PartialEq)]
pub struct Family {
    /// Without `_total` for a counter, nor `_info` for an info: those are added to its samples.
    pub name: String,
    pub kind: Kind,
    pub help: String,
    /// The unit, which the name ends in (`bytes`, `celsius`, `watts`); none for a count or a ratio.
    pub unit: Option<&'static str>,
    pub samples: Vec<Sample>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Sample {
    pub labels: Vec<(String, String)>,
    pub value: f64,
}

impl Family {
    pub fn new(name: &str, kind: Kind, help: &str) -> Self {
        Self {
            name: name.into(),
            kind,
            help: help.into(),
            unit: None,
            samples: Vec::new(),
        }
    }

    /// The same family, measured in `unit`, which its name must end in.
    pub fn unit(mut self, unit: &'static str) -> Self {
        debug_assert!(
            self.name.ends_with(&format!("_{unit}")),
            "{} must end in _{unit}",
            self.name
        );
        self.unit = Some(unit);
        self
    }

    /// Adds a sample with these labels.
    pub fn sample(&mut self, labels: &[(&'static str, &str)], value: f64) -> &mut Self {
        self.samples.push(Sample {
            labels: labels.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            value,
        });
        self
    }

    /// The name of its samples: `_total` after a counter's, `_info` after an info's.
    fn sample_name(&self) -> String {
        match self.kind {
            Kind::Counter => format!("{}_total", self.name),
            Kind::Info => format!("{}_info", self.name),
            Kind::Gauge => self.name.clone(),
        }
    }
}

/// The service's own series, as `who` may read them: what the host answers when the door is scraped.
pub type MetricsSource = Arc<dyn Fn(Credential) -> BoxFuture<'static, Vec<Family>> + Send + Sync>;

/// Which text the scraper asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Prometheus,
    OpenMetrics,
}

impl Format {
    /// OpenMetrics when the `Accept` header names it, the Prometheus text otherwise, as collectors expect.
    pub fn from_accept(accept: Option<&str>) -> Self {
        match accept {
            Some(a) if a.contains("application/openmetrics-text") => Format::OpenMetrics,
            _ => Format::Prometheus,
        }
    }

    pub fn content_type(self) -> &'static str {
        match self {
            Format::Prometheus => PROMETHEUS_TEXT,
            Format::OpenMetrics => OPENMETRICS_TEXT,
        }
    }
}

/// A label value or help text with what the format escapes escaped: the backslash and the newline everywhere, and
/// the double quote in a label value, and in OpenMetrics in help text too (the Prometheus text leaves it there).
fn escape(s: &str, quote: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '"' if quote => out.push_str("\\\""),
            c => out.push(c),
        }
    }
    out
}

/// A number as the formats write it: integers without a fraction, the special values by name.
fn number(v: f64) -> String {
    if v.is_nan() {
        "NaN".into()
    } else if v.is_infinite() {
        if v > 0.0 {
            "+Inf".into()
        } else {
            "-Inf".into()
        }
    } else if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

/// The families as text in `format`, each family once, in the order given; an empty family has its help and type
/// and no samples. Two families of one name are merged, the first's help and type kept.
pub fn render(families: &[Family], format: Format) -> String {
    let mut merged: Vec<Family> = Vec::new();
    for f in families {
        match merged.iter_mut().find(|m| m.name == f.name) {
            Some(m) => m.samples.extend(f.samples.iter().cloned()),
            None => merged.push(f.clone()),
        }
    }
    let mut out = String::new();
    for f in &merged {
        // OpenMetrics names a family without its samples' suffix; the Prometheus text names it as its samples.
        let family_name = match format {
            Format::OpenMetrics => f.name.clone(),
            Format::Prometheus => f.sample_name(),
        };
        let kind = match (f.kind, format) {
            (Kind::Gauge, _) => "gauge",
            (Kind::Counter, _) => "counter",
            (Kind::Info, Format::OpenMetrics) => "info",
            (Kind::Info, Format::Prometheus) => "gauge",
        };
        let _ = writeln!(
            out,
            "# HELP {family_name} {}",
            escape(&f.help, format == Format::OpenMetrics)
        );
        let _ = writeln!(out, "# TYPE {family_name} {kind}");
        if let (Some(unit), Format::OpenMetrics) = (f.unit, format) {
            let _ = writeln!(out, "# UNIT {family_name} {unit}");
        }
        let name = f.sample_name();
        for s in &f.samples {
            if s.labels.is_empty() {
                let _ = writeln!(out, "{name} {}", number(s.value));
            } else {
                let labels: Vec<String> = s
                    .labels
                    .iter()
                    .map(|(k, v)| format!("{k}=\"{}\"", escape(v, true)))
                    .collect();
                let _ = writeln!(out, "{name}{{{}}} {}", labels.join(","), number(s.value));
            }
        }
    }
    if format == Format::OpenMetrics {
        out.push_str("# EOF\n");
    }
    out
}

/// The families of a Prometheus text exposition, as another door renders it: what a cloud door reads from a
/// member's `/metrics` to serve again under its own labels. A counter's family is named without `_total`, and a
/// gauge named `…_info` whose every sample is 1 is an info, so [`render`] writes the text back as it came. A line
/// that is not a comment, a type or a sample is an error naming it, so a member that answers something else is not
/// taken for one that measures nothing.
pub fn parse(text: &str) -> Result<Vec<Family>, String> {
    let mut families: Vec<Family> = Vec::new();
    let mut helps: BTreeMap<String, String> = BTreeMap::new();
    let mut kinds: BTreeMap<String, Kind> = BTreeMap::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim_end();
        if line.is_empty() || line == "# EOF" {
            continue;
        }
        if let Some(rest) = line.strip_prefix("# HELP ") {
            let (name, help) = rest.split_once(' ').unwrap_or((rest, ""));
            helps.insert(name.to_string(), unescape(help));
            continue;
        }
        if let Some(rest) = line.strip_prefix("# TYPE ") {
            let (name, kind) = rest.split_once(' ').unwrap_or((rest, ""));
            let kind = match kind {
                "counter" => Kind::Counter,
                "gauge" | "untyped" | "unknown" => Kind::Gauge,
                "info" => Kind::Info,
                other => {
                    return Err(format!(
                        "line {}: a series of type {other:?}, which this door does not read",
                        n + 1
                    ))
                }
            };
            kinds.insert(name.to_string(), kind);
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        let (name, labels, value) = sample_line(line).ok_or_else(|| format!("line {}: not a sample: {line}", n + 1))?;
        // The family a sample belongs to: its own name, or its name without the suffix its type adds.
        let (family, kind) = match kinds.get(&name) {
            Some(Kind::Counter) => (name.strip_suffix("_total").unwrap_or(&name).to_string(), Kind::Counter),
            Some(k) => (name.clone(), *k),
            None => match name
                .strip_suffix("_total")
                .filter(|f| kinds.get(*f) == Some(&Kind::Counter))
            {
                Some(f) => (f.to_string(), Kind::Counter),
                None => (name.clone(), Kind::Gauge),
            },
        };
        let help = helps
            .get(&name)
            .or_else(|| helps.get(&family))
            .cloned()
            .unwrap_or_default();
        let at = match families.iter().position(|f| f.name == family) {
            Some(i) => i,
            None => {
                families.push(Family::new(&family, kind, &help));
                families.len() - 1
            }
        };
        families[at].samples.push(Sample { labels, value });
    }
    for f in &mut families {
        if f.kind == Kind::Gauge
            && f.name.ends_with("_info")
            && !f.samples.is_empty()
            && f.samples.iter().all(|s| s.value == 1.0)
        {
            f.name.truncate(f.name.len() - "_info".len());
            f.kind = Kind::Info;
        }
    }
    Ok(families)
}

/// A sample's labels, by name, in the order they came.
type Labels = Vec<(String, String)>;

/// `name{labels} value`, or `name value`, with an optional timestamp after the value, which is dropped.
fn sample_line(line: &str) -> Option<(String, Labels, f64)> {
    let (name, labels, rest) = match line.find('{') {
        Some(open) => {
            let name = &line[..open];
            let (labels, after) = label_set(&line[open + 1..])?;
            (name, labels, after)
        }
        None => {
            let (name, rest) = line.split_once(' ')?;
            (name, Vec::new(), rest)
        }
    };
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':') {
        return None;
    }
    let value = rest.split_whitespace().next()?;
    let value = match value {
        "NaN" => f64::NAN,
        "+Inf" | "Inf" => f64::INFINITY,
        "-Inf" => f64::NEG_INFINITY,
        v => v.parse().ok()?,
    };
    Some((name.to_string(), labels, value))
}

/// The labels after `{`, up to and including `}`, and what follows them.
fn label_set(s: &str) -> Option<(Labels, &str)> {
    let mut labels = Vec::new();
    let mut rest = s.trim_start();
    loop {
        if let Some(after) = rest.strip_prefix('}') {
            return Some((labels, after));
        }
        let eq = rest.find('=')?;
        let key = rest[..eq].trim().to_string();
        let mut chars = rest[eq + 1..].char_indices();
        if chars.next()?.1 != '"' {
            return None;
        }
        let mut value = String::new();
        let mut escaped = false;
        let mut end = None;
        for (i, c) in chars {
            match (escaped, c) {
                (true, 'n') => {
                    value.push('\n');
                    escaped = false;
                }
                (true, c) => {
                    value.push(c);
                    escaped = false;
                }
                (false, '\\') => escaped = true,
                (false, '"') => {
                    end = Some(i);
                    break;
                }
                (false, c) => value.push(c),
            }
        }
        rest = rest[eq + 1 + end? + 1..].trim_start();
        rest = rest.strip_prefix(',').unwrap_or(rest).trim_start();
        labels.push((key, value));
    }
}

/// Help text as the formats escape it, read back: `\\` and `\n`, and `\"` where OpenMetrics wrote one.
fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut escaped = false;
    for c in s.chars() {
        match (escaped, c) {
            (true, 'n') => {
                out.push('\n');
                escaped = false;
            }
            (true, c) => {
                out.push(c);
                escaped = false;
            }
            (false, '\\') => escaped = true,
            (false, c) => out.push(c),
        }
    }
    out
}

/// The same families with `labels` added in front of each sample's own, where a sample does not already carry a
/// label of that name: a cloud door names where a member's series sit, and a series that already says (a member
/// that is itself a cloud door, re-serving its own members) keeps what it says.
pub fn labelled(families: Vec<Family>, labels: &[(&str, &str)]) -> Vec<Family> {
    families
        .into_iter()
        .map(|mut f| {
            for s in &mut f.samples {
                let mut added: Vec<(String, String)> = labels
                    .iter()
                    .filter(|(k, _)| !s.labels.iter().any(|(own, _)| own == k))
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect();
                added.append(&mut s.labels);
                s.labels = added;
            }
            f
        })
        .collect()
}

/// Commands refused at the door before they were accepted, by type and refusal code, since the door started. A
/// refusal is told to its sender only, and kept nowhere else, so this count is the one record of how many there
/// were.
#[derive(Default)]
pub struct Refusals(Mutex<BTreeMap<(String, &'static str), u64>>);

impl Refusals {
    pub fn count(&self, command: &str, code: &'static str) {
        *self.0.lock().unwrap().entry((command.to_string(), code)).or_default() += 1;
    }

    pub fn snapshot(&self) -> BTreeMap<(String, &'static str), u64> {
        self.0.lock().unwrap().clone()
    }
}

/// How many event streams are open on the door now.
#[derive(Default)]
pub struct OpenStreams(Arc<AtomicUsize>);

/// One open stream, counted while it lives.
pub struct Held(Arc<AtomicUsize>);

impl OpenStreams {
    pub fn hold(&self) -> Held {
        self.0.fetch_add(1, Ordering::Relaxed);
        Held(self.0.clone())
    }

    pub fn now(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The series of the whole door: commands accepted and refused since the door started (a finished command's line
/// in the log keeps no type to count again from), the events it told by type since its log began, and the event
/// streams open now.
pub fn door_families(
    accepted: &BTreeMap<String, u64>,
    refused: &Refusals,
    events: &BTreeMap<String, u64>,
    open_streams: usize,
) -> Vec<Family> {
    let mut a = Family::new(
        "best_peer_commands_accepted",
        Kind::Counter,
        "Commands the door accepted, by type, since it started.",
    );
    for (command, n) in accepted {
        a.sample(&[("command", command)], *n as f64);
    }
    let mut r = Family::new(
        "best_peer_commands_refused",
        Kind::Counter,
        "Commands the door refused before accepting them, by type and refusal code, since it started.",
    );
    for ((command, code), n) in refused.snapshot() {
        r.sample(&[("command", &command), ("code", code)], n as f64);
    }
    let mut e = Family::new(
        "best_peer_events",
        Kind::Counter,
        "Events the door told, by type, since its log began: placements (DeploymentStarted, JobStarted), failures, prompts answered.",
    );
    for (event, n) in events {
        e.sample(&[("event", event)], *n as f64);
    }
    let mut s = Family::new(
        "best_peer_event_streams",
        Kind::Gauge,
        "Event streams open on the door now.",
    );
    s.sample(&[], open_streams as f64);
    vec![a, r, e, s]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn families() -> Vec<Family> {
        let mut free =
            Family::new("best_peer_device_memory_free_bytes", Kind::Gauge, "Free device memory.").unit("bytes");
        free.sample(&[("device", "GPU-1"), ("vendor", "nvidia")], 1024.0);
        let mut c = Family::new("best_peer_events", Kind::Counter, "Events told,\nby type.");
        c.sample(&[("event", "Say \"hi\" \\ there")], 3.0);
        let mut i = Family::new("best_peer_device", Kind::Info, "What a device is.");
        i.sample(&[("device", "GPU-1"), ("name", "RTX")], 1.0);
        let mut t = Family::new("best_peer_device_temperature_celsius", Kind::Gauge, "Temperature.").unit("celsius");
        t.sample(&[("device", "GPU-1")], 41.5);
        vec![free, c, i, t]
    }

    #[test]
    fn what_render_writes_parse_reads_back_family_by_family() {
        let text = render(&families(), Format::Prometheus);
        let back = parse(&text).unwrap();
        let mut expected = families();
        for f in &mut expected {
            f.unit = None;
        }
        assert_eq!(back, expected, "{text}");
        assert_eq!(render(&back, Format::Prometheus), text);
        assert!(parse("best_peer_x{a=\"1\"} oops\n").unwrap_err().contains("line 1"));
        assert!(parse("<html>\n").is_err());
    }

    #[test]
    fn labelled_names_where_a_series_sits_and_keeps_what_it_already_says() {
        let mut f = Family::new("best_peer_device_power_watts", Kind::Gauge, "Power.");
        f.sample(&[("device", "gpu-0")], 300.0);
        f.sample(&[("peer", "inner"), ("device", "gpu-1")], 200.0);
        let out = labelled(vec![f], &[("workspace", "ws-1"), ("cloud", "lab"), ("peer", "a")]);
        let text = render(&out, Format::Prometheus);
        assert!(
            text.contains(
                "best_peer_device_power_watts{workspace=\"ws-1\",cloud=\"lab\",peer=\"a\",device=\"gpu-0\"} 300\n"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "best_peer_device_power_watts{workspace=\"ws-1\",cloud=\"lab\",peer=\"inner\",device=\"gpu-1\"} 200\n"
            ),
            "{text}"
        );
    }

    #[test]
    fn the_prometheus_text_names_types_and_escapes() {
        let text = render(&families(), Format::Prometheus);
        assert!(
            text.contains("# TYPE best_peer_device_memory_free_bytes gauge\n"),
            "{text}"
        );
        assert!(
            text.contains("best_peer_device_memory_free_bytes{device=\"GPU-1\",vendor=\"nvidia\"} 1024\n"),
            "{text}"
        );
        assert!(
            text.contains("# HELP best_peer_events_total Events told,\\nby type.\n"),
            "{text}"
        );
        assert!(text.contains("# TYPE best_peer_events_total counter\n"), "{text}");
        assert!(
            text.contains("best_peer_events_total{event=\"Say \\\"hi\\\" \\\\ there\"} 3\n"),
            "{text}"
        );
        assert!(
            text.contains("# TYPE best_peer_device_info gauge\n"),
            "an info is a gauge of 1 here: {text}"
        );
        assert!(
            text.contains("best_peer_device_temperature_celsius{device=\"GPU-1\"} 41.5\n"),
            "{text}"
        );
        assert!(!text.contains("# EOF") && !text.contains("# UNIT"), "{text}");
    }

    #[test]
    fn openmetrics_names_families_without_suffixes_says_units_and_ends() {
        let text = render(&families(), Format::OpenMetrics);
        assert!(text.contains("# TYPE best_peer_events counter\n"), "{text}");
        assert!(text.contains("best_peer_events_total{"), "{text}");
        assert!(text.contains("# TYPE best_peer_device info\n"), "{text}");
        assert!(
            text.contains("best_peer_device_info{device=\"GPU-1\",name=\"RTX\"} 1\n"),
            "{text}"
        );
        assert!(
            text.contains("# UNIT best_peer_device_memory_free_bytes bytes\n"),
            "{text}"
        );
        assert!(text.ends_with("# EOF\n"), "{text}");
    }

    #[test]
    fn a_family_named_twice_is_written_once() {
        let mut a = Family::new("best_peer_x", Kind::Gauge, "X.");
        a.sample(&[("k", "1")], 1.0);
        let mut b = Family::new("best_peer_x", Kind::Gauge, "Other help.");
        b.sample(&[("k", "2")], 2.0);
        let text = render(&[a, b], Format::Prometheus);
        assert_eq!(text.matches("# TYPE best_peer_x gauge").count(), 1, "{text}");
        assert!(
            text.contains("best_peer_x{k=\"1\"} 1\nbest_peer_x{k=\"2\"} 2\n"),
            "{text}"
        );
    }

    #[test]
    fn numbers_read_as_the_formats_write_them() {
        assert_eq!(number(3.0), "3");
        assert_eq!(number(0.25), "0.25");
        assert_eq!(number(f64::NAN), "NaN");
        assert_eq!(number(f64::INFINITY), "+Inf");
        assert_eq!(number(12_884_901_888.0), "12884901888");
    }

    #[test]
    fn the_scraper_chooses_the_format() {
        assert_eq!(Format::from_accept(None), Format::Prometheus);
        assert_eq!(Format::from_accept(Some("text/plain")), Format::Prometheus);
        assert_eq!(
            Format::from_accept(Some("application/openmetrics-text;version=1.0.0,text/plain;q=0.5")),
            Format::OpenMetrics
        );
    }

    #[test]
    fn an_open_stream_is_counted_while_it_lives() {
        let open = OpenStreams::default();
        let a = open.hold();
        let b = open.hold();
        assert_eq!(open.now(), 2);
        drop(a);
        assert_eq!(open.now(), 1);
        drop(b);
        assert_eq!(open.now(), 0);
    }

    #[test]
    fn a_quote_in_help_is_escaped_for_openmetrics_and_left_for_the_prometheus_text() {
        let f = Family::new("best_peer_q", Kind::Gauge, "Say \"why\".");
        assert!(render(std::slice::from_ref(&f), Format::OpenMetrics).contains("# HELP best_peer_q Say \\\"why\\\".\n"));
        assert!(render(&[f], Format::Prometheus).contains("# HELP best_peer_q Say \"why\".\n"));
    }
}
