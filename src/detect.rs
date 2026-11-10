use crate::event::Event;
use anyhow::{Context, Result};
use evtx::Timestamp;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

/// An event that matched a detection rule.
#[derive(Debug)]
pub struct Alert {
    pub severity: Severity,
    pub timestamp: Timestamp,
    pub event_id: u64,
    /// Machine that logged the event (several can be merged in one run).
    pub computer: String,
    pub message: String,
    /// Who / from where, e.g. "target=bob by=admin ip=10.0.0.5".
    pub details: String,
}

impl Alert {
    fn new(e: &Event, severity: Severity, message: &str) -> Alert {
        Alert {
            severity,
            timestamp: e.timestamp,
            event_id: e.event_id,
            computer: e.computer.clone(),
            message: message.to_string(),
            details: details(e),
        }
    }
}

/// The rules shipped inside the binary, used unless the user brings a file.
pub const DEFAULT_RULES: &str = include_str!("../rules.toml");

/// A TOML value that may be written alone or as a list: `4624` or `[4728, 4732]`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> OneOrMany<T> {
    fn as_slice(&self) -> &[T] {
        match self {
            OneOrMany::One(x) => std::slice::from_ref(x),
            OneOrMany::Many(xs) => xs,
        }
    }
}

/// One per-event detection rule, as written in the rules file (see rules.toml
/// for the format).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    id: OneOrMany<u64>,
    channel: Option<String>,
    severity: Severity,
    message: String,
    /// Payload field -> accepted pattern(s). All fields must match.
    #[serde(default, rename = "where")]
    conditions: HashMap<String, OneOrMany<String>>,
}

impl Rule {
    fn matches(&self, e: &Event) -> bool {
        self.id.as_slice().contains(&e.event_id)
            && self
                .channel
                .as_ref()
                .is_none_or(|c| c.eq_ignore_ascii_case(&e.channel))
            && self.conditions.iter().all(|(field, patterns)| {
                let value = e.field(field);
                patterns.as_slice().iter().any(|p| wildcard_match(p, value))
            })
    }
}

/// Case-insensitive match where the pattern may start and/or end with `*`.
fn wildcard_match(pattern: &str, value: &str) -> bool {
    let (p, v) = (pattern.to_lowercase(), value.to_lowercase());
    match (p.strip_prefix('*'), p.strip_suffix('*')) {
        (Some(_), Some(_)) if p.len() >= 2 => v.contains(&p[1..p.len() - 1]),
        (Some(suffix), _) => v.ends_with(suffix),
        (_, Some(prefix)) => v.starts_with(prefix),
        _ => v == p,
    }
}

/// Parse a rules file. Typos (unknown key, bad severity) are errors, so a
/// broken rule never silently stops detecting.
pub fn parse_rules(text: &str) -> Result<Vec<Rule>> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RuleFile {
        rule: Vec<Rule>,
    }
    let file: RuleFile = toml::from_str(text).context("invalid rules file")?;
    Ok(file.rule)
}

/// Run every detection over the events (expected in chronological order):
/// the per-event rules (first matching rule wins), then the stateful
/// detections that look at sequences.
pub fn scan(events: &[Event], rules: &[Rule]) -> Vec<Alert> {
    let mut alerts: Vec<Alert> = events
        .iter()
        .filter_map(|e| {
            let rule = rules.iter().find(|r| r.matches(e))?;
            Some(Alert::new(e, rule.severity, &rule.message))
        })
        .collect();

    alerts.extend(detect_bruteforce(events));
    alerts.sort_by_key(|a| a.timestamp);
    alerts
}

/// Payload fields worth showing next to an alert, with their short label.
const CONTEXT_FIELDS: [(&str, &str); 15] = [
    ("TargetUserName", "target"),
    ("MemberSid", "member"),
    ("SubjectUserName", "by"),
    ("IpAddress", "ip"),
    ("WorkstationName", "host"),
    ("LogonType", "logon_type"),
    ("ServiceName", "service"),
    ("ImagePath", "path"),
    ("TaskName", "task"),
    ("Image", "image"),
    ("SourceImage", "source"),
    ("TargetImage", "target_image"),
    ("CommandLine", "cmd"),
    ("Threat Name", "threat"),
    ("ScriptBlockText", "script"),
];

/// Longest field value shown in an alert line (command lines can be huge).
const MAX_DETAIL_CHARS: usize = 200;

/// Build the "label=value ..." context string from whichever fields exist.
fn details(e: &Event) -> String {
    CONTEXT_FIELDS
        .iter()
        .filter(|(key, _)| !e.field(key).is_empty())
        .map(|(key, label)| {
            // Scripts span lines; an alert must stay on one.
            let value: String = e
                .field(key)
                .chars()
                .take(MAX_DETAIL_CHARS)
                .map(|c| if c.is_control() { ' ' } else { c })
                .collect();
            format!("{label}={value}")
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// How many failed logons before a success looks like brute force...
const BRUTEFORCE_THRESHOLD: usize = 5;
/// ...when they all happened within this many seconds before the success.
const BRUTEFORCE_WINDOW_SECS: i64 = 600;

/// Flag a burst of failed logons (4625) on one account ending in a success
/// (4624) on that same account: a likely successful brute force.
/// Events must be in chronological order.
pub fn detect_bruteforce(events: &[Event]) -> Vec<Alert> {
    let mut alerts = Vec::new();
    // Account name (lowercased, Windows names are case-insensitive) -> times
    // of the failed logons since its last success.
    let mut failures: HashMap<String, Vec<Timestamp>> = HashMap::new();

    for e in events {
        let account = e.field("TargetUserName").to_lowercase();
        match e.event_id {
            4625 => failures.entry(account).or_default().push(e.timestamp),
            4624 => {
                let recent = failures
                    .remove(&account)
                    .unwrap_or_default()
                    .iter()
                    .filter(|t| e.timestamp.duration_since(**t).as_secs() <= BRUTEFORCE_WINDOW_SECS)
                    .count();
                if recent >= BRUTEFORCE_THRESHOLD {
                    let mut alert = Alert::new(
                        e,
                        Severity::Critical,
                        "Successful logon after repeated failures (possible brute force)",
                    );
                    alert.details += &format!(" failures={recent}");
                    alerts.push(alert);
                }
            }
            _ => {}
        }
    }

    alerts
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Build a minimal event: an EventID, a payload, and a time in seconds.
    fn ev(event_id: u64, secs: i64, data: serde_json::Value) -> Event {
        Event {
            timestamp: Timestamp::from_second(secs).unwrap(),
            event_id,
            channel: String::new(),
            provider: String::new(),
            computer: String::new(),
            data,
        }
    }

    /// A logon event (4625 failure / 4624 success) for one account.
    fn logon(event_id: u64, secs: i64, user: &str) -> Event {
        ev(event_id, secs, json!({ "TargetUserName": user }))
    }

    /// `n` failed logons for `user`, one per second starting at `start`.
    fn failures(n: i64, start: i64, user: &str) -> Vec<Event> {
        (0..n).map(|i| logon(4625, start + i, user)).collect()
    }

    #[test]
    fn fires_after_threshold_failures_then_success() {
        let mut events = failures(5, 0, "bob");
        events.push(logon(4624, 10, "BOB")); // account names ignore case
        let alerts = detect_bruteforce(&events);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].details, "target=BOB failures=5");
    }

    #[test]
    fn success_resets_the_failure_streak() {
        let mut events = failures(3, 0, "bob");
        events.push(logon(4624, 10, "bob"));
        events.extend(failures(3, 20, "bob"));
        events.push(logon(4624, 30, "bob"));
        assert_eq!(detect_bruteforce(&events).len(), 0);
    }

    #[test]
    fn failures_on_another_account_do_not_count() {
        let mut events = failures(5, 0, "bob");
        events.push(logon(4624, 10, "alice"));
        assert_eq!(detect_bruteforce(&events).len(), 0);
    }

    #[test]
    fn failures_outside_the_window_do_not_count() {
        let mut events = failures(5, 0, "bob");
        events.push(logon(4624, BRUTEFORCE_WINDOW_SECS + 60, "bob"));
        assert_eq!(detect_bruteforce(&events).len(), 0);
    }

    /// Scan one event with the shipped rules; return its alert, if any.
    fn scan_one(mut e: Event, channel: &str) -> Option<Alert> {
        e.channel = channel.to_string();
        let rules = parse_rules(DEFAULT_RULES).expect("shipped rules must parse");
        scan(&[e], &rules).pop()
    }

    #[test]
    fn only_privileged_groups_are_critical() {
        let admins = ev(4732, 0, json!({ "TargetSid": "S-1-5-32-544" }));
        let users = ev(4732, 0, json!({ "TargetSid": "S-1-5-32-545" }));
        let severity = |e| scan_one(e, "Security").unwrap().severity;
        assert_eq!(severity(admins), Severity::Critical);
        assert_eq!(severity(users), Severity::Warning);
    }

    #[test]
    fn same_id_in_another_channel_is_not_flagged() {
        assert!(scan_one(ev(1102, 0, json!({})), "security").is_some());
        assert!(scan_one(ev(1102, 0, json!({})), "Application").is_none());
    }

    #[test]
    fn where_conditions_must_hold() {
        let rdp = ev(4624, 0, json!({ "LogonType": "10" }));
        let console = ev(4624, 0, json!({ "LogonType": "2" }));
        assert_eq!(
            scan_one(rdp, "Security").unwrap().message,
            "Remote Desktop logon"
        );
        assert!(scan_one(console, "Security").is_none());
    }

    #[test]
    fn details_stay_on_one_line() {
        let e = ev(4104, 0, json!({ "ScriptBlockText": "a\r\n\tb" }));
        assert_eq!(details(&e), "script=a   b");
    }

    #[test]
    fn wildcards() {
        assert!(wildcard_match("*-544", "S-1-5-32-544"));
        assert!(!wildcard_match("*-544", "S-1-5-32-545"));
        assert!(wildcard_match("cmd*", "CMD.EXE /c whoami"));
        assert!(wildcard_match(
            "*downloadstring*",
            "IEX (x).DownloadString('u')"
        ));
        assert!(wildcard_match("0x17", "0X17"));
        assert!(!wildcard_match("0x17", "0x170"));
    }

    #[test]
    fn rule_typos_are_rejected() {
        let rule = |extra: &str| {
            format!("[[rule]]\nid = 1\nseverity = \"info\"\nmessage = \"m\"\n{extra}")
        };
        assert!(parse_rules(&rule("")).is_ok());
        assert!(parse_rules(&rule("chanel = \"Security\"")).is_err());
        assert!(parse_rules(&rule("").replace("info", "severe")).is_err());
    }
}
