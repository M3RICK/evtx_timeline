use crate::event::Event;
use evtx::Timestamp;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq)]
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
    pub message: &'static str,
    /// Who / from where, e.g. "target=bob by=admin ip=10.0.0.5".
    pub details: String,
}

impl Alert {
    fn new(e: &Event, severity: Severity, message: &'static str) -> Alert {
        Alert {
            severity,
            timestamp: e.timestamp,
            event_id: e.event_id,
            message,
            details: details(e),
        }
    }
}

/// Run every detection rule over the events (expected in chronological
/// order): the per-event rules, then the stateful ones that look at sequences.
pub fn scan(events: &[Event]) -> Vec<Alert> {
    let mut alerts: Vec<Alert> = events
        .iter()
        .filter_map(|e| {
            let (severity, message) = rule_for(e)?;
            Some(Alert::new(e, severity, message))
        })
        .collect();

    alerts.extend(detect_bruteforce(events));
    alerts.sort_by_key(|a| a.timestamp);
    alerts
}

/// Payload fields worth showing next to an alert, with their short label.
const CONTEXT_FIELDS: [(&str, &str); 7] = [
    ("TargetUserName", "target"),
    ("MemberSid", "member"),
    ("SubjectUserName", "by"),
    ("IpAddress", "ip"),
    ("WorkstationName", "host"),
    ("ServiceName", "service"),
    ("ImagePath", "path"),
];

/// Build the "label=value ..." context string from whichever fields exist.
fn details(e: &Event) -> String {
    CONTEXT_FIELDS
        .iter()
        .filter(|(key, _)| !e.field(key).is_empty())
        .map(|(key, label)| format!("{label}={}", e.field(key)))
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

/// Well-known RIDs of groups that grant admin rights: Administrators,
/// Domain Admins, Schema Admins, Enterprise Admins.
const PRIVILEGED_RIDS: [&str; 4] = ["544", "512", "518", "519"];

/// Map a suspicious Windows event to (severity, description).
/// None means we do not flag this event.
fn rule_for(e: &Event) -> Option<(Severity, &'static str)> {
    match e.event_id {
        1102 => Some((Severity::Critical, "Security audit log was cleared")),
        4625 => Some((Severity::Info, "Failed logon attempt")),
        4719 => Some((Severity::Critical, "System audit policy was changed")),
        4720 => Some((Severity::Warning, "User account was created")),
        4722 => Some((Severity::Info, "User account was enabled")),
        // The group is the "target" here; its SID ends with the group's RID.
        4728 | 4732 => {
            let rid = e.field("TargetSid").rsplit('-').next().unwrap_or("");
            Some(if PRIVILEGED_RIDS.contains(&rid) {
                (Severity::Critical, "Member added to a privileged group")
            } else {
                (Severity::Warning, "Member added to a security group")
            })
        }
        7045 => Some((Severity::Warning, "A service was installed on the system")),
        _ => None,
    }
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

    #[test]
    fn only_privileged_groups_are_critical() {
        let admins = ev(4732, 0, json!({ "TargetSid": "S-1-5-32-544" }));
        let users = ev(4732, 0, json!({ "TargetSid": "S-1-5-32-545" }));
        assert_eq!(rule_for(&admins).unwrap().0, Severity::Critical);
        assert_eq!(rule_for(&users).unwrap().0, Severity::Warning);
    }
}
