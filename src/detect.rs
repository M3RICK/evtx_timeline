use crate::event::Event;
use evtx::Timestamp;

#[derive(Debug, Clone, Copy)]
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
}

/// Run every detection rule over the events: the per-event rules first,
/// then the stateful ones that look at sequences.
pub fn scan(events: &[Event]) -> Vec<Alert> {
    let mut alerts: Vec<Alert> = events
        .iter()
        .filter_map(|e| {
            let (severity, message) = rule_for(e.event_id)?;
            Some(Alert {
                severity,
                timestamp: e.timestamp,
                event_id: e.event_id,
                message,
            })
        })
        .collect();

    alerts.extend(detect_bruteforce(events));
    alerts
}

/// How many failed logons in a row before a success looks like brute force.
const BRUTEFORCE_THRESHOLD: u32 = 5;

/// Flag a burst of failed logons (4625) ending in a success (4624): a likely
/// successful brute force. Counter is global for now, not per-account.
pub fn detect_bruteforce(events: &[Event]) -> Vec<Alert> {
    let mut alerts = Vec::new();
    let mut failures = 0u32;

    for e in events {
        match e.event_id {
            4625 => failures += 1,
            4624 => {
                if failures >= BRUTEFORCE_THRESHOLD {
                    alerts.push(bruteforce_alert(e));
                }
                failures = 0;
            }
            _ => {}
        }
    }

    alerts
}

/// Build the alert raised when a brute-force burst ends in a success.
fn bruteforce_alert(e: &Event) -> Alert {
    Alert {
        severity: Severity::Critical,
        timestamp: e.timestamp,
        event_id: e.event_id,
        message: "Successful logon after repeated failures (possible brute force)",
    }
}

/// Map a suspicious Windows Security EventID to (severity, description).
/// None means we do not flag this event.
fn rule_for(event_id: u64) -> Option<(Severity, &'static str)> {
    match event_id {
        1102 => Some((Severity::Critical, "Security audit log was cleared")),
        4625 => Some((Severity::Info, "Failed logon attempt")),
        4719 => Some((Severity::Critical, "System audit policy was changed")),
        4720 => Some((Severity::Warning, "User account was created")),
        4722 => Some((Severity::Info, "User account was enabled")),
        4728 => Some((
            Severity::Critical,
            "Member added to a security-enabled global group",
        )),
        4732 => Some((
            Severity::Critical,
            "Member added to a security-enabled local group",
        )),
        7045 => Some((Severity::Warning, "A service was installed on the system")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal event carrying just an EventID (enough for detection).
    fn ev(event_id: u64) -> Event {
        Event {
            timestamp: Timestamp::UNIX_EPOCH,
            event_id,
            channel: String::new(),
            provider: String::new(),
        }
    }

    #[test]
    fn fires_after_threshold_failures_then_success() {
        let events = vec![ev(4625), ev(4625), ev(4625), ev(4625), ev(4625), ev(4624)];
        let alerts = detect_bruteforce(&events);
        assert_eq!(alerts.len(), 1);
    }

    #[test]
    fn success_resets_the_failure_streak() {
        let events = vec![
            ev(4625),
            ev(4625),
            ev(4625),
            ev(4624),
            ev(4625),
            ev(4625),
            ev(4625),
            ev(4624),
        ];
        let resets_failures = detect_bruteforce(&events);
        assert_eq!(resets_failures.len(), 0);
    }
}
