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

/// Flag every event whose EventID matches a known rule.
pub fn scan(events: &[Event]) -> Vec<Alert> {
    events
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
        .collect()
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
