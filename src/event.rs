use evtx::{SerializedEvtxRecord, Timestamp};
use serde_json::Value;

/// A Windows event reduced to the fields a timeline needs.
#[derive(Debug)]
pub struct Event {
    pub timestamp: Timestamp,
    pub event_id: u64,
    pub channel: String,
    pub provider: String,
}

impl Event {
    /// Parse one record; None if it is malformed, so a bad record is skipped.
    pub fn from_record(record: &SerializedEvtxRecord<Value>) -> Option<Event> {
        let system = record.data.get("Event")?.get("System")?;

        Some(Event {
            timestamp: record.timestamp,
            event_id: extract_event_id(system)?,
            channel: system
                .get("Channel")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            provider: system
                .get("Provider")
                .and_then(|p| p.get("#attributes"))
                .and_then(|a| a.get("Name"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        })
    }
}

/// EventID is a bare number, or `{"#text": N, "#attributes": {...}}` when the
/// event has a Qualifiers attribute. Handle both.
fn extract_event_id(system: &Value) -> Option<u64> {
    let eid = system.get("EventID")?;
    eid.as_u64()
        .or_else(|| eid.get("#text").and_then(|v| v.as_u64()))
}
