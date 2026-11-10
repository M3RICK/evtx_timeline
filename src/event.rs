use evtx::{SerializedEvtxRecord, Timestamp};
use serde_json::Value;

/// A Windows event reduced to the fields a timeline needs.
#[derive(Debug)]
pub struct Event {
    pub timestamp: Timestamp,
    pub event_id: u64,
    pub channel: String,
    pub provider: String,
    pub computer: String,
    /// The event payload (EventData, or the UserData child), read via `field`.
    pub data: Value,
}

impl Event {
    /// Parse one record; None if it is malformed, so a bad record is skipped.
    pub fn from_record(mut record: SerializedEvtxRecord<Value>) -> Option<Event> {
        let event = record.data.get_mut("Event")?;
        let data = take_payload(event);
        let system = event.get("System")?;
        let text = |v: Option<&Value>| v.and_then(Value::as_str).unwrap_or("").to_string();

        Some(Event {
            timestamp: record.timestamp,
            event_id: extract_event_id(system)?,
            channel: text(system.get("Channel")),
            provider: text(
                system
                    .get("Provider")
                    .and_then(|p| p.get("#attributes"))
                    .and_then(|a| a.get("Name")),
            ),
            computer: text(system.get("Computer")),
            data,
        })
    }

    /// A string field of the payload (e.g. "TargetUserName"). Missing fields
    /// and the Windows placeholder "-" both come back as "".
    pub fn field(&self, key: &str) -> &str {
        match self.data.get(key).and_then(Value::as_str) {
            Some("-") | None => "",
            Some(s) => s,
        }
    }
}

/// Most events carry their fields in EventData; a few (like 1102, log cleared)
/// nest them one level down in UserData instead.
fn take_payload(event: &mut Value) -> Value {
    if let Some(data) = event.get_mut("EventData").filter(|d| d.is_object()) {
        return data.take();
    }
    event
        .get_mut("UserData")
        .and_then(Value::as_object_mut)
        .and_then(|u| u.values_mut().next())
        .map(Value::take)
        .unwrap_or_default()
}

/// EventID is a bare number, or `{"#text": N, "#attributes": {...}}` when the
/// event has a Qualifiers attribute. Handle both.
fn extract_event_id(system: &Value) -> Option<u64> {
    let eid = system.get("EventID")?;
    eid.as_u64()
        .or_else(|| eid.get("#text").and_then(|v| v.as_u64()))
}
