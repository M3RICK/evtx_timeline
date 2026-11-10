use crate::event::Event;
use anyhow::{Context, Result};
use std::path::Path;

/// Write all events to a CSV file, in the order given (chronological).
pub fn write_csv(events: &[Event], path: &Path) -> Result<()> {
    let mut wtr =
        csv::Writer::from_path(path).with_context(|| format!("cannot write {}", path.display()))?;
    wtr.write_record([
        "timestamp",
        "event_id",
        "channel",
        "provider",
        "computer",
        "target_user",
        "subject_user",
        "ip",
    ])?;

    for e in events {
        wtr.write_record([
            &e.timestamp.to_string(),
            &e.event_id.to_string(),
            &e.channel,
            &e.provider,
            &e.computer,
            e.field("TargetUserName"),
            e.field("SubjectUserName"),
            e.field("IpAddress"),
        ])?;
    }

    wtr.flush()?;
    Ok(())
}
