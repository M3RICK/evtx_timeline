use crate::event::Event;
use anyhow::{Context, Result};
use std::path::Path;

/// Write all events to a CSV file, sorted chronologically.
pub fn write_csv(events: &[Event], path: &Path) -> Result<()> {
    let mut sorted: Vec<&Event> = events.iter().collect();
    sorted.sort_by_key(|e| e.timestamp);

    let mut wtr =
        csv::Writer::from_path(path).with_context(|| format!("cannot write {}", path.display()))?;
    wtr.write_record(["timestamp", "event_id", "channel", "provider"])?;

    for e in sorted {
        wtr.write_record([
            e.timestamp.to_string(),
            e.event_id.to_string(),
            e.channel.clone(),
            e.provider.clone(),
        ])?;
    }

    wtr.flush()?;
    Ok(())
}
