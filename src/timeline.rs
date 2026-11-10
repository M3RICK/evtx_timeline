use crate::event::Event;
use anyhow::{Context, Result};
use serde_json::json;
use std::io::{BufWriter, Write};
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

/// Write all events as JSON Lines, in the order given (chronological). Unlike
/// the CSV, each line carries the event's whole payload.
pub fn write_jsonl(events: &[Event], path: &Path) -> Result<()> {
    let file =
        std::fs::File::create(path).with_context(|| format!("cannot write {}", path.display()))?;
    let mut out = BufWriter::new(file);

    for e in events {
        let line = json!({
            "timestamp": e.timestamp.to_string(),
            "event_id": e.event_id,
            "channel": e.channel,
            "provider": e.provider,
            "computer": e.computer,
            "data": e.data,
        });
        writeln!(out, "{line}")?;
    }

    out.flush()?;
    Ok(())
}
