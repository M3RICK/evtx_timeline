mod detect;
mod event;
mod timeline;

use anyhow::{Context, Result};
use detect::Alert;
use event::Event;
use evtx::EvtxParser;

fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .context("usage: evtx_timeline <file.evtx> [timeline.csv]")?;

    let events = load_events(&path)?;
    eprintln!("parsed {} events", events.len());

    let alerts = detect::scan(&events);
    eprintln!("found {} alerts", alerts.len());
    print_alerts(&alerts);

    if let Some(csv_path) = std::env::args().nth(2) {
        timeline::write_csv(&events, std::path::Path::new(&csv_path))?;
        eprintln!("wrote timeline to {csv_path}");
    }

    Ok(())
}

/// Read every parsable event from an .evtx file into memory, oldest first.
/// Corrupted records are common in forensic images: skip them, don't abort.
fn load_events(path: &str) -> Result<Vec<Event>> {
    let mut parser = EvtxParser::from_path(path).with_context(|| format!("cannot open {path}"))?;
    let mut events = Vec::new();
    let mut skipped = 0u32;

    for record in parser.records_json_value() {
        match record.ok().and_then(Event::from_record) {
            Some(event) => events.push(event),
            None => skipped += 1,
        }
    }

    if skipped > 0 {
        eprintln!("warning: skipped {skipped} unreadable records");
    }
    events.sort_by_key(|e| e.timestamp);

    Ok(events)
}

/// Print one line per alert.
fn print_alerts(alerts: &[Alert]) {
    for a in alerts {
        println!(
            "[{:?}] {}  id={:<5}  {}  {}",
            a.severity, a.timestamp, a.event_id, a.message, a.details
        );
    }
}
