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
        .context("usage: evtx_timeline <file.evtx>")?;

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

/// Read every parsable event from an .evtx file into memory.
fn load_events(path: &str) -> Result<Vec<Event>> {
    let mut parser = EvtxParser::from_path(path).with_context(|| format!("cannot open {path}"))?;
    let mut events = Vec::new();

    for record in parser.records_json_value() {
        let record = record.context("failed to read a record")?;
        if let Some(event) = Event::from_record(&record) {
            events.push(event);
        }
    }

    Ok(events)
}

/// Print one line per alert.
fn print_alerts(alerts: &[Alert]) {
    for a in alerts {
        println!(
            "[{:?}] {}  id={:<5}  {}",
            a.severity, a.timestamp, a.event_id, a.message
        );
    }
}
