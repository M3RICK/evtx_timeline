mod event;

use anyhow::{Context, Result};
use event::Event;
use evtx::EvtxParser;

fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .context("usage: evtx_timeline <file.evtx>")?;

    let mut parser = EvtxParser::from_path(&path)
        .with_context(|| format!("cannot open {path}"))?;

    let mut count = 0u64;
    for record in parser.records_json_value() {
        let record = record.context("failed to read a record")?;
        if let Some(event) = Event::from_record(&record) {
            println!(
                "{}  id={:<5}  {}  ({})",
                event.timestamp, event.event_id, event.channel, event.provider
            );
            count += 1;
        }
    }

    eprintln!("parsed {count} events");
    Ok(())
}
