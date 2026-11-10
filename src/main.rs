mod detect;
mod event;
mod timeline;

use anyhow::{Context, Result, bail};
use clap::Parser;
use detect::{Alert, Severity};
use event::Event;
use evtx::EvtxParser;
use serde_json::json;
use std::path::{Path, PathBuf};

/// Parse Windows Event Logs, flag suspicious activity, export a timeline.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// .evtx files, or folders to search (recursively) for .evtx files
    #[arg(required = true)]
    paths: Vec<PathBuf>,

    /// Use this rules file instead of the built-in rules
    #[arg(long, value_name = "FILE")]
    rules: Option<PathBuf>,

    /// Only show alerts of at least this severity
    #[arg(long, value_enum, default_value = "info", value_name = "LEVEL")]
    min_severity: Severity,

    /// Print alerts as JSON, one object per line
    #[arg(long)]
    json: bool,

    /// Write the full timeline (every event) to a CSV file
    #[arg(long, value_name = "FILE")]
    csv: Option<PathBuf>,

    /// Write the full timeline, with each event's payload, as JSON Lines
    #[arg(long, value_name = "FILE")]
    jsonl: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let rules = match &cli.rules {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("cannot read {}", path.display()))?;
            detect::parse_rules(&text).with_context(|| format!("in {}", path.display()))?
        }
        None => detect::parse_rules(detect::DEFAULT_RULES)?,
    };

    let mut files = Vec::new();
    for path in &cli.paths {
        collect_evtx(path, &mut files)?;
    }
    let events = load_events(&files)?;
    eprintln!("parsed {} events from {} files", events.len(), files.len());

    let mut alerts = detect::scan(&events, &rules);
    alerts.retain(|a| a.severity >= cli.min_severity);
    eprintln!("found {} alerts", alerts.len());
    print_alerts(&alerts, cli.json);

    if let Some(path) = &cli.csv {
        timeline::write_csv(&events, path)?;
        eprintln!("wrote timeline to {}", path.display());
    }
    if let Some(path) = &cli.jsonl {
        timeline::write_jsonl(&events, path)?;
        eprintln!("wrote timeline to {}", path.display());
    }

    Ok(())
}

/// Add `path` to `files` if it is a file (whatever its name: the user asked
/// for it), or every .evtx file under it if it is a folder.
fn collect_evtx(path: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    if !path.is_dir() {
        files.push(path.to_path_buf());
        return Ok(());
    }

    let entries =
        std::fs::read_dir(path).with_context(|| format!("cannot read {}", path.display()))?;
    for entry in entries {
        let entry = entry?;
        let child = entry.path();
        // file_type() does not follow symlinks, so a link loop cannot trap us.
        if entry.file_type()?.is_dir() {
            collect_evtx(&child, files)?;
        } else if child
            .extension()
            .is_some_and(|x| x.eq_ignore_ascii_case("evtx"))
        {
            files.push(child);
        }
    }
    Ok(())
}

/// Read every parsable event from the files into memory, oldest first.
/// Forensic images are full of empty or damaged logs: a file that will not
/// open and a record that will not parse are reported and skipped. Only
/// having nothing readable at all is an error.
fn load_events(files: &[PathBuf]) -> Result<Vec<Event>> {
    let mut events = Vec::new();
    let mut opened = 0;

    for path in files {
        let mut parser = match EvtxParser::from_path(path) {
            Ok(parser) => parser,
            Err(e) => {
                eprintln!("warning: skipping {}: {e}", path.display());
                continue;
            }
        };
        opened += 1;

        let mut skipped = 0u32;
        for record in parser.records_json_value() {
            match record.ok().and_then(Event::from_record) {
                Some(event) => events.push(event),
                None => skipped += 1,
            }
        }
        if skipped > 0 {
            eprintln!(
                "warning: {}: skipped {skipped} unreadable records",
                path.display()
            );
        }
    }

    if opened == 0 {
        bail!("no readable .evtx file found");
    }
    events.sort_by_key(|e| e.timestamp);
    Ok(events)
}

/// Print one line per alert: human-readable text, or JSON for other tools.
fn print_alerts(alerts: &[Alert], as_json: bool) {
    for a in alerts {
        if as_json {
            println!(
                "{}",
                json!({
                    "severity": format!("{:?}", a.severity).to_lowercase(),
                    "timestamp": a.timestamp.to_string(),
                    "event_id": a.event_id,
                    "computer": a.computer,
                    "message": a.message,
                    "details": a.details,
                })
            );
        } else {
            println!(
                "[{:?}] {}  {}  id={:<5}  {}  {}",
                a.severity, a.timestamp, a.computer, a.event_id, a.message, a.details
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folders_are_searched_recursively_for_evtx_only() {
        let root = std::env::temp_dir().join(format!("evtx_timeline_test_{}", std::process::id()));
        std::fs::create_dir_all(root.join("sub")).unwrap();
        for name in ["a.evtx", "notes.txt", "sub/B.EVTX"] {
            std::fs::write(root.join(name), "").unwrap();
        }

        let mut files = Vec::new();
        collect_evtx(&root, &mut files).unwrap();
        collect_evtx(&root.join("notes.txt"), &mut files).unwrap(); // explicit file: kept
        files.sort();
        std::fs::remove_dir_all(&root).unwrap();

        let names: Vec<_> = files
            .iter()
            .map(|f| f.strip_prefix(&root).unwrap())
            .collect();
        assert_eq!(names, ["a.evtx", "notes.txt", "sub/B.EVTX"].map(Path::new));
    }
}
