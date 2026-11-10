# evtx_timeline

A small DFIR tool that parses Windows Event Log (`.evtx`) files and flags
suspicious activity, written in Rust.

It reads a log, normalizes each record, and runs two kinds of detection rules:

- **Per-event rules** -> flag a single event known to matter (log cleared,
  account created, service installed, privilege-group change...), defined in
  a TOML file.
- **Stateful rules** -> look at sequences, e.g. a burst of failed logons
  followed by a success (a likely successful brute force).

## Build

```bash
cargo build --release
```

## Usage

```bash
evtx_timeline <PATHS>... [OPTIONS]

# one log
cargo run --release -- Security.evtx

# a whole collected log folder, critical alerts only, plus a timeline
cargo run --release -- ./winevt/Logs --min-severity critical --csv timeline.csv
```

Each path is an `.evtx` file or a folder, searched recursively. Everything is
merged into one chronological timeline.

| Option | Effect |
|--------|--------|
| `--min-severity <info\|warning\|critical>` | Hide alerts below this level |
| `--json` | Print alerts as JSON, one object per line |
| `--csv <FILE>` | Write every event to a CSV timeline |
| `--jsonl <FILE>` | Write every event, with its full payload, as JSON Lines |
| `--rules <FILE>` | Use your own rules file instead of the built-in one |

Alerts go to stdout, one per line, in chronological order, with the machine
and who / from where when the event says so (`target=`, `by=`, `ip=`...). The
summary and warnings go to stderr. Files that will not open and records that
will not parse are skipped and reported, not fatal.

## What it detects

Per-event rules live in [`rules.toml`](rules.toml), which is compiled into the
binary (`--rules` swaps in your own file). A rule is an EventID, the channel it belongs to, a severity, and
optional conditions on the event's fields:

```toml
[[rule]]
id = [4728, 4732, 4756]
channel = "Security"
severity = "critical"
message = "Member added to a privileged group"
where = { TargetSid = ["*-544", "*-512", "*-518", "*-519"] }
```

The first matching rule wins. The shipped set covers log clearing, audit policy
changes, account and group changes, RDP logons, Kerberoasting, scheduled tasks,
service installs (PsExec-style ones are critical), suspicious PowerShell, a few
Sysmon events (encoded command lines, remote thread injection, LSASS access)
and Windows Defender alerts.

Plus a behavioral rule, in code: *5 or more failed logons (4625) on an account
within 10 minutes, followed by a success (4624) on that same account* →
possible brute force.

## Tests

```bash
cargo test                          # unit tests

./scripts/fetch-samples.sh          # download real attack logs (once)
cargo test -- --include-ignored     # + end-to-end tests against them
```

The end-to-end tests run the binary on logs recorded during real attack
techniques (mimikatz, PsExec-style services, log clearing...) from
[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) and
check each one raises its alert. CI runs both on every push.

## Roadmap

- [x] Parse EVTX and normalize events
- [x] EventID-based detection with severity levels
- [x] Stateful brute-force detection (+ unit tests)
- [x] CSV timeline export
- [x] JSON timeline export
- [x] Per-account and time-windowed brute-force detection
- [x] Rules in a TOML file, with channel and field conditions
- [x] Folder input, severity filter, JSON alerts
- [ ] Sigma rule support
- [ ] Password-spraying detection (many accounts from one source)

---

*Personal project, work in progress. I'm using it to learn Rust while building
something useful for forensics, so the code grows one rule at a time.*
