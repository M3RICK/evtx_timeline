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
cargo run -- <path/to/file.evtx> [timeline.csv]
```

It prints one line per alert, in chronological order, with who and where when
the event says so (`target=`, `by=`, `ip=`...), and a summary (events parsed /
alerts found) on stderr. Unreadable records are skipped and counted, not fatal. Pass an optional second argument to also write the full, chronologically
sorted timeline to a CSV file.

## What it detects

Per-event rules live in [`rules.toml`](rules.toml), which is compiled into the
binary. A rule is an EventID, the channel it belongs to, a severity, and
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
cargo test
```

## Roadmap

- [x] Parse EVTX and normalize events
- [x] EventID-based detection with severity levels
- [x] Stateful brute-force detection (+ unit tests)
- [x] CSV timeline export
- [ ] JSON timeline export
- [x] Per-account and time-windowed brute-force detection
- [ ] More detection rules

---

*Personal project, work in progress. I'm using it to learn Rust while building
something useful for forensics, so the code grows one rule at a time.*
