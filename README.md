# evtx_timeline

A small DFIR tool that parses Windows Event Log (`.evtx`) files and flags
suspicious activity, written in Rust.

It reads a log, normalizes each record, and runs two kinds of detection rules:

- **Per-event rules** -> flag a single EventID known to matter (log cleared,
  account created, service installed, privilege-group change...).
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

| EventID | Meaning | Severity |
|---------|---------|----------|
| 1102 | Security audit log was cleared | Critical |
| 4719 | System audit policy was changed | Critical |
| 4728 / 4732 | Member added to a privileged group (Administrators, Domain/Schema/Enterprise Admins) | Critical |
| 4728 / 4732 | Member added to any other security group | Warning |
| 7045 | A service was installed | Warning |
| 4720 | User account was created | Warning |
| 4722 | User account was enabled | Info |
| 4625 | Failed logon attempt | Info |

Plus a behavioral rule: *5 or more failed logons (4625) on an account within
10 minutes, followed by a success (4624) on that same account* → possible brute
force.

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
