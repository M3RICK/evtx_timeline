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
cargo run -- <path/to/file.evtx>
```

It prints one line per alert and a summary (events parsed / alerts found) on
stderr.

## What it detects

| EventID | Meaning | Severity |
|---------|---------|----------|
| 1102 | Security audit log was cleared | Critical |
| 4719 | System audit policy was changed | Critical |
| 4728 | Member added to a security-enabled global group | Critical |
| 4732 | Member added to a security-enabled local group | Critical |
| 7045 | A service was installed | Warning |
| 4720 | User account was created | Warning |
| 4722 | User account was enabled | Info |
| 4625 | Failed logon attempt | Info |

Plus a behavioral rule: *N failed logons (4625) followed by a success (4624)*
→ possible brute force.

## Tests

```bash
cargo test
```

## Roadmap

- [x] Parse EVTX and normalize events
- [x] EventID-based detection with severity levels
- [x] Stateful brute-force detection (+ unit tests)
- [ ] CSV / JSON timeline export
- [ ] Per-account and time-windowed brute-force detection
- [ ] More detection rules

---

*Personal project, work in progress. I'm using it to learn Rust while building
something useful for forensics, so the code grows one rule at a time.*
