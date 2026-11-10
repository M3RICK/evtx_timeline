//! End-to-end check against real attack logs: run the binary on each sample
//! and expect the detection it was recorded to demonstrate.
//!
//! The samples are not in the repository. Fetch them, then include this test:
//!
//!     ./scripts/fetch-samples.sh
//!     cargo test -- --include-ignored

use std::process::Command;

/// (sample file, severity, message of the alert it must raise)
const EXPECTED: [(&str, &str, &str); 12] = [
    (
        "DE_1102_security_log_cleared",
        "critical",
        "Security audit log was cleared",
    ),
    (
        "DE_104_system_log_cleared",
        "critical",
        "An event log was cleared",
    ),
    (
        "DE_Fake_ComputerAccount_4720",
        "warning",
        "User account was created",
    ),
    (
        "meterpreter_migrate_to_explorer_sysmon_8",
        "warning",
        "Thread injected into another process (CreateRemoteThread)",
    ),
    (
        "sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords",
        "critical",
        "LSASS process memory was accessed (possible credential dumping)",
    ),
    (
        "Powershell_4104_MiniDumpWriteDump_Lsass",
        "warning",
        "Suspicious PowerShell script block",
    ),
    (
        "LM_Remote_Service02_7045",
        "critical",
        "Service runs a command interpreter or admin share (PsExec-style)",
    ),
    (
        "System_7045_namedpipe_privesc",
        "critical",
        "Service runs a command interpreter or admin share (PsExec-style)",
    ),
    ("DE_RDP_Tunneling_4624", "warning", "Remote Desktop logon"),
    (
        "Network_Service_Guest_added_to_admins_4732",
        "critical",
        "Member added to a privileged group",
    ),
    (
        "temp_scheduled_task_4698_4699",
        "warning",
        "Scheduled task was created",
    ),
    (
        "WinDefender_Events_1117_1116_AtomicRedTeam",
        "critical",
        "Defender detected malware",
    ),
];

/// Run the binary and return its alerts, parsed from `--json` output.
fn alerts(args: &[&str]) -> Vec<serde_json::Value> {
    let out = Command::new(env!("CARGO_BIN_EXE_evtx_timeline"))
        .args(args)
        .arg("--json")
        .output()
        .expect("cannot run the binary");
    assert!(
        out.status.success(),
        "{args:?} failed: {}\n(did you run ./scripts/fetch-samples.sh?)",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).expect("each alert is one JSON object"))
        .collect()
}

#[test]
#[ignore = "needs ./scripts/fetch-samples.sh"]
fn each_attack_sample_raises_its_alert() {
    let missed: Vec<_> = EXPECTED
        .iter()
        .filter(|(file, severity, message)| {
            let path = format!("samples/attack/{file}.evtx");
            !alerts(&[&path])
                .iter()
                .any(|a| a["severity"] == *severity && a["message"] == *message)
        })
        .collect();
    assert!(missed.is_empty(), "not detected: {missed:#?}");
}

#[test]
#[ignore = "needs ./scripts/fetch-samples.sh"]
fn a_folder_is_merged_in_time_order_and_filtered_by_severity() {
    let all = alerts(&["samples/attack"]);
    let times: Vec<_> = all
        .iter()
        .map(|a| a["timestamp"].as_str().unwrap())
        .collect();
    assert!(
        times.is_sorted(),
        "alerts from several files must be merged chronologically"
    );

    let critical = alerts(&["samples/attack", "--min-severity", "critical"]);
    assert!(!critical.is_empty() && critical.len() < all.len());
    assert!(critical.iter().all(|a| a["severity"] == "critical"));
}

#[test]
#[ignore = "needs ./scripts/fetch-samples.sh"]
fn time_comes_from_the_event_when_the_record_header_is_zeroed() {
    // This sample's record headers carry no timestamp (it would read as 1601).
    let found = alerts(&["samples/attack/Powershell_4104_MiniDumpWriteDump_Lsass.evtx"]);
    let time = found[0]["timestamp"].as_str().unwrap();
    assert!(time.starts_with("2020-06-30T14:24:08"), "got {time}");
}
