#!/usr/bin/env bash
# Download the real attack logs the integration tests run against, into
# samples/attack/. They come from sbousseaden/EVTX-ATTACK-SAMPLES (GPL-3.0),
# pinned to one commit, and are deliberately not stored in this repository.
set -euo pipefail

commit=4ceed2f4706daf601c212a8f91c113dd85349a2c
base="https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/$commit"
dest="$(dirname "$0")/../samples/attack"

files=(
  "Defense Evasion/DE_1102_security_log_cleared.evtx"
  "Defense Evasion/DE_104_system_log_cleared.evtx"
  "Defense Evasion/DE_Fake_ComputerAccount_4720.evtx"
  "Defense Evasion/meterpreter_migrate_to_explorer_sysmon_8.evtx"
  "Credential Access/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx"
  "Credential Access/Powershell_4104_MiniDumpWriteDump_Lsass.evtx"
  "Lateral Movement/LM_Remote_Service02_7045.evtx"
  "Privilege Escalation/System_7045_namedpipe_privesc.evtx"
  "Command and Control/DE_RDP_Tunneling_4624.evtx"
  "Persistence/Network_Service_Guest_added_to_admins_4732.evtx"
  "Execution/temp_scheduled_task_4698_4699.evtx"
  "AutomatedTestingTools/WinDefender_Events_1117_1116_AtomicRedTeam.evtx"
)

mkdir -p "$dest"
for f in "${files[@]}"; do
  out="$dest/$(basename "$f")"
  [ -s "$out" ] || curl --fail --silent --show-error --location -o "$out" "$base/${f// /%20}"
done
echo "${#files[@]} samples in $dest"
