# Detection coverage

| Rule | Signal | Score | ATT&CK | Tactic |
|---|---|---:|---|---|
| PS_ENCODED | PowerShell encoded-command switch | 75 | T1059.001 | Execution |
| PS_DOWNLOAD | PowerShell retrieval primitive | 65 | T1059.001 | Execution |
| LSASS_READ | Sysmon 10 targeting lsass.exe, access mask includes 0x10 | 90 | T1003.001 | Credential Access |
| PSEXEC | Sysmon 1 PsExec executable or service process | 65 | T1569.002 | Execution |
| SCHEDULED_TASK | schtasks /create or Security 4698 | 60 | T1053.005 | Persistence |

These mappings describe investigation leads. Legitimate administration can trigger
all of them. The LSASS rule records an access request containing VM_READ, not proof
of credential extraction. PsExec maps to service execution; a filename alone does
not prove lateral movement. Renamed binaries, alternative PowerShell switches,
obfuscation, missing channels, and missing GUID enrichment can evade these rules.

Rules are intentionally short Python functions in `detections.py` so reviewers
can inspect the exact predicates. No reputation is inferred from an executable
name alone. This is not a replacement for a maintained detection-content library.

Technique references: [PowerShell](https://attack.mitre.org/techniques/T1059/001/),
[LSASS memory](https://attack.mitre.org/techniques/T1003/001/),
[service execution](https://attack.mitre.org/techniques/T1569/002/),
[scheduled tasks](https://attack.mitre.org/techniques/T1053/005/).
