# Event input

Accepts JSON arrays (`.json`) or one JSON object per line (`.jsonl`). Flat schema:

```json
{"record_id":"123", "event_id":1, "host":"LAB-WS01", "timestamp":"2026-10-01T09:00:00Z", "data":{"ProcessGuid":"{guid}", "ParentProcessGuid":"{parent}", "Image":"C:\\Windows\\System32\\cmd.exe", "CommandLine":"cmd.exe /c whoami"}}
```

`record_id`, `event_id`, and `host` are required. Timestamp is retained as supplied;
use UTC ISO 8601 timestamps for chronological reports. Field names inside `data`
are case-sensitive and retain Sysmon spelling. The nested shape
`Event.System` plus `Event.EventData.Data` with `@Name` / `#text` entries is also
supported. Duplicate host/record identities are rejected. When merging log
channels, prefix each record ID with its channel to prevent collisions.

## Export from Windows

With Sysmon installed and the relevant events enabled, run the read-only helper
from PowerShell on the Windows machine:

```powershell
.\scripts\export-sysmon.ps1 -OutputPath .\events.jsonl -MaxEvents 1000
```

It exports Sysmon IDs 1, 3, and 10. Sysmon network connection logging is not
necessarily enabled in every deployment. No matches may mean missing telemetry.
The exporter has not been executed on Windows as part of this release; validate
its output in your environment. Raw `.evtx` and XML files need conversion first.

To include PowerShell 4104 or Security 4698, normalize them into the same schema.
Event data varies by source. Process-led investigations require upstream process
GUID enrichment for channels that do not provide Sysmon GUIDs. The projects do
not infer GUIDs from PIDs or execute logged commands.

Telemetry can contain usernames, internal addresses, and sensitive command-line
arguments. Use synthetic fixtures for public examples. Jev mode sends the event
and detector hits to TypeSafe; optional Ollama sends the triaged record to the
configured endpoint. The offline and MCP demo paths perform no model calls.
