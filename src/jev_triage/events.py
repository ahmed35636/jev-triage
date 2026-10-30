"""Normalize exported Windows events without executing telemetry content."""

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Event:
    record_id: str
    event_id: int
    host: str
    timestamp: str
    data: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)

    def value(self, key: str) -> str:
        return str(self.data.get(key, ""))


def normalize(raw: dict) -> Event:
    # Supports flat exports and PowerShell ConvertTo-Json output from XML.
    if not isinstance(raw, dict):
        raise ValueError("event must be an object")
    body = raw.get("Event", raw)
    system = body.get("System", body)
    data = body.get("EventData", body.get("data", {}))
    if isinstance(data, dict) and "Data" in data:
        data = data["Data"]
    if isinstance(data, list):
        data = {item["@Name"]: item.get("#text", "") for item in data}
    if not isinstance(data, dict):
        raise ValueError("EventData must be an object or named Data list")
    event_id = system.get("EventID", body.get("event_id"))
    if isinstance(event_id, dict):
        event_id = event_id.get("#text")
    record_id = system.get("EventRecordID", body.get("record_id"))
    host = system.get("Computer", body.get("host"))
    timestamp = system.get("TimeCreated", body.get("timestamp", ""))
    if isinstance(timestamp, dict):
        timestamp = timestamp.get("@SystemTime", "")
    if record_id is None or not host or event_id is None:
        raise ValueError("event requires EventID, EventRecordID and Computer (or flat equivalents)")
    return Event(str(record_id), int(event_id), str(host), str(timestamp), data)


def load_events(path: str | Path) -> list[Event]:
    path = Path(path)
    if path.suffix.lower() == ".jsonl":
        rows = []
        for line_no, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
            if line.strip():
                try:
                    rows.append(normalize(json.loads(line)))
                except (ValueError, KeyError, TypeError) as exc:
                    raise ValueError(f"{path.name}:{line_no}: invalid event: {exc}") from exc
    else:
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(raw, list):
            raise ValueError("JSON input must be an array; use JSONL for one object per line")
        rows = [normalize(row) for row in raw]
    keys = [(row.host.casefold(), row.record_id) for row in rows]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate record IDs on the same host")
    return rows
