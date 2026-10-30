"""Small, inspectable detection set. Matches are leads, not proof of compromise."""

import re
from dataclasses import asdict, dataclass

from .events import Event


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: int
    technique: str
    tactic: str
    record_id: str
    reason: str

    def to_dict(self):
        return asdict(self)


def detect(event: Event) -> list[Finding]:
    cmd = event.value("CommandLine").casefold()
    image = event.value("Image").casefold().replace("/", "\\")
    target = event.value("TargetImage").casefold().replace("/", "\\")
    script = event.value("ScriptBlockText").casefold()
    text = cmd + " " + script
    hits = []

    def add(key, title, severity, technique, tactic, reason):
        hits.append(Finding(key, title, severity, technique, tactic, event.record_id, reason))

    ps = image.endswith(("\\powershell.exe", "\\pwsh.exe")) or event.event_id == 4104
    if ps and re.search(r"(?:^|\s)-(?:enc|encodedcommand|e)\s+\S+", text):
        add(
            "PS_ENCODED",
            "Encoded PowerShell command",
            75,
            "T1059.001",
            "Execution",
            "Encoded command flag in PowerShell telemetry",
        )
    if ps and any(
        token in text for token in ("downloadstring", "invoke-webrequest", "downloadfile")
    ):
        add(
            "PS_DOWNLOAD",
            "PowerShell network retrieval",
            65,
            "T1059.001",
            "Execution",
            "Network retrieval primitive in PowerShell telemetry",
        )
    # Sysmon 10 is process access, not process creation.
    if event.event_id == 10 and target.endswith("\\lsass.exe"):
        raw_mask = event.value("GrantedAccess")
        try:
            mask = int(raw_mask, 16)
        except ValueError:
            mask = 0
        if mask & 0x10:  # PROCESS_VM_READ; does not imply a successful credential dump.
            add(
                "LSASS_READ",
                "LSASS memory-read access",
                90,
                "T1003.001",
                "Credential Access",
                f"Process access to LSASS with VM_READ (mask {raw_mask})",
            )
    if event.event_id == 1 and (image.endswith("\\psexec.exe") or "psexesvc" in image):
        add(
            "PSEXEC",
            "PsExec process observed",
            65,
            "T1569.002",
            "Execution",
            "PsExec binary or service observed; verify remote-service context",
        )
    if event.event_id in (1, 4698) and (
        (image.endswith("\\schtasks.exe") and "/create" in cmd) or event.event_id == 4698
    ):
        add(
            "SCHEDULED_TASK",
            "Scheduled task creation",
            60,
            "T1053.005",
            "Persistence",
            "Task creation event or schtasks /create command",
        )
    return hits
