"""Auditable routing with reproducible sampling for low-risk review."""

import hashlib
from dataclasses import asdict, dataclass

from .classifier import Classifier, Decision
from .detections import detect
from .events import Event


@dataclass(frozen=True)
class RoutingPolicy:
    severity_threshold: int = 70
    confidence_threshold: float = 0.75
    audit_rate: float = 0.05
    seed: str = "triage-v1"

    def __post_init__(self):
        if not 0 <= self.severity_threshold <= 100:
            raise ValueError("severity threshold must be between 0 and 100")
        if not 0 <= self.confidence_threshold <= 1 or not 0 <= self.audit_rate <= 1:
            raise ValueError("confidence threshold and audit rate must be between 0 and 1")

    def route(self, event: Event, decision: Decision) -> tuple[bool, list[str]]:
        reasons = []
        if decision.severity >= self.severity_threshold:
            reasons.append("high_severity")
        if decision.confidence < self.confidence_threshold:
            reasons.append("low_confidence")
        if decision.label in ("unknown", "malicious"):
            reasons.append(decision.label)
        key = f"{self.seed}:{event.host.casefold()}:{event.record_id}"
        draw = int.from_bytes(hashlib.sha256(key.encode()).digest()[:8], "big") / 2**64
        if not reasons and draw < self.audit_rate:
            reasons.append("audit_sample")
        return bool(reasons), reasons


def triage(event: Event, classifier: Classifier, policy: RoutingPolicy, investigator=None) -> dict:
    findings = [f.to_dict() for f in detect(event)]
    try:
        decision = classifier.classify(event)
        error = None
    except Exception as exc:
        # Fail visibly into manual review. Never turn an API failure into a benign verdict.
        decision = Decision(
            "unknown",
            0.0,
            max((f["severity"] for f in findings), default=30),
            "error",
            "unavailable",
        )
        error = type(exc).__name__  # Do not serialize provider exceptions that may contain secrets.
    escalated, reasons = policy.route(event, decision)
    result = {
        "event": event.to_dict(),
        "decision": asdict(decision),
        "findings": findings,
        "routing": {"escalated": escalated, "reasons": reasons, "policy": asdict(policy)},
        "investigation": {"status": "queued" if escalated else "not_requested"},
    }
    if error:
        result["classification_error"] = error
    if escalated and investigator:
        try:
            result["investigation"] = {
                "status": "completed",
                "analysis": investigator.investigate(result),
            }
        except Exception as exc:
            result["investigation"] = {"status": "failed", "error": type(exc).__name__}
    return result
