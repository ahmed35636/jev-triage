import json
import math
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from jev_triage.classifier import Decision, JevClassifier, RuleClassifier
from jev_triage.events import Event, load_events, normalize
from jev_triage.investigation import OllamaInvestigator
from jev_triage.pipeline import RoutingPolicy, triage

DATA = Path(__file__).resolve().parents[1] / "data/events.jsonl"


@pytest.mark.parametrize("confidence", [-0.1, 1.1, math.nan, math.inf])
def test_reject_invalid_confidence(confidence):
    with pytest.raises(ValueError):
        Decision("benign", confidence, 10, "test", "test")


def test_nested_windows_export():
    event = normalize(
        {
            "Event": {
                "System": {
                    "EventID": {"#text": "10"},
                    "EventRecordID": 1,
                    "Computer": "host",
                    "TimeCreated": {"@SystemTime": "2026-10-01Z"},
                },
                "EventData": {"Data": [{"@Name": "TargetImage", "#text": "lsass.exe"}]},
            }
        }
    )
    assert event.event_id == 10 and event.data["TargetImage"] == "lsass.exe"


@pytest.mark.parametrize("raw", [{}, {"record_id": "1", "host": "a"}, []])
def test_invalid_event(raw):
    with pytest.raises(ValueError):
        normalize(raw)


def test_duplicate_records(tmp_path):
    event = Event("1", 1, "a", "").to_dict()
    path = tmp_path / "events.json"
    path.write_text(json.dumps([event, event]))
    with pytest.raises(ValueError, match="duplicate"):
        load_events(path)


def test_routing_and_stable_sampling():
    event = Event("1", 1, "host", "")
    low = Decision("benign", 0.99, 10, "test", "test")
    assert RoutingPolicy(audit_rate=0).route(event, low) == (False, [])
    assert RoutingPolicy(audit_rate=1).route(event, low) == (True, ["audit_sample"])
    policy = RoutingPolicy(audit_rate=0.5)
    assert policy.route(event, low) == policy.route(event, low)
    high = Decision("suspicious", 0.99, 90, "test", "test")
    assert "high_severity" in policy.route(event, high)[1]
    unknown = Decision("unknown", 0.2, 10, "test", "test")
    assert policy.route(event, unknown)[1] == ["low_confidence", "unknown"]


def test_provider_failure_never_closes_alert():
    class Broken:
        def classify(self, event):
            raise RuntimeError("secret-key-not-for-output")

    result = triage(Event("1", 1, "host", ""), Broken(), RoutingPolicy())
    assert result["routing"]["escalated"]
    assert result["decision"]["label"] == "unknown"
    assert "secret-key" not in json.dumps(result)


def test_offline_scenario():
    rows = [triage(e, RuleClassifier(), RoutingPolicy(audit_rate=0)) for e in load_events(DATA)]
    lsass = next(r for r in rows if r["event"]["record_id"] == "6")
    assert lsass["decision"]["severity"] == 90
    assert lsass["findings"][0]["technique"] == "T1003.001"
    assert lsass["routing"]["escalated"]


def test_jev_adapter_contract_and_severity_floor():
    class Client:
        def system_one(self, **kwargs):
            assert kwargs["model"] == "test-jev"
            assert set(kwargs["questions"]) == {"classification", "severity"}
            assert kwargs["questions"]["classification"].type == "choice"
            return SimpleNamespace(
                model="test-jev",
                choices={
                    "classification": SimpleNamespace(choice="suspicious", confidence=0.91),
                    "severity": SimpleNamespace(choice="low"),
                },
            )

    event = next(e for e in load_events(DATA) if e.record_id == "6")
    result = JevClassifier(Client(), "test-jev").classify(event)
    assert result.confidence == 0.91 and result.severity == 90


@pytest.mark.parametrize("bad_ids", [False, True])
def test_ollama_schema_and_evidence_validation(monkeypatch, bad_ids):
    analysis = {
        "summary": "Review this event",
        "evidence_record_ids": ["99" if bad_ids else "1"],
        "hypotheses": ["Needs context"],
        "next_steps": ["Review logs"],
    }

    def post(url, **kwargs):
        assert url.endswith("/api/chat")
        assert kwargs["json"]["stream"] is False
        return httpx.Response(
            200,
            json={"message": {"content": json.dumps(analysis)}},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(httpx, "post", post)
    investigator = OllamaInvestigator("test-model")
    if bad_ids:
        with pytest.raises(ValueError, match="unknown record"):
            investigator.investigate({"event": {"record_id": "1"}})
    else:
        assert investigator.investigate({"event": {"record_id": "1"}})["model"] == "test-model"


def test_evaluation_matches_host_and_record():
    from jev_triage.evaluation import evaluate

    result = triage(Event("1", 1, "h", ""), RuleClassifier(), RoutingPolicy())
    scores = evaluate([result], {"h:1": "unknown"})
    assert scores["accuracy"] == 1
    with pytest.raises(ValueError, match="No host:record_id"):
        evaluate([result], {"another:1": "unknown"})


def test_real_sdk_response_contract():
    from typesafe_sdk import SystemOneResponse

    class Client:
        def system_one(self, **kwargs):
            return SystemOneResponse.model_validate(
                {
                    "model": "jev-test",
                    "usage": {},
                    "answers": {
                        "classification": {
                            "type": "choice",
                            "choice": "unknown",
                            "confidence": 0.4,
                            "probabilities": {
                                "benign": 0.2,
                                "suspicious": 0.2,
                                "malicious": 0.2,
                                "unknown": 0.4,
                            },
                        },
                        "severity": {
                            "type": "choice",
                            "choice": "medium",
                            "confidence": 0.7,
                            "probabilities": {
                                "low": 0.1,
                                "medium": 0.7,
                                "high": 0.1,
                                "critical": 0.1,
                            },
                        },
                    },
                }
            )

    decision = JevClassifier(Client(), "jev-test").classify(Event("1", 3, "h", ""))
    assert decision.label == "unknown" and decision.confidence == 0.4 and decision.severity == 50
