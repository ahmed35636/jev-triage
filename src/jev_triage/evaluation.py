"""Evaluate labeled fixtures without treating synthetic results as field accuracy."""

import argparse
import json
from collections import Counter
from pathlib import Path

from .classifier import RuleClassifier
from .events import load_events
from .pipeline import RoutingPolicy, triage


def evaluate(results: list[dict], labels: dict) -> dict:
    confusion = Counter()
    matched = 0
    for result in results:
        event = result["event"]
        key = f"{event['host']}:{event['record_id']}"
        expected = labels.get(key)
        if expected is None:
            continue
        confusion[expected, result["decision"]["label"]] += 1
        matched += 1
    if matched == 0:
        raise ValueError("No host:record_id labels matched the output")
    return {
        "labeled_events": matched,
        "accuracy": sum(
            count for (expected, predicted), count in confusion.items() if expected == predicted
        )
        / matched,
        "escalation_rate": sum(r["routing"]["escalated"] for r in results) / len(results),
        "confusion_matrix": [
            {"expected": expected, "predicted": predicted, "count": count}
            for (expected, predicted), count in sorted(confusion.items())
        ],
        "note": "Synthetic fixture results test behavior; they do not estimate production accuracy or confidence calibration.",
    }


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate rules or a previously recorded model run"
    )
    parser.add_argument("--events", type=Path, default=Path("data/events.jsonl"))
    parser.add_argument("--results", type=Path, help="Existing triage JSONL, e.g. a live Jev run")
    parser.add_argument("--labels", type=Path, default=Path("data/labels.json"))
    args = parser.parse_args()
    results = (
        [json.loads(line) for line in args.results.read_text().splitlines() if line.strip()]
        if args.results
        else [
            triage(e, RuleClassifier(), RoutingPolicy(audit_rate=0))
            for e in load_events(args.events)
        ]
    )
    print(json.dumps(evaluate(results, json.loads(args.labels.read_text())), indent=2))


if __name__ == "__main__":
    main()
