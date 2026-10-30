import argparse
import json
import os
from contextlib import ExitStack
from pathlib import Path

from .classifier import JevClassifier, RuleClassifier
from .events import load_events
from .investigation import OllamaInvestigator
from .pipeline import RoutingPolicy, triage


def main():
    parser = argparse.ArgumentParser(
        description="Classify Windows events and route investigation candidates"
    )
    parser.add_argument("events", type=Path)
    parser.add_argument("--backend", choices=["rules", "jev"], default="rules")
    parser.add_argument("--model", default=os.getenv("TYPESAFE_MODEL"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--severity-threshold", type=int, default=70)
    parser.add_argument("--confidence-threshold", type=float, default=0.75)
    parser.add_argument("--audit-rate", type=float, default=0.05)
    parser.add_argument("--seed", default="triage-v1")
    parser.add_argument(
        "--ollama-model", help="Enable local LLM investigation for escalated events"
    )
    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    args = parser.parse_args()
    try:
        events = load_events(args.events)
        policy = RoutingPolicy(
            args.severity_threshold, args.confidence_threshold, args.audit_rate, args.seed
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    if args.backend == "jev" and (not os.getenv("TYPESAFE_API_KEY") or not args.model):
        parser.error("jev requires TYPESAFE_API_KEY and --model (or TYPESAFE_MODEL)")
    with ExitStack() as stack:
        classifier = RuleClassifier()
        if args.backend == "jev":
            from typesafe_sdk import TypeSafeClient

            classifier = JevClassifier(stack.enter_context(TypeSafeClient()), args.model)
        investigator = (
            OllamaInvestigator(args.ollama_model, args.ollama_url) if args.ollama_model else None
        )
        results = [triage(event, classifier, policy, investigator) for event in events]
    output = "\n".join(json.dumps(result) for result in results) + ("\n" if results else "")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
    else:
        print(output, end="")
    # Failure is both recorded in output and visible to scripts/CI.
    if any(
        "classification_error" in r or r["investigation"]["status"] == "failed" for r in results
    ):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
