# Development

Install with `python -m pip install -e '.[dev]'` inside a virtual environment.
Run `ruff check .`, `ruff format --check .`, and `pytest -q` before opening a change.
Tests use synthetic telemetry. Do not commit endpoint exports, credentials, or
customer indicators. Add positive and negative fixtures when changing a detector.
Include the evidence that supports a new ATT&CK mapping and describe expected
false positives.
