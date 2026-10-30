# Design decisions

## Separate inference from policy

The classifier returns a typed decision. Routing is a separate deterministic
policy so threshold changes can be reviewed without modifying model prompts.
Detector results remain in the output even when the model disagrees. Severity is
an ordinal priority score, not a calibrated probability. The SDK's confidence is
retained as reported; the offline baseline's confidence is a heuristic.

## Reproducible review sampling

A SHA-256 digest of seed, host, and record ID selects routine records for audit.
The first 64 bits give a uniform draw in [0,1). Re-running with the same seed keeps
the same selection, which helps debug policies. This is deterministic sampling,
not randomness from Jev, and is not appropriate as a secret adversarial control.

## Model boundary

TypeSafe is an explicit opt-in backend. Failed API calls and malformed answers
become unknown results and are escalated, with an exit status indicating failure.
The Ollama stage has no tools and its suggestions are untrusted analyst aids.
Telemetry is delimited as data in the request, but prompt-injection resistance
cannot be guaranteed by instructions. Generated references are checked against
the supplied record ID; this checks provenance, not factual correctness.

## Evaluation

The fixture label file uses host:record_id keys. `evaluation.py` can evaluate either
the baseline or saved model JSONL. It reports a confusion matrix, label accuracy,
and escalation rate. The ten hand-authored fixtures overlap the rule design and
are regression checks, not an independent benchmark. A proper study would use a
held-out, host-diverse dataset, analyst labels, per-class recall, false-positive
rates, calibration, latency, costs, and sensitivity to missing telemetry.

Processing is sequential to keep failures and outputs inspectable. There is no
retry queue, durable service, batching, or database. Those belong in a deployment
layer once the classifier and policy have been evaluated.
