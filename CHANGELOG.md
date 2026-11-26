# Changelog

## Sentinel quality pass — 2026-11-26

- Reworked threat scanning with Unicode normalization, expanded attack families (data exfiltration and tool misuse), severity labels, category-aware risk scoring, and local-clause defensive-negation handling.
- Improved prompt analysis to measure role, task, output requirements, ambiguity, boundaries, fallback behavior, and privacy protections separately.
- Improved optimizer templates with instruction-hierarchy, authorization, confidentiality, and untrusted-input guidance; normalized persona values.
- Added regression tests for defensive prompts, attacks following defensive text, exfiltration, input normalization, empty/non-string input, and analysis metrics.
- Clarified in the UI and README that scoring and battle results are heuristic simulations, not live LLM tests or security guarantees.

Validation: `python -m unittest discover -q` — 46 tests passed. Coverage report for `server.py,core/*`: 88% total.
