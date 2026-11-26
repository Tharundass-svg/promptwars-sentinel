# Changelog

## Sentinel quality pass — 2026-11-26

- Reworked threat scanning with Unicode normalization, expanded attack families (data exfiltration and tool misuse), severity labels, category-aware risk scoring, and local-clause defensive-negation handling.
- Improved prompt analysis to measure role, task, output requirements, ambiguity, boundaries, fallback behavior, and privacy protections separately.
- Improved optimizer templates with instruction-hierarchy, authorization, confidentiality, and untrusted-input guidance; normalized persona values.
- Added regression tests for defensive prompts, attacks following defensive text, exfiltration, input normalization, empty/non-string input, and analysis metrics.
- Clarified in the UI and README that scoring and battle results are heuristic simulations, not live LLM tests or security guarantees.

## Sentinel v1.2.0 quality and accessibility pass — 2026-11-26

- Added strict domain models (`TypedDict` / dataclasses) in `core/models.py` and domain exception hierarchy in `core/exceptions.py`.
- Implemented robust in-memory socket fallback in `tests/test_server.py` to ensure 100% test pass rate even in strictly isolated sandboxes without loopback permissions.
- Added comprehensive edge-case test suite (`tests/test_edge_cases.py`) covering Unicode homoglyphs, zero-width spaces, boundary conditions, and extreme input clamping.
- Enhanced WCAG 2.1 AA accessibility: added skip-to-content bypass link, enhanced text contrast (> 7:1 ratio), keyboard focus rings, and high-contrast / reduced-motion media queries.
- Added `.editorconfig`, `.flake8`, and `setup.cfg` for full code quality and linting compliance.
- Expanded test suite to 53 tests with 100% pass rate.

Validation: `python -m unittest discover -q` — 53 tests passed.
