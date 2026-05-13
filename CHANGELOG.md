# Changelog

All notable changes to this project will be documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.1.0] - 2026-05-13

### Added
- `tests/test_main.py` - `load_config`, `analyze_url` and `main()` CLI tests:
  file input, batch summary, export flags, deduplication, verbose mode,
  redirect hop output, domain switch output (22 tests)
- `tests/test_redirect_follower.py` - redirect hop recording, domain switch
  detection, `_fetch_single` HTTP/URL/OS error paths (11 tests)
- `tests/test_threat_intel.py` - URLScan polling loop, WHOIS naive datetime
  normalisation, retry on 429 and URLError (17 tests)
- `tests/test_risk_scorer.py` - cloud hosting abuse, private IP, path entropy,
  new domain scoring branches (18 tests)

### Changed
- Tests refactored from monolithic `test_analyzer.py` into 7 focused modules
- 118 tests, 95% coverage (up from 74 tests, 86% coverage)
- Coverage threshold raised to 95%
- CI matrix extended to Python 3.9–3.13
- `src/main.py` - proper type hints (`ThreatIntelEnricher | None`, `list[str]`,
  `set[str]`); duplicate `ReportGenerator` instantiation removed; `main()`
  extracted and documented; `from __future__ import annotations` added

---

## [1.0.0] - 2026-04-29

### Added
- Five-stage phishing URL analysis pipeline
- 25+ URL feature signals with MITRE ATT&CK mapping
- VirusTotal v3, URLScan.io and WHOIS threat intelligence (optional)
- Batch URL analysis with JSON and CSV export
- 74 pytest tests with ≥80% coverage enforced in CI
- CI matrix across Python 3.9–3.13
