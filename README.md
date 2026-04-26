# Phishing URL Analyzer

![CI](https://github.com/Pingu314/phishing_url_analyzer/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.9%20%7C%203.11%20%7C%203.12-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A SOC triage tool that analyzes URLs for phishing indicators, enriches them with threat intelligence, and maps findings to MITRE ATT&CK techniques. Built as a portfolio project to demonstrate Tier-1 SOC analyst workflows in code.

## What it does

Runs a five-stage pipeline for every URL submitted:

1. **Redirect chain following** - tracks hops, detects domain switches
2. **Feature extraction** - 25+ signals: brand impersonation, typosquatting, homoglyphs, entropy, cloud hosting abuse, malware extensions, private IPs, and more
3. **Threat intelligence enrichment** - VirusTotal v3, URLScan.io, WHOIS domain age (all optional, degrades gracefully without API keys)
4. **Risk scoring** - weighted, rule-based 0–100 score with BENIGN / SUSPICIOUS / MALICIOUS verdict and HIGH / MEDIUM / LOW / VERY_LOW confidence
5. **MITRE ATT&CK mapping** - tags each result with relevant technique IDs

## Installation

```bash
git clone https://github.com/Pingu314/phishing_url_analyzer.git
cd phishing_url_analyzer
pip install -e ".[dev]"
cp config/config.json.example config/config.json
# Edit config/config.json and add your API keys (optional)
```

## Usage

**Single URL:**
```bash
python -m src.main -u "http://paypa1.com/verify"
```

**Batch file:**
```bash
python -m src.main -f data/sample_urls/urls.txt
```

**With all options:**
```bash
python -m src.main -u "http://suspicious-site.com/login" --verbose --export --csv
```

| Flag | Description |
|------|-------------|
| `-u URL` | Single URL to analyze |
| `-f FILE` | File with one URL per line (auto-exports JSON) |
| `-v` / `--verbose` | Show full feature dict and intel output |
| `--export` | Export JSON report to `reports/` |
| `--csv` | Export CSV summary to `reports/` |
| `--config PATH` | Path to config file (default: `config/config.json`) |

## How scoring works

Each signal adds a fixed number of points. Score is capped at 100.

| Signal | Weight | MITRE |
|--------|--------|-------|
| VirusTotal malicious engines | 20 × engines (max 40) | T1566 |
| URLScan malicious verdict | 20 | T1566 |
| Brand impersonation | 18 | T1566.002 |
| Typosquatting (homoglyph/edit-distance) | 18 | T1566.002 |
| Cloud hosting abuse | 18 | T1583.006 |
| Private IP as host | 20 | T1583.005 |
| Brand in subdomain | 15 | T1566.002 |
| Malware extension in path | 15 | T1105 |
| Uses IP as host | 15 | T1583.005 |
| Redirect domain switch | 12 | T1659 |
| Suspicious TLD | 10 | — |
| New domain (< 30 days) | 8 | — |
| Suspicious keywords in URL | 8 | T1566.002 |
| Malware path keyword | 8 | T1105 |
| At-symbol in URL | 8 | — |
| No HTTPS | 7 | — |
| High path entropy | 6 | T1027 |
| Hex encoding | 6 | T1027 |
| Redirect parameter | 6 | T1659 |
| High domain entropy | 5 | — |
| Double slash in path | 5 | — |
| Long URL (> 75 chars) | 4 | — |
| Many redirect hops (> 1) | 4 | T1027 |
| Many hyphens (> 3) | 3 | — |
| Deep path (> 4 levels) | 3 | — |
| Many subdomains (> 2) | 3 | — |
| Non-standard port | 3 | — |

**Verdict thresholds:** BENIGN 0–20 · SUSPICIOUS 21–49 · MALICIOUS 50–100

**Confidence levels:**

| Level | Condition |
|-------|-----------|
| HIGH | TI confirms malicious AND 3+ signals fired |
| MEDIUM | 4+ signals fired OR TI present |
| LOW | 2–3 signals fired |
| VERY_LOW | 0–1 signals fired |

## Architecture
URL input
│
▼
RedirectFollower ──────────────────────────────► redirect_chain dict
│
▼
URLFeatureExtractor (original URL) ────────────► features dict (25+ signals)
│
▼
ThreatIntelEnricher (final URL) ───────────────► intel dict (VT · URLScan · WHOIS)
│
▼
RiskScorer ────────────────────────────────────► {score, verdict, confidence, breakdown}
│
▼
map_to_mitre ──────────────────────────────────► [T1566.002, T1027, ...]
│
▼
ReportGenerator ───────────────────────────────► reports/report_YYYYMMDD_HHMMSS.json / .csv

## Project structure
phishing_url_analyzer/
├── src/
│   ├── url_extractor.py      # Feature extraction (25+ signals)
│   ├── risk_scorer.py        # Weighted scoring + confidence
│   ├── threat_intel.py       # VirusTotal · URLScan · WHOIS
│   ├── redirect_follower.py  # Redirect chain follower
│   ├── report_generator.py   # JSON + CSV export
│   ├── mitre_mapper.py       # MITRE ATT&CK tag mapper
│   └── main.py               # CLI entrypoint
├── config/
│   ├── settings.py           # All weights, lists, thresholds
│   └── config.json.example   # API key template
├── tests/
│   └── test_analyzer.py      # pytest test suite
└── data/
└── sample_urls/
└── urls.txt          # Sample URLs for batch testing

## Running tests

```bash
pytest tests/ -v
pytest tests/ --cov=src --cov-report=term-missing
```

## Disclaimer

This tool is built for **educational and portfolio purposes** as part of a SOC analyst learning path (CompTIA Security+, TryHackMe SOC Level 1).

- Do **not** use this tool to analyze URLs you do not have permission to test
- Threat intelligence lookups (VirusTotal, URLScan.io) submit URLs to third-party services - do not analyze sensitive or internal URLs with API keys configured
- Results are heuristic and rule-based - false positives and false negatives are expected
- This is not a replacement for production security tooling


## Roadmap

- **P3** — `email_header_analyzer`: SPF/DKIM/DMARC parsing, Received-chain IP enrichment, embedded URL analysis via this library
- **P4** — unified SOC triage interface combining phishing URL, email header, and IOC analysis into a single pipeline