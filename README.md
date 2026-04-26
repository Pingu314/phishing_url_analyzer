# Phishing URL Analyzer

Rule-based phishing URL analyzer with MITRE ATT&CK mapping, WHOIS enrichment and JSON/CSV export
URL Input
│
▼
RedirectFollower    ← follows up to 6 hops, detects domain switches
│
▼
URLFeatureExtractor ← 25+ signals: brand, typosquatting, entropy, cloud abuse
│
▼
ThreatIntelEnricher ← VirusTotal API · URLScan.io API · WHOIS
│
▼
RiskScorer          ← weighted rule-based scoring (0–100) + confidence
│
▼
ReportGenerator     ← JSON + CSV export with MITRE ATT&CK tags

---

## Quickstart

```bash
git clone https://github.com/Pingu314/phishing_url_analyzer
cd phishing_url_analyzer
pip install -r requirements.txt

# Single URL - no API keys needed
python src/main.py -u "http://paypal-login.tk/verify"

# Verbose - shows per-signal feature breakdown
python src/main.py -u "http://paypal-login.tk/verify" --verbose

# Batch mode - auto-exports report.json to reports/
python src/main.py -f data/sample_urls/urls.txt

# Batch with CSV export
python src/main.py -f data/sample_urls/urls.txt --csv

# With threat intelligence (add API keys to config/config.json first)
python src/main.py -u "http://suspicious.xyz" --verbose --export
```

---

## API Keys (Optional)

Edit `config/config.json`:

```json
{
  "virustotal_api_key": "YOUR_KEY_HERE",
  "urlscan_api_key": "YOUR_KEY_HERE"
}
```

Free keys: [VirusTotal](https://www.virustotal.com) | [URLScan.io](https://urlscan.io)

The tool runs fully offline without keys - threat intel stages are skipped gracefully

---

## Risk Scoring

| Signal | Points |
|---|---|
| VirusTotal malicious detections | +20 per engine (cap 40) |
| URLScan.io malicious verdict | +20 |
| Brand impersonation in domain | +18 |
| Typosquatting / homoglyph hit | +18 |
| Cloud storage hosting abuse (GCS, S3, Azure…) | +18 |
| Brand name in subdomain | +15 |
| IP address used as host | +15 |
| Malware file extension (.exe, .ps1…) | +15 |
| Redirect domain switch | +12 |
| Suspicious TLD (.xyz, .tk, .ml…) | +10 |
| Private IP (RFC 1918) as host | +10 |
| New domain (< 30 days, via WHOIS) | +8 |
| Malware path keyword (payload, dropper…) | +8 |
| Suspicious keywords (login, verify…) | +8 |
| @ symbol in URL | +8 |
| No HTTPS | +7 |
| High path-segment entropy | +6 |
| Hex/percent encoding | +6 |
| Open redirect parameter | +6 |
| High domain entropy (> 3.8) | +5 |
| URL length > 75 chars | +4 |
| Many redirect hops (> 1) | +4 |
| Many hyphens (> 3) | +3 |
| Deep path (> 4 segments) | +3 |
| Many subdomains (> 2) | +3 |
| Non-standard port | +3 |

**Thresholds:** 0–20 = BENIGN / 21–49 = SUSPICIOUS / 50–100 = MALICIOUS

**Confidence:** HIGH / MEDIUM / LOW / VERY_LOW - reflects signal count and whether TI APIs confirmed the verdict

---

## MITRE ATT&CK Coverage

| Technique                                | Trigger |
|------------------------------------------|---|
| T1566 - Phishing                         | VirusTotal or URLScan confirmed |
| T1566.002 - Spearphishing Link           | Brand impersonation, typosquatting, brand in subdomain |
| T1583.005 - Botnet / IP-based C2         | IP address as host |
| T1583.006 - Web Services / Cloud Storage | Cloud storage domain detected (GCS, S3, Azure…) |
| T1027 - Obfuscated Files or Information  | Redirect hops or hex encoding |
| T1659 - Content Injection / Redirect     | Domain switch detected in redirect chain |
| T1105 - Ingress Tool Transfer            | Malware extension or path keyword |

---

## Project Structure
phishing_url_analyzer/
├── config/
│   ├── config.json          # API keys (gitignored)
│   └── settings.py          # Weights, brand lists, cloud domains, thresholds
├── data/
│   └── sample_urls/
│       └── urls.txt         # Test URLs (benign / suspicious / malicious)
├── src/
│   ├── main.py              # CLI entry point
│   ├── url_extractor.py     # Feature extraction (25+ signals)
│   ├── risk_scorer.py       # Scoring engine + confidence
│   ├── threat_intel.py      # VirusTotal / URLScan.io / WHOIS
│   ├── redirect_follower.py # HTTP redirect chain follower
│   └── report_generator.py  # JSON + CSV export
├── tests/
│   └── test_analyzer.py     # 63 unit tests
├── pyproject.toml
└── requirements.txt

---

## CLI Reference
python src/main.py [-u URL] [-f FILE] [-v] [--export] [--csv] [--config PATH]
-u URL        Single URL to analyze
-f FILE       File with URLs (one per line, # = comment)
-v            Verbose output — shows feature dict and intel
--export      Export JSON report to reports/  (auto-on for -f)
--csv         Also export a CSV summary to reports/
--config PATH Path to config JSON (default: config/config.json)

---

## Tests

```bash
python -m pytest tests/
python -m pytest tests/ --cov=src --cov=config --cov-report=term-missing
```

---

## Development

```bash
# Install dev + lint deps
pip install -e ".[dev,lint]"

# Lint
flake8 src/ tests/ config/
```

---

## Limitations

- Static URL analysis only - no JavaScript rendering
- WHOIS lookups add 2–10s per URL depending on registrar
- VirusTotal free tier: 4 requests/minute, 500/day
- URLScan.io free tier: rate limited, ~15s per scan
- Some privacy-protected domains return no WHOIS data

---

## Disclaimer

For educational and portfolio purposes. Do not use to analyze URLs you do not have permission to scan.