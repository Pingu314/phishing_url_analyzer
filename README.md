# Phishing URL Analyzer

A SOC-focused command-line tool for analyzing URLs against phishing indicators. Combines static feature extraction, threat intelligence enrichment (VirusTotal, URLScan.io), and a transparent risk scoring model mapped to MITRE ATT&CK.

---

## Demo

```
$ python src/main.py -u "http://paypal-secure-verify.xyz/login?redirect=evil.com" --verbose

[*] Analyzing: http://paypal-secure-verify.xyz/login?redirect=evil.com
[*] Extracting URL features...
[*] Enriching with threat intelligence...
[*] Calculating risk score...

==================================================
  VERDICT: MALICIOUS
  Risk Score: 49/100
  MITRE: T1566.002 - Spearphishing Link
==================================================
```

---

## Features

- **Static feature extraction** — URL structure, entropy, brand impersonation detection, TLD analysis, IP-as-host, redirect parameters, encoding obfuscation
- **Threat intelligence enrichment** — VirusTotal v3 API, URLScan.io (gracefully degrades without API keys)
- **Risk scoring** — Transparent weighted model (0–100), three-tier verdict: `BENIGN` / `SUSPICIOUS` / `MALICIOUS`
- **MITRE ATT&CK mapping** — T1566, T1566.002, T1027, T1583.005
- **Redirect chain following** — follows up to 6 hops, detects mid-chain domain switches (T1027)
- **Batch mode** — Analyze a list of URLs from a file
- **JSON export** — Timestamped report with full breakdown

---

## Architecture

```
URL Input
    │
    ▼
URLFeatureExtractor     ← Static analysis, no network calls
    │
    ▼
ThreatIntelEnricher     ← VirusTotal API, URLScan.io API
    │
    ▼
RiskScorer              ← Weighted rule-based scoring
    │
    ▼
ReportGenerator         ← JSON export with MITRE tags
```

---

## Quickstart

```bash
git clone https://github.com/Pingu314/phishing_url_analyzer
cd phishing_url_analyzer
pip install -r requirements.txt

# Single URL (no API keys needed)
python src/main.py -u "http://paypal-login.tk/verify"

# Batch mode
python src/main.py -f data/sample_urls/urls.txt

# With threat intelligence (add API keys to config/config.json first)
python src/main.py -u "http://suspicious.xyz" --export --verbose
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

Free keys: [VirusTotal](https://www.virustotal.com/gui/join-us) | [URLScan.io](https://urlscan.io/user/signup)

The tool runs fully offline without keys — threat intel stages are skipped gracefully.

---

## Risk Scoring Model

| Signal | Points |
|---|---|
| VirusTotal malicious detections | +25 per engine (capped at 40) |
| URLScan.io malicious verdict | +20 |
| Brand impersonation in domain | +18 |
| Brand name in subdomain | +15 |
| IP address used as host | +15 |
| Suspicious TLD (.xyz, .tk, .ml…) | +10 |
| Suspicious keywords (login, verify…) | +8 |
| @ symbol in URL | +8 |
| No HTTPS | +7 |
| Hex/percent encoding | +6 |
| Open redirect parameter | +6 |
| High domain entropy (>3.8) | +5 |
| URL length > 75 chars | +4 |

**Thresholds:** 0–20 = BENIGN | 21–49 = SUSPICIOUS | 50–100 = MALICIOUS

---

## Tests

```bash
pip install pytest
pytest tests/ -v
```

23 unit tests covering feature extraction and scoring logic.

---

## MITRE ATT&CK Coverage

| Technique | ID | Trigger |
|---|---|---|
| Phishing | T1566 | VT/URLScan flags |
| Spearphishing Link | T1566.002 | Brand impersonation + suspicious keywords |
| Obfuscated Files or Information | T1027 | Redirect chains, hex encoding |
| Botnet / IP-based C2 | T1583.005 | IP address as host |

---

## Roadmap

- [x] Redirect chain following (v1.1) (up to N hops)
- [ ] WHOIS domain age lookup
- [ ] Flask-based web UI
- [ ] CSV export format
- [ ] Integration with soc_threat_analyzer pipeline

---

## Limitations

- Threat intel depends on public free-tier APIs (rate limited)
- No JavaScript rendering (static URL analysis only)
- Simulated sample data — not production traffic

---

## Disclaimer

For educational and portfolio purposes. Do not use to analyze URLs you do not have permission to scan.
