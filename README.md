# Phishing URL Analyzer
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
python -m src.main -u "http://paypal-login.tk/verify"

# Batch mode
python -m src.main -f data/sample_urls/urls.txt

# With threat intelligence (add API keys to config/config.json first)
python -m src.main -u "http://suspicious.xyz" --export --verbose
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

The tool runs fully offline without keys - threat intel stages are skipped gracefully.

---

## Risk Scoring Model

| Signal | Points |
|---|---|
| VirusTotal malicious detections | +20 per engine (capped at 40) |
| URLScan.io malicious verdict | +20 |
| Brand impersonation in domain | +18 |
| Typosquatting / homoglyph hit | +18 |
| Brand name in subdomain | +15 |
| IP address used as host | +15 |
| Malware file extension (.exe, .ps1…) | +15 |
| Redirect domain switch | +12 |
| Suspicious TLD (.xyz, .tk, .ml…) | +10 |
| Malware path keyword (payload, dropper…) | +8 |
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
python -m pytest tests/ -v