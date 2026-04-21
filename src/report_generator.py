"""
Report Generator
Exports analysis results to timestamped JSON files in /reports.

Designed as a stable output interface so soc_threat_analyzer can
consume the same JSON schema without modification.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

# Keep in sync with map_to_mitre() in main.py
MITRE_COVERAGE = [
    "T1566",          # Phishing (VT/URLScan confirmed)
    "T1566.002",      # Spearphishing Link (brand impersonation / typosquatting)
    "T1027",          # Obfuscated Files or Information (redirects, hex encoding)
    "T1659",          # Content Injection / Redirect (domain switch mid-chain)
    "T1583.005",      # Botnet / IP-based C2 (IP as host)
    "T1105",          # Ingress Tool Transfer (.exe/.ps1/payload in path)
]


class ReportGenerator:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

    def export(self, results: list) -> str:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"phishing_analysis_{timestamp}.json"
        filepath = self.output_dir / filename

        report = {"generated_at": datetime.now(timezone.utc).isoformat(),
                  "tool": "Phishing URL Analyzer",
                  "mitre_coverage": MITRE_COVERAGE,
                  "total_urls": len(results),
                  "summary": self._summarize(results),
                  "results": results}

        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)

        return str(filepath)

    def _summarize(self, results: list) -> dict:
        if not results:
            return {"MALICIOUS": 0, "SUSPICIOUS": 0, "BENIGN": 0, "avg_score": 0}
        verdicts = [r["risk"]["verdict"] for r in results]
        return {"MALICIOUS": verdicts.count("MALICIOUS"),
                "SUSPICIOUS": verdicts.count("SUSPICIOUS"),
                "BENIGN": verdicts.count("BENIGN"),
                "avg_score": round(sum(r["risk"]["score"] for r in results) / len(results), 1)}
