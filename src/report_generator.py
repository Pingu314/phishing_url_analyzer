"""
Report Generator
Exports analysis results to timestamped JSON files in /reports
"""

import json
from datetime import datetime, timezone
from pathlib import Path


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
                  "mitre_coverage": ["T1566", "T1566.002", "T1027", "T1583.005"],
                  "total_urls": len(results),
                  "summary": self._summarize(results),
                  "results": results}

        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)

        return str(filepath)

    def _summarize(self, results: list) -> dict:
        verdicts = [r["risk"]["verdict"] for r in results]
        return {"MALICIOUS": verdicts.count("MALICIOUS"),
                "SUSPICIOUS": verdicts.count("SUSPICIOUS"),
                "BENIGN": verdicts.count("BENIGN"),
                "avg_score": round(sum(r["risk"]["score"] for r in results) / len(results), 1) if results else 0}