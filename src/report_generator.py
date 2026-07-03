"""
Report Generator
Serializes analysis results to JSON and/or CSV.
"""

import csv
import json
from datetime import datetime, timezone
from pathlib import Path


class ReportGenerator:

    REPORT_DIR = Path("reports")

    def __init__(self):
        # Single timestamp per instance so JSON + CSV exports always share
        # the same suffix even when called in rapid succession
        self._ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    def _ensure_dir(self) -> None:
        self.REPORT_DIR.mkdir(parents=True, exist_ok=True)

    def export(self, results: list) -> str:
        """Write results to a timestamped JSON file. Returns the file path"""
        self._ensure_dir()
        filename = self.REPORT_DIR / f"report_{self._ts}.json"
        with open(filename, "w") as f:
            json.dump(results, f, indent=2, default=str)
        return str(filename)

    def export_csv(self, results: list) -> str:
        """Write a flat summary CSV - one row per URL. Returns the file path"""
        self._ensure_dir()
        filename = self.REPORT_DIR / f"report_{self._ts}.csv"

        fieldnames = ["url", "verdict", "score", "confidence", "final_url", "redirect_hops",
                      "brand_impersonation", "typosquatting", "cloud_hosting_abuse", "private_ip",
                      "uses_ip_as_host", "vt_malicious", "urlscan_malicious", "domain_age_days", "mitre_tags"]

        with open(filename, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for r in results:
                features = r.get("features", {})
                intel = r.get("threat_intel", {})
                risk = r.get("risk", {})
                writer.writerow({"url":                 r.get("url", ""),
                                 "verdict":             risk.get("verdict", ""),
                                 "score":               risk.get("score", 0),
                                 "confidence":          risk.get("confidence", ""),
                                 "final_url":           r.get("final_url", ""),
                                 "redirect_hops":       r.get("redirect_chain", {}).get("hop_count", 0),
                                 "brand_impersonation": features.get("brand_impersonation", False),
                                 "typosquatting":       features.get("typosquatting", False),
                                 "cloud_hosting_abuse": features.get("cloud_hosting_abuse", False),
                                 "private_ip":          features.get("private_ip", False),
                                 "uses_ip_as_host":     features.get("uses_ip_as_host", False),
                                 "vt_malicious":        intel.get("vt_malicious", 0),
                                 "urlscan_malicious":   intel.get("urlscan_malicious", False),
                                 "domain_age_days":     intel.get("domain_age_days", ""),
                                 "mitre_tags":          " | ".join(r.get("mitre", []))})
        return str(filename)

    _HTML_HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Phishing URL Analyzer - Triage Report</title>
<style>
  body { font-family: "Segoe UI", system-ui, sans-serif; background: #0f1419;
         color: #e6e6e6; margin: 0; padding: 32px; }
  h1 { font-size: 20px; margin: 0 0 4px; }
  .sub { color: #8a9aa0; font-size: 13px; margin-bottom: 24px; }
  .cards { display: flex; gap: 16px; margin-bottom: 24px; }
  .card { background: #1a222b; border-radius: 8px; padding: 14px 24px; min-width: 110px; }
  .card .num { font-size: 28px; font-weight: 600; }
  .card .lbl { font-size: 11px; color: #8a9aa0; text-transform: uppercase;
               letter-spacing: 1px; }
  .card.MALICIOUS .num { color: #ff5c5c; }
  .card.SUSPICIOUS .num { color: #ffb347; }
  .card.BENIGN .num { color: #7bd88f; }
  table { width: 100%; border-collapse: collapse; background: #1a222b;
          border-radius: 8px; overflow: hidden; }
  th, td { padding: 10px 14px; text-align: left; font-size: 13px; vertical-align: top; }
  th { background: #232d38; color: #8a9aa0; text-transform: uppercase;
       font-size: 11px; letter-spacing: 1px; }
  tr { border-top: 1px solid #232d38; }
  .chip { padding: 2px 10px; border-radius: 12px; font-size: 11px;
          font-weight: 600; white-space: nowrap; }
  .chip.MALICIOUS { background: #4a1f1f; color: #ff5c5c; }
  .chip.SUSPICIOUS { background: #4a3a1f; color: #ffb347; }
  .chip.BENIGN { background: #1f4a2b; color: #7bd88f; }
  .score { font-weight: 600; }
  .url { word-break: break-all; }
  .tag { color: #8a9aa0; font-size: 12px; }
</style>
</head>
<body>
<h1>Phishing URL Analyzer</h1>
"""

    def export_html(self, results: list) -> str:
        """Write a styled HTML triage report. Returns the file path"""
        self._ensure_dir()
        filename = self.REPORT_DIR / f"report_{self._ts}.html"

        counts: dict = {"MALICIOUS": 0, "SUSPICIOUS": 0, "BENIGN": 0}
        for r in results:
            verdict = r.get("risk", {}).get("verdict", "BENIGN")
            counts[verdict] = counts.get(verdict, 0) + 1

        rows = []
        ordered = sorted(results,
                         key=lambda r: r.get("risk", {}).get("score", 0),
                         reverse=True)
        for r in ordered:
            risk = r.get("risk", {})
            intel = r.get("threat_intel", {})
            features = r.get("features", {})
            verdict = risk.get("verdict", "BENIGN")
            fired = ", ".join(k for k, v in features.items() if v is True) or "-"
            mitre = ", ".join(r.get("mitre", [])) or "-"
            age = intel.get("domain_age_days")
            rows.append(
                "<tr>"
                f'<td class="url">{self._escape(r.get("url", ""))}</td>'
                f'<td><span class="chip {verdict}">{verdict}</span></td>'
                f'<td class="score">{risk.get("score", 0)}</td>'
                f'<td>{risk.get("confidence", "")}</td>'
                f'<td>{r.get("redirect_chain", {}).get("hop_count", 0)}</td>'
                f'<td class="tag">{self._escape(fired)}</td>'
                f'<td>{intel.get("vt_malicious", 0)}</td>'
                f'<td>{age if age is not None else "-"}</td>'
                f'<td class="tag">{self._escape(mitre)}</td>'
                "</tr>"
            )

        cards = "".join(
            f'<div class="card {v}"><div class="num">{counts.get(v, 0)}</div>'
            f'<div class="lbl">{v}</div></div>'
            for v in ("MALICIOUS", "SUSPICIOUS", "BENIGN")
        ) + (f'<div class="card"><div class="num">{len(results)}</div>'
             f'<div class="lbl">Total</div></div>')

        html = (self._HTML_HEAD
                + f'<div class="sub">Triage report &middot; generated {self._ts} UTC</div>'
                + f'<div class="cards">{cards}</div>'
                + "<table><tr><th>URL</th><th>Verdict</th><th>Score</th>"
                  "<th>Confidence</th><th>Hops</th><th>Indicators</th>"
                  "<th>VT hits</th><th>Domain age (d)</th><th>MITRE</th></tr>"
                + "".join(rows)
                + "</table></body></html>")

        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)
        return str(filename)

    @staticmethod
    def _escape(text: str) -> str:
        """Minimal HTML escaping for report cell content."""
        return (text.replace("&", "&amp;").replace("<", "&lt;")
                    .replace(">", "&gt;").replace('"', "&quot;"))