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