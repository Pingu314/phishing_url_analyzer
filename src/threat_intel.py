"""
Threat Intelligence Enricher
Integrates with VirusTotal and URLScan.io APIs.
Gracefully degrades if API keys are not configured.
"""

import time
import urllib.request
import urllib.error
import json
from typing import Optional


class ThreatIntelEnricher:
    def __init__(self, config: dict):
        self.vt_api_key = config.get("virustotal_api_key", "")
        self.urlscan_api_key = config.get("urlscan_api_key", "")

    def enrich(self, url: str, domain: str) -> dict:
        intel = {
            "vt_checked": False,
            "vt_malicious": 0,
            "vt_suspicious": 0,
            "vt_harmless": 0,
            "vt_undetected": 0,
            "vt_engines_total": 0,
            "vt_link": "",
            "urlscan_checked": False,
            "urlscan_malicious": False,
            "urlscan_score": 0,
            "urlscan_link": "",
            "enrichment_errors": [],
        }

        if self.vt_api_key:
            vt_result = self._query_virustotal(url)
            if vt_result:
                intel.update(vt_result)
        else:
            intel["enrichment_errors"].append("VirusTotal: no API key configured")

        if self.urlscan_api_key:
            urlscan_result = self._query_urlscan(url)
            if urlscan_result:
                intel.update(urlscan_result)
        else:
            intel["enrichment_errors"].append("URLScan.io: no API key configured")

        return intel

    def _query_virustotal(self, url: str) -> Optional[dict]:
        """Query VirusTotal URL analysis endpoint."""
        try:
            import base64
            # VT v3: URL must be base64url-encoded without padding
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

            req = urllib.request.Request(
                endpoint,
                headers={"x-apikey": self.vt_api_key}
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read())

            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {
                "vt_checked": True,
                "vt_malicious": stats.get("malicious", 0),
                "vt_suspicious": stats.get("suspicious", 0),
                "vt_harmless": stats.get("harmless", 0),
                "vt_undetected": stats.get("undetected", 0),
                "vt_engines_total": sum(stats.values()),
                "vt_link": f"https://www.virustotal.com/gui/url/{url_id}",
            }

        except urllib.error.HTTPError as e:
            if e.code == 404:
                # URL not in VT yet — submit for analysis
                return self._submit_to_virustotal(url)
            return {"enrichment_errors": [f"VirusTotal HTTP error: {e.code}"]}
        except Exception as e:
            return {"enrichment_errors": [f"VirusTotal error: {str(e)}"]}

    def _submit_to_virustotal(self, url: str) -> Optional[dict]:
        """Submit a new URL to VirusTotal for analysis."""
        try:
            data = urllib.parse.urlencode({"url": url}).encode()
            req = urllib.request.Request(
                "https://www.virustotal.com/api/v3/urls",
                data=data,
                headers={"x-apikey": self.vt_api_key},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                result = json.loads(response.read())
            analysis_id = result["data"]["id"]
            return {
                "vt_checked": True,
                "vt_note": "URL submitted for analysis (not yet in database)",
                "vt_link": f"https://www.virustotal.com/gui/analysis/{analysis_id}",
            }
        except Exception as e:
            return {"enrichment_errors": [f"VirusTotal submit error: {str(e)}"]}

    def _query_urlscan(self, url: str) -> Optional[dict]:
        """Submit URL to URLScan.io and return verdict."""
        try:
            payload = json.dumps({"url": url, "visibility": "private"}).encode()
            req = urllib.request.Request(
                "https://urlscan.io/api/v1/scan/",
                data=payload,
                headers={
                    "API-Key": self.urlscan_api_key,
                    "Content-Type": "application/json",
                },
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                submit_data = json.loads(response.read())

            scan_uuid = submit_data.get("uuid")
            if not scan_uuid:
                return None

            # URLScan takes ~10s to process
            time.sleep(12)

            result_url = f"https://urlscan.io/api/v1/result/{scan_uuid}/"
            req2 = urllib.request.Request(result_url, headers={"API-Key": self.urlscan_api_key})
            with urllib.request.urlopen(req2, timeout=10) as response:
                result_data = json.loads(response.read())

            verdicts = result_data.get("verdicts", {}).get("overall", {})
            return {
                "urlscan_checked": True,
                "urlscan_malicious": verdicts.get("malicious", False),
                "urlscan_score": verdicts.get("score", 0),
                "urlscan_link": f"https://urlscan.io/result/{scan_uuid}/",
            }

        except Exception as e:
            return {"enrichment_errors": [f"URLScan error: {str(e)}"]}


# Allow import without circular issues
import urllib.parse
