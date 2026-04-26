"""
Threat Intelligence Enricher
Integrates with VirusTotal and URLScan.io APIs.
Gracefully degrades if API keys are not configured.

Designed for easy extension — additional enrichers (e.g. WHOIS,
AbuseIPDB) can be added as new _query_* methods and wired into enrich().
This interface is kept stable so soc_threat_analyzer can call it directly.
"""

import time
import urllib.parse
import urllib.request
import urllib.error
import json
import datetime
import whois
from typing import Optional


def _urlopen_with_retry(req: urllib.request.Request, max_retries: int = 3, timeout: int = 10,) -> bytes:
    """
    Open a urllib Request with exponential backoff on 429 / 5xx.
    Returns response body as bytes, raises on final failure.
    """
    last_exc: Exception = RuntimeError("No attempts made")
    for attempt in range(max_retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            last_exc = exc
            if exc.code == 429:
                wait = int(exc.headers.get("Retry-After", 2 ** (attempt + 1)))
                time.sleep(wait)
            elif exc.code >= 500:
                time.sleep(2 ** attempt)
            else:
                raise
        except urllib.error.URLError:
            raise
    raise last_exc

class ThreatIntelEnricher:
    def __init__(self, config: dict):
        self.vt_api_key = config.get("virustotal_api_key", "")
        self.urlscan_api_key = config.get("urlscan_api_key", "")

    def enrich(self, url: str) -> dict:
        """Run all available TI checks and return a merged result dict."""
        intel = {"vt_checked": False,
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
                 "enrichment_errors": []}

        if self.vt_api_key:
            vt_result = self._query_virustotal(url)
            if vt_result:
                errors = vt_result.pop("enrichment_errors", [])
                intel["enrichment_errors"].extend(errors)
                intel.update(vt_result)
        else:
            intel["enrichment_errors"].append("VirusTotal: no API key configured")

        if self.urlscan_api_key:
            urlscan_result = self._query_urlscan(url)
            if urlscan_result:
                errors = urlscan_result.pop("enrichment_errors", [])
                intel["enrichment_errors"].extend(errors)
                intel.update(urlscan_result)
        else:
            intel["enrichment_errors"].append("URLScan.io: no API key configured")

        # WHOIS age — offline-safe, skipped when python-whois not installed
        domain = urllib.parse.urlparse(url if url.startswith("http") else "http://" + url).netloc.split(":")[0]
        intel.update(self._query_whois(domain))

        return intel

    def _query_virustotal(self, url: str) -> Optional[dict]:
        """Query VirusTotal URL analysis endpoint."""
        try:
            import base64
            # VT v3: URL must be base64url-encoded without padding
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

            req = urllib.request.Request(endpoint, headers={"x-apikey": self.vt_api_key})
            data = json.loads(_urlopen_with_retry(req))

            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {"vt_checked": True,
                    "vt_malicious": stats.get("malicious", 0),
                    "vt_suspicious": stats.get("suspicious", 0),
                    "vt_harmless": stats.get("harmless", 0),
                    "vt_undetected": stats.get("undetected", 0),
                    "vt_engines_total": sum(stats.values()),
                    "vt_link": f"https://www.virustotal.com/gui/url/{url_id}"}

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
            req = urllib.request.Request("https://www.virustotal.com/api/v3/urls",
                                         data=data,
                                         headers={"x-apikey": self.vt_api_key},
                                         method="POST")
            result = json.loads(_urlopen_with_retry(req))
            analysis_id = result["data"]["id"]
            return {"vt_checked": True,
                    "vt_note": "URL submitted for analysis (not yet in database)",
                    "vt_link": f"https://www.virustotal.com/gui/analysis/{analysis_id}"}
        except Exception as e:
            return {"enrichment_errors": [f"VirusTotal submit error: {str(e)}"]}

    def _query_urlscan(self, url: str) -> Optional[dict]:
        """Submit URL to URLScan.io and poll for the verdict."""
        try:
            payload = json.dumps({"url": url, "visibility": "private"}).encode()
            req = urllib.request.Request("https://urlscan.io/api/v1/scan/",
                                         data=payload,
                                         headers={"API-Key": self.urlscan_api_key,
                                                  "Content-Type": "application/json"},
                                         method="POST")
            submit_data = json.loads(_urlopen_with_retry(req))

            scan_uuid = submit_data.get("uuid")
            if not scan_uuid:
                return {"enrichment_errors": ["URLScan: no uuid returned"]}

            # Poll for results (URLScan typically takes 10-20s to process)
            result_url = f"https://urlscan.io/api/v1/result/{scan_uuid}/"
            req2 = urllib.request.Request(result_url,
                                          headers={"API-Key": self.urlscan_api_key})
            for attempt in range(10):
                time.sleep(3)
                try:
                    with urllib.request.urlopen(req2, timeout=10) as response:
                        result_data = json.loads(response.read())
                    verdicts = result_data.get("verdicts", {}).get("overall", {})
                    return {"urlscan_checked": True,
                            "urlscan_malicious": verdicts.get("malicious", False),
                            "urlscan_score": verdicts.get("score", 0),
                            "urlscan_link": f"https://urlscan.io/result/{scan_uuid}/"}
                except urllib.error.HTTPError as e:
                    if e.code == 404:
                        continue   # Not ready yet - keep polling
                    raise

            return {"enrichment_errors": [f"URLScan: result not ready after polling"]}

        except Exception as e:
            return {"enrichment_errors": [f"URLScan error: {str(e)}"]}

    def _query_whois(self, domain: str) -> dict:
        """WHOIS domain age lookup. Fails silently if python-whois not installed."""
        result = {"domain_age_days": None, "creation_date": None, "whois_available": False}
        try:
            w = whois.whois(domain)
            created = w.creation_date
            if isinstance(created, list):
                created = created[0]
            if isinstance(created, datetime.datetime):
                age = (datetime.datetime.now(datetime.timezone.utc) - created.replace(tzinfo=datetime.timezone.utc)).days
                result["domain_age_days"] = age
                result["creation_date"] = created.date().isoformat()
                result["whois_available"] = True
        except Exception:
            pass
        return result