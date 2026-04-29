"""
Threat Intelligence Enricher
Integrates with VirusTotal and URLScan.io APIs
Gracefully degrades if API keys are not configured

Designed for easy extension - additional enrichers (e.g. WHOIS,
AbuseIPDB) can be added as new _query_* methods and wired into enrich()
"""

import base64
import time
import urllib.parse
import urllib.request
import urllib.error
import json
import datetime
import whois
from typing import Optional


def _urlopen_with_retry(req: urllib.request.Request, max_retries: int = 3, timeout: int = 10) -> bytes:
    """
    Open a urllib Request with exponential backoff on 429 / 5xx
    Returns response body as bytes, raises on final failure
    """
    last_exc: Exception = RuntimeError("No attempts made")
    for attempt in range(max_retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            if e.code == 429 or e.code >= 500:
                time.sleep(2 ** attempt)
                last_exc = e
            else:
                raise
        except (urllib.error.URLError, OSError) as e:
            time.sleep(2 ** attempt)
            last_exc = e
    raise last_exc


class ThreatIntelEnricher:
    def __init__(self, config: dict):
        self.vt_api_key = config.get("virustotal_api_key", "")
        self.urlscan_api_key = config.get("urlscan_api_key", "")

    def enrich(self, url: str) -> dict:
        """Run all available TI checks and return a merged result dict"""
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

        # WHOIS age - offline-safe, skipped when python-whois not installed
        domain = urllib.parse.urlparse(url if url.startswith(("http://", "https://")) else "http://" + url).netloc
        domain = domain.split(":")[0]
        if domain:
            whois_result = self._query_whois(domain)
            intel.update(whois_result)

        return intel

    def _query_virustotal(self, url: str) -> Optional[dict]:
        """Query VirusTotal URL analysis endpoint

        Flow:
          1. GET /api/v3/urls/{url_id}  - returns stats if URL is known
          2. On 404 (URL never submitted), POST to /api/v3/urls to submit
             it for analysis and return a "submitted" note instead of an error
        """
        try:
            # VT v3: URL must be base64url-encoded without padding
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

            try:
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
                if e.code != 404:
                    raise
                # URL not in VT database - submit it for future analysis
                encoded = urllib.parse.urlencode({"url": url}).encode()
                submit_req = urllib.request.Request("https://www.virustotal.com/api/v3/urls",
                                                    data=encoded,
                                                    headers={"x-apikey": self.vt_api_key},
                                                    method="POST")
                result = json.loads(_urlopen_with_retry(submit_req))
                analysis_id = result["data"]["id"]
                return {"vt_checked": True,
                        "vt_note": "URL submitted for analysis (not yet in database)",
                        "vt_link": f"https://www.virustotal.com/gui/analysis/{analysis_id}"}

        except Exception as e:
            return {"enrichment_errors": [f"VirusTotal error: {str(e)}"]}

    def _query_urlscan(self, url: str) -> Optional[dict]:
        """Submit URL to URLScan.io and poll for the verdict"""
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
                return {"enrichment_errors": ["URLScan: no UUID returned"]}

            # Poll up to 6 times (~ 30 s) for the result
            result_url = f"https://urlscan.io/api/v1/result/{scan_uuid}/"
            for _ in range(6):
                time.sleep(5)
                try:
                    with urllib.request.urlopen(result_url, timeout=10) as response:
                        result_data = json.loads(response.read())
                    verdicts = result_data.get("verdicts", {}).get("overall", {})
                    # Note: scan was submitted as private; the result link is only
                    # accessible to the submitter's account
                    return {"urlscan_checked": True,
                            "urlscan_malicious": verdicts.get("malicious", False),
                            "urlscan_score": verdicts.get("score", 0),
                            "urlscan_link": f"https://urlscan.io/result/{scan_uuid}/"}
                except urllib.error.HTTPError as e:
                    if e.code == 404:
                        continue   # Not ready yet - keep polling
                    raise

            return {"enrichment_errors": ["URLScan: result not ready after polling"]}

        except Exception as e:
            return {"enrichment_errors": [f"URLScan error: {str(e)}"]}

    def _query_whois(self, domain: str) -> dict:
        """WHOIS domain age lookup. Fails silently if python-whois not installed"""
        result = {"domain_age_days": None, "creation_date": None, "whois_available": False}
        try:
            w = whois.whois(domain)
            created = w.creation_date
            if isinstance(created, list):
                created = created[0]
            if isinstance(created, datetime.datetime):
                # Normalize: attach UTC only if the datetime is naive
                if created.tzinfo is None:
                    created = created.replace(tzinfo=datetime.timezone.utc)
                age = (datetime.datetime.now(datetime.timezone.utc) - created).days
                result["domain_age_days"] = age
                result["creation_date"] = created.date().isoformat()
                result["whois_available"] = True
        except Exception:
            pass
        return result