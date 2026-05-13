"""
Tests for src/threat_intel.py - ThreatIntelEnricher, _urlopen_with_retry
"""

import datetime
import json as _json
import urllib.error
import urllib.request
from unittest.mock import MagicMock, patch

from src.threat_intel import ThreatIntelEnricher, _urlopen_with_retry


class TestThreatIntelEnricher:

    def test_no_api_keys_returns_defaults(self):
        enricher = ThreatIntelEnricher({})
        result = enricher.enrich("http://example.com")
        assert result["vt_checked"] is False
        assert result["urlscan_checked"] is False
        assert result["vt_malicious"] == 0

    def test_no_vt_key_adds_error_message(self):
        enricher = ThreatIntelEnricher({})
        result = enricher.enrich("http://example.com")
        assert any("VirusTotal" in e for e in result["enrichment_errors"])

    def test_no_urlscan_key_adds_error_message(self):
        enricher = ThreatIntelEnricher({})
        result = enricher.enrich("http://example.com")
        assert any("URLScan" in e for e in result["enrichment_errors"])

    def test_vt_malicious_count_parsed(self):
        fake_body = _json.dumps(
            {"data": {"attributes": {"last_analysis_stats": {
                "malicious": 4, "suspicious": 1,
                "harmless": 55, "undetected": 5}}}}
        ).encode()
        with patch("src.threat_intel._urlopen_with_retry", return_value=fake_body):
            enricher = ThreatIntelEnricher({"virustotal_api_key": "fake"})
            result = enricher.enrich("http://evil.com")
        assert result["vt_malicious"] == 4
        assert result["vt_checked"] is True

    def test_vt_http_error_returns_enrichment_error(self):
        with patch("src.threat_intel._urlopen_with_retry",
                   side_effect=urllib.error.HTTPError(None, 403, "Forbidden", {}, None)):
            enricher = ThreatIntelEnricher({"virustotal_api_key": "fake"})
            result = enricher.enrich("http://example.com")
        assert any("VirusTotal" in e for e in result.get("enrichment_errors", []))


class TestThreatIntelEnricherExtended:

    def test_whois_age_parsed(self):
        enricher = ThreatIntelEnricher({})
        fake_whois = MagicMock()
        fake_whois.creation_date = datetime.datetime(2025, 1, 1,
                                                     tzinfo=datetime.timezone.utc)
        with patch("src.threat_intel.whois.whois", return_value=fake_whois):
            result = enricher._query_whois("example.com")
        assert result["domain_age_days"] is not None
        assert result["whois_available"] is True
        assert result["creation_date"] == "2025-01-01"

    def test_whois_list_creation_date_uses_first(self):
        enricher = ThreatIntelEnricher({})
        fake_whois = MagicMock()
        d1 = datetime.datetime(2024, 6, 1, tzinfo=datetime.timezone.utc)
        d2 = datetime.datetime(2023, 1, 1, tzinfo=datetime.timezone.utc)
        fake_whois.creation_date = [d1, d2]
        with patch("src.threat_intel.whois.whois", return_value=fake_whois):
            result = enricher._query_whois("example.com")
        assert result["creation_date"] == "2024-06-01"

    def test_whois_exception_returns_defaults(self):
        enricher = ThreatIntelEnricher({})
        with patch("src.threat_intel.whois.whois", side_effect=Exception("timeout")):
            result = enricher._query_whois("example.com")
        assert result["domain_age_days"] is None
        assert result["whois_available"] is False

    def test_vt_404_submits_url(self):
        """VT 404 branch: URL not in database - should submit and return analysis link."""
        submit_body = _json.dumps({"data": {"id": "abc-analysis-id"}}).encode()
        enricher = ThreatIntelEnricher({"virustotal_api_key": "fake"})

        def side_effect(req, **kwargs):
            # POST request has data set; GET does not
            if req.data is not None:
                return submit_body
            raise urllib.error.HTTPError(None, 404, "Not Found", {}, None)

        with patch("src.threat_intel._urlopen_with_retry", side_effect=side_effect):
            result = enricher._query_virustotal("http://newsite.com")

        assert result is not None
        assert result.get("vt_checked") is True
        assert "vt_note" in result
        assert "abc-analysis-id" in result.get("vt_link", "")

    def test_vt_non_404_error_returns_enrichment_error(self):
        enricher = ThreatIntelEnricher({"virustotal_api_key": "fake"})
        with patch("src.threat_intel._urlopen_with_retry",
                   side_effect=urllib.error.HTTPError(None, 500, "Server Error", {}, None)):
            result = enricher._query_virustotal("http://example.com")
        assert result is not None
        assert "enrichment_errors" in result

    def test_urlscan_no_uuid_returns_error(self):
        submit_body = _json.dumps({"message": "ok"}).encode()
        enricher = ThreatIntelEnricher({"urlscan_api_key": "fake"})
        with patch("src.threat_intel._urlopen_with_retry", return_value=submit_body):
            result = enricher._query_urlscan("http://example.com")
        assert result is not None
        assert "enrichment_errors" in result

    def test_urlopen_with_retry_retries_on_429(self):
        """_urlopen_with_retry must retry on 429 and succeed on third attempt."""
        call_count = 0

        def fake_urlopen(req, timeout):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise urllib.error.HTTPError(None, 429, "Too Many Requests", {}, None)
            mock_resp = MagicMock()
            mock_resp.read.return_value = b'{"ok": true}'
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            return mock_resp

        req = urllib.request.Request("http://example.com")
        with patch("urllib.request.urlopen", side_effect=fake_urlopen), \
             patch("time.sleep"):
            result = _urlopen_with_retry(req, max_retries=3)
        assert result == b'{"ok": true}'
        assert call_count == 3

    def test_urlscan_full_result_returned(self):
        """Polling loop returns result when URLScan completes successfully"""

        submit_body = _json.dumps({"uuid": "test-uuid-123"}).encode()
        result_body = _json.dumps({
            "verdicts": {"overall": {"malicious": True, "score": 75}}
        }).encode()

        enricher = ThreatIntelEnricher({"urlscan_api_key": "fake"})

        call_count = 0

        def fake_urlopen(url_or_req, timeout=None):
            nonlocal call_count
            call_count += 1
            mock_resp = MagicMock()
            mock_resp.read.return_value = result_body
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            return mock_resp

        with patch("src.threat_intel._urlopen_with_retry", return_value=submit_body), \
             patch("urllib.request.urlopen", side_effect=fake_urlopen), \
             patch("time.sleep"):
            result = enricher._query_urlscan("http://evil.com")

        assert result is not None
        assert result.get("urlscan_checked") is True
        assert result.get("urlscan_malicious") is True

    def test_urlscan_result_not_ready_returns_error(self):
        """Returns error message when scan is not ready after all polling attempts"""
        import json as _json

        submit_body = _json.dumps({"uuid": "test-uuid-456"}).encode()
        enricher = ThreatIntelEnricher({"urlscan_api_key": "fake"})

        with patch("src.threat_intel._urlopen_with_retry", return_value=submit_body), \
             patch("urllib.request.urlopen",
                   side_effect=urllib.error.HTTPError(None, 404, "Not Found", {}, None)), \
             patch("time.sleep"):
            result = enricher._query_urlscan("http://example.com")

        assert result is not None
        assert "enrichment_errors" in result
        assert any("not ready" in e for e in result["enrichment_errors"])

    def test_urlscan_with_api_key_calls_enrich(self):
        """enrich() runs URLScan when api key is configured"""
        import json as _json

        submit_body = _json.dumps({"uuid": "abc"}).encode()
        result_body = _json.dumps({
            "verdicts": {"overall": {"malicious": False, "score": 0}}
        }).encode()
        enricher = ThreatIntelEnricher({"urlscan_api_key": "fake"})

        with patch("src.threat_intel._urlopen_with_retry", return_value=submit_body), \
             patch("urllib.request.urlopen") as mock_open, \
             patch("time.sleep"):
            mock_resp = MagicMock()
            mock_resp.read.return_value = result_body
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_open.return_value = mock_resp
            result = enricher.enrich("http://example.com")

        assert result["urlscan_checked"] is True

    def test_urlopen_with_retry_handles_urlerror(self):
        """URLError triggers exponential backoff and retry"""
        from src.threat_intel import _urlopen_with_retry

        call_count = 0

        def fake_urlopen(req, timeout):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise urllib.error.URLError("connection refused")
            mock_resp = MagicMock()
            mock_resp.read.return_value = b'{"ok": true}'
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            return mock_resp

        req = urllib.request.Request("http://example.com")
        with patch("urllib.request.urlopen", side_effect=fake_urlopen), \
             patch("time.sleep"):
            result = _urlopen_with_retry(req, max_retries=3)
        assert result == b'{"ok": true}'

    def test_whois_naive_datetime_gets_utc(self):
        """Naive datetime from WHOIS is normalised to UTC before age calculation"""
        import datetime
        enricher = ThreatIntelEnricher({})
        fake_whois = MagicMock()
        # naive datetime - no tzinfo
        fake_whois.creation_date = datetime.datetime(2025, 3, 1)
        with patch("src.threat_intel.whois.whois", return_value=fake_whois):
            result = enricher._query_whois("example.com")
        assert result["whois_available"] is True
        assert result["domain_age_days"] is not None
