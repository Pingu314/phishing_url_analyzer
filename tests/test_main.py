"""
Tests for src/main.py - load_config, analyze_url
"""

import pytest
from unittest.mock import MagicMock, patch

from src.main import analyze_url, main, load_config


class TestLoadConfig:

    def test_returns_empty_dict_when_file_missing(self, tmp_path):
        result = load_config(str(tmp_path / "nonexistent.json"))
        assert result == {}

    def test_returns_config_when_file_exists(self, tmp_path):
        cfg = tmp_path / "config.json"
        cfg.write_text('{"virustotal_api_key": "abc123"}')
        result = load_config(str(cfg))
        assert result["virustotal_api_key"] == "abc123"

    def test_returns_empty_dict_on_invalid_json(self, tmp_path):
        cfg = tmp_path / "config.json"
        cfg.write_text("not valid json {{")
        result = load_config(str(cfg))
        assert result == {}

    def test_returns_empty_dict_on_empty_file(self, tmp_path):
        cfg = tmp_path / "config.json"
        cfg.write_text("")
        result = load_config(str(cfg))
        assert result == {}


class TestAnalyzeUrl:
    """Integration tests for the full analyze_url pipeline (all network mocked)."""

    def _mock_redirect(self, url: str) -> dict:
        return {"hop_count": 0,
                "domain_switches": [],
                "chain": [],
                "final_url": url,
                "initial_url": url,
                "domain_changed": False,
                "initial_domain": "example.com",
                "final_domain": "example.com",
                "errors": []}

    def _mock_intel(self) -> dict:
        return {"vt_checked": False,
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
                "domain_age_days": None,
                "enrichment_errors": []}

    def _mock_risk(self, verdict="BENIGN", score=5):
        return {"score": score, "verdict": verdict,
                "confidence": "VERY_LOW", "breakdown": {}}

    def test_returns_required_keys(self):
        url = "https://example.com/page"
        mock_enricher = MagicMock()
        mock_enricher.enrich.return_value = self._mock_intel()
        mock_scorer = MagicMock()
        mock_scorer.score.return_value = self._mock_risk()
        with patch("src.main.RedirectFollower") as mock_rf:
            mock_rf.return_value.follow.return_value = self._mock_redirect(url)
            result = analyze_url(url, {}, enricher=mock_enricher, scorer=mock_scorer)
        for key in ["url", "final_url", "redirect_chain", "features",
                    "threat_intel", "risk", "mitre"]:
            assert key in result, f"Missing key: {key}"

    def test_features_extracted_from_original_url(self):
        """Features must come from original URL, not the redirect destination."""
        original = "http://paypa1.com/signin"
        final = "https://paypal.com"
        redirect_data = self._mock_redirect(original)
        redirect_data["final_url"] = final
        redirect_data["hop_count"] = 1
        redirect_data["chain"] = [{"hop": 1, "from_url": original,
                                   "to_url": final, "status_code": 301}]
        mock_enricher = MagicMock()
        mock_enricher.enrich.return_value = self._mock_intel()
        mock_scorer = MagicMock()
        mock_scorer.score.return_value = self._mock_risk("SUSPICIOUS", 18)
        with patch("src.main.RedirectFollower") as mock_rf:
            mock_rf.return_value.follow.return_value = redirect_data
            result = analyze_url(original, {}, enricher=mock_enricher, scorer=mock_scorer)
        assert result["url"] == original
        assert result["final_url"] == final
        assert result["features"]["typosquatting"] is True

    def test_enricher_called_with_final_url(self):
        """TI enrichment must use the final URL, not the original."""
        original = "http://paypa1.com/signin"
        final = "https://paypal.com"
        redirect_data = self._mock_redirect(original)
        redirect_data["final_url"] = final
        mock_enricher = MagicMock()
        mock_enricher.enrich.return_value = self._mock_intel()
        mock_scorer = MagicMock()
        mock_scorer.score.return_value = self._mock_risk()
        with patch("src.main.RedirectFollower") as mock_rf:
            mock_rf.return_value.follow.return_value = redirect_data
            analyze_url(original, {}, enricher=mock_enricher, scorer=mock_scorer)
        mock_enricher.enrich.assert_called_once_with(final)

    def test_creates_enricher_when_none(self):
        """analyze_url must create ThreatIntelEnricher when enricher=None."""
        url = "https://example.com"
        mock_scorer = MagicMock()
        mock_scorer.score.return_value = self._mock_risk()
        with patch("src.main.RedirectFollower") as mock_rf, \
             patch("src.main.ThreatIntelEnricher") as mock_ti:
            mock_rf.return_value.follow.return_value = self._mock_redirect(url)
            mock_ti.return_value.enrich.return_value = self._mock_intel()
            analyze_url(url, {"key": "val"}, scorer=mock_scorer)
        mock_ti.assert_called_once_with({"key": "val"})

    def test_creates_scorer_when_none(self):
        """analyze_url must create RiskScorer when scorer=None."""
        url = "https://example.com"
        mock_enricher = MagicMock()
        mock_enricher.enrich.return_value = self._mock_intel()
        with patch("src.main.RedirectFollower") as mock_rf, \
             patch("src.main.RiskScorer") as mock_rs:
            mock_rf.return_value.follow.return_value = self._mock_redirect(url)
            mock_rs.return_value.score.return_value = self._mock_risk()
            analyze_url(url, {}, enricher=mock_enricher)
        mock_rs.assert_called_once()

    def test_redirect_count_added_to_features(self):
        url = "https://example.com"
        redirect_data = self._mock_redirect(url)
        redirect_data["hop_count"] = 3
        mock_enricher = MagicMock()
        mock_enricher.enrich.return_value = self._mock_intel()
        mock_scorer = MagicMock()
        mock_scorer.score.return_value = self._mock_risk()
        with patch("src.main.RedirectFollower") as mock_rf:
            mock_rf.return_value.follow.return_value = redirect_data
            result = analyze_url(url, {}, enricher=mock_enricher, scorer=mock_scorer)
        assert result["features"]["redirect_count"] == 3

    def test_mitre_tags_populated(self):
        url = "http://paypa1.com/signin"
        mock_enricher = MagicMock()
        mock_enricher.enrich.return_value = self._mock_intel()
        mock_scorer = MagicMock()
        mock_scorer.score.return_value = self._mock_risk("SUSPICIOUS", 18)
        with patch("src.main.RedirectFollower") as mock_rf:
            mock_rf.return_value.follow.return_value = self._mock_redirect(url)
            result = analyze_url(url, {}, enricher=mock_enricher, scorer=mock_scorer)
        assert isinstance(result["mitre"], list)


class TestAnalyzeUrlBranches:

    def _mock_redirect_with_hops(self, url: str, final: str) -> dict:
        return {"hop_count": 2,
                "domain_switches": [{"from_domain": "evil.com", "to_domain": "other.com"}],
                "chain": [{"hop": 1, "from_url": url, "to_url": final,
                           "status_code": 301}],
                "final_url": final,
                "initial_url": url,
                "domain_changed": True,
                "initial_domain": "evil.com",
                "final_domain": "other.com",
                "errors": []}

    def _mock_intel(self) -> dict:
        return {"vt_checked": False, "vt_malicious": 0, "vt_suspicious": 0,
                "vt_harmless": 0, "vt_undetected": 0, "vt_engines_total": 0,
                "vt_link": "", "urlscan_checked": False, "urlscan_malicious": False,
                "urlscan_score": 0, "urlscan_link": "", "domain_age_days": None,
                "enrichment_errors": []}

    def _mock_risk(self, verdict="SUSPICIOUS", score=30):
        return {"score": score, "verdict": verdict,
                "confidence": "LOW", "breakdown": {}}

    def test_verbose_mode_does_not_raise(self, capsys):
        """verbose=True path - prints features and intel without error."""
        url = "https://example.com"
        mock_enricher = MagicMock()
        mock_enricher.enrich.return_value = self._mock_intel()
        mock_scorer = MagicMock()
        mock_scorer.score.return_value = self._mock_risk("BENIGN", 5)
        redirect = {"hop_count": 0, "domain_switches": [], "chain": [],
                    "final_url": url, "initial_url": url, "domain_changed": False,
                    "initial_domain": "example.com", "final_domain": "example.com",
                    "errors": []}
        with patch("src.main.RedirectFollower") as mock_rf:
            mock_rf.return_value.follow.return_value = redirect
            result = analyze_url(url, {}, verbose=True,
                                 enricher=mock_enricher, scorer=mock_scorer)
        assert result["url"] == url

    def test_hop_count_with_domain_switch_in_output(self, capsys):
        """hop_count > 0 with domain switches - prints SUSPICIOUS message."""
        url = "http://evil.com/redirect"
        final = "http://other.com/landing"
        mock_enricher = MagicMock()
        mock_enricher.enrich.return_value = self._mock_intel()
        mock_scorer = MagicMock()
        mock_scorer.score.return_value = self._mock_risk()
        with patch("src.main.RedirectFollower") as mock_rf:
            mock_rf.return_value.follow.return_value = self._mock_redirect_with_hops(
                url, final)
            analyze_url(url, {}, enricher=mock_enricher, scorer=mock_scorer)
        captured = capsys.readouterr()
        assert "SUSPICIOUS" in captured.out

    def test_final_url_different_prints_destination(self, capsys):
        """When final_url != url, destination is printed in verdict block."""
        url = "http://paypa1.com/signin"
        final = "https://paypal.com"
        redirect = {"hop_count": 1, "domain_switches": [],
                    "chain": [{"hop": 1, "from_url": url, "to_url": final,
                               "status_code": 301}],
                    "final_url": final, "initial_url": url,
                    "domain_changed": True, "initial_domain": "paypa1.com",
                    "final_domain": "paypal.com", "errors": []}
        mock_enricher = MagicMock()
        mock_enricher.enrich.return_value = self._mock_intel()
        mock_scorer = MagicMock()
        mock_scorer.score.return_value = self._mock_risk()
        with patch("src.main.RedirectFollower") as mock_rf:
            mock_rf.return_value.follow.return_value = redirect
            analyze_url(url, {}, enricher=mock_enricher, scorer=mock_scorer)
        captured = capsys.readouterr()
        assert "Final URL" in captured.out


class TestMain:
    """Tests for the main() CLI entrypoint."""

    def _make_result(self, url="http://evil.com", verdict="MALICIOUS", score=75):
        return {"url": url,
                "final_url": url,
                "redirect_chain": {"hop_count": 0, "domain_switches": [],
                                   "chain": [], "final_url": url,
                                   "initial_url": url, "domain_changed": False,
                                   "initial_domain": "evil.com",
                                   "final_domain": "evil.com", "errors": []},
                "features": {},
                "threat_intel": {},
                "risk": {"score": score, "verdict": verdict,
                         "confidence": "HIGH", "breakdown": {}},
                "mitre": ["T1566.002 - Spearphishing Link"]}

    def test_no_args_exits_1(self):
        with patch("sys.argv", ["phishing-analyze"]):
            with pytest.raises(SystemExit) as exc:
                main()
        assert exc.value.code == 1

    def test_single_url_runs(self, tmp_path):
        result = self._make_result()
        with patch("sys.argv", ["phishing-analyze", "-u", "http://evil.com",
                                "--config", str(tmp_path / "noconfig.json")]), \
             patch("src.main.analyze_url", return_value=result):
            main()  # should not raise

    def test_file_not_found_exits_1(self, tmp_path):
        with patch("sys.argv", ["phishing-analyze", "-f",
                                str(tmp_path / "missing.txt")]):
            with pytest.raises(SystemExit) as exc:
                main()
        assert exc.value.code == 1

    def test_file_with_urls_runs(self, tmp_path):
        url_file = tmp_path / "urls.txt"
        url_file.write_text("http://evil.com\n# comment\n\n")
        result = self._make_result()
        with patch("sys.argv", ["phishing-analyze", "-f", str(url_file),
                                "--config", str(tmp_path / "noconfig.json")]), \
             patch("src.main.analyze_url", return_value=result), \
             patch("src.main.ReportGenerator") as mock_rg:
            mock_rg.return_value.export.return_value = str(tmp_path / "report.json")
            main()

    def test_duplicate_urls_deduplicated(self, tmp_path, capsys):
        url_file = tmp_path / "urls.txt"
        url_file.write_text("http://evil.com\nhttp://evil.com\n")
        result = self._make_result()
        with patch("sys.argv", ["phishing-analyze", "-f", str(url_file),
                                "--config", str(tmp_path / "noconfig.json"),
                                "--no-export"]) if False else \
             patch("sys.argv", ["phishing-analyze", "-f", str(url_file),
                                "--config", str(tmp_path / "noconfig.json")]), \
             patch("src.main.analyze_url", return_value=result) as mock_au, \
             patch("src.main.ReportGenerator") as mock_rg:
            mock_rg.return_value.export.return_value = str(tmp_path / "r.json")
            main()
        # analyze_url called once, not twice
        assert mock_au.call_count == 1

    def test_export_flag_calls_reporter(self, tmp_path):
        result = self._make_result()
        with patch("sys.argv", ["phishing-analyze", "-u", "http://evil.com",
                                "--export",
                                "--config", str(tmp_path / "noconfig.json")]), \
             patch("src.main.analyze_url", return_value=result), \
             patch("src.main.ReportGenerator") as mock_rg:
            mock_rg.return_value.export.return_value = str(tmp_path / "r.json")
            main()
        mock_rg.return_value.export.assert_called_once()

    def test_csv_flag_calls_export_csv(self, tmp_path):
        result = self._make_result()
        with patch("sys.argv", ["phishing-analyze", "-u", "http://evil.com",
                                "--csv",
                                "--config", str(tmp_path / "noconfig.json")]), \
             patch("src.main.analyze_url", return_value=result), \
             patch("src.main.ReportGenerator") as mock_rg:
            mock_rg.return_value.export_csv.return_value = str(tmp_path / "r.csv")
            main()
        mock_rg.return_value.export_csv.assert_called_once()

    def test_batch_summary_printed_for_multiple_urls(self, tmp_path, capsys):
        url_file = tmp_path / "urls.txt"
        url_file.write_text("http://evil.com\nhttp://other.com\n")
        results = [self._make_result("http://evil.com"),
                   self._make_result("http://other.com", "SUSPICIOUS", 35)]
        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            r = results[call_count]
            call_count += 1
            return r

        with patch("sys.argv", ["phishing-analyze", "-f", str(url_file),
                                "--config", str(tmp_path / "noconfig.json")]), \
             patch("src.main.analyze_url", side_effect=side_effect), \
             patch("src.main.ReportGenerator") as mock_rg:
            mock_rg.return_value.export.return_value = str(tmp_path / "r.json")
            main()
        captured = capsys.readouterr()
        assert "BATCH SUMMARY" in captured.out
