"""
Unit tests for Phishing URL Analyzer
Run: pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../src"))

import pytest
from url_extractor import URLFeatureExtractor
from risk_scorer import RiskScorer
from redirect_follower import RedirectFollower


# ── Feature Extractor Tests ──────────────────────────────────────────────────

class TestURLFeatureExtractor:

    def test_brand_impersonation_detected(self):
        f = URLFeatureExtractor("http://paypal-secure.com/login").extract()
        assert f["brand_impersonation"] is True

    def test_legitimate_brand_not_flagged(self):
        f = URLFeatureExtractor("https://paypal.com/signin").extract()
        assert f["brand_impersonation"] is False

    def test_ip_as_host(self):
        f = URLFeatureExtractor("http://192.168.1.1/login").extract()
        assert f["uses_ip_as_host"] is True

    def test_no_ip_for_domain(self):
        f = URLFeatureExtractor("https://google.com").extract()
        assert f["uses_ip_as_host"] is False

    def test_suspicious_tld(self):
        f = URLFeatureExtractor("https://banking-secure.xyz/verify").extract()
        assert f["suspicious_tld"] is True

    def test_https_detected(self):
        f = URLFeatureExtractor("https://google.com").extract()
        assert f["uses_https"] is True

    def test_no_https_flagged(self):
        f = URLFeatureExtractor("http://google.com").extract()
        assert f["uses_https"] is False

    def test_hex_encoding_detected(self):
        f = URLFeatureExtractor("http://evil.com/path%2Fevade%2F").extract()
        assert f["hex_encoding"] is True

    def test_at_symbol_detected(self):
        f = URLFeatureExtractor("http://legit.com@evil.com").extract()
        assert f["at_symbol"] is True

    def test_brand_in_subdomain(self):
        f = URLFeatureExtractor("http://paypal.evil.com/login").extract()
        assert f["brand_in_subdomain"] is True

    def test_subdomain_count(self):
        f = URLFeatureExtractor("http://a.b.c.evil.com").extract()
        assert f["subdomain_count"] >= 3

    def test_redirect_param_detected(self):
        f = URLFeatureExtractor("http://site.com/page?redirect=http://evil.com").extract()
        assert f["has_redirect_param"] is True

    def test_url_length(self):
        f = URLFeatureExtractor("https://" + "a" * 80 + ".com").extract()
        assert f["url_length"] > 75

    def test_entropy_computed(self):
        f = URLFeatureExtractor("https://google.com").extract()
        assert isinstance(f["domain_entropy"], float)

    def test_suspicious_keywords_found(self):
        f = URLFeatureExtractor("http://evil.com/login/verify/account").extract()
        assert f["has_suspicious_keywords"] is True
        assert len(f["suspicious_keywords_found"]) >= 1


# ── Risk Scorer Tests ────────────────────────────────────────────────────────

class TestRiskScorer:

    @pytest.fixture
    def scorer(self):
        return RiskScorer()

    @pytest.fixture
    def clean_features(self):
        return {
            "uses_https": True,
            "brand_impersonation": False,
            "brand_in_subdomain": False,
            "uses_ip_as_host": False,
            "suspicious_tld": False,
            "has_suspicious_keywords": False,
            "at_symbol": False,
            "hex_encoding": False,
            "has_redirect_param": False,
            "double_slash": False,
            "redirect_domain_switch": False,
            "redirect_count": 1,
            "domain_entropy": 2.0,
            "url_length": 30,
            "hyphen_count": 0,
            "path_depth": 1,
            "subdomain_count": 0,
            "port_in_url": False,
        }

    @pytest.fixture
    def clean_intel(self):
        return {"vt_malicious": 0, "urlscan_malicious": False}

    def test_benign_url_scores_low(self, scorer, clean_features, clean_intel):
        result = scorer.score(clean_features, clean_intel)
        assert result["verdict"] == "BENIGN"
        assert result["score"] <= 20

    def test_vt_2_engines_hits_malicious(self, scorer, clean_features, clean_intel):
        # 2 engines × 20pts = 40pts → SUSPICIOUS edge, + no_https pushes to MALICIOUS
        intel = {**clean_intel, "vt_malicious": 2}
        features = {**clean_features, "uses_https": False}
        result = scorer.score(features, intel)
        assert result["score"] >= 47

    def test_vt_malicious_score_capped_at_40(self, scorer, clean_features, clean_intel):
        intel = {**clean_intel, "vt_malicious": 10}
        result = scorer.score(clean_features, intel)
        assert result["breakdown"]["vt_malicious_engines"] == 40

    def test_brand_impersonation_adds_points(self, scorer, clean_features, clean_intel):
        features = {**clean_features, "brand_impersonation": True}
        result = scorer.score(features, clean_intel)
        assert result["score"] >= 18

    def test_ip_host_raises_score(self, scorer, clean_features, clean_intel):
        features = {**clean_features, "uses_ip_as_host": True}
        result = scorer.score(features, clean_intel)
        assert result["score"] >= 15

    def test_redirect_domain_switch_raises_score(self, scorer, clean_features, clean_intel):
        features = {**clean_features, "redirect_domain_switch": True}
        result = scorer.score(features, clean_intel)
        assert result["score"] >= 12

    def test_score_capped_at_100(self, scorer, clean_intel):
        features = {
            "uses_https": False,
            "brand_impersonation": True,
            "brand_in_subdomain": True,
            "uses_ip_as_host": True,
            "suspicious_tld": True,
            "has_suspicious_keywords": True,
            "at_symbol": True,
            "hex_encoding": True,
            "has_redirect_param": True,
            "double_slash": True,
            "redirect_domain_switch": True,
            "redirect_count": 5,
            "domain_entropy": 4.5,
            "url_length": 200,
            "hyphen_count": 6,
            "path_depth": 8,
            "subdomain_count": 4,
            "port_in_url": True,
        }
        intel = {"vt_malicious": 20, "urlscan_malicious": True}
        result = scorer.score(features, intel)
        assert result["score"] == 100

    def test_breakdown_populated(self, scorer, clean_features, clean_intel):
        features = {**clean_features, "brand_impersonation": True}
        result = scorer.score(features, clean_intel)
        assert "brand_impersonation" in result["breakdown"]

    def test_verdict_suspicious_range(self, scorer, clean_features, clean_intel):
        features = {**clean_features, "suspicious_tld": True, "has_suspicious_keywords": True, "uses_https": False}
        result = scorer.score(features, clean_intel)
        assert result["verdict"] == "SUSPICIOUS"
        assert 21 <= result["score"] <= 49

# ── Redirect Follower Tests (no network — unit test domain parsing only) ─────

class TestRedirectFollower:

    def test_extract_domain(self):
        rf = RedirectFollower()
        assert rf._extract_domain("https://evil.com/path") == "evil.com"

    def test_extract_domain_with_port(self):
        rf = RedirectFollower()
        assert rf._extract_domain("http://evil.com:8080/path") == "evil.com:8080"

    def test_extract_domain_invalid(self):
        rf = RedirectFollower()
        result = rf._extract_domain("not-a-url")
        assert isinstance(result, str)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
