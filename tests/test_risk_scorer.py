"""
Tests for src/risk_scorer.py - RiskScorer
"""

import pytest

from src.risk_scorer import RiskScorer
from src.url_extractor import URLFeatureExtractor


class TestRiskScorer:

    @pytest.fixture
    def scorer(self):
        return RiskScorer()

    @pytest.fixture
    def clean_features(self):
        return {"uses_https": True,
                "brand_impersonation": False,
                "typosquatting": False,
                "brand_in_subdomain": False,
                "uses_ip_as_host": False,
                "redirect_domain_switch": False,
                "suspicious_tld": False,
                "has_suspicious_keywords": False,
                "at_symbol": False,
                "hex_encoding": False,
                "has_redirect_param": False,
                "double_slash": False,
                "domain_entropy": 2.0,
                "url_length": 30,
                "redirect_count": 0,
                "hyphen_count": 0,
                "path_depth": 1,
                "subdomain_count": 0,
                "port_in_url": False,
                "path": "/page",
                "malware_extension": False,
                "malware_path_keyword": False}

    @pytest.fixture
    def clean_intel(self):
        return {"vt_malicious": 0, "urlscan_malicious": False}

    def test_benign_url_scores_low(self, scorer, clean_features, clean_intel):
        risk = scorer.score(clean_features, clean_intel)
        assert risk["verdict"] == "BENIGN"
        assert risk["score"] <= 20

    def test_vt_2_engines_hits_malicious(self, scorer, clean_features, clean_intel):
        intel = {**clean_intel, "vt_malicious": 2}
        features = {**clean_features,
                    "brand_impersonation": True,
                    "suspicious_tld": True,
                    "has_suspicious_keywords": True}
        risk = scorer.score(features, intel)
        assert risk["score"] >= 50

    def test_vt_malicious_score_capped_at_40(self, scorer, clean_features, clean_intel):
        intel = {**clean_intel, "vt_malicious": 100}
        risk = scorer.score(clean_features, intel)
        assert risk["breakdown"].get("vt_malicious_engines", 0) <= 40

    def test_brand_impersonation_adds_points(self, scorer, clean_features, clean_intel):
        features = {**clean_features, "brand_impersonation": True}
        risk = scorer.score(features, clean_intel)
        assert risk["score"] >= 18

    def test_typosquatting_adds_points(self, scorer, clean_features, clean_intel):
        features = {**clean_features, "typosquatting": True}
        risk = scorer.score(features, clean_intel)
        assert risk["score"] >= 18

    def test_malware_extension_adds_points(self, scorer, clean_features, clean_intel):
        features = {**clean_features, "malware_extension": True}
        risk = scorer.score(features, clean_intel)
        assert risk["score"] >= 15

    def test_malware_path_keyword_adds_points(self, scorer, clean_features, clean_intel):
        features = {**clean_features, "malware_path_keyword": True}
        risk = scorer.score(features, clean_intel)
        assert risk["score"] >= 8

    def test_ip_host_raises_score(self, scorer, clean_features, clean_intel):
        features = {**clean_features, "uses_ip_as_host": True}
        risk = scorer.score(features, clean_intel)
        assert risk["score"] >= 15

    def test_redirect_domain_switch_raises_score(self, scorer, clean_features, clean_intel):
        features = {**clean_features, "redirect_domain_switch": True}
        risk = scorer.score(features, clean_intel)
        assert risk["score"] >= 12

    def test_score_capped_at_100(self, scorer, clean_intel):
        maxed = {"uses_https": False,
                 "brand_impersonation": True,
                 "typosquatting": True,
                 "brand_in_subdomain": True,
                 "uses_ip_as_host": True,
                 "redirect_domain_switch": True,
                 "suspicious_tld": True,
                 "has_suspicious_keywords": True,
                 "at_symbol": True,
                 "hex_encoding": True,
                 "has_redirect_param": True,
                 "double_slash": True,
                 "domain_entropy": 4.5,
                 "url_length": 200,
                 "redirect_count": 5,
                 "hyphen_count": 10,
                 "path_depth": 10,
                 "subdomain_count": 5,
                 "port_in_url": True,
                 "path": "/payload/evil.exe",
                 "malware_extension": False,
                 "malware_path_keyword": False}
        intel = {**clean_intel, "vt_malicious": 10, "urlscan_malicious": True}
        risk = scorer.score(maxed, intel)
        assert risk["score"] == 100

    def test_breakdown_populated(self, scorer, clean_features, clean_intel):
        features = {**clean_features, "brand_impersonation": True}
        risk = scorer.score(features, clean_intel)
        assert "brand_impersonation" in risk["breakdown"]

    def test_verdict_suspicious_range(self, scorer, clean_features, clean_intel):
        features = {**clean_features,
                    "uses_https": False,
                    "uses_ip_as_host": True,
                    "suspicious_tld": True}
        risk = scorer.score(features, clean_intel)
        assert risk["verdict"] == "SUSPICIOUS"

    def test_no_https_adds_points(self, scorer, clean_features, clean_intel):
        features = {**clean_features, "uses_https": False}
        risk = scorer.score(features, clean_intel)
        assert risk["score"] >= 7

    def test_microsoft_account_update_xyz_is_suspicious_or_malicious(self, scorer, clean_intel):
        """Regression: microsoft-account-update.xyz was scoring only 18 (brand missed)."""
        f = URLFeatureExtractor("https://microsoft-account-update.xyz/verify").extract()
        risk = scorer.score({**f, "redirect_count": 0, "redirect_domain_switch": False},
                            clean_intel)
        assert risk["score"] >= 36
        assert risk["verdict"] in ("SUSPICIOUS", "MALICIOUS")

    def test_cloud_hosting_abuse_adds_points(self, scorer, clean_features, clean_intel):
        features = {**clean_features, "cloud_hosting_abuse": True}
        risk = scorer.score(features, clean_intel)
        assert risk["score"] >= 18
        assert "cloud_hosting_abuse" in risk["breakdown"]

    def test_private_ip_adds_points(self, scorer, clean_features, clean_intel):
        features = {**clean_features, "private_ip": True}
        risk = scorer.score(features, clean_intel)
        assert risk["score"] >= 20
        assert "private_ip" in risk["breakdown"]

    def test_high_path_entropy_adds_points(self, scorer, clean_features, clean_intel):
        features = {**clean_features, "path_entropy": 4.0}
        risk = scorer.score(features, clean_intel)
        assert "high_path_entropy" in risk["breakdown"]

    def test_new_domain_adds_points(self, scorer, clean_features, clean_intel):
        intel = {**clean_intel, "domain_age_days": 5}
        risk = scorer.score(clean_features, intel)
        assert "new_domain" in risk["breakdown"]
        assert risk["score"] >= 8
