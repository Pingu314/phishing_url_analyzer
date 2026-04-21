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
from main import map_to_mitre


# ===========================================================================
# Feature Extractor Tests
# ===========================================================================

class TestURLFeatureExtractor:

    # --- Brand impersonation (exact label) ---

    def test_brand_impersonation_detected(self):
        f = URLFeatureExtractor("http://paypal-secure.com/login").extract()
        assert f["brand_impersonation"] is True

    def test_brand_impersonation_hyphenated_label(self):
        """microsoft-account-update.xyz — brand in hyphenated label must be detected."""
        f = URLFeatureExtractor("https://microsoft-account-update.xyz/verify").extract()
        assert f["brand_impersonation"] is True

    def test_brand_impersonation_apple_subdomain_compound(self):
        """secure.apple.com.phishing-site.tk — apple as subdomain label."""
        f = URLFeatureExtractor("https://secure.apple.com.phishing-site.tk/id/verify").extract()
        assert f["brand_impersonation"] is True

    def test_legitimate_brand_dot_com_not_flagged(self):
        f = URLFeatureExtractor("https://paypal.com/signin").extract()
        assert f["brand_impersonation"] is False

    def test_legitimate_brand_non_com_tld_not_flagged(self):
        """paypal.de must NOT be flagged — old bug was .com-only whitelist."""
        f = URLFeatureExtractor("https://paypal.de/signin").extract()
        assert f["brand_impersonation"] is False

    def test_legitimate_microsoft_not_flagged(self):
        f = URLFeatureExtractor("https://microsoft.com/en-us").extract()
        assert f["brand_impersonation"] is False

    def test_brand_in_path_not_flagged(self):
        """Brand only in path should NOT trigger domain impersonation."""
        f = URLFeatureExtractor("https://example.com/paypal/redirect").extract()
        assert f["brand_impersonation"] is False

    # --- Typosquatting ---

    def test_typosquatting_homoglyph_detected(self):
        """paypa1.com — '1' instead of 'l'."""
        f = URLFeatureExtractor("http://paypa1.com/signin").extract()
        assert f["typosquatting"] is True

    def test_typosquatting_edit_distance_detected(self):
        """paypel.com — single char substitution."""
        f = URLFeatureExtractor("http://paypel.com/login").extract()
        assert f["typosquatting"] is True

    def test_no_typosquatting_on_real_brand(self):
        f = URLFeatureExtractor("https://paypal.com/signin").extract()
        assert f["typosquatting"] is False

    def test_no_typosquatting_on_unrelated_domain(self):
        f = URLFeatureExtractor("https://example.com/page").extract()
        assert f["typosquatting"] is False

    # --- IP as host ---

    def test_ip_as_host(self):
        f = URLFeatureExtractor("http://192.168.1.1/login").extract()
        assert f["uses_ip_as_host"] is True

    def test_no_ip_for_domain(self):
        f = URLFeatureExtractor("https://google.com").extract()
        assert f["uses_ip_as_host"] is False

    def test_subdomain_count_zero_for_ip(self):
        """IPs must not produce false subdomain counts."""
        f = URLFeatureExtractor("http://192.168.1.105/bank/login.php").extract()
        assert f["subdomain_count"] == 0

    # --- Entropy ---

    def test_entropy_uses_registered_label(self):
        """Entropy must be computed on the SLD label, not 'www'."""
        f_www = URLFeatureExtractor("https://www.google.com").extract()
        f_bare = URLFeatureExtractor("https://google.com").extract()
        assert f_www["domain_entropy"] == f_bare["domain_entropy"]

    def test_entropy_computed(self):
        f = URLFeatureExtractor("https://google.com").extract()
        assert isinstance(f["domain_entropy"], float)

    # --- TLD ---

    def test_suspicious_tld(self):
        f = URLFeatureExtractor("https://banking-secure.xyz/verify").extract()
        assert f["suspicious_tld"] is True

    # --- HTTPS ---

    def test_https_detected(self):
        f = URLFeatureExtractor("https://google.com").extract()
        assert f["uses_https"] is True

    def test_no_https_flagged(self):
        f = URLFeatureExtractor("http://google.com").extract()
        assert f["uses_https"] is False

    # --- Encoding / symbols ---

    def test_hex_encoding_detected(self):
        f = URLFeatureExtractor("http://evil.com/path%2Fevade%2F").extract()
        assert f["hex_encoding"] is True

    def test_at_symbol_detected(self):
        f = URLFeatureExtractor("http://legit.com@evil.com").extract()
        assert f["at_symbol"] is True

    # --- Brand in subdomain ---

    def test_brand_in_subdomain(self):
        f = URLFeatureExtractor("http://paypal.evil.com/login").extract()
        assert f["brand_in_subdomain"] is True

    def test_no_brand_in_subdomain_for_legit(self):
        f = URLFeatureExtractor("https://paypal.com/signin").extract()
        assert f["brand_in_subdomain"] is False

    # --- Subdomain count ---

    def test_subdomain_count(self):
        f = URLFeatureExtractor("http://a.b.c.evil.com/login").extract()
        assert f["subdomain_count"] >= 3

    # --- Redirect param ---

    def test_redirect_param_detected(self):
        f = URLFeatureExtractor("http://site.com/page?next=http://evil.com").extract()
        assert f["has_redirect_param"] is True

    # --- URL length ---

    def test_url_length(self):
        f = URLFeatureExtractor("https://" + "a" * 80 + ".com").extract()
        assert f["url_length"] > 75

    # --- Suspicious keywords (label-aware) ---

    def test_suspicious_keywords_found(self):
        f = URLFeatureExtractor("http://evil.com/login/verify/account").extract()
        assert f["has_suspicious_keywords"] is True
        assert len(f["suspicious_keywords_found"]) >= 1

    def test_post_keyword_no_false_positive(self):
        """'post' brand must NOT trigger on unrelated URLs containing the string 'post'."""
        f = URLFeatureExtractor("https://example.com/blog/repost/article").extract()
        assert f["brand_impersonation"] is False

    # --- Malware feature keys ---

    def test_malware_extension_key_present(self):
        """extract() must always return malware_extension key."""
        f = URLFeatureExtractor("https://google.com").extract()
        assert "malware_extension" in f
        assert f["malware_extension"] is False

    def test_malware_extension_detected(self):
        f = URLFeatureExtractor("http://evil.com/download/payload.exe").extract()
        assert f["malware_extension"] is True

    def test_malware_path_keyword_key_present(self):
        """extract() must always return malware_path_keyword key."""
        f = URLFeatureExtractor("https://google.com").extract()
        assert "malware_path_keyword" in f
        assert f["malware_path_keyword"] is False

    def test_malware_path_keyword_detected(self):
        f = URLFeatureExtractor("http://185.220.101.55/payload/download.exe").extract()
        assert f["malware_path_keyword"] is True

    def test_real_world_malware_url(self):
        """185.220.101.55/payload/download.exe should flag both malware signals."""
        f = URLFeatureExtractor("http://185.220.101.55/payload/download.exe").extract()
        assert f["uses_ip_as_host"] is True
        assert f["malware_extension"] is True
        assert f["malware_path_keyword"] is True
        assert f["uses_https"] is False


# ===========================================================================
# Risk Scorer Tests
# ===========================================================================

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
        features = {**clean_features}
        features["brand_impersonation"] = True
        features["suspicious_tld"] = True
        features["has_suspicious_keywords"] = True
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
        features = {**clean_features, "path": "/download/payload.exe"}
        risk = scorer.score(features, clean_intel)
        assert risk["score"] >= 15

    def test_malware_path_keyword_adds_points(self, scorer, clean_features, clean_intel):
        features = {**clean_features, "path": "/payload/stage1"}
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
        risk = scorer.score({**f, "redirect_count": 0, "redirect_domain_switch": False}, clean_intel)
        # Should have: brand_impersonation(18) + suspicious_tld(10) + keywords(8) + ... >= 36
        assert risk["score"] >= 36
        assert risk["verdict"] in ("SUSPICIOUS", "MALICIOUS")


# ===========================================================================
# Redirect Follower Tests
# ===========================================================================

class TestRedirectFollower:

    def test_extract_domain(self):
        rf = RedirectFollower()
        assert rf._extract_domain("https://www.example.com/path") == "www.example.com"

    def test_extract_domain_with_port(self):
        rf = RedirectFollower()
        assert rf._extract_domain("http://example.com:8080/path") == "example.com:8080"

    def test_extract_domain_invalid(self):
        rf = RedirectFollower()
        result = rf._extract_domain("not-a-url")
        assert isinstance(result, str)

    def test_no_redirect_returns_zero_hops(self):
        """A URL with no Location header should return hop_count == 0."""
        rf = RedirectFollower()
        result = rf.follow("https://www.google.com")
        assert result["hop_count"] == 0
        assert result["final_url"] == "https://www.google.com"
        assert result["chain"] == []

    def test_follow_returns_required_keys(self):
        """Result dict must always contain all expected keys."""
        rf = RedirectFollower()
        result = rf.follow("https://www.google.com")
        for key in ["initial_url", "final_url", "hop_count", "chain",
                    "domain_switches", "domain_changed", "errors", "suspicious"]:
            assert key in result, f"Missing key: {key}"


# ===========================================================================
# MITRE Mapping Tests
# ===========================================================================

class TestMapToMitre:

    def _base_features(self, **overrides):
        f = {"brand_impersonation": False,
             "typosquatting": False,
             "brand_in_subdomain": False,
             "hex_encoding": False,
             "uses_ip_as_host": False,
             "malware_extension": False,
             "malware_path_keyword": False}
        f.update(overrides)
        return f

    def _base_intel(self, **overrides):
        i = {"vt_malicious": 0, "urlscan_malicious": False}
        i.update(overrides)
        return i

    def _base_redirect(self, **overrides):
        r = {"hop_count": 0, "domain_switches": []}
        r.update(overrides)
        return r

    def test_t1566_002_requires_brand_signal(self):
        """T1566.002 must NOT fire on keywords alone."""
        f = self._base_features()
        tags = map_to_mitre(f, self._base_intel(), self._base_redirect())
        assert "T1566.002 - Spearphishing Link" not in tags

    def test_t1566_002_fires_on_brand_impersonation(self):
        f = self._base_features(brand_impersonation=True)
        tags = map_to_mitre(f, self._base_intel(), self._base_redirect())
        assert "T1566.002 - Spearphishing Link" in tags

    def test_t1566_002_fires_on_typosquatting(self):
        f = self._base_features(typosquatting=True)
        tags = map_to_mitre(f, self._base_intel(), self._base_redirect())
        assert "T1566.002 - Spearphishing Link" in tags

    def test_t1027_fires_on_redirect(self):
        tags = map_to_mitre(self._base_features(), self._base_intel(),
                            self._base_redirect(hop_count=1))
        assert "T1027 - Obfuscated Files or Information" in tags

    def test_t1027_not_on_zero_hops(self):
        """Zero hops AND no hex encoding must NOT trigger T1027."""
        tags = map_to_mitre(self._base_features(), self._base_intel(),
                            self._base_redirect(hop_count=0))
        assert "T1027 - Obfuscated Files or Information" not in tags

    def test_t1583_fires_on_ip_host(self):
        f = self._base_features(uses_ip_as_host=True)
        tags = map_to_mitre(f, self._base_intel(), self._base_redirect())
        assert "T1583.005 - Botnet / IP-based C2" in tags

    def test_t1566_fires_on_vt_hit(self):
        tags = map_to_mitre(self._base_features(),
                            self._base_intel(vt_malicious=1),
                            self._base_redirect())
        assert "T1566 - Phishing" in tags

    def test_t1105_fires_on_malware_extension(self):
        """Regression: T1105 was never firing because feature key was missing."""
        f = self._base_features(malware_extension=True)
        tags = map_to_mitre(f, self._base_intel(), self._base_redirect())
        assert "T1105 - Ingress Tool Transfer" in tags

    def test_t1105_fires_on_malware_path(self):
        f = self._base_features(malware_path_keyword=True)
        tags = map_to_mitre(f, self._base_intel(), self._base_redirect())
        assert "T1105 - Ingress Tool Transfer" in tags

    def test_t1105_fires_on_real_world_url(self):
        """185.220.101.55/payload/download.exe must trigger T1105."""
        f = URLFeatureExtractor("http://185.220.101.55/payload/download.exe").extract()
        tags = map_to_mitre(f, self._base_intel(), self._base_redirect())
        assert "T1105 - Ingress Tool Transfer" in tags
        assert "T1583.005 - Botnet / IP-based C2" in tags

    def test_no_tags_for_clean_url(self):
        tags = map_to_mitre(self._base_features(), self._base_intel(),
                            self._base_redirect())
        assert tags == []
