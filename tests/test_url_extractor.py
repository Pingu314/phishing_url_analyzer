"""
Tests for src/url_extractor.py - URLFeatureExtractor
"""

from src.url_extractor import URLFeatureExtractor


class TestBrandImpersonation:
    def test_detected(self):
        f = URLFeatureExtractor("http://paypal-secure.com/login").extract()
        assert f["brand_impersonation"] is True

    def test_hyphenated_label(self):
        """microsoft-account-update.xyz — brand in hyphenated label must be detected."""
        f = URLFeatureExtractor("https://microsoft-account-update.xyz/verify").extract()
        assert f["brand_impersonation"] is True

    def test_apple_subdomain_compound(self):
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


class TestTyposquatting:
    def test_homoglyph_detected(self):
        """paypa1.com — '1' instead of 'l'."""
        f = URLFeatureExtractor("http://paypa1.com/signin").extract()
        assert f["typosquatting"] is True

    def test_edit_distance_detected(self):
        """paypel.com — single char substitution."""
        f = URLFeatureExtractor("http://paypel.com/login").extract()
        assert f["typosquatting"] is True

    def test_no_typosquatting_on_real_brand(self):
        f = URLFeatureExtractor("https://paypal.com/signin").extract()
        assert f["typosquatting"] is False

    def test_no_typosquatting_on_unrelated_domain(self):
        f = URLFeatureExtractor("https://example.com/page").extract()
        assert f["typosquatting"] is False


class TestIpHost:
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


class TestEntropy:
    def test_uses_registered_label(self):
        """Entropy must be computed on the SLD label, not 'www'."""
        f_www = URLFeatureExtractor("https://www.google.com").extract()
        f_bare = URLFeatureExtractor("https://google.com").extract()
        assert f_www["domain_entropy"] == f_bare["domain_entropy"]

    def test_entropy_computed(self):
        f = URLFeatureExtractor("https://google.com").extract()
        assert isinstance(f["domain_entropy"], float)


class TestTldAndHttps:
    def test_suspicious_tld(self):
        f = URLFeatureExtractor("https://banking-secure.xyz/verify").extract()
        assert f["suspicious_tld"] is True

    def test_https_detected(self):
        f = URLFeatureExtractor("https://google.com").extract()
        assert f["uses_https"] is True

    def test_no_https_flagged(self):
        f = URLFeatureExtractor("http://google.com").extract()
        assert f["uses_https"] is False


class TestEncodingAndSymbols:
    def test_hex_encoding_detected(self):
        f = URLFeatureExtractor("http://evil.com/path%2Fevade%2F").extract()
        assert f["hex_encoding"] is True

    def test_at_symbol_detected(self):
        f = URLFeatureExtractor("http://legit.com@evil.com").extract()
        assert f["at_symbol"] is True


class TestSubdomainAndBrand:
    def test_brand_in_subdomain(self):
        f = URLFeatureExtractor("http://paypal.evil.com/login").extract()
        assert f["brand_in_subdomain"] is True

    def test_no_brand_in_subdomain_for_legit(self):
        f = URLFeatureExtractor("https://paypal.com/signin").extract()
        assert f["brand_in_subdomain"] is False

    def test_subdomain_count(self):
        f = URLFeatureExtractor("http://a.b.c.evil.com/login").extract()
        assert f["subdomain_count"] >= 3


class TestUrlStructure:
    def test_redirect_param_detected(self):
        f = URLFeatureExtractor("http://site.com/page?next=http://evil.com").extract()
        assert f["has_redirect_param"] is True

    def test_url_length(self):
        f = URLFeatureExtractor("https://" + "a" * 80 + ".com").extract()
        assert f["url_length"] > 75

    def test_suspicious_keywords_found(self):
        f = URLFeatureExtractor("http://evil.com/login/verify/account").extract()
        assert f["has_suspicious_keywords"] is True
        assert len(f["suspicious_keywords_found"]) >= 1

    def test_post_keyword_no_false_positive(self):
        """'post' brand must NOT trigger on unrelated URLs containing the string 'post'."""
        f = URLFeatureExtractor("https://example.com/blog/repost/article").extract()
        assert f["brand_impersonation"] is False


class TestMalwareSignals:
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
        """185.220.101.55/payload/download.exe should flag all malware signals."""
        f = URLFeatureExtractor("http://185.220.101.55/payload/download.exe").extract()
        assert f["uses_ip_as_host"] is True
        assert f["malware_extension"] is True
        assert f["malware_path_keyword"] is True
        assert f["uses_https"] is False
