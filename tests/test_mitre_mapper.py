"""
Tests for src/mitre_mapper.py - map_to_mitre
"""

from src.mitre_mapper import map_to_mitre
from src.url_extractor import URLFeatureExtractor


class TestMapToMitre:

    def _base_features(self, **overrides):
        f = {"brand_impersonation": False,
             "typosquatting": False,
             "brand_in_subdomain": False,
             "hex_encoding": False,
             "uses_ip_as_host": False,
             "cloud_hosting_abuse": False,
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
        tags = map_to_mitre(self._base_features(), self._base_intel(), self._base_redirect())
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

    def test_t1659_fires_on_domain_switches(self):
        tags = map_to_mitre(self._base_features(), self._base_intel(),
                            self._base_redirect(domain_switches=[{"hop": 1}]))
        assert "T1659 - Content Injection / Redirect" in tags

    def test_t1583_006_fires_on_cloud_abuse(self):
        f = self._base_features(cloud_hosting_abuse=True)
        tags = map_to_mitre(f, self._base_intel(), self._base_redirect())
        assert "T1583.006 - Web Services / Cloud Storage" in tags

    def test_no_tags_for_clean_url(self):
        tags = map_to_mitre(self._base_features(), self._base_intel(), self._base_redirect())
        assert tags == []
