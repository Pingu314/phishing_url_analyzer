import pytest


@pytest.fixture
def sample_result():
    return {"url": "http://test.com",
            "final_url": "http://test.com",
            "redirect_chain": {"hop_count": 0,
                               "domain_switches": [],
                               "chain": []},
            "features": {"brand_impersonation": False,
                         "typosquatting": False,
                         "cloud_hosting_abuse": False,
                         "private_ip": False,
                         "uses_ip_as_host": False,
                         "suspicious_tld": False},
            "threat_intel": {"vt_malicious": 0,
                             "urlscan_malicious": False,
                             "domain_age_days": None},
            "risk": {"score": 10,
                     "verdict": "BENIGN",
                     "confidence": "VERY_LOW",
                     "breakdown": {}},
            "mitre": []}