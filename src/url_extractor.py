"""
URL Feature Extractor
Parses and extracts structural/statistical features from a URL
without making any network requests.
"""

import re
import math
import urllib.parse
from typing import Optional


# Known brands commonly impersonated in phishing
BRAND_KEYWORDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "linkedin", "twitter", "dropbox",
    "office365", "onedrive", "chase", "wellsfargo", "bankofamerica",
    "ubs", "postfinance", "raiffeisen", "swisscom", "sbb", "post"
]

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "update", "confirm",
    "account", "banking", "password", "credential", "validate",
    "suspended", "locked", "unusual", "activity", "click", "urgent"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".club",
    ".click", ".link", ".live", ".online", ".site", ".website",
    ".info", ".biz", ".pw", ".cc", ".icu"
]

LEGITIMATE_TLDS = [".com", ".org", ".gov", ".edu", ".co.uk", ".de", ".ch", ".fr"]


class URLFeatureExtractor:
    def __init__(self, url: str):
        self.raw_url = url
        self.parsed = self._safe_parse(url)

    def _safe_parse(self, url: str) -> Optional[urllib.parse.ParseResult]:
        try:
            if not url.startswith(("http://", "https://")):
                url = "http://" + url
            return urllib.parse.urlparse(url)
        except Exception:
            return None

    def extract(self) -> dict:
        if not self.parsed:
            return {"error": "Could not parse URL", "url": self.raw_url}

        url_lower = self.raw_url.lower()
        domain = self.parsed.netloc.lower()
        path = self.parsed.path.lower()
        full = url_lower

        features = {
            # Basic structure
            "url": self.raw_url,
            "scheme": self.parsed.scheme,
            "domain": domain,
            "path": path,
            "query_string": self.parsed.query,

            # Length features
            "url_length": len(self.raw_url),
            "domain_length": len(domain),
            "path_length": len(path),
            "subdomain_count": self._count_subdomains(domain),
            "path_depth": len([p for p in path.split("/") if p]),

            # Entropy (randomness — high entropy = possible DGA domain)
            "domain_entropy": self._shannon_entropy(domain.split(".")[0]),

            # Special character features
            "hyphen_count": full.count("-"),
            "at_symbol": "@" in full,
            "double_slash": "//" in path,
            "hex_encoding": bool(re.search(r"%[0-9a-fA-F]{2}", full)),
            "ip_in_url": bool(re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", full)),
            "uses_ip_as_host": bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}", domain)),
            "port_in_url": bool(self.parsed.port),

            # Protocol
            "uses_https": self.parsed.scheme == "https",

            # Content features
            "has_suspicious_keywords": self._has_any(url_lower, SUSPICIOUS_KEYWORDS),
            "suspicious_keywords_found": self._find_all(url_lower, SUSPICIOUS_KEYWORDS),
            "brand_impersonation": self._detect_brand_impersonation(domain),
            "brand_found": self._find_all(domain, BRAND_KEYWORDS),

            # TLD analysis
            "tld": self._get_tld(domain),
            "suspicious_tld": self._has_any(domain, SUSPICIOUS_TLDS),
            "legitimate_tld": self._has_any(domain, LEGITIMATE_TLDS),

            # Subdomain suspicion (e.g. paypal.attacker.com)
            "brand_in_subdomain": self._brand_in_subdomain(domain),

            # Query string
            "query_param_count": len(urllib.parse.parse_qs(self.parsed.query)),
            "has_redirect_param": bool(re.search(r"(redirect|url|next|goto|return)=", full)),
        }

        return features

    def _count_subdomains(self, domain: str) -> int:
        parts = domain.split(".")
        return max(0, len(parts) - 2)

    def _shannon_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        freq = {c: s.count(c) / len(s) for c in set(s)}
        return round(-sum(p * math.log2(p) for p in freq.values()), 3)

    def _has_any(self, text: str, keywords: list) -> bool:
        return any(kw in text for kw in keywords)

    def _find_all(self, text: str, keywords: list) -> list:
        return [kw for kw in keywords if kw in text]

    def _get_tld(self, domain: str) -> str:
        parts = domain.split(".")
        return "." + parts[-1] if len(parts) >= 2 else ""

    def _detect_brand_impersonation(self, domain: str) -> bool:
        """Detect if a brand name appears in domain but domain isn't the brand's official one."""
        for brand in BRAND_KEYWORDS:
            if brand in domain:
                # Check if it's actually the legit domain (e.g. paypal.com)
                if not domain == f"{brand}.com" and not domain.endswith(f".{brand}.com"):
                    return True
        return False

    def _brand_in_subdomain(self, domain: str) -> bool:
        """Detect brand in subdomain: paypal.evil.com"""
        parts = domain.split(".")
        if len(parts) > 2:
            subdomain = ".".join(parts[:-2])
            return self._has_any(subdomain, BRAND_KEYWORDS)
        return False
