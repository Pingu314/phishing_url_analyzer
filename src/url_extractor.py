"""
URL Feature Extractor
Parses and extracts structural/statistical features from a URL
without making any network requests.
"""

import re
import math
import urllib.parse
from typing import Optional

from settings import (
    BRAND_KEYWORDS,
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS,
    LEGITIMATE_TLDS,
)


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

        features = {# Basic structure
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
                    # Computed on the registered domain label (not www or IP)
                    "domain_entropy": self._shannon_entropy(self._registered_label(domain)),

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
                    "has_suspicious_keywords": self._has_any_label(url_lower, SUSPICIOUS_KEYWORDS),
                    "suspicious_keywords_found": self._find_all_labels(url_lower, SUSPICIOUS_KEYWORDS),
                    "brand_impersonation": self._detect_brand_impersonation(domain),
                    "brand_found": self._find_brands_in_domain(domain),

                    # TLD analysis
                    "tld": self._get_tld(domain),
                    "suspicious_tld": self._has_any(domain, SUSPICIOUS_TLDS),
                    "legitimate_tld": self._has_any(domain, LEGITIMATE_TLDS),

                    # Subdomain suspicion (e.g. paypal.attacker.com)
                    "brand_in_subdomain": self._brand_in_subdomain(domain),

                    # Query string
                    "query_param_count": len(urllib.parse.parse_qs(self.parsed.query)),
                    "has_redirect_param": bool(re.search(r"(redirect|url|next|goto|return)=", full))}

        return features

    # ------------------------------------------------------------------
    # Subdomain / domain helpers
    # ------------------------------------------------------------------

    def _count_subdomains(self, domain: str) -> int:
        """Return number of subdomain labels, skipping IP addresses."""
        if self._is_ip(domain):
            return 0
        parts = domain.split(".")
        return max(0, len(parts) - 2)

    def _is_ip(self, domain: str) -> bool:
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", domain))

    def _registered_label(self, domain: str) -> str:
        """Return the second-level label (e.g. 'google' from 'www.google.com').
        Falls back to the first label for IPs or bare hostnames."""
        if self._is_ip(domain):
            return domain
        parts = [p for p in domain.split(".") if p]
        if len(parts) >= 2:
            return parts[-2]   # e.g. 'google', 'paypal', 'phishing-site'
        return parts[0] if parts else domain

    # ------------------------------------------------------------------
    # Entropy
    # ------------------------------------------------------------------

    def _shannon_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        freq = {c: s.count(c) / len(s) for c in set(s)}
        return round(-sum(p * math.log2(p) for p in freq.values()), 3)

    # ------------------------------------------------------------------
    # Keyword / brand matching helpers  (label-aware)
    # ------------------------------------------------------------------

    def _has_any(self, text: str, keywords: list) -> bool:
        """Plain substring match — used only for TLD checks."""
        return any(kw in text for kw in keywords)

    def _has_any_label(self, text: str, keywords: list) -> bool:
        """Match keywords as whole path/query tokens (word-boundary aware)."""
        for kw in keywords:
            if re.search(r"(?<![a-z0-9])" + re.escape(kw) + r"(?![a-z0-9])", text):
                return True
        return False

    def _find_all_labels(self, text: str, keywords: list) -> list:
        return [kw for kw in keywords
                if re.search(r"(?<![a-z0-9])" + re.escape(kw) + r"(?![a-z0-9])", text)]

    def _find_brands_in_domain(self, domain: str) -> list:
        """Return brand names found as full domain labels."""
        labels = domain.replace(":", "").split(".")
        return [b for b in BRAND_KEYWORDS if b in labels]

    # ------------------------------------------------------------------
    # TLD / brand detection
    # ------------------------------------------------------------------

    def _get_tld(self, domain: str) -> str:
        parts = domain.split(".")
        return "." + parts[-1] if len(parts) >= 2 else ""

    def _detect_brand_impersonation(self, domain: str) -> bool:
        """Detect if a brand label appears in the domain but the domain is
        not the brand's own official domain.

        Strategy: split the domain into labels and check if any label
        exactly matches a known brand.  Then verify the registered domain
        (SLD) is NOT the brand itself — if the brand IS the SLD we assume
        it's legitimate (e.g. paypal.com, paypal.de, microsoft.co.uk).
        """
        if self._is_ip(domain):
            return False
        labels = [p for p in domain.split(".") if p]
        registered = labels[-2] if len(labels) >= 2 else labels[0]
        for brand in BRAND_KEYWORDS:
            if brand in labels:
                # It's legitimate if the brand IS the registered domain label
                if registered == brand:
                    return False
                return True
        return False

    def _brand_in_subdomain(self, domain: str) -> bool:
        """Detect brand name used as a subdomain label: paypal.evil.com"""
        if self._is_ip(domain):
            return False
        parts = [p for p in domain.split(".") if p]
        if len(parts) > 2:
            subdomain_labels = parts[:-2]
            for brand in BRAND_KEYWORDS:
                if brand in subdomain_labels:
                    return True
        return False
