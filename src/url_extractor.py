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
    HOMOGLYPH_MAP,
    MALWARE_EXTENSIONS,
    MALWARE_PATH_KEYWORDS,
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

                    # Entropy (computed on the registered domain label, not www or IP)
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

                    # Typosquatting / homoglyph detection
                    "typosquatting": self._detect_typosquatting(domain),

                    # TLD analysis
                    "tld": self._get_tld(domain),
                    "suspicious_tld": self._has_any(domain, SUSPICIOUS_TLDS),
                    "legitimate_tld": self._has_any(domain, LEGITIMATE_TLDS),

                    # Subdomain suspicion (e.g. paypal.attacker.com)
                    "brand_in_subdomain": self._brand_in_subdomain(domain),

                    # Query string
                    "query_param_count": len(urllib.parse.parse_qs(self.parsed.query)),
                    "has_redirect_param": bool(re.search(r"(redirect|url|next|goto|return)=", full)),

                    # Malware delivery signals (pre-computed for MITRE mapping)
                    "malware_extension": any(ext in path for ext in MALWARE_EXTENSIONS),
                    "malware_path_keyword": any(kw in path for kw in MALWARE_PATH_KEYWORDS)}

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
        Falls back sensibly for IPs or bare hostnames."""
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
    # Keyword / brand matching helpers
    # ------------------------------------------------------------------

    def _has_any(self, text: str, keywords: list) -> bool:
        """Plain substring match — used only for TLD checks."""
        return any(kw in text for kw in keywords)

    def _has_any_label(self, text: str, keywords: list) -> bool:
        """Match keywords as whole tokens (word-boundary aware).
        Uses non-alphanumeric boundaries so 'verify' matches in '/verify?'
        but NOT in 'unverified' or 'overwrite'.
        """
        for kw in keywords:
            if re.search(r"(?<![a-z0-9])" + re.escape(kw) + r"(?![a-z0-9])", text):
                return True
        return False

    def _find_all_labels(self, text: str, keywords: list) -> list:
        return [kw for kw in keywords
                if re.search(r"(?<![a-z0-9])" + re.escape(kw) + r"(?![a-z0-9])", text)]

    def _find_brands_in_domain(self, domain: str) -> list:
        """Return brand names found as full domain labels or within hyphenated labels."""
        labels = domain.replace(":", "").split(".")
        found = []
        for b in BRAND_KEYWORDS:
            for label in labels:
                # Exact label match OR brand as a hyphen-delimited segment
                parts = label.split("-")
                if b == label or b in parts:
                    if b not in found:
                        found.append(b)
        return found

    # ------------------------------------------------------------------
    # TLD / brand detection
    # ------------------------------------------------------------------

    def _get_tld(self, domain: str) -> str:
        parts = domain.split(".")
        return "." + parts[-1] if len(parts) >= 2 else ""

    def _detect_brand_impersonation(self, domain: str) -> bool:
        """Detect if a brand appears in the domain but the domain is not
        the brand's own official domain.

        Matching strategy — checks two levels:
        1. Exact label match: 'paypal' in ['secure', 'paypal', 'evil', 'com']
        2. Hyphenated segment: 'microsoft' in 'microsoft-account-update' (split by '-')

        Legitimate check: brand IS the registered domain label (SLD),
        regardless of TLD — handles paypal.de, microsoft.co.uk, etc.
        """
        if self._is_ip(domain):
            return False
        labels = [p for p in domain.split(".") if p]
        registered = labels[-2] if len(labels) >= 2 else (labels[0] if labels else "")

        for brand in BRAND_KEYWORDS:
            brand_present = False
            for label in labels:
                # Check exact label OR brand as a hyphen-delimited part of the label
                if brand == label or brand in label.split("-"):
                    brand_present = True
                    break

            if brand_present:
                # Legitimate: brand IS the registered domain label
                # (e.g. paypal.com, paypal.de, microsoft.co.uk)
                # registered == "paypal" or registered == "microsoft" -> legit
                # registered == "microsoft-account-update" -> impersonation
                if registered == brand:
                    return False
                return True
        return False

    def _brand_in_subdomain(self, domain: str) -> bool:
        """Detect brand name used as a subdomain label or hyphenated segment."""
        if self._is_ip(domain):
            return False
        parts = [p for p in domain.split(".") if p]
        if len(parts) > 2:
            subdomain_labels = parts[:-2]
            for label in subdomain_labels:
                label_parts = label.split("-")
                for brand in BRAND_KEYWORDS:
                    if brand == label or brand in label_parts:
                        return True
        return False

    # ------------------------------------------------------------------
    # Typosquatting / homoglyph detection
    # ------------------------------------------------------------------

    def _detect_typosquatting(self, domain: str) -> bool:
        """Detect common typosquatting techniques:
        1. Homoglyph substitution (paypa1.com, m1crosoft.com)
        2. Edit-distance-1 from a known brand in the registered label

        Returns True if the registered label looks like a brand impersonation
        that would be missed by exact-label matching.
        """
        if self._is_ip(domain):
            return False

        registered = self._registered_label(domain)

        # Skip if this IS a legitimate brand label (caught by brand_impersonation)
        if registered in BRAND_KEYWORDS:
            return False

        # 1. Homoglyph normalisation
        normalised = registered
        for fake, real in HOMOGLYPH_MAP.items():
            normalised = normalised.replace(fake, real)
        if normalised != registered and normalised in BRAND_KEYWORDS:
            return True

        # 2. Edit distance 1
        for brand in BRAND_KEYWORDS:
            if self._edit_distance_1(registered, brand):
                return True

        return False

    @staticmethod
    def _edit_distance_1(a: str, b: str) -> bool:
        """Return True if strings a and b have Levenshtein distance exactly 1."""
        la, lb = len(a), len(b)
        if abs(la - lb) > 1:
            return False
        if la == lb:
            diffs = [i for i in range(la) if a[i] != b[i]]
            if len(diffs) == 1:
                return True
            if len(diffs) == 2 and a[diffs[0]] == b[diffs[1]] and a[diffs[1]] == b[diffs[0]]:
                return True
            return False
        shorter, longer = (a, b) if la < lb else (b, a)
        i = 0
        skipped = False
        for j in range(len(longer)):
            if i < len(shorter) and shorter[i] == longer[j]:
                i += 1
            elif skipped:
                return False
            else:
                skipped = True
        return True
