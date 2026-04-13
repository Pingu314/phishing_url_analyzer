"""
Risk Scorer
Combines URL features and threat intel into a 0-100 risk score.
Verdict tiers: BENIGN / SUSPICIOUS / MALICIOUS

Scoring is intentionally rule-based and transparent —
every point can be explained in an interview or incident report.
"""


class RiskScorer:

    WEIGHTS = {
        # High-signal
        "vt_malicious":            20,   # per engine (capped at 40)
        "urlscan_malicious":       20,
        "brand_impersonation":     18,
        "brand_in_subdomain":      15,
        "uses_ip_as_host":         15,

        # Medium-signal
        "redirect_domain_switch":  12,   # domain changed mid-redirect chain
        "suspicious_tld":          10,
        "has_suspicious_keywords":  8,
        "at_symbol":                8,
        "no_https":                 7,
        "hex_encoding":             6,
        "has_redirect_param":       6,
        "double_slash":             5,

        # Low-signal (accumulate)
        "high_entropy":             5,   # domain entropy > 3.8
        "long_url":                 4,   # url length > 75
        "many_hops":                4,   # redirect hops > 2
        "many_hyphens":             3,   # > 3 hyphens
        "deep_path":                3,   # path depth > 4
        "many_subdomains":          3,   # subdomains > 2
        "port_in_url":              3,
    }

    THRESHOLDS = {
        "BENIGN":     (0, 20),
        "SUSPICIOUS": (21, 49),
        "MALICIOUS":  (50, 100),
    }

    def score(self, features: dict, intel: dict) -> dict:
        breakdown = {}
        total = 0

        def add(key, points):
            breakdown[key] = points
            nonlocal total
            total += points

        # Threat intel
        vt_mal = intel.get("vt_malicious", 0)
        if vt_mal > 0:
            pts = min(vt_mal * self.WEIGHTS["vt_malicious"], 40)
            add("vt_malicious_engines", pts)

        if intel.get("urlscan_malicious"):
            add("urlscan_malicious", self.WEIGHTS["urlscan_malicious"])

        # Structural / content
        if features.get("brand_impersonation"):
            add("brand_impersonation", self.WEIGHTS["brand_impersonation"])

        if features.get("brand_in_subdomain"):
            add("brand_in_subdomain", self.WEIGHTS["brand_in_subdomain"])

        if features.get("uses_ip_as_host"):
            add("uses_ip_as_host", self.WEIGHTS["uses_ip_as_host"])

        if features.get("redirect_domain_switch"):
            add("redirect_domain_switch", self.WEIGHTS["redirect_domain_switch"])

        if features.get("suspicious_tld"):
            add("suspicious_tld", self.WEIGHTS["suspicious_tld"])

        if features.get("has_suspicious_keywords"):
            add("suspicious_keywords", self.WEIGHTS["has_suspicious_keywords"])

        if features.get("at_symbol"):
            add("at_symbol", self.WEIGHTS["at_symbol"])

        if not features.get("uses_https"):
            add("no_https", self.WEIGHTS["no_https"])

        if features.get("hex_encoding"):
            add("hex_encoding", self.WEIGHTS["hex_encoding"])

        if features.get("has_redirect_param"):
            add("redirect_param", self.WEIGHTS["has_redirect_param"])

        if features.get("double_slash"):
            add("double_slash", self.WEIGHTS["double_slash"])

        # Soft signals
        if features.get("domain_entropy", 0) > 3.8:
            add("high_entropy", self.WEIGHTS["high_entropy"])

        if features.get("url_length", 0) > 75:
            add("long_url", self.WEIGHTS["long_url"])

        if features.get("redirect_count", 0) > 2:
            add("many_hops", self.WEIGHTS["many_hops"])

        if features.get("hyphen_count", 0) > 3:
            add("many_hyphens", self.WEIGHTS["many_hyphens"])

        if features.get("path_depth", 0) > 4:
            add("deep_path", self.WEIGHTS["deep_path"])

        if features.get("subdomain_count", 0) > 2:
            add("many_subdomains", self.WEIGHTS["many_subdomains"])

        if features.get("port_in_url"):
            add("port_in_url", self.WEIGHTS["port_in_url"])

        final_score = min(total, 100)

        verdict = "BENIGN"
        for v, (low, high) in self.THRESHOLDS.items():
            if low <= final_score <= high:
                verdict = v
                break

        return {
            "score": final_score,
            "verdict": verdict,
            "breakdown": breakdown,
        }
