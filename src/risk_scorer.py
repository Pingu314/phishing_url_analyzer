"""
Risk Scorer
Combines URL features and threat intel into a 0-100 risk score.
Verdict tiers: BENIGN / SUSPICIOUS / MALICIOUS

Scoring is intentionally rule-based and transparent —
every point can be explained in an interview or incident report.
"""

from settings import WEIGHTS, THRESHOLDS, MALWARE_EXTENSIONS, MALWARE_PATH_KEYWORDS


class RiskScorer:

    def score(self, features: dict, intel: dict) -> dict:
        breakdown = {}
        total = 0

        def add(key, points):
            breakdown[key] = points
            nonlocal total
            total += points

        # Threat intel signals
        vt_mal = intel.get("vt_malicious", 0)
        if vt_mal > 0:
            pts = min(vt_mal * WEIGHTS["vt_malicious"], 40)
            add("vt_malicious_engines", pts)

        if intel.get("urlscan_malicious"):
            add("urlscan_malicious", WEIGHTS["urlscan_malicious"])

        # Structural / content signals
        if features.get("brand_impersonation"):
            add("brand_impersonation", WEIGHTS["brand_impersonation"])

        if features.get("typosquatting"):
            add("typosquatting", WEIGHTS["typosquatting"])

        if features.get("brand_in_subdomain"):
            add("brand_in_subdomain", WEIGHTS["brand_in_subdomain"])

        if features.get("uses_ip_as_host"):
            add("uses_ip_as_host", WEIGHTS["uses_ip_as_host"])

        if features.get("redirect_domain_switch"):
            add("redirect_domain_switch", WEIGHTS["redirect_domain_switch"])

        if features.get("suspicious_tld"):
            add("suspicious_tld", WEIGHTS["suspicious_tld"])

        if features.get("has_suspicious_keywords"):
            add("suspicious_keywords", WEIGHTS["has_suspicious_keywords"])

        if features.get("at_symbol"):
            add("at_symbol", WEIGHTS["at_symbol"])

        if not features.get("uses_https"):
            add("no_https", WEIGHTS["no_https"])

        if features.get("hex_encoding"):
            add("hex_encoding", WEIGHTS["hex_encoding"])

        if features.get("has_redirect_param"):
            add("has_redirect_param", WEIGHTS["has_redirect_param"])

        if features.get("double_slash"):
            add("double_slash", WEIGHTS["double_slash"])

        # Malware delivery signals (path-based)
        path_lower = features.get("path", "").lower()
        if any(ext in path_lower for ext in MALWARE_EXTENSIONS):
            add("malware_extension", WEIGHTS["malware_extension"])

        if any(kw in path_lower for kw in MALWARE_PATH_KEYWORDS):
            add("malware_path_keyword", WEIGHTS["malware_path_keyword"])

        # Soft / statistical signals
        if features.get("domain_entropy", 0) > 3.8:
            add("high_entropy", WEIGHTS["high_entropy"])

        if features.get("url_length", 0) > 75:
            add("long_url", WEIGHTS["long_url"])

        # redirect_count == number of actual hops (0 means no redirects)
        if features.get("redirect_count", 0) > 1:
            add("many_hops", WEIGHTS["many_hops"])

        if features.get("hyphen_count", 0) > 3:
            add("many_hyphens", WEIGHTS["many_hyphens"])

        if features.get("path_depth", 0) > 4:
            add("deep_path", WEIGHTS["deep_path"])

        if features.get("subdomain_count", 0) > 2:
            add("many_subdomains", WEIGHTS["many_subdomains"])

        if features.get("port_in_url"):
            add("port_in_url", WEIGHTS["port_in_url"])

        final_score = min(total, 100)

        verdict = "BENIGN"
        for v, (low, high) in THRESHOLDS.items():
            if low <= final_score <= high:
                verdict = v
                break

        return {"score": final_score,
                "verdict": verdict,
                "breakdown": breakdown}