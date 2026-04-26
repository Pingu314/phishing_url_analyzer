"""
MITRE ATT&CK tag mapper for Phishing URL Analyzer.

"""


def map_to_mitre(features: dict, intel: dict, redirect_data: dict) -> list:
    """Map extracted URL features to MITRE ATT&CK technique IDs.

    Args:
        features:      Feature dict produced by URLFeatureExtractor.extract()
        intel:         Enrichment dict produced by ThreatIntelEnricher.enrich()
        redirect_data: Chain dict produced by RedirectFollower.follow()

    Returns:
        List of MITRE technique strings, e.g. ['T1566.002 - Spearphishing Link']
    """
    tags = []

    # T1566.002 - Spearphishing Link
    if (features.get("brand_impersonation") or features.get("typosquatting")
            or features.get("brand_in_subdomain")):
        tags.append("T1566.002 - Spearphishing Link")

    # T1027 - Obfuscated Files or Information
    if redirect_data.get("hop_count", 0) > 0 or features.get("hex_encoding"):
        tags.append("T1027 - Obfuscated Files or Information")

    # T1659 - Content Injection / Redirect
    if redirect_data.get("domain_switches"):
        tags.append("T1659 - Content Injection / Redirect")

    # T1566 - Phishing (confirmed by external TI)
    if intel.get("vt_malicious", 0) > 0 or intel.get("urlscan_malicious"):
        tags.append("T1566 - Phishing")

    # T1583.005 - Botnet / IP-based C2
    if features.get("uses_ip_as_host"):
        tags.append("T1583.005 - Botnet / IP-based C2")

    # T1583.006 - Web Services / Cloud Storage
    if features.get("cloud_hosting_abuse"):
        tags.append("T1583.006 - Web Services / Cloud Storage")

    # T1105 - Ingress Tool Transfer
    if features.get("malware_extension") or features.get("malware_path_keyword"):
        tags.append("T1105 - Ingress Tool Transfer")

    return tags