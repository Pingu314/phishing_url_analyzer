"""
Phishing URL Analyzer - Main Entry Point
SOC Portfolio Project | MITRE ATT&CK: T1566 (Phishing)
"""

import argparse
import json
import sys
from pathlib import Path

from url_extractor import URLFeatureExtractor
from threat_intel import ThreatIntelEnricher
from risk_scorer import RiskScorer
from report_generator import ReportGenerator
from redirect_follower import RedirectFollower


def analyze_url(url: str, config: dict, verbose: bool = False) -> dict:
    """Full analysis pipeline for a single URL."""
    print(f"\n[*] Analyzing: {url}")

    # Stage 1: Redirect chain following
    print("[*] Following redirect chain...")
    follower = RedirectFollower()
    redirect_data = follower.follow(url)
    hop_count = redirect_data["hop_count"]
    domain_switches = len(redirect_data["domain_switches"])

    if hop_count > 1:
        msg = f"    {hop_count} hops"
        if domain_switches:
            msg += f", {domain_switches} domain switch(es) — SUSPICIOUS"
        print(msg)
    else:
        print("    No redirects detected")

    if verbose:
        for hop in redirect_data["chain"]:
            print(f"    Hop {hop['hop']}: [{hop.get('status_code', '?')}] {hop['url']}")

    # Stage 2: Feature extraction (on final URL after redirects)
    final_url = redirect_data["final_url"]
    if final_url != url:
        print(f"[*] Extracting features (final destination: {final_url[:70]})")
    else:
        print("[*] Extracting URL features...")

    extractor = URLFeatureExtractor(final_url)
    features = extractor.extract()
    features["redirect_count"] = hop_count
    features["redirect_domain_switch"] = domain_switches > 0

    if verbose:
        print(f"    Features: {json.dumps(features, indent=2)}")

    # Stage 3: Threat intelligence enrichment
    print("[*] Enriching with threat intelligence...")
    enricher = ThreatIntelEnricher(config)
    intel = enricher.enrich(final_url, features["domain"])
    if verbose:
        print(f"    Intel: {json.dumps(intel, indent=2)}")

    # Stage 4: Risk scoring
    print("[*] Calculating risk score...")
    scorer = RiskScorer()
    risk = scorer.score(features, intel)

    # Stage 5: MITRE ATT&CK mapping
    mitre_tags = map_to_mitre(features, intel, redirect_data)

    result = {
        "url": url,
        "final_url": final_url,
        "redirect_chain": redirect_data,
        "features": features,
        "threat_intel": intel,
        "risk": risk,
        "mitre": mitre_tags,
    }

    verdict_color = {
        "BENIGN":     "\033[92m",
        "SUSPICIOUS": "\033[93m",
        "MALICIOUS":  "\033[91m",
    }
    reset = "\033[0m"
    color = verdict_color.get(risk["verdict"], "")

    print(f"\n{'='*55}")
    print(f"  VERDICT  : {color}{risk['verdict']}{reset}")
    print(f"  Score    : {risk['score']}/100")
    if final_url != url:
        print(f"  Final URL: {final_url[:55]}")
    print(f"  MITRE    : {', '.join(mitre_tags) if mitre_tags else 'N/A'}")
    print(f"{'='*55}")

    return result


def map_to_mitre(features: dict, intel: dict, redirect_data: dict) -> list:
    tags = []
    if features.get("has_suspicious_keywords") or features.get("brand_impersonation"):
        tags.append("T1566.002 - Spearphishing Link")
    if redirect_data.get("hop_count", 0) > 1 or features.get("hex_encoding"):
        tags.append("T1027 - Obfuscated Files or Information")
    if redirect_data.get("domain_switches"):
        tags.append("T1659 - Content Injection / Redirect")
    if intel.get("vt_malicious", 0) > 0 or intel.get("urlscan_malicious"):
        tags.append("T1566 - Phishing")
    if features.get("uses_ip_as_host"):
        tags.append("T1583.005 - Botnet / IP-based C2")
    return tags


def load_config(config_path: str = "config/config.json") -> dict:
    path = Path(config_path)
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {}


def main():
    parser = argparse.ArgumentParser(
        description="Phishing URL Analyzer - SOC Triage Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -u "http://suspicious-site.com/login"
  python main.py -f data/sample_urls/urls.txt
  python main.py -u "http://paypa1.com/verify" --verbose --export
        """
    )
    parser.add_argument("-u", "--url", help="Single URL to analyze")
    parser.add_argument("-f", "--file", help="File with URLs (one per line)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--export", action="store_true", help="Export JSON report to /reports")
    parser.add_argument("--config", default="config/config.json", help="Path to config file")
    args = parser.parse_args()

    if not args.url and not args.file:
        parser.print_help()
        sys.exit(1)

    config = load_config(args.config)
    urls = []

    if args.url:
        urls.append(args.url)
    if args.file:
        with open(args.file) as f:
            urls.extend([
                line.strip() for line in f
                if line.strip() and not line.startswith("#")
            ])

    results = []
    for url in urls:
        result = analyze_url(url, config, verbose=args.verbose)
        results.append(result)

    if args.export:
        reporter = ReportGenerator()
        report_path = reporter.export(results)
        print(f"\n[+] Report exported: {report_path}")

    if len(results) > 1:
        print(f"\n{'='*55}")
        print(f"  BATCH SUMMARY ({len(results)} URLs analyzed)")
        print(f"{'='*55}")
        for r in results:
            v = r["risk"]["verdict"]
            s = r["risk"]["score"]
            hops = r["redirect_chain"]["hop_count"]
            print(f"  [{v:10s}] Score:{s:3d} Hops:{hops} | {r['url'][:45]}")


if __name__ == "__main__":
    main()
