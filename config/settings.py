"""
settings.py — Central configuration for Phishing URL Analyzer

All tunable constants live here so every module (and a future
soc_threat_analyzer integration) can import from one place
"""

# Brand / keyword lists
# Brands commonly impersonated in phishing
# Each entry is the canonical second-level label (no TLD)
# Used for label-aware matching only — do NOT use plain substring search
BRAND_KEYWORDS = ["paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook", "instagram",
                  "linkedin", "twitter", "dropbox", "office365", "onedrive", "chase", "wellsfargo", "bankofamerica",
                  "ubs", "postfinance", "raiffeisen", "swisscom", "sbb", "post", "zkb", ]

# Keywords that raise suspicion when found in the URL path/query
SUSPICIOUS_KEYWORDS = ["login", "signin", "verify", "secure", "update", "confirm", "account", "banking", "password",
                       "credential", "validate", "suspended", "locked", "unusual", "activity", "click", "urgent",
                       "unsubscribe", "token", "reset", ]

# Path-level keywords strongly associated with malware delivery
MALWARE_PATH_KEYWORDS = ["payload", "dropper", "install", "setup", "download", ]

# File extensions that are high-risk in a URL path
MALWARE_EXTENSIONS = [".exe", ".bat", ".ps1", ".vbs", ".jar", ".msi", ".scr", ".hta", ]

# Common homoglyph / typo substitutions used in typosquatting
# Maps look-alike characters back to their ASCII equivalents
HOMOGLYPH_MAP = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
                 "@": "a", "$": "s", "rn": "m", "vv": "w", }

# Cloud / object-storage hosting domains abused to serve phishing pages
# Full domain suffixes - used with endswith() matching in url_extractor.py
# Add new entries here; do NOT use bare labels (e.g. "blob") -> too broad
CLOUD_HOSTING_DOMAINS = ["storage.googleapis.com",       # GCS public buckets
                         "s3.amazonaws.com",             # AWS S3
                         "blob.core.windows.net",        # Azure Blob Storage
                         "azureedge.net",                # Azure CDN
                         "azurewebsites.net",            # Azure App Service
                         "cloudfront.net",               # AWS CloudFront
                         "digitaloceanspaces.com",       # DigitalOcean Spaces
                         "backblazeb2.com",              # Backblaze B2
                         "r2.dev",                       # Cloudflare R2 public buckets
                         "pages.dev",                    # Cloudflare Pages
                         "netlify.app",                  # Netlify
                         "github.io",                    # GitHub Pages
                         "web.app",                      # Firebase Hosting
                         "firebaseapp.com", ]            # Firebase Hosting (legacy)

# TLD lists
SUSPICIOUS_TLDS = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".club", ".click", ".link", ".live", ".online",
                   ".site", ".website", ".info", ".biz", ".pw", ".cc", ".icu", ]

LEGITIMATE_TLDS = [".com", ".org", ".gov", ".edu", ".co.uk", ".de", ".ch", ".fr", ]


# Redirect follower
MAX_HOPS = 6
REQUEST_TIMEOUT = 6     # seconds per hop


# Risk scorer weights  (0-100 scale, capped at 100)
WEIGHTS = {  # High-signal
           "vt_malicious":           20,   # per engine (capped at 40 total)
           "urlscan_malicious":      20,
           "brand_impersonation":    18,
           "brand_in_subdomain":     15,
           "uses_ip_as_host":        15,
           "private_ip":             20,   # RFC1918 host - almost certainly internal recon/C2
           "typosquatting":          18,   # homoglyph / edit-distance brand hit
           "cloud_hosting_abuse":    18,   # T1583.006 - payload hosted on cloud storage

           # Medium-signal
           "redirect_domain_switch": 12,
           "suspicious_tld":         10,
           "has_suspicious_keywords": 8,
           "at_symbol":               8,
           "no_https":                7,
           "hex_encoding":            6,
           "has_redirect_param":      6,
           "double_slash":            5,
           "malware_extension":      15,   # .exe / .ps1 / etc. in path
           "malware_path_keyword":    8,   # "payload", "dropper", etc.

           # Soft signals
           "high_entropy":            5,   # domain entropy > 3.8
           "high_path_entropy":       6,   # random-looking path segment (bucket names, tokens)
           "long_url":                4,   # url length > 75
           "many_hops":               4,   # redirect hops > 1 (excluding origin)
           "new_domain":              8,   # domain registered < 30 days ago (WHOIS)
           "many_hyphens":            3,
           "deep_path":               3,
           "many_subdomains":         3,
           "port_in_url":             3}

# Verdict thresholds
THRESHOLDS = {"BENIGN":     (0, 20),
              "SUSPICIOUS": (21, 49),
              "MALICIOUS":  (50, 100)}