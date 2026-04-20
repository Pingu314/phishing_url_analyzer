"""
Redirect Chain Follower
Follows HTTP redirects up to MAX_HOPS, recording each hop.
Detects domain switching mid-chain — a strong phishing indicator.

MITRE ATT&CK: T1027 - Obfuscated Files or Information
"""

import urllib.request
import urllib.error
import urllib.parse
import socket
from typing import Optional


MAX_HOPS = 6
TIMEOUT = 8  # seconds per request


class RedirectFollower:
    def __init__(self):
        pass

    def follow(self, url: str) -> dict:
        """
        Follow redirect chain from initial URL.
        Returns chain metadata, domain switches, and any errors.
        """
        chain = []
        domain_switches = []
        errors = []
        current_url = url
        prev_domain = self._extract_domain(url)

        for hop in range(MAX_HOPS):
            result = self._fetch_single(current_url)

            hop_entry = {"hop": hop + 1,
                         "url": current_url,
                         "domain": self._extract_domain(current_url),
                         "status_code": result.get("status_code"),
                         "error": result.get("error")}
            chain.append(hop_entry)

            if result.get("error"):
                errors.append(f"Hop {hop + 1}: {result['error']}")
                break

            # Detect domain switch
            current_domain = self._extract_domain(current_url)
            if hop > 0 and current_domain != prev_domain:
                domain_switches.append({"hop": hop + 1,
                                        "from": prev_domain,
                                        "to": current_domain})
            prev_domain = current_domain

            next_url = result.get("location")
            if not next_url:
                # No more redirects — this is the final destination
                break

            # Handle relative redirects
            next_url = urllib.parse.urljoin(current_url, next_url)
            current_url = next_url

        final_url = chain[-1]["url"] if chain else url
        final_domain = self._extract_domain(final_url)
        initial_domain = self._extract_domain(url)

        return {"initial_url": url,
                "final_url": final_url,
                "hop_count": len(chain),
                "chain": chain,
                "domain_switches": domain_switches,
                "domain_changed": initial_domain != final_domain,
                "initial_domain": initial_domain,
                "final_domain": final_domain,
                "errors": errors,
                # Risk indicators
                "suspicious": len(domain_switches) > 0 or len(chain) > 3}

    def _fetch_single(self, url: str) -> dict:
        """
        Fetch a single URL without following redirects.
        Returns status code and Location header if present.
        """
        try:
            # Build a custom opener that does NOT follow redirects
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None  # Block auto-follow

            opener = urllib.request.build_opener(NoRedirect)
            req = urllib.request.Request(url,
                                         headers={"User-Agent": "Mozilla/5.0 (compatible; SOC-Analyzer/1.0)"})

            try:
                with opener.open(req, timeout=TIMEOUT) as response:
                    return {"status_code": response.status,
                            "location": response.headers.get("Location")}
            except urllib.error.HTTPError as e:
                location = e.headers.get("Location") if e.headers else None
                return {"status_code": e.code,
                        "location": location}

        except urllib.error.URLError as e:
            return {"error": f"URLError: {str(e.reason)}"}
        except socket.timeout:
            return {"error": "Timeout"}
        except Exception as e:
            return {"error": str(e)}

    def _extract_domain(self, url: str) -> str:
        try:
            parsed = urllib.parse.urlparse(url)
            return parsed.netloc.lower()
        except Exception:
            return url