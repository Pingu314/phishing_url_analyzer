"""
Redirect Follower
Follows HTTP redirect chains up to MAX_HOPS hops.
Detects mid-chain domain switches (potential cloaking / open-redirect abuse).

MITRE ATT&CK: T1027 (Obfuscated Files or Information)
"""

import urllib.request
import urllib.error
import urllib.parse
import socket

from config.settings import MAX_HOPS, REQUEST_TIMEOUT


class RedirectFollower:
    def __init__(self):
        pass

    def follow(self, url: str) -> dict:
        """
        Follow redirects from `url` up to MAX_HOPS times.
        Returns a dict with the full chain, domain switch events, and
        the final resolved URL.

        hop_count reflects the number of *redirect hops* (0 = no redirects).
        The initial request is NOT counted as a hop.
        """
        chain = []
        domain_switches = []
        errors = []
        current_url = url
        prev_domain = self._extract_domain(url)

        for _ in range(MAX_HOPS):
            result = self._fetch_single(current_url)

            if result.get("error"):
                errors.append(f"Fetch error on {current_url}: {result['error']}")
                break

            next_url = result.get("location")

            if not next_url:
                # No Location header - this is the final destination (not a hop)
                break

            # Handle relative redirects before recording the hop
            next_url = urllib.parse.urljoin(current_url, next_url)
            next_domain = self._extract_domain(next_url)

            # Record this hop (current_url -> next_url)
            chain.append({"hop": len(chain) + 1,
                          "from_url": current_url,
                          "to_url": next_url,
                          "domain": next_domain,
                          "status_code": result.get("status_code")})

            # Detect domain switch on this hop
            if next_domain != prev_domain:
                domain_switches.append({"hop": len(chain),
                                        "from": prev_domain,
                                        "to": next_domain})

            prev_domain = next_domain
            current_url = next_url

        final_url = current_url
        final_domain = self._extract_domain(final_url)
        initial_domain = self._extract_domain(url)

        return {"initial_url": url,
                "final_url": final_url,
                "hop_count": len(chain),          # 0 = no redirects
                "chain": chain,
                "domain_switches": domain_switches,
                "domain_changed": initial_domain != final_domain,
                "initial_domain": initial_domain,
                "final_domain": final_domain,
                "errors": errors,
                # Convenience flag for downstream scoring
                "suspicious": len(domain_switches) > 0 or len(chain) > 3}

    def _fetch_single(self, url: str) -> dict:
        """
        Fetch one URL without auto-following redirects.
        Returns status_code + location header (if redirect) or error.
        """
        try:
            # Build a custom opener that does NOT follow redirects
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None  # Block auto-follow

            opener = urllib.request.build_opener(NoRedirect)
            req = urllib.request.Request(url,
                                         headers={"User-Agent": "Mozilla/5.0"})

            try:
                with opener.open(req, timeout=REQUEST_TIMEOUT) as response:
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