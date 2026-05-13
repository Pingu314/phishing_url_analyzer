"""
Tests for src/redirect_follower.py - RedirectFollower
"""

from src.redirect_follower import RedirectFollower


class TestRedirectFollower:

    def test_extract_domain(self):
        rf = RedirectFollower()
        assert rf._extract_domain("https://www.example.com/path") == "www.example.com"

    def test_extract_domain_with_port(self):
        rf = RedirectFollower()
        assert rf._extract_domain("http://example.com:8080/path") == "example.com:8080"

    def test_extract_domain_invalid(self):
        rf = RedirectFollower()
        result = rf._extract_domain("not-a-url")
        assert isinstance(result, str)

    def test_no_redirect_returns_zero_hops(self):
        """A URL with no Location header should return hop_count == 0."""
        rf = RedirectFollower()
        result = rf.follow("https://www.google.com")
        assert result["hop_count"] == 0
        assert result["final_url"] == "https://www.google.com"
        assert result["chain"] == []

    def test_follow_returns_required_keys(self):
        """Result dict must always contain all expected keys."""
        rf = RedirectFollower()
        result = rf.follow("https://www.google.com")
        for key in ["initial_url", "final_url", "hop_count", "chain", "domain_switches",
                    "domain_changed", "initial_domain", "final_domain", "errors"]:
            assert key in result, f"Missing key: {key}"

    def test_single_redirect_hop_recorded(self):
        """follow() records a hop when _fetch_single returns a Location header."""
        rf = RedirectFollower()
        responses = [
            {"status_code": 301, "location": "http://final.com/page"},
            {"status_code": 200, "location": None},
        ]
        call_count = 0

        def fake_fetch(url):
            nonlocal call_count
            r = responses[call_count]
            call_count += 1
            return r

        rf._fetch_single = fake_fetch
        result = rf.follow("http://original.com")
        assert result["hop_count"] == 1
        assert result["final_url"] == "http://final.com/page"
        assert len(result["chain"]) == 1

    def test_domain_switch_detected(self):
        """Domain switch is recorded when redirect crosses domain boundary."""
        rf = RedirectFollower()
        responses = [
            {"status_code": 302, "location": "http://different.com/landing"},
            {"status_code": 200, "location": None},
        ]
        call_count = 0

        def fake_fetch(url):
            nonlocal call_count
            r = responses[call_count]
            call_count += 1
            return r

        rf._fetch_single = fake_fetch
        result = rf.follow("http://original.com/start")
        assert len(result["domain_switches"]) == 1
        assert result["domain_switches"][0]["from_domain"] == "original.com"
        assert result["domain_switches"][0]["to_domain"] == "different.com"

    def test_fetch_error_breaks_chain(self):
        """An error from _fetch_single stops the chain and records the error."""
        rf = RedirectFollower()

        def fake_fetch(url):
            return {"error": "URLError: connection refused"}

        rf._fetch_single = fake_fetch
        result = rf.follow("http://unreachable.com")
        assert result["hop_count"] == 0
        assert len(result["errors"]) == 1
        assert "connection refused" in result["errors"][0]

    def test_fetch_single_http_error_returns_location(self):
        """_fetch_single returns status_code and location on HTTPError redirect."""
        import urllib.error
        from unittest.mock import MagicMock, patch

        rf = RedirectFollower()
        mock_headers = MagicMock()
        mock_headers.get.return_value = "http://redirected.com"
        http_err = urllib.error.HTTPError(
            None, 301, "Moved", mock_headers, None)

        with patch("urllib.request.build_opener") as mock_opener:
            mock_opener.return_value.open.side_effect = http_err
            result = rf._fetch_single("http://original.com")

        assert result["status_code"] == 301
        assert result["location"] == "http://redirected.com"

    def test_fetch_single_url_error_returns_error_key(self):
        """_fetch_single returns error dict on URLError."""
        import urllib.error
        from unittest.mock import patch

        rf = RedirectFollower()
        with patch("urllib.request.build_opener") as mock_opener:
            mock_opener.return_value.open.side_effect = urllib.error.URLError(
                "connection refused")
            result = rf._fetch_single("http://unreachable.com")

        assert "error" in result
        assert "URLError" in result["error"]

    def test_fetch_single_os_error_returns_error_key(self):
        """_fetch_single returns error dict on OSError/socket.timeout."""
        from unittest.mock import patch

        rf = RedirectFollower()
        with patch("urllib.request.build_opener") as mock_opener:
            mock_opener.return_value.open.side_effect = OSError("timed out")
            result = rf._fetch_single("http://example.com")

        assert "error" in result
        assert "Connection error" in result["error"]
