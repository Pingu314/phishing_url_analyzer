"""
Tests for src/report_generator.py - ReportGenerator
"""

import csv as _csv
import json as _json
import os

from src.report_generator import ReportGenerator


class TestReportGenerator:

    def test_export_json_valid_list(self, tmp_path, monkeypatch, sample_result):
        monkeypatch.chdir(tmp_path)
        os.makedirs("reports", exist_ok=True)
        rg = ReportGenerator()
        path = rg.export([sample_result])
        with open(path) as f:
            data = _json.load(f)
        assert isinstance(data, list)
        assert data[0]["url"] == "http://test.com"

    def test_export_csv_correct_headers(self, tmp_path, monkeypatch, sample_result):
        monkeypatch.chdir(tmp_path)
        os.makedirs("reports", exist_ok=True)
        rg = ReportGenerator()
        path = rg.export_csv([sample_result])
        with open(path) as f:
            headers = _csv.DictReader(f).fieldnames
        assert "verdict" in headers
        assert "confidence" in headers
        assert "score" in headers
        assert "mitre_tags" in headers

    def test_export_csv_confidence_value(self, tmp_path, monkeypatch, sample_result):
        monkeypatch.chdir(tmp_path)
        os.makedirs("reports", exist_ok=True)
        rg = ReportGenerator()
        path = rg.export_csv([sample_result])
        with open(path) as f:
            row = next(_csv.DictReader(f))
        assert row["confidence"] == "VERY_LOW"
        assert row["verdict"] == "BENIGN"
        assert row["mitre_tags"] == ""

    def test_export_csv_mitre_tags_pipe_separated(self, tmp_path, monkeypatch, sample_result):
        monkeypatch.chdir(tmp_path)
        os.makedirs("reports", exist_ok=True)
        result = {**sample_result,
                  "mitre": ["T1566.002 - Spearphishing Link",
                             "T1027 - Obfuscated Files or Information"]}
        rg = ReportGenerator()
        path = rg.export_csv([result])
        with open(path) as f:
            row = next(_csv.DictReader(f))
        assert "|" in row["mitre_tags"]
        assert "T1566.002" in row["mitre_tags"]

    def test_export_html_creates_file(self, tmp_path, monkeypatch, sample_result):
        monkeypatch.chdir(tmp_path)
        os.makedirs("reports", exist_ok=True)
        rg = ReportGenerator()
        path = rg.export_html([sample_result])
        assert path.endswith(".html")
        assert os.path.exists(path)

    def test_export_html_contains_verdict_chip(self, tmp_path, monkeypatch, sample_result):
        monkeypatch.chdir(tmp_path)
        os.makedirs("reports", exist_ok=True)
        rg = ReportGenerator()
        path = rg.export_html([sample_result])
        with open(path, encoding="utf-8") as f:
            html = f.read()
        assert "chip BENIGN" in html
        assert "http://test.com" in html
        assert "<!doctype html>" in html

    def test_export_html_summary_counts(self, tmp_path, monkeypatch, sample_result):
        monkeypatch.chdir(tmp_path)
        os.makedirs("reports", exist_ok=True)
        malicious = {**sample_result,
                     "url": "http://paypa1-verify.com/login",
                     "risk": {"score": 85, "verdict": "MALICIOUS",
                              "confidence": "HIGH", "breakdown": {}}}
        rg = ReportGenerator()
        path = rg.export_html([sample_result, malicious])
        with open(path, encoding="utf-8") as f:
            html = f.read()
        assert 'card MALICIOUS' in html
        assert 'card BENIGN' in html
        # Sorted by score: malicious row must come first
        assert html.index("paypa1-verify") < html.index("test.com")

    def test_export_html_escapes_content(self, tmp_path, monkeypatch, sample_result):
        monkeypatch.chdir(tmp_path)
        os.makedirs("reports", exist_ok=True)
        xss = {**sample_result, "url": 'http://evil.com/<script>alert(1)</script>'}
        rg = ReportGenerator()
        path = rg.export_html([xss])
        with open(path, encoding="utf-8") as f:
            html = f.read()
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    def test_export_html_indicators_only_fired_booleans(self, tmp_path, monkeypatch, sample_result):
        monkeypatch.chdir(tmp_path)
        os.makedirs("reports", exist_ok=True)
        noisy = {**sample_result,
                 "features": {"brand_impersonation": True,
                              "typosquatting": False,
                              "url_length": 54,
                              "domain_entropy": 3.7}}
        rg = ReportGenerator()
        path = rg.export_html([noisy])
        with open(path, encoding="utf-8") as f:
            html = f.read()
        assert "brand_impersonation" in html
        assert "url_length" not in html.split("<table>")[1]
        assert "domain_entropy" not in html.split("<table>")[1]