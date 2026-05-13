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
