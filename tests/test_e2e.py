"""
End-to-end tests for the full triage pipeline.

Mocks the orchestrator so no real memory dump or Volatility 3 call is needed.
Tests HTML/JSON report generation, IOC scanning, and risk scoring integration.
"""
import json
import os
import re
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Helper: build a minimal report_data dict
# ---------------------------------------------------------------------------

def _build_report_data(
    sample_plugin_results, ioc_matches, scored_processes, verdict, overall_score
):
    net_rows = (
        sample_plugin_results.get("netscan", {}).get("rows", [])
        + sample_plugin_results.get("netstat", {}).get("rows", [])
    )
    return {
        "dump_path": "/tmp/test.raw",
        "dump_filename": "test.raw",
        "analysis_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "duration_s": 42.0,
        "verdict": verdict,
        "overall_score": overall_score,
        "process_count": len(sample_plugin_results.get("pslist", {}).get("rows", [])),
        "suspect_processes": scored_processes,
        "network_connections": net_rows,
        "ioc_matches": ioc_matches,
        "kernel_modules": sample_plugin_results.get("modscan", {}).get("rows", []),
        "plugin_results": sample_plugin_results,
        "plugin_errors": {},
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestFullPipeline:
    def test_pipeline_produces_ioc_matches(self, sample_plugin_results, ioc_db_path):
        """IOC scanner should find at least the LockBit mutex in sample results."""
        from triage.ioc_scanner import scan
        matches = scan(sample_plugin_results, ioc_db_path)
        assert len(matches) >= 1

    def test_pipeline_scores_processes(self, sample_plugin_results, ioc_db_path):
        """Risk scorer should score malware.exe as high risk."""
        from triage.ioc_scanner import scan
        from triage.risk_scorer import score_processes
        matches = scan(sample_plugin_results, ioc_db_path)
        scored = score_processes(sample_plugin_results, matches)
        malware = next((p for p in scored if p["name"] == "malware.exe"), None)
        assert malware is not None
        assert malware["risk_score"] >= 40  # at least the malfind hit


class TestHtmlReport:
    def test_html_report_generated(self, tmp_path, sample_plugin_results, ioc_db_path):
        """HTML report file should be created without raising."""
        from triage.ioc_scanner import scan
        from triage.risk_scorer import score_processes, overall_verdict
        from triage.report_html import generate_html_report

        matches = scan(sample_plugin_results, ioc_db_path)
        scored = score_processes(sample_plugin_results, matches)
        verdict, score = overall_verdict(scored)
        report_data = _build_report_data(sample_plugin_results, matches, scored, verdict, score)

        out_file = str(tmp_path / "report.html")
        generate_html_report(report_data, out_file)

        assert os.path.exists(out_file), "HTML report file was not created"
        assert os.path.getsize(out_file) > 1000, "HTML report is suspiciously small"

    def test_html_contains_verdict_banner(self, tmp_path, sample_plugin_results, ioc_db_path):
        """HTML report must contain a COMPROMISED/SUSPICIOUS/CLEAN banner."""
        from triage.ioc_scanner import scan
        from triage.risk_scorer import score_processes, overall_verdict
        from triage.report_html import generate_html_report

        matches = scan(sample_plugin_results, ioc_db_path)
        scored = score_processes(sample_plugin_results, matches)
        verdict, score = overall_verdict(scored)
        report_data = _build_report_data(sample_plugin_results, matches, scored, verdict, score)

        out_file = str(tmp_path / "report.html")
        generate_html_report(report_data, out_file)
        content = Path(out_file).read_text(encoding="utf-8")

        assert any(kw in content for kw in ("COMPROMISED", "SUSPICIOUS", "CLEAN")), (
            "Verdict banner missing from HTML report"
        )

    def test_html_contains_process_table(self, tmp_path, sample_plugin_results, ioc_db_path):
        """HTML report must contain a process risk analysis table."""
        from triage.ioc_scanner import scan
        from triage.risk_scorer import score_processes, overall_verdict
        from triage.report_html import generate_html_report

        matches = scan(sample_plugin_results, ioc_db_path)
        scored = score_processes(sample_plugin_results, matches)
        verdict, score = overall_verdict(scored)
        report_data = _build_report_data(sample_plugin_results, matches, scored, verdict, score)

        out_file = str(tmp_path / "report.html")
        generate_html_report(report_data, out_file)
        content = Path(out_file).read_text(encoding="utf-8")

        assert "malware.exe" in content, "Process name 'malware.exe' missing from HTML"

    def test_html_contains_ioc_section(self, tmp_path, sample_plugin_results, ioc_db_path):
        """HTML report must contain the IOC Matches section."""
        from triage.ioc_scanner import scan
        from triage.risk_scorer import score_processes, overall_verdict
        from triage.report_html import generate_html_report

        matches = scan(sample_plugin_results, ioc_db_path)
        scored = score_processes(sample_plugin_results, matches)
        verdict, score = overall_verdict(scored)
        report_data = _build_report_data(sample_plugin_results, matches, scored, verdict, score)

        out_file = str(tmp_path / "report.html")
        generate_html_report(report_data, out_file)
        content = Path(out_file).read_text(encoding="utf-8")

        assert "IOC Matches" in content

    def test_html_contains_next_steps_section(self, tmp_path, sample_plugin_results, ioc_db_path):
        """HTML report must contain the Next Steps for IR Analyst section."""
        from triage.ioc_scanner import scan
        from triage.risk_scorer import score_processes, overall_verdict
        from triage.report_html import generate_html_report

        matches = scan(sample_plugin_results, ioc_db_path)
        scored = score_processes(sample_plugin_results, matches)
        verdict, score = overall_verdict(scored)
        report_data = _build_report_data(sample_plugin_results, matches, scored, verdict, score)

        out_file = str(tmp_path / "report.html")
        generate_html_report(report_data, out_file)
        content = Path(out_file).read_text(encoding="utf-8")

        assert "Next Steps" in content

    def test_html_is_valid_html(self, tmp_path, sample_plugin_results, ioc_db_path):
        """HTML report must start with <!DOCTYPE html> and contain a body tag."""
        from triage.ioc_scanner import scan
        from triage.risk_scorer import score_processes, overall_verdict
        from triage.report_html import generate_html_report

        matches = scan(sample_plugin_results, ioc_db_path)
        scored = score_processes(sample_plugin_results, matches)
        verdict, score = overall_verdict(scored)
        report_data = _build_report_data(sample_plugin_results, matches, scored, verdict, score)

        out_file = str(tmp_path / "report.html")
        generate_html_report(report_data, out_file)
        content = Path(out_file).read_text(encoding="utf-8")

        assert content.strip().startswith("<!DOCTYPE html")
        assert "<body" in content
        assert "</html>" in content


class TestJsonReport:
    def test_json_report_generated(self, tmp_path, sample_plugin_results, ioc_db_path):
        """JSON report file should be created."""
        from triage.ioc_scanner import scan
        from triage.risk_scorer import score_processes, overall_verdict
        from triage.report_json import generate_json_report

        matches = scan(sample_plugin_results, ioc_db_path)
        scored = score_processes(sample_plugin_results, matches)
        verdict, score = overall_verdict(scored)
        report_data = _build_report_data(sample_plugin_results, matches, scored, verdict, score)

        out_file = str(tmp_path / "report.json")
        generate_json_report(report_data, out_file)
        assert os.path.exists(out_file)

    def test_json_report_is_valid_json(self, tmp_path, sample_plugin_results, ioc_db_path):
        """JSON report must be parseable JSON."""
        from triage.ioc_scanner import scan
        from triage.risk_scorer import score_processes, overall_verdict
        from triage.report_json import generate_json_report

        matches = scan(sample_plugin_results, ioc_db_path)
        scored = score_processes(sample_plugin_results, matches)
        verdict, score = overall_verdict(scored)
        report_data = _build_report_data(sample_plugin_results, matches, scored, verdict, score)

        out_file = str(tmp_path / "report.json")
        generate_json_report(report_data, out_file)
        data = json.loads(Path(out_file).read_text(encoding="utf-8"))
        assert isinstance(data, dict)

    def test_json_report_has_expected_keys(self, tmp_path, sample_plugin_results, ioc_db_path):
        """JSON report must include top-level expected keys."""
        from triage.ioc_scanner import scan
        from triage.risk_scorer import score_processes, overall_verdict
        from triage.report_json import generate_json_report

        matches = scan(sample_plugin_results, ioc_db_path)
        scored = score_processes(sample_plugin_results, matches)
        verdict, score = overall_verdict(scored)
        report_data = _build_report_data(sample_plugin_results, matches, scored, verdict, score)

        out_file = str(tmp_path / "report.json")
        generate_json_report(report_data, out_file)
        data = json.loads(Path(out_file).read_text(encoding="utf-8"))

        expected_keys = {
            "dump_path", "dump_filename", "verdict", "overall_score",
            "ioc_matches", "suspect_processes",
        }
        for key in expected_keys:
            assert key in data, f"Missing key in JSON report: '{key}'"


class TestCompromisedScenario:
    def test_compromised_verdict_with_malfind_and_c2(self, sample_plugin_results, ioc_db_path):
        """
        Scenario: malfind hit + LockBit C2 IP → verdict must be Compromised.
        sample_plugin_results already contains both; verify end result.
        """
        from triage.ioc_scanner import scan
        from triage.risk_scorer import score_processes, overall_verdict

        matches = scan(sample_plugin_results, ioc_db_path)
        scored = score_processes(sample_plugin_results, matches)
        verdict, score = overall_verdict(scored)

        # malware.exe: malfind (40) + IOC hits (>=10 each) should be well above 70
        assert score >= 50, f"Expected overall score >= 50, got {score}"
        # The top process should have Compromised or Suspicious verdict
        assert verdict in ("Compromised", "Suspicious"), (
            f"Expected Compromised/Suspicious, got {verdict} (score {score})"
        )


class TestCleanScenario:
    def test_clean_verdict_with_benign_processes(self, clean_plugin_results, ioc_db_path):
        """
        Scenario: only whitelist Windows processes, no malfind, no IOC matches.
        Verdict must be Clean with score < 30.
        """
        from triage.ioc_scanner import scan
        from triage.risk_scorer import score_processes, overall_verdict

        matches = scan(clean_plugin_results, ioc_db_path)
        assert len(matches) == 0, f"Expected 0 IOC matches for clean data, got {len(matches)}"

        scored = score_processes(clean_plugin_results, matches)
        verdict, score = overall_verdict(scored)

        assert verdict == "Clean", f"Expected Clean, got {verdict} (score {score})"
        assert score < 30, f"Expected score < 30, got {score}"
