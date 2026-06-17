"""
Tests for src/triage/orchestrator.py

Mocks individual plugin modules so no real Volatility 3 / memory dump needed.
"""
import time
import pytest
from unittest.mock import patch, MagicMock
from triage.orchestrator import run_all_plugins, PLUGINS


class TestRunAllPlugins:
    def _make_plugin_mock(self, rows=None, delay=0.0, raise_exc=None):
        """Helper to create a mock plugin module."""
        mock = MagicMock()
        if raise_exc:
            mock.run.side_effect = raise_exc
        else:
            def run_fn(dump_path, profile=None):
                if delay:
                    time.sleep(delay)
                return (rows or [], delay)
            mock.run.side_effect = run_fn
        return mock

    def test_returns_results_for_all_plugins(self, mock_dump):
        """run_all_plugins should return a results dict with all 12 plugin keys."""
        mocks = {f"triage.plugins.{name}": self._make_plugin_mock([]) for name in PLUGINS}
        with patch.dict("sys.modules", mocks):
            results, total = run_all_plugins(mock_dump)

        assert set(results.keys()) == set(PLUGINS)

    def test_successful_plugin_has_rows_and_no_error(self, mock_dump):
        """Successful plugin results should have rows list and error=None."""
        fake_rows = [{"PID": "123", "Name": "test.exe"}]
        mocks = {f"triage.plugins.{name}": self._make_plugin_mock(fake_rows) for name in PLUGINS}
        with patch.dict("sys.modules", mocks):
            results, _ = run_all_plugins(mock_dump)

        for name in PLUGINS:
            assert results[name]["error"] is None, f"{name} had unexpected error"
            assert isinstance(results[name]["rows"], list)

    def test_plugin_error_captured_gracefully(self, mock_dump):
        """A plugin that raises an exception should be captured in error field, not propagate."""
        mocks = {}
        for name in PLUGINS:
            if name == "malfind":
                mocks[f"triage.plugins.{name}"] = self._make_plugin_mock(
                    raise_exc=RuntimeError("simulated malfind failure")
                )
            else:
                mocks[f"triage.plugins.{name}"] = self._make_plugin_mock([])

        with patch.dict("sys.modules", mocks):
            results, _ = run_all_plugins(mock_dump)

        # No exception raised; malfind result has error field
        assert results["malfind"]["error"] is not None
        assert "simulated malfind failure" in results["malfind"]["error"]
        assert results["malfind"]["rows"] == []

    def test_plugin_error_does_not_stop_others(self, mock_dump):
        """A failing plugin should not prevent other plugins from running."""
        mocks = {}
        for name in PLUGINS:
            if name == "netscan":
                mocks[f"triage.plugins.{name}"] = self._make_plugin_mock(
                    raise_exc=Exception("network layer not found")
                )
            else:
                mocks[f"triage.plugins.{name}"] = self._make_plugin_mock(
                    [{"PID": "1", "Name": "test.exe"}]
                )

        with patch.dict("sys.modules", mocks):
            results, _ = run_all_plugins(mock_dump)

        # All other plugins should have succeeded
        for name in PLUGINS:
            if name != "netscan":
                assert results[name]["error"] is None, f"{name} failed unexpectedly"

    def test_total_duration_returned(self, mock_dump):
        """run_all_plugins should return a numeric total duration."""
        mocks = {f"triage.plugins.{name}": self._make_plugin_mock([]) for name in PLUGINS}
        with patch.dict("sys.modules", mocks):
            results, total = run_all_plugins(mock_dump)
        assert isinstance(total, float)
        assert total >= 0

    def test_all_12_plugins_attempted(self, mock_dump):
        """All 12 plugin names should appear in PLUGINS list."""
        expected = {
            "pslist", "psscan", "pstree", "malfind",
            "netscan", "netstat", "cmdline", "handles",
            "dlllist", "modscan", "mutantscan", "svcscan",
        }
        assert set(PLUGINS) == expected

    def test_multiple_errors_all_captured(self, mock_dump):
        """Multiple plugin failures should all be captured independently."""
        failing = {"malfind", "handles", "dlllist"}
        mocks = {}
        for name in PLUGINS:
            if name in failing:
                mocks[f"triage.plugins.{name}"] = self._make_plugin_mock(
                    raise_exc=ValueError(f"{name} failed")
                )
            else:
                mocks[f"triage.plugins.{name}"] = self._make_plugin_mock([])

        with patch.dict("sys.modules", mocks):
            results, _ = run_all_plugins(mock_dump)

        for name in failing:
            assert results[name]["error"] is not None
        for name in set(PLUGINS) - failing:
            assert results[name]["error"] is None

    def test_duration_s_is_float(self, mock_dump):
        """Each plugin result's duration_s should be a float."""
        mocks = {f"triage.plugins.{name}": self._make_plugin_mock([]) for name in PLUGINS}
        with patch.dict("sys.modules", mocks):
            results, _ = run_all_plugins(mock_dump)
        for name in PLUGINS:
            assert isinstance(results[name]["duration_s"], float)
