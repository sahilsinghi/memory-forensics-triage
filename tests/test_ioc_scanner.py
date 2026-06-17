"""
Tests for src/triage/ioc_scanner.py

No real memory dump required — uses synthetic plugin results from conftest.py.
"""
import os
import pytest
from triage.ioc_scanner import load_ioc_database, scan


class TestLoadIocDatabase:
    def test_loads_yaml_files(self, ioc_db_path):
        """Database should load indicators from all 10 YAML files."""
        indicators = load_ioc_database(ioc_db_path)
        assert len(indicators) > 0, "No indicators loaded from database"

    def test_minimum_indicator_count(self, ioc_db_path):
        """We expect at least 300 indicators across 10 actor files."""
        indicators = load_ioc_database(ioc_db_path)
        assert len(indicators) >= 300, f"Expected >= 300 indicators, got {len(indicators)}"

    def test_indicator_has_required_fields(self, ioc_db_path):
        """Each indicator must have type, value, severity, actor."""
        indicators = load_ioc_database(ioc_db_path)
        for ioc in indicators[:20]:  # spot-check first 20
            assert "type" in ioc, f"Missing 'type': {ioc}"
            assert "value" in ioc, f"Missing 'value': {ioc}"
            assert "severity" in ioc, f"Missing 'severity': {ioc}"
            assert "actor" in ioc, f"Missing 'actor' (should be injected): {ioc}"

    def test_known_actors_present(self, ioc_db_path):
        """Key threat actors must be represented in the database."""
        indicators = load_ioc_database(ioc_db_path)
        actors = {i["actor"] for i in indicators}
        for expected in ("LockBit", "Conti", "APT29", "Lazarus", "DarkSide"):
            assert any(expected in a for a in actors), f"Actor '{expected}' not found in IOC DB"

    def test_empty_path_returns_empty_list(self, tmp_path):
        """Non-existent directory should return empty list, not raise."""
        result = load_ioc_database(str(tmp_path / "nonexistent"))
        assert result == []

    def test_indicator_types_are_valid(self, ioc_db_path):
        """All indicator types should be from the known set."""
        valid_types = {"process_name", "mutex", "network_ip", "file_path", "registry_key"}
        indicators = load_ioc_database(ioc_db_path)
        for ioc in indicators:
            assert ioc["type"] in valid_types, f"Unknown indicator type: {ioc['type']}"


class TestScan:
    def test_detects_lockbit_mutex(self, sample_plugin_results, ioc_db_path):
        """
        sample_plugin_results contains:
        Global\\{BEF7C86E-11D7-6B75-D7A0-7D6E4DA89768}
        which is a LockBit 3.0 mutex in lockbit.yml.
        """
        matches = scan(sample_plugin_results, ioc_db_path)
        mutex_matches = [
            m for m in matches
            if m["ioc"]["type"] == "mutex"
            and "BEF7C86E" in m["ioc"]["value"]
        ]
        assert len(mutex_matches) >= 1, (
            "LockBit mutex not detected. Matches: "
            + str([m["ioc"]["value"] for m in matches if m["ioc"]["type"] == "mutex"])
        )

    def test_detects_lockbit_mutex_actor(self, sample_plugin_results, ioc_db_path):
        """The mutex match should be attributed to LockBit."""
        matches = scan(sample_plugin_results, ioc_db_path)
        lockbit_mutex = [
            m for m in matches
            if m["ioc"]["type"] == "mutex"
            and "BEF7C86E" in m["ioc"]["value"]
        ]
        assert lockbit_mutex[0]["ioc"]["actor"] == "LockBit"

    def test_detects_c2_ip_in_netscan(self, sample_plugin_results, ioc_db_path):
        """
        sample_plugin_results contains ForeignAddr=185.220.101.45
        which is a LockBit C2 IP in lockbit.yml.
        """
        matches = scan(sample_plugin_results, ioc_db_path)
        ip_matches = [
            m for m in matches
            if m["ioc"]["type"] == "network_ip"
            and "185.220.101.45" in m["ioc"]["value"]
        ]
        assert len(ip_matches) >= 1, "LockBit C2 IP 185.220.101.45 not detected in netscan"

    def test_ip_match_has_plugin_field(self, sample_plugin_results, ioc_db_path):
        """IP matches should reference netscan as the source plugin."""
        matches = scan(sample_plugin_results, ioc_db_path)
        ip_matches = [
            m for m in matches
            if m["ioc"]["type"] == "network_ip"
            and "185.220.101.45" in m["ioc"]["value"]
        ]
        plugins = {m["plugin"] for m in ip_matches}
        assert "netscan" in plugins, f"Expected 'netscan' plugin, got: {plugins}"

    def test_match_structure(self, sample_plugin_results, ioc_db_path):
        """Every match must have required keys."""
        matches = scan(sample_plugin_results, ioc_db_path)
        required_keys = {"ioc", "plugin", "process_pid", "process_name", "context"}
        for m in matches:
            missing = required_keys - set(m.keys())
            assert not missing, f"Match missing keys {missing}: {m}"

    def test_no_false_positives_on_clean(self, clean_plugin_results, ioc_db_path):
        """Clean plugin results should produce no IOC matches."""
        matches = scan(clean_plugin_results, ioc_db_path)
        assert len(matches) == 0, f"Expected 0 matches for clean results, got {len(matches)}: {matches}"

    def test_returns_list(self, sample_plugin_results, ioc_db_path):
        """scan() should always return a list."""
        result = scan(sample_plugin_results, ioc_db_path)
        assert isinstance(result, list)

    def test_ioc_severity_field_present(self, sample_plugin_results, ioc_db_path):
        """Each match's ioc dict must have a severity field."""
        matches = scan(sample_plugin_results, ioc_db_path)
        for m in matches:
            assert "severity" in m["ioc"], f"Missing severity in match: {m}"
