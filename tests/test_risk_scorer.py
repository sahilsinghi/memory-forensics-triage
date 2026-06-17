"""
Tests for src/triage/risk_scorer.py

No real memory dump required — uses synthetic plugin results.
"""
import pytest
from triage.risk_scorer import score_processes, overall_verdict, WHITELIST


class TestScoreProcesses:
    def test_malfind_hit_adds_40_points(self, sample_plugin_results):
        """Process with malfind entry should get >= 40 risk score."""
        scored = score_processes(sample_plugin_results, [])
        malware_proc = next((p for p in scored if p["name"] == "malware.exe"), None)
        assert malware_proc is not None, "malware.exe not found in scored results"
        assert malware_proc["risk_score"] >= 40, (
            f"Expected >= 40, got {malware_proc['risk_score']} "
            f"(factors: {malware_proc['risk_factors']})"
        )

    def test_malfind_factor_in_risk_factors(self, sample_plugin_results):
        """malfind factor description should appear in process risk factors."""
        scored = score_processes(sample_plugin_results, [])
        malware_proc = next(p for p in scored if p["name"] == "malware.exe")
        has_malfind = any("malfind" in f.lower() for f in malware_proc["risk_factors"])
        assert has_malfind, f"malfind not in risk_factors: {malware_proc['risk_factors']}"

    def test_whitelist_processes_have_reduced_score(self, sample_plugin_results):
        """
        lsass.exe and System are on the whitelist.
        Even if they score > 0, whitelist should halve it.
        """
        # Inject a malfind hit for lsass to force a score before halving
        results = dict(sample_plugin_results)
        results["malfind"] = {
            "rows": [
                {"PID": "888", "Process": "lsass.exe", "Protection": "PAGE_EXECUTE_READWRITE"},
                {"PID": "1234", "Process": "malware.exe", "Protection": "PAGE_EXECUTE_READWRITE"},
            ],
            "error": None,
            "duration_s": 5.0,
        }
        scored = score_processes(results, [])
        lsass = next((p for p in scored if p["name"] == "lsass.exe"), None)
        assert lsass is not None
        # Without whitelist: 40. With whitelist halving: 20
        assert lsass["risk_score"] <= 20, (
            f"lsass.exe not properly whitelisted: score={lsass['risk_score']}"
        )

    def test_whitelist_contains_expected_processes(self):
        """Whitelist set must contain all expected system processes."""
        expected = [
            "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
            "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
        ]
        for proc in expected:
            assert proc in WHITELIST, f"'{proc}' missing from WHITELIST"

    def test_compromised_verdict_at_70_plus(self, sample_plugin_results):
        """Processes with score >= 70 should get 'Compromised' verdict."""
        # malware.exe will have malfind (40) + ioc match boost (10 per match)
        # Inject enough IOC matches to push above 70
        ioc_matches = [
            {"ioc": {"type": "network_ip", "value": "185.220.101.45", "actor": "LockBit",
                     "severity": "critical"}, "plugin": "netscan", "process_pid": "1234",
             "process_name": "malware.exe", "context": "185.220.101.45"},
            {"ioc": {"type": "mutex", "value": "BEF7C86E", "actor": "LockBit",
                     "severity": "critical"}, "plugin": "mutantscan", "process_pid": "1234",
             "process_name": "malware.exe", "context": "Global\\{BEF7C86E}"},
            {"ioc": {"type": "process_name", "value": "malware.exe", "actor": "TestActor",
                     "severity": "critical"}, "plugin": "pslist", "process_pid": "1234",
             "process_name": "malware.exe", "context": "malware.exe"},
            {"ioc": {"type": "process_name", "value": "malware.exe", "actor": "TestActor2",
                     "severity": "critical"}, "plugin": "pslist", "process_pid": "1234",
             "process_name": "malware.exe", "context": "malware.exe"},
        ]
        scored = score_processes(sample_plugin_results, ioc_matches)
        malware = next((p for p in scored if p["name"] == "malware.exe"), None)
        assert malware is not None
        # malfind=40 + 4 ioc matches=40 = 80 → Compromised
        assert malware["risk_score"] >= 70, f"Expected >= 70, got {malware['risk_score']}"
        assert malware["verdict"] == "Compromised"

    def test_clean_verdict_below_30(self, clean_plugin_results):
        """Benign processes with no flags should produce Clean verdict."""
        scored = score_processes(clean_plugin_results, [])
        for proc in scored:
            assert proc["risk_score"] < 30, (
                f"{proc['name']} scored {proc['risk_score']} — expected Clean (<30) "
                f"(factors: {proc['risk_factors']})"
            )
            assert proc["verdict"] == "Clean"

    def test_processes_sorted_by_score_descending(self, sample_plugin_results):
        """Scored list must be sorted highest to lowest risk_score."""
        ioc_matches = [
            {"ioc": {"type": "network_ip", "value": "185.220.101.45", "actor": "LockBit",
                     "severity": "critical"}, "plugin": "netscan", "process_pid": "1234",
             "process_name": "malware.exe", "context": "185.220.101.45"},
        ]
        scored = score_processes(sample_plugin_results, ioc_matches)
        scores = [p["risk_score"] for p in scored]
        assert scores == sorted(scores, reverse=True), (
            f"Processes not sorted: {[(p['name'], p['risk_score']) for p in scored]}"
        )

    def test_returns_list_of_dicts(self, sample_plugin_results):
        """score_processes should return a list of dicts."""
        result = score_processes(sample_plugin_results, [])
        assert isinstance(result, list)
        for item in result:
            assert isinstance(item, dict)

    def test_each_process_has_required_keys(self, sample_plugin_results):
        """Each process dict must contain all required output keys."""
        scored = score_processes(sample_plugin_results, [])
        required = {"pid", "name", "ppid", "path", "risk_score", "verdict", "risk_factors"}
        for proc in scored:
            missing = required - set(proc.keys())
            assert not missing, f"Process missing keys {missing}: {proc}"

    def test_ioc_match_increases_score(self, sample_plugin_results):
        """Adding IOC matches for a process should increase its score."""
        scored_no_ioc = score_processes(sample_plugin_results, [])
        malware_no_ioc = next(p for p in scored_no_ioc if p["name"] == "malware.exe")

        ioc_matches = [
            {"ioc": {"type": "network_ip", "value": "185.220.101.45", "actor": "LockBit",
                     "severity": "critical"}, "plugin": "netscan", "process_pid": "1234",
             "process_name": "malware.exe", "context": "185.220.101.45"},
        ]
        scored_with_ioc = score_processes(sample_plugin_results, ioc_matches)
        malware_with_ioc = next(p for p in scored_with_ioc if p["name"] == "malware.exe")
        assert malware_with_ioc["risk_score"] > malware_no_ioc["risk_score"]


class TestOverallVerdict:
    def test_compromised_verdict_from_high_score(self):
        """overall_verdict should return Compromised for score >= 70."""
        scored = [{"name": "evil.exe", "pid": "999", "ppid": "1",
                   "path": "", "risk_score": 85, "verdict": "Compromised",
                   "risk_factors": ["malfind", "ioc"]}]
        verdict, score = overall_verdict(scored)
        assert verdict == "Compromised"
        assert score == 85

    def test_clean_verdict_from_empty_list(self):
        """Empty process list should return Clean/0."""
        verdict, score = overall_verdict([])
        assert verdict == "Clean"
        assert score == 0

    def test_returns_highest_scoring_verdict(self):
        """Should pick the top process (highest score)."""
        scored = [
            {"name": "a.exe", "risk_score": 80, "verdict": "Compromised"},
            {"name": "b.exe", "risk_score": 40, "verdict": "Suspicious"},
            {"name": "c.exe", "risk_score": 5, "verdict": "Clean"},
        ]
        verdict, score = overall_verdict(scored)
        assert verdict == "Compromised"
        assert score == 80

    def test_suspicious_verdict(self):
        scored = [{"name": "x.exe", "risk_score": 50, "verdict": "Suspicious",
                   "pid": "1", "ppid": "0", "path": "", "risk_factors": []}]
        verdict, score = overall_verdict(scored)
        assert verdict == "Suspicious"
