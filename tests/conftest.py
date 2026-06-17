"""
Shared pytest fixtures for memory-forensics-triage tests.

No real memory dump is required — all Volatility 3 calls are mocked.
"""
import os
import pytest


@pytest.fixture
def mock_dump(tmp_path):
    """Create a minimal fake memory dump file for testing."""
    dump = tmp_path / "test.raw"
    dump.write_bytes(b"\x4d\x5a\x00\x00" + b"\x00" * 1020)  # MZ header + padding
    return str(dump)


@pytest.fixture
def sample_plugin_results():
    """
    Realistic mock Volatility 3 plugin output.

    Includes a LockBit mutex, known-bad C2 IP (185.220.101.45),
    and a process with malfind hit to trigger scoring.
    """
    return {
        "pslist": {
            "rows": [
                {
                    "PID": "4",
                    "PPID": "0",
                    "ImageFileName": "System",
                    "Offset": "0xfa8000c9a040",
                    "Threads": "108",
                    "Handles": "588",
                    "SessionId": "N/A",
                    "Wow64": "False",
                    "CreateTime": "2024-01-01 00:00:01.000000",
                    "ExitTime": "",
                    "File output": "Disabled",
                },
                {
                    "PID": "668",
                    "PPID": "4",
                    "ImageFileName": "smss.exe",
                    "Offset": "0xfa8000d29060",
                    "Threads": "3",
                    "Handles": "37",
                    "SessionId": "N/A",
                    "Wow64": "False",
                    "CreateTime": "2024-01-01 00:00:05.000000",
                    "ExitTime": "",
                    "File output": "Disabled",
                },
                {
                    "PID": "1234",
                    "PPID": "668",
                    "ImageFileName": "malware.exe",
                    "Offset": "0xfa8001a9b0c0",
                    "Threads": "4",
                    "Handles": "72",
                    "SessionId": "1",
                    "Wow64": "False",
                    "CreateTime": "2024-01-01 10:23:45.000000",
                    "ExitTime": "",
                    "File output": "Disabled",
                },
                {
                    "PID": "5678",
                    "PPID": "1234",
                    "ImageFileName": "cmd.exe",
                    "Offset": "0xfa8001c9d0e0",
                    "Threads": "1",
                    "Handles": "21",
                    "SessionId": "1",
                    "Wow64": "False",
                    "CreateTime": "2024-01-01 10:24:01.000000",
                    "ExitTime": "",
                    "File output": "Disabled",
                },
                {
                    "PID": "888",
                    "PPID": "4",
                    "ImageFileName": "lsass.exe",
                    "Offset": "0xfa8000e1b020",
                    "Threads": "11",
                    "Handles": "552",
                    "SessionId": "0",
                    "Wow64": "False",
                    "CreateTime": "2024-01-01 00:00:10.000000",
                    "ExitTime": "",
                    "File output": "Disabled",
                },
            ],
            "error": None,
            "duration_s": 2.1,
        },
        "psscan": {
            "rows": [
                {
                    "PID": "4",
                    "PPID": "0",
                    "ImageFileName": "System",
                    "Offset": "0xfa8000c9a040",
                },
                {
                    "PID": "668",
                    "PPID": "4",
                    "ImageFileName": "smss.exe",
                    "Offset": "0xfa8000d29060",
                },
                {
                    "PID": "1234",
                    "PPID": "668",
                    "ImageFileName": "malware.exe",
                    "Offset": "0xfa8001a9b0c0",
                },
                {
                    "PID": "5678",
                    "PPID": "1234",
                    "ImageFileName": "cmd.exe",
                    "Offset": "0xfa8001c9d0e0",
                },
            ],
            "error": None,
            "duration_s": 3.2,
        },
        "pstree": {
            "rows": [
                {"PID": "4", "PPID": "0", "ImageFileName": "System", "Offset": "0xfa8000c9a040"},
                {"PID": "668", "PPID": "4", "ImageFileName": "smss.exe", "Offset": "0xfa8000d29060"},
                {"PID": "1234", "PPID": "668", "ImageFileName": "malware.exe", "Offset": "0xfa8001a9b0c0"},
                {"PID": "5678", "PPID": "1234", "ImageFileName": "cmd.exe", "Offset": "0xfa8001c9d0e0"},
            ],
            "error": None,
            "duration_s": 1.8,
        },
        "malfind": {
            "rows": [
                {
                    "PID": "1234",
                    "Process": "malware.exe",
                    "Start VPN": "0x00400000",
                    "End VPN": "0x00420000",
                    "Tag": "VadS",
                    "Protection": "PAGE_EXECUTE_READWRITE",
                    "CommitCharge": "32",
                    "PrivateMemory": "1",
                    "Parent": "0",
                    "File": "",
                    "Hexdump": "4d 5a 90 00",
                    "Disasm": "dec ebp",
                    "File output": "Disabled",
                },
            ],
            "error": None,
            "duration_s": 8.3,
        },
        "netscan": {
            "rows": [
                {
                    "Offset": "0xfa8001b9c0d0",
                    "Proto": "TCPv4",
                    "LocalAddr": "192.168.1.5",
                    "LocalPort": "49152",
                    "ForeignAddr": "185.220.101.45",
                    "ForeignPort": "443",
                    "State": "ESTABLISHED",
                    "PID": "1234",
                    "Owner": "malware.exe",
                    "Created": "2024-01-01 10:23:50.000000",
                },
            ],
            "error": None,
            "duration_s": 4.1,
        },
        "netstat": {
            "rows": [],
            "error": None,
            "duration_s": 0.5,
        },
        "cmdline": {
            "rows": [
                {
                    "PID": "1234",
                    "Process": "malware.exe",
                    "Args": 'malware.exe -c 185.220.101.45 -p 443 --encrypt',
                },
                {
                    "PID": "5678",
                    "Process": "cmd.exe",
                    "Args": 'cmd.exe /c whoami',
                },
            ],
            "error": None,
            "duration_s": 1.2,
        },
        "handles": {
            "rows": [],
            "error": None,
            "duration_s": 15.0,
        },
        "dlllist": {
            "rows": [],
            "error": None,
            "duration_s": 12.0,
        },
        "modscan": {
            "rows": [
                {
                    "Offset": "0xf97fffba0000",
                    "Base": "0xfffff80002a52000",
                    "Size": "0x19000",
                    "Name": "ntoskrnl.exe",
                    "File": "\\SystemRoot\\system32\\ntoskrnl.exe",
                },
            ],
            "error": None,
            "duration_s": 5.0,
        },
        "mutantscan": {
            "rows": [
                {
                    "Offset": "0xfa8001c8a0f0",
                    "Name": "Global\\{BEF7C86E-11D7-6B75-D7A0-7D6E4DA89768}",
                },
                {
                    "Offset": "0xfa8001d8b100",
                    "Name": "Global\\BF6B9C5D-E3C8-49C1-A34A-8E77DA0AB03E",
                },
            ],
            "error": None,
            "duration_s": 3.3,
        },
        "svcscan": {
            "rows": [],
            "error": None,
            "duration_s": 2.5,
        },
    }


@pytest.fixture
def clean_plugin_results():
    """Plugin results with only benign Windows processes — should produce Clean verdict."""
    return {
        "pslist": {
            "rows": [
                {"PID": "4", "PPID": "0", "ImageFileName": "System", "Offset": "0x0"},
                {"PID": "668", "PPID": "4", "ImageFileName": "smss.exe", "Offset": "0x1"},
                {"PID": "888", "PPID": "4", "ImageFileName": "lsass.exe", "Offset": "0x2"},
                {"PID": "1000", "PPID": "668", "ImageFileName": "csrss.exe", "Offset": "0x3"},
                {"PID": "1200", "PPID": "668", "ImageFileName": "winlogon.exe", "Offset": "0x4"},
                {"PID": "1400", "PPID": "668", "ImageFileName": "services.exe", "Offset": "0x5"},
                {"PID": "1600", "PPID": "1400", "ImageFileName": "svchost.exe", "Offset": "0x6"},
            ],
            "error": None,
            "duration_s": 2.0,
        },
        "psscan": {"rows": [], "error": None, "duration_s": 2.0},
        "pstree": {"rows": [], "error": None, "duration_s": 1.0},
        "malfind": {"rows": [], "error": None, "duration_s": 5.0},
        "netscan": {"rows": [], "error": None, "duration_s": 3.0},
        "netstat": {"rows": [], "error": None, "duration_s": 0.5},
        "cmdline": {"rows": [], "error": None, "duration_s": 1.0},
        "handles": {"rows": [], "error": None, "duration_s": 10.0},
        "dlllist": {"rows": [], "error": None, "duration_s": 8.0},
        "modscan": {"rows": [], "error": None, "duration_s": 4.0},
        "mutantscan": {"rows": [], "error": None, "duration_s": 2.0},
        "svcscan": {"rows": [], "error": None, "duration_s": 1.5},
    }


@pytest.fixture
def ioc_db_path():
    """Path to the project's data/iocs/ directory."""
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "data", "iocs")
