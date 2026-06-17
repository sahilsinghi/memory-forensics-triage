"""Wrapper for Volatility 3 windows.pslist.PsList."""
from triage.plugins.base import run_volatility_plugin


def run(dump_path: str, profile: str = None):
    from volatility3.plugins.windows import pslist
    return run_volatility_plugin(pslist.PsList, dump_path, profile)
