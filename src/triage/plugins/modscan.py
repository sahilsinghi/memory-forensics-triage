"""Wrapper for Volatility 3 windows.modscan.ModScan."""
from triage.plugins.base import run_volatility_plugin


def run(dump_path: str, profile: str = None):
    from volatility3.plugins.windows import modscan
    return run_volatility_plugin(modscan.ModScan, dump_path, profile)
