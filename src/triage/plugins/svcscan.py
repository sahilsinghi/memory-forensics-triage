"""Wrapper for Volatility 3 windows.svcscan.SvcScan."""
from triage.plugins.base import run_volatility_plugin


def run(dump_path: str, profile: str = None):
    from volatility3.plugins.windows import svcscan
    return run_volatility_plugin(svcscan.SvcScan, dump_path, profile)
