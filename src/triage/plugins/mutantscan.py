"""Wrapper for Volatility 3 windows.mutantscan.MutantScan."""
from triage.plugins.base import run_volatility_plugin


def run(dump_path: str, profile: str = None):
    from volatility3.plugins.windows import mutantscan
    return run_volatility_plugin(mutantscan.MutantScan, dump_path, profile)
