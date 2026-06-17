"""Wrapper for Volatility 3 windows.dlllist.DllList."""
from triage.plugins.base import run_volatility_plugin


def run(dump_path: str, profile: str = None):
    from volatility3.plugins.windows import dlllist
    return run_volatility_plugin(dlllist.DllList, dump_path, profile)
