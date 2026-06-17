"""Wrapper for Volatility 3 windows.handles.Handles."""
from triage.plugins.base import run_volatility_plugin


def run(dump_path: str, profile: str = None):
    from volatility3.plugins.windows import handles
    return run_volatility_plugin(handles.Handles, dump_path, profile)
