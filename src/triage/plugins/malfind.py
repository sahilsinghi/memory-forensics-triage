"""Wrapper for Volatility 3 windows.malfind.Malfind."""
from triage.plugins.base import run_volatility_plugin


def run(dump_path: str, profile: str = None):
    from volatility3.plugins.windows import malfind
    return run_volatility_plugin(malfind.Malfind, dump_path, profile)
