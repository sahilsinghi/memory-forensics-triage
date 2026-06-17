"""Wrapper for Volatility 3 windows.pstree.PsTree."""
from triage.plugins.base import run_volatility_plugin


def run(dump_path: str, profile: str = None):
    from volatility3.plugins.windows import pstree
    return run_volatility_plugin(pstree.PsTree, dump_path, profile)
