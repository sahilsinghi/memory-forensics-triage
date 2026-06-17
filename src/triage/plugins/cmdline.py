"""Wrapper for Volatility 3 windows.cmdline.CmdLine."""
from triage.plugins.base import run_volatility_plugin


def run(dump_path: str, profile: str = None):
    from volatility3.plugins.windows import cmdline
    return run_volatility_plugin(cmdline.CmdLine, dump_path, profile)
