"""Wrapper for Volatility 3 windows.netstat.NetStat."""
from triage.plugins.base import run_volatility_plugin


def run(dump_path: str, profile: str = None):
    from volatility3.plugins.windows import netstat
    return run_volatility_plugin(netstat.NetStat, dump_path, profile)
