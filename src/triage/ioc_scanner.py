"""
IOC Scanner — loads YAML indicator databases and scans Volatility plugin output.

Supported indicator types:
  process_name  – matched against pslist/psscan ImageFileName (case-insensitive)
  mutex         – matched against mutantscan Name (case-insensitive substring)
  network_ip    – exact match against netscan/netstat ForeignAddr
  file_path     – substring match against dlllist/handles path columns (case-insensitive)
  registry_key  – substring match against svcscan/handles Name columns (case-insensitive)
"""
import logging
import os
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_ioc_database(ioc_db_path: str) -> list[dict]:
    """
    Load all YAML files from *ioc_db_path* and return a flat list of indicator
    dicts, each with an extra ``actor`` key injected from the file-level field.
    """
    db_path = Path(ioc_db_path)
    indicators: list[dict] = []

    if not db_path.exists():
        logger.warning("IOC database path does not exist: %s", ioc_db_path)
        return indicators

    yaml_files = list(db_path.glob("*.yml")) + list(db_path.glob("*.yaml"))
    logger.debug("Loading IOC database from %d files in %s", len(yaml_files), ioc_db_path)

    for yf in sorted(yaml_files):
        try:
            with yf.open() as fh:
                doc = yaml.safe_load(fh)
            if not doc or "indicators" not in doc:
                continue
            actor = doc.get("actor", yf.stem)
            for ioc in doc["indicators"]:
                ioc = dict(ioc)
                ioc.setdefault("actor", actor)
                indicators.append(ioc)
        except Exception as exc:
            logger.warning("Failed to load IOC file %s: %s", yf, exc)

    logger.info("Loaded %d IOC indicators from %d files", len(indicators), len(yaml_files))
    return indicators


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ci(s: Any) -> str:
    """Case-insensitive string coercion."""
    return str(s).lower() if s is not None else ""


def _rows(plugin_results: dict, plugin_name: str) -> list[dict]:
    return plugin_results.get(plugin_name, {}).get("rows", [])


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------

def scan(plugin_results: dict, ioc_db_path: str) -> list[dict]:
    """
    Scan all plugin output against the IOC database.

    Returns list of match dicts:
    {
        "ioc": dict,            # full IOC record (type/value/severity/actor/…)
        "plugin": str,          # which plugin produced the hit
        "process_pid": str,
        "process_name": str,
        "context": str,         # the raw matched value from plugin output
    }
    """
    indicators = load_ioc_database(ioc_db_path)
    if not indicators:
        return []

    matches: list[dict] = []

    # Group indicators by type for efficient scanning
    by_type: dict[str, list[dict]] = {}
    for ioc in indicators:
        t = ioc.get("type", "")
        by_type.setdefault(t, []).append(ioc)

    # --- process_name ---
    for proc_ioc in by_type.get("process_name", []):
        needle = _ci(proc_ioc["value"])
        for plugin in ("pslist", "psscan"):
            for row in _rows(plugin_results, plugin):
                name_field = (
                    row.get("ImageFileName") or row.get("Name") or row.get("Process") or ""
                )
                if _ci(name_field) == needle or needle in _ci(name_field):
                    matches.append(
                        _make_match(proc_ioc, plugin, row.get("PID", ""), name_field, name_field)
                    )

    # --- mutex ---
    for mutex_ioc in by_type.get("mutex", []):
        needle = _ci(mutex_ioc["value"])
        for row in _rows(plugin_results, "mutantscan"):
            name_val = row.get("Name") or row.get("Mutant") or ""
            if needle in _ci(name_val):
                matches.append(
                    _make_match(mutex_ioc, "mutantscan", row.get("PID", ""), "", name_val)
                )

    # --- network_ip ---
    for ip_ioc in by_type.get("network_ip", []):
        needle = ip_ioc["value"].strip()
        for plugin in ("netscan", "netstat"):
            for row in _rows(plugin_results, plugin):
                foreign = row.get("ForeignAddr") or row.get("ForeignAddress") or ""
                # Strip port if present (e.g. "185.1.2.3:443")
                foreign_ip = foreign.split(":")[0].strip()
                if foreign_ip == needle:
                    pid = row.get("PID") or row.get("Pid") or ""
                    proc = row.get("Owner") or row.get("Process") or row.get("Name") or ""
                    matches.append(
                        _make_match(ip_ioc, plugin, pid, proc, foreign)
                    )

    # --- file_path ---
    for fp_ioc in by_type.get("file_path", []):
        needle = _ci(fp_ioc["value"])
        for plugin in ("dlllist", "handles"):
            path_keys = (
                "Path", "FullDllName", "DllPath", "File", "Name", "FullPath", "BaseDllName"
            )
            for row in _rows(plugin_results, plugin):
                for pk in path_keys:
                    val = row.get(pk, "")
                    if val and needle in _ci(val):
                        pid = row.get("PID") or row.get("Pid") or ""
                        proc = row.get("Process") or row.get("Name") or ""
                        matches.append(_make_match(fp_ioc, plugin, pid, proc, val))
                        break  # avoid duplicate matches for same row

    # --- registry_key ---
    for reg_ioc in by_type.get("registry_key", []):
        needle = _ci(reg_ioc["value"])
        for plugin in ("svcscan", "handles"):
            key_keys = ("Name", "ServiceKey", "Key", "Path", "FullPath")
            for row in _rows(plugin_results, plugin):
                for kk in key_keys:
                    val = row.get(kk, "")
                    if val and needle in _ci(val):
                        pid = row.get("PID") or row.get("Pid") or ""
                        proc = row.get("Process") or row.get("ServiceName") or ""
                        matches.append(_make_match(reg_ioc, plugin, pid, proc, val))
                        break

    logger.info("IOC scan complete: %d matches found", len(matches))
    return matches


def _make_match(ioc: dict, plugin: str, pid: str, proc: str, context: str) -> dict:
    return {
        "ioc": ioc,
        "plugin": plugin,
        "process_pid": str(pid),
        "process_name": str(proc),
        "context": str(context),
    }
