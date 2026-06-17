"""
Orchestrates concurrent execution of all 12 Volatility 3 plugins.

Uses ThreadPoolExecutor (not asyncio) because Volatility 3 is CPU-bound
and shares file handles — threads work better here than processes.
"""
import importlib
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from typing import Optional

logger = logging.getLogger(__name__)

PLUGINS = [
    "pslist",
    "psscan",
    "pstree",
    "malfind",
    "netscan",
    "netstat",
    "cmdline",
    "handles",
    "dlllist",
    "modscan",
    "mutantscan",
    "svcscan",
]

# Per-plugin wall-clock timeout in seconds
PLUGIN_TIMEOUT_S = 60


def run_single_plugin(
    name: str, dump_path: str, profile: Optional[str] = None
) -> tuple[list, float]:
    """
    Load and run a named plugin module.

    Returns (rows, duration_s).
    Raises on any plugin error (caller catches this).
    """
    logger.info("Starting plugin: %s", name)
    module = importlib.import_module(f"triage.plugins.{name}")
    rows, duration = module.run(dump_path, profile)
    logger.info("Finished plugin: %s (%.2fs, %d rows)", name, duration, len(rows))
    return rows, duration


def run_all_plugins(
    dump_path: str, verbose: bool = False, profile: Optional[str] = None
) -> tuple[dict, float]:
    """
    Run all 12 plugins in parallel.

    Returns:
        results – {plugin_name: {"rows": [...], "error": str|None, "duration_s": float}}
        total_duration_s – float
    """
    if verbose:
        logging.basicConfig(level=logging.DEBUG)

    results: dict = {}
    overall_start = time.time()

    with ThreadPoolExecutor(max_workers=6) as executor:
        future_to_plugin = {
            executor.submit(run_single_plugin, name, dump_path, profile): name
            for name in PLUGINS
        }

        for future in as_completed(future_to_plugin):
            plugin_name = future_to_plugin[future]
            try:
                rows, duration = future.result(timeout=PLUGIN_TIMEOUT_S)
                results[plugin_name] = {
                    "rows": rows,
                    "error": None,
                    "duration_s": round(duration, 3),
                }
            except TimeoutError:
                logger.warning("Plugin %s timed out after %ds", plugin_name, PLUGIN_TIMEOUT_S)
                results[plugin_name] = {
                    "rows": [],
                    "error": f"Timed out after {PLUGIN_TIMEOUT_S}s",
                    "duration_s": PLUGIN_TIMEOUT_S,
                }
            except Exception as exc:
                logger.warning("Plugin %s failed: %s", plugin_name, exc)
                results[plugin_name] = {
                    "rows": [],
                    "error": str(exc),
                    "duration_s": 0.0,
                }

    total = round(time.time() - overall_start, 3)
    logger.info("All plugins completed in %.2fs", total)
    return results, total
