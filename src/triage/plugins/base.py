"""Base Volatility 3 plugin runner used by all individual plugin wrappers."""
import os
import time
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def run_volatility_plugin(plugin_class, dump_path: str, profile: Optional[str] = None):
    """
    Run a Volatility 3 plugin against a memory dump.

    Returns (rows: list[dict], duration_s: float)

    Uses Volatility 3 as a library via its automagic framework. Each call
    creates a fresh Context so plugins do not interfere with each other when
    run concurrently via ThreadPoolExecutor.
    """
    import volatility3.framework
    from volatility3.framework import automagic, contexts, plugins as vol_plugins
    import volatility3.plugins
    import volatility3.plugins.windows  # noqa: F401 – ensure windows sub-package is importable

    volatility3.framework.require_interface_version(2, 0, 0)

    start = time.time()

    # Fresh context for every plugin invocation (thread-safe isolation)
    ctx = contexts.Context()

    # Import all bundled plugins so automagic can locate them
    volatility3.framework.import_files(volatility3.plugins, True)

    single_location = f"file://{os.path.abspath(dump_path)}"
    base_config_path = "plugins"

    ctx.config["automagic.LayerStacker.single_location"] = single_location

    if profile:
        ctx.config[f"{base_config_path}.kernel.class"] = profile

    available_automagics = automagic.available(ctx)
    chosen_automagics = automagic.choose_automagic(available_automagics, plugin_class)
    automagic.run(chosen_automagics, ctx, plugin_class, base_config_path)

    plugin_obj = vol_plugins.construct_plugin(
        ctx, [], plugin_class, base_config_path, None, None
    )
    result = plugin_obj.run()  # returns a TreeGrid

    col_names = [col.name for col in result.columns]
    rows: list[dict] = []

    def visitor(node, accumulator):
        row = {}
        for i, val in enumerate(node.values):
            if i < len(col_names):
                row[col_names[i]] = str(val) if val is not None else ""
        accumulator.append(row)
        return accumulator

    # visit(node, function, initial_accumulator) — node=None starts from root
    result.visit(None, visitor, rows)

    duration = time.time() - start
    logger.debug(
        "Plugin %s finished in %.2fs, returned %d rows",
        plugin_class.__name__,
        duration,
        len(rows),
    )
    return rows, duration
