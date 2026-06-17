"""Validates a memory dump is parseable by Volatility 3."""
import os
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def validate_dump(dump_path: str) -> dict:
    """
    Validate a memory dump file and attempt OS profile detection.

    Returns dict with keys:
        valid      – bool
        os_profile – str | None   (e.g. "Windows10x64_19041")
        error      – str | None
    """
    result = {"valid": False, "os_profile": None, "error": None}

    # Basic file checks
    path = Path(dump_path)
    if not path.exists():
        result["error"] = f"File not found: {dump_path}"
        return result
    if not path.is_file():
        result["error"] = f"Path is not a file: {dump_path}"
        return result
    if path.stat().st_size == 0:
        result["error"] = f"File is empty (0 bytes): {dump_path}"
        return result

    logger.debug("File exists and is non-empty (%d bytes): %s", path.stat().st_size, dump_path)

    # Attempt Volatility 3 automagic layer detection
    try:
        import volatility3.framework
        from volatility3.framework import automagic, contexts, plugins as vol_plugins
        import volatility3.plugins
        import volatility3.plugins.windows  # noqa: F401
        from volatility3.plugins.windows import pslist

        volatility3.framework.require_interface_version(2, 0, 0)

        ctx = contexts.Context()
        volatility3.framework.import_files(volatility3.plugins, True)

        single_location = f"file://{os.path.abspath(dump_path)}"
        base_config_path = "plugins"
        ctx.config["automagic.LayerStacker.single_location"] = single_location

        available_automagics = automagic.available(ctx)
        chosen_automagics = automagic.choose_automagic(available_automagics, pslist.PsList)

        # Run automagic – this resolves layers and fills ctx.config
        automagic.run(chosen_automagics, ctx, pslist.PsList, base_config_path)

        # Try to detect OS profile from the stacker layer name
        os_profile = _extract_os_profile(ctx)
        result["valid"] = True
        result["os_profile"] = os_profile
        logger.info("Dump validated. Detected OS profile: %s", os_profile)

    except Exception as exc:
        logger.warning("Volatility 3 could not parse dump: %s", exc)
        result["error"] = str(exc)

    return result


def _extract_os_profile(ctx) -> Optional[str]:
    """
    Extract OS profile hint from context config after automagic runs.
    Returns a string like 'Windows10x64_19041' or None.
    """
    try:
        # Walk the config tree looking for kernel/layer keys that contain OS info
        for key, val in ctx.config.data.items():
            key_str = str(key)
            val_str = str(val) if val else ""
            if "kernel" in key_str.lower() and "class" in key_str.lower():
                return val_str
        # Fallback: look for layer names
        if hasattr(ctx, "layers") and ctx.layers:
            for layer_name in ctx.layers:
                if "windows" in layer_name.lower() or "Win" in layer_name:
                    return layer_name
        return "Windows (autodetected)"
    except Exception:
        return None
