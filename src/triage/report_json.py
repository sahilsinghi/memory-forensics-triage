"""Generate machine-readable JSON report for SIEM ingestion."""
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


def _safe_serialize(obj):
    """Fallback serializer for non-JSON-serializable objects."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)


def generate_json_report(report_data: dict, output_path: str) -> None:
    """
    Write a machine-readable JSON report to *output_path*.

    The JSON structure preserves all report_data fields and is suitable
    for ingestion into Splunk, Elastic, or other SIEM platforms.
    """
    # Sanitise plugin_results for JSON (remove raw bytes, etc.)
    safe_data = _prepare_data(report_data)

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(safe_data, fh, indent=2, default=_safe_serialize, ensure_ascii=False)

    logger.info("JSON report written to %s", output_path)


def _prepare_data(data: dict) -> dict:
    """Recursively ensure all values are JSON-safe."""
    if isinstance(data, dict):
        return {k: _prepare_data(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_prepare_data(i) for i in data]
    if isinstance(data, (str, int, float, bool, type(None))):
        return data
    return str(data)
