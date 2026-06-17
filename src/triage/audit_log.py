"""Structured JSONL audit logging for triage runs."""
import json
import logging
from datetime import datetime, timezone
from pathlib import Path


def get_audit_logger(log_path: str) -> logging.Logger:
    """
    Return a Logger that writes one JSON object per line to *log_path*.
    The file is created (or appended) automatically.
    """
    Path(log_path).parent.mkdir(parents=True, exist_ok=True)

    logger_name = f"triage.audit.{Path(log_path).stem}"
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)
    logger.propagate = False  # Don't bubble up to root logger

    if not logger.handlers:
        handler = logging.FileHandler(log_path, mode="a", encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)

    return logger


def log_event(logger: logging.Logger, event_type: str, **kwargs) -> None:
    """Write a structured JSONL audit event."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event_type,
        **kwargs,
    }
    logger.info(json.dumps(entry))
