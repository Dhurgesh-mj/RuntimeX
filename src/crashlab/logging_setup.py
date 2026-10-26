"""Logging setup: console plus per-run file logs."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

_CONSOLE_FORMAT = "%(asctime)s %(levelname)-7s %(message)s"
_DATE_FORMAT = "%H:%M:%S"
_CONFIGURED = False


def configure_logging(level: str | int = "INFO") -> None:
    """Configure the root ``crashlab`` logger exactly once."""

    global _CONFIGURED
    logger = logging.getLogger("crashlab")
    if _CONFIGURED:
        logger.setLevel(level)
        return

    logger.setLevel(level)
    logger.propagate = False
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(logging.Formatter(_CONSOLE_FORMAT, _DATE_FORMAT))
    logger.addHandler(handler)
    _CONFIGURED = True


def add_run_log(logger: logging.Logger, path: str | Path) -> logging.Handler:
    """Attach a UTF-8 file handler to a run logger and return it."""

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(target, mode="w", encoding="utf-8", delay=False)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)-7s [%(threadName)s] %(name)s: %(message)s"
        )
    )
    logger.addHandler(handler)
    return handler


def remove_handler(logger: logging.Logger, handler: logging.Handler | None) -> None:
    """Detach and close a run file handler."""

    if handler is None:
        return
    logger.removeHandler(handler)
    handler.close()
