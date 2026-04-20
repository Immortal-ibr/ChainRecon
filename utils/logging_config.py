"""Centralized logging configuration for ChainRecon."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

_configured = False


def setup_logging(
    verbose: bool = False,
    log_file: Optional[str] = None,
) -> logging.Logger:
    """Configure the root ``chainrecon`` logger.

    Call once at application startup.  Subsequent calls are no-ops unless
    you call ``reset_logging()`` first.

    Parameters
    ----------
    verbose:
        When True, set level to DEBUG; otherwise INFO.
    log_file:
        Optional path to a log file.  The directory is created automatically.
    """
    global _configured
    if _configured:
        return logging.getLogger("chainrecon")

    logger = logging.getLogger("chainrecon")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False

    # ── Console handler ──────────────────────────────────────────────
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)

    try:
        from rich.logging import RichHandler  # type: ignore

        console = RichHandler(
            show_time=True,
            show_path=verbose,
            markup=True,
            rich_tracebacks=True,
        )
    except ImportError:
        fmt = logging.Formatter(
            "[%(levelname)s] %(name)s: %(message)s"
        )
        console.setFormatter(fmt)

    logger.addHandler(console)

    # ── File handler (optional) ──────────────────────────────────────
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(str(log_path), encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_fmt = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_fmt)
        logger.addHandler(file_handler)

    _configured = True
    return logger


def get_logger(name: str = "chainrecon") -> logging.Logger:
    """Return a child logger under the ``chainrecon`` namespace."""
    return logging.getLogger(f"chainrecon.{name}" if name != "chainrecon" else name)


def reset_logging() -> None:
    """Remove all handlers and allow re-configuration (for testing)."""
    global _configured
    logger = logging.getLogger("chainrecon")
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    _configured = False
