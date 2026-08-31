"""RedOps Automático — Automated Pentesting Framework orchestrated by LLM.

This package provides an end-to-end penetration testing pipeline that uses
a local LLM (Ollama/Mistral) to orchestrate reconnaissance, scanning,
exploitation, post-exploitation and reporting against intentionally
vulnerable lab targets.

WARNING: This framework is designed EXCLUSIVELY for use in authorized,
isolated laboratory environments (VirtualBox: Kali Linux + Metasploitable2
/ DVWA). Using it against systems without explicit authorization is illegal.
"""

from __future__ import annotations

import logging
import os
import sys

import structlog


def _configure_logging() -> None:
    """Configure structlog with JSON or console rendering based on environment."""
    log_level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, log_level_name, logging.INFO)

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stderr,
        level=log_level,
    )

    is_production = os.getenv("ENV", "development").lower() == "production"

    renderer: structlog.types.Processor = (
        structlog.processors.JSONRenderer()
        if is_production
        else structlog.dev.ConsoleRenderer(colors=True)
    )

    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.ExceptionRenderer(),
            structlog.processors.UnicodeDecoder(),
            renderer,
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


_configure_logging()

__version__ = "1.0.0"


def set_log_level(level: str) -> None:
    """Update the effective log level at runtime.

    Use this after CLI flag parsing so ``--verbose`` takes effect even though
    ``_configure_logging()`` was already called at import time.

    Args:
        level: One of ``DEBUG``, ``INFO``, ``WARNING``, ``ERROR``.
    """
    numeric = getattr(logging, level.upper(), logging.INFO)
    logging.getLogger().setLevel(numeric)
