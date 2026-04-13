# utils/logger.py
"""
Logging configuration for DIGI TEAM.
Provides file-based logging that doesn't interfere with CLI output.
"""

import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler


def setup_logger(
    name: str,
    log_file: str = "digiteam.log",
    level: int = logging.DEBUG,
) -> logging.Logger:
    """
    Configure and return a logger instance.
    Logs to file only to keep CLI clean.
    """
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    logger.setLevel(level)
    logger.propagate = False

    file_handler = RotatingFileHandler(
        log_dir / log_file,
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        "%(asctime)s | %(name)-40s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    return logger