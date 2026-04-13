# utils/helpers.py
"""
Helper utilities for DIGI TEAM.
Common functions used across the project.
"""

import subprocess
import shutil
import socket
import re
from typing import Optional, List, Tuple
from pathlib import Path

from utils.logger import setup_logger

logger = setup_logger("digiteam.helpers")


def is_tool_installed(tool_name: str) -> bool:
    """Check if an external tool is available in PATH."""
    return shutil.which(tool_name) is not None


def run_command(
    cmd: List[str],
    timeout: int = 300,
    stdin_data: Optional[str] = None,
) -> Tuple[int, str, str]:
    """
    Run a shell command and return (returncode, stdout, stderr).
    """
    try:
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.PIPE if stdin_data else None,
            input=stdin_data,
        )
        return process.returncode, process.stdout, process.stderr
    except subprocess.TimeoutExpired:
        logger.warning(f"Command timed out after {timeout}s: {' '.join(cmd)}")
        return -1, "", f"Timeout after {timeout}s"
    except FileNotFoundError:
        logger.error(f"Tool not found: {cmd[0]}")
        return -1, "", f"Tool not found: {cmd[0]}"
    except Exception as e:
        logger.error(f"Command execution failed: {e}")
        return -1, "", str(e)


def resolve_domain(domain: str) -> Optional[str]:
    """Resolve a domain to its IP address."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def is_valid_domain(domain: str) -> bool:
    """Validate domain format."""
    pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$"
    )
    return bool(pattern.match(domain))


def deduplicate(items: list) -> list:
    """Deduplicate a list while preserving order."""
    seen = set()
    result = []
    for item in items:
        key = str(item)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def safe_filename(name: str) -> str:
    """Create a safe filename from a string."""
    return re.sub(r'[^\w\-.]', '_', name)


def chunk_list(lst: list, chunk_size: int) -> list:
    """Split a list into chunks of specified size."""
    return [lst[i : i + chunk_size] for i in range(0, len(lst), chunk_size)]