# integrations/subfinder.py
"""
Subfinder integration wrapper.
"""

import json
from typing import List, Optional

from utils.helpers import run_command, is_tool_installed
from utils.logger import setup_logger

logger = setup_logger("digiteam.integration.subfinder")


class SubfinderRunner:
    """Wrapper for the subfinder subdomain enumeration tool."""

    def __init__(self, config):
        self.config = config
        self.timeout = config.get("tools.subfinder.timeout", 300)

    @property
    def is_available(self) -> bool:
        return is_tool_installed("subfinder")

    def enumerate(self, domain: str) -> List[str]:
        """Run subfinder and return discovered subdomains."""
        if not self.is_available:
            logger.warning("subfinder is not installed")
            return []

        cmd = [
            "subfinder",
            "-d", domain,
            "-silent",
            "-all",
            "-json",
        ]

        code, stdout, stderr = run_command(cmd, timeout=self.timeout)

        subdomains = []
        if code == 0 and stdout:
            for line in stdout.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    host = data.get("host", "")
                    if host:
                        subdomains.append(host)
                except json.JSONDecodeError:
                    # Plain text output
                    subdomains.append(line.strip())

        logger.info(f"subfinder found {len(subdomains)} subdomains for {domain}")
        return subdomains