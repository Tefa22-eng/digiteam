# integrations/httpx_runner.py
"""
httpx integration wrapper.
"""

import json
from typing import List, Dict

from utils.helpers import run_command, is_tool_installed
from utils.logger import setup_logger

logger = setup_logger("digiteam.integration.httpx")


class HttpxRunner:
    """Wrapper for the httpx HTTP probing tool."""

    def __init__(self, config):
        self.config = config
        self.timeout = config.get("tools.httpx.timeout", 300)
        self.rate_limit = config.get("tools.httpx.rate_limit", 150)

    @property
    def is_available(self) -> bool:
        return is_tool_installed("httpx")

    def probe(
        self, targets: List[str], extra_args: List[str] = None
    ) -> List[Dict]:
        """Probe a list of targets for live HTTP services."""
        if not self.is_available:
            logger.warning("httpx is not installed")
            return []

        input_data = "\n".join(targets)

        cmd = [
            "httpx",
            "-silent",
            "-json",
            "-status-code",
            "-title",
            "-tech-detect",
            "-follow-redirects",
            "-rate-limit", str(self.rate_limit),
        ]

        if extra_args:
            cmd.extend(extra_args)

        code, stdout, _ = run_command(
            cmd, timeout=self.timeout, stdin_data=input_data
        )

        results = []
        if code == 0 and stdout:
            for line in stdout.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    results.append(data)
                except json.JSONDecodeError:
                    continue

        return results