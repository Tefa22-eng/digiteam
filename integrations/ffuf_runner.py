# integrations/ffuf_runner.py
"""
ffuf fuzzer integration wrapper.
"""

import json
from typing import List, Dict

from utils.helpers import run_command, is_tool_installed
from utils.logger import setup_logger

logger = setup_logger("digiteam.integration.ffuf")


class FfufRunner:
    """Wrapper for the ffuf web fuzzer."""

    def __init__(self, config):
        self.config = config
        self.timeout = config.get("tools.ffuf.timeout", 600)
        self.wordlist = config.get(
            "tools.ffuf.wordlist",
            "/usr/share/wordlists/dirb/common.txt",
        )
        self.rate_limit = config.get("tools.ffuf.rate_limit", 100)

    @property
    def is_available(self) -> bool:
        return is_tool_installed("ffuf")

    def fuzz(
        self, url: str, wordlist: str = None, extra_args: List[str] = None
    ) -> List[Dict]:
        """Run ffuf against a URL."""
        if not self.is_available:
            logger.warning("ffuf is not installed")
            return []

        wl = wordlist or self.wordlist

        cmd = [
            "ffuf",
            "-u", url,
            "-w", wl,
            "-mc", "200,204,301,302,307,401,403",
            "-rate", str(self.rate_limit),
            "-json",
            "-s",
        ]

        if extra_args:
            cmd.extend(extra_args)

        code, stdout, _ = run_command(cmd, timeout=self.timeout)

        results = []
        if code == 0 and stdout:
            try:
                data = json.loads(stdout)
                results = data.get("results", [])
            except json.JSONDecodeError:
                for line in stdout.strip().split("\n"):
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        return results