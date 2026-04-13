# integrations/gau_runner.py
"""
gau (GetAllURLs) integration wrapper.
"""

from typing import List

from utils.helpers import run_command, is_tool_installed
from utils.logger import setup_logger

logger = setup_logger("digiteam.integration.gau")


class GauRunner:
    """Wrapper for the gau URL fetching tool."""

    def __init__(self, config):
        self.config = config
        self.timeout = config.get("tools.gau.timeout", 300)

    @property
    def is_available(self) -> bool:
        return is_tool_installed("gau")

    def fetch(self, domain: str, include_subs: bool = True) -> List[str]:
        """Fetch URLs from multiple sources using gau."""
        if not self.is_available:
            logger.warning("gau is not installed")
            return []

        cmd = ["gau", domain]
        if include_subs:
            cmd.append("--subs")

        code, stdout, _ = run_command(cmd, timeout=self.timeout)

        urls = []
        if code == 0 and stdout:
            urls = [
                line.strip()
                for line in stdout.split("\n")
                if line.strip()
            ]

        logger.info(f"gau found {len(urls)} URLs for {domain}")
        return urls