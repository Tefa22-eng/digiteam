# integrations/waybackurls.py
"""
waybackurls integration wrapper.
"""

from typing import List

from utils.helpers import run_command, is_tool_installed
from utils.logger import setup_logger

logger = setup_logger("digiteam.integration.waybackurls")


class WaybackurlsRunner:
    """Wrapper for the waybackurls URL discovery tool."""

    def __init__(self, config):
        self.config = config
        self.timeout = config.get("tools.waybackurls.timeout", 300)

    @property
    def is_available(self) -> bool:
        return is_tool_installed("waybackurls")

    def fetch(self, domain: str) -> List[str]:
        """Fetch historical URLs for a domain."""
        if not self.is_available:
            logger.warning("waybackurls is not installed")
            return []

        cmd = ["waybackurls", domain]
        code, stdout, _ = run_command(cmd, timeout=self.timeout)

        urls = []
        if code == 0 and stdout:
            urls = [
                line.strip()
                for line in stdout.split("\n")
                if line.strip()
            ]

        logger.info(f"waybackurls found {len(urls)} URLs for {domain}")
        return urls