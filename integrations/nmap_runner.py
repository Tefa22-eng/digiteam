# integrations/nmap_runner.py
"""
Nmap integration wrapper.
"""

from typing import Dict, List, Optional

from utils.helpers import run_command, is_tool_installed
from utils.logger import setup_logger

logger = setup_logger("digiteam.integration.nmap")


class NmapRunner:
    """Wrapper for nmap network scanner."""

    def __init__(self, config):
        self.config = config
        self.timeout = config.get("tools.nmap.timeout", 900)
        self.arguments = config.get("tools.nmap.arguments", "-sV -sC")

    @property
    def is_available(self) -> bool:
        return is_tool_installed("nmap")

    def scan(
        self, target: str, ports: str = None, arguments: str = None
    ) -> Dict:
        """Run nmap scan on target."""
        if not self.is_available:
            logger.warning("nmap is not installed")
            return {}

        args = arguments or self.arguments
        cmd = ["nmap"] + args.split() + ["-oX", "-"]

        if ports:
            cmd.extend(["-p", ports])

        cmd.append(target)

        code, stdout, stderr = run_command(cmd, timeout=self.timeout)

        if code == 0:
            return {"raw_xml": stdout, "success": True}
        else:
            return {"error": stderr, "success": False}