# integrations/naabu.py
"""
Naabu port scanner integration wrapper.
"""

import json
from typing import List, Dict

from utils.helpers import run_command, is_tool_installed
from utils.logger import setup_logger

logger = setup_logger("digiteam.integration.naabu")


class NaabuRunner:
    """Wrapper for the naabu port scanning tool."""

    def __init__(self, config):
        self.config = config
        self.timeout = config.get("tools.naabu.timeout", 600)
        self.top_ports = config.get("tools.naabu.top_ports", 1000)

    @property
    def is_available(self) -> bool:
        return is_tool_installed("naabu")

    def scan(self, target: str, ports: str = None) -> List[Dict]:
        """Scan a target for open ports."""
        if not self.is_available:
            logger.warning("naabu is not installed")
            return []

        cmd = [
            "naabu",
            "-host", target,
            "-json",
            "-silent",
        ]

        if ports:
            cmd.extend(["-p", ports])
        else:
            cmd.extend(["-top-ports", str(self.top_ports)])

        code, stdout, _ = run_command(cmd, timeout=self.timeout)

        results = []
        if code == 0 and stdout:
            for line in stdout.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    results.append(data)
                except json.JSONDecodeError:
                    if ":" in line:
                        parts = line.strip().split(":")
                        try:
                            results.append({
                                "host": parts[0],
                                "port": int(parts[1]),
                            })
                        except (ValueError, IndexError):
                            pass

        return results