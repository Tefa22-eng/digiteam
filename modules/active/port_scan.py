# modules/active/port_scan.py
"""
Port Scanning Module
Performs port scanning using naabu or nmap.
"""

import json
import re
from typing import Dict, Any, List

from core.base_module import BaseModule
from utils.helpers import run_command, is_tool_installed


class PortScanModule(BaseModule):
    """Scan for open ports on the target."""

    def __init__(self, target: str, config):
        super().__init__(target, config, module_name="Port Scanner")

    @property
    def description(self) -> str:
        return "Open port discovery and service detection"

    @property
    def category(self) -> str:
        return "active"

    def _run(self) -> Dict[str, Any]:
        self.logger.info(f"Scanning ports for {self.target}")

        open_ports = []

        if is_tool_installed("naabu"):
            open_ports = self._scan_naabu()
        elif is_tool_installed("nmap"):
            open_ports = self._scan_nmap()
        else:
            self.logger.warning("Neither naabu nor nmap found, using socket scan")
            open_ports = self._scan_socket()

        return {
            "open_ports": open_ports,
            "ports": open_ports,
            "total_ports": len(open_ports),
        }

    def _scan_naabu(self) -> List[dict]:
        """Use naabu for fast port discovery."""
        timeout = self.config.get("tools.naabu.timeout", 600)
        top_ports = self.config.get("tools.naabu.top_ports", 1000)

        cmd = [
            "naabu",
            "-host", self.target,
            "-top-ports", str(top_ports),
            "-json",
            "-silent",
        ]

        code, stdout, _ = run_command(cmd, timeout=timeout)

        results = []
        if code == 0 and stdout:
            for line in stdout.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    results.append({
                        "host": data.get("host", self.target),
                        "port": data.get("port", 0),
                        "service": "",
                        "version": "",
                    })
                except json.JSONDecodeError:
                    # Parse non-JSON output: host:port
                    if ":" in line:
                        parts = line.strip().split(":")
                        if len(parts) >= 2:
                            try:
                                results.append({
                                    "host": parts[0],
                                    "port": int(parts[1]),
                                    "service": "",
                                    "version": "",
                                })
                            except ValueError:
                                pass
        return results

    def _scan_nmap(self) -> List[dict]:
        """Use nmap for port scanning with service detection."""
        timeout = self.config.get("tools.nmap.timeout", 900)
        nmap_args = self.config.get("tools.nmap.arguments", "-sV -sC")

        cmd = ["nmap"] + nmap_args.split() + [
            "--top-ports", "1000",
            "-oG", "-",
            self.target,
        ]

        code, stdout, _ = run_command(cmd, timeout=timeout)

        results = []
        if code == 0 and stdout:
            for line in stdout.split("\n"):
                if "/open/" in line:
                    # Parse grepable nmap output
                    matches = re.findall(
                        r"(\d+)/open/tcp//([^/]*)/[^/]*/([^/]*)/",
                        line,
                    )
                    for port, service, version in matches:
                        results.append({
                            "host": self.target,
                            "port": int(port),
                            "service": service.strip(),
                            "version": version.strip(),
                        })

        return results

    def _scan_socket(self) -> List[dict]:
        """Fallback: scan common ports using Python sockets."""
        import socket

        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
            445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443,
            8888, 9090,
        ]

        results = []
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.target, port))
                if result == 0:
                    results.append({
                        "host": self.target,
                        "port": port,
                        "service": self._guess_service(port),
                        "version": "",
                    })
                sock.close()
            except Exception:
                continue

        return results

    @staticmethod
    def _guess_service(port: int) -> str:
        """Guess service name from common port numbers."""
        services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 143: "imap",
            443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
            3306: "mysql", 3389: "rdp", 5432: "postgresql",
            5900: "vnc", 8080: "http-proxy", 8443: "https-alt",
        }
        return services.get(port, "unknown")