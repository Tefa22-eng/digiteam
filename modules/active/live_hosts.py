# modules/active/live_hosts.py
"""
Live Host Detection Module
Checks which discovered subdomains are alive using httpx.
"""

import json
from typing import Dict, Any, List

from core.base_module import BaseModule
from utils.helpers import run_command, is_tool_installed

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class LiveHostsModule(BaseModule):
    """Detect live hosts from discovered subdomains."""

    def __init__(self, target: str, config):
        super().__init__(target, config, module_name="Live Host Detection")

    @property
    def description(self) -> str:
        return "Detect alive hosts using HTTP probing"

    @property
    def category(self) -> str:
        return "active"

    def _run(self) -> Dict[str, Any]:
        self.logger.info(f"Probing live hosts for {self.target}")

        live_hosts = []

        if is_tool_installed("httpx"):
            live_hosts = self._probe_with_httpx()
        else:
            self.logger.info("httpx not found, using Python fallback")
            live_hosts = self._probe_with_requests()

        return {
            "live_hosts": live_hosts,
            "total_alive": len(live_hosts),
        }

    def _probe_with_httpx(self) -> List[dict]:
        """Use httpx tool for HTTP probing."""
        timeout = self.config.get("tools.httpx.timeout", 300)
        rate = self.config.get("tools.httpx.rate_limit", 150)

        # Probe the main domain and common subdomains
        targets = [
            self.target,
            f"www.{self.target}",
            f"mail.{self.target}",
            f"api.{self.target}",
            f"dev.{self.target}",
            f"staging.{self.target}",
            f"admin.{self.target}",
        ]

        input_data = "\n".join(targets)

        cmd = [
            "httpx",
            "-silent",
            "-json",
            "-status-code",
            "-title",
            "-tech-detect",
            "-follow-redirects",
            "-rate-limit", str(rate),
        ]

        code, stdout, _ = run_command(
            cmd, timeout=timeout, stdin_data=input_data
        )

        results = []
        if code == 0 and stdout:
            for line in stdout.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    results.append({
                        "url": data.get("url", ""),
                        "status_code": data.get("status_code", 0),
                        "title": data.get("title", ""),
                        "technologies": data.get("tech", []),
                        "content_length": data.get("content_length", 0),
                        "host": data.get("host", ""),
                    })
                except json.JSONDecodeError:
                    continue

        return results

    def _probe_with_requests(self) -> List[dict]:
        """Fallback: probe hosts using Python requests."""
        if not REQUESTS_AVAILABLE:
            return []

        targets = [
            f"https://{self.target}",
            f"http://{self.target}",
            f"https://www.{self.target}",
        ]

        results = []
        for url in targets:
            try:
                resp = requests.get(
                    url,
                    timeout=10,
                    allow_redirects=True,
                    verify=False,
                    headers={"User-Agent": self.config.get(
                        "general.user_agent", "DIGI-TEAM/2.0"
                    )},
                )
                title = ""
                if "<title>" in resp.text.lower():
                    import re
                    match = re.search(
                        r"<title[^>]*>(.*?)</title>",
                        resp.text,
                        re.IGNORECASE | re.DOTALL,
                    )
                    if match:
                        title = match.group(1).strip()[:100]

                results.append({
                    "url": url,
                    "status_code": resp.status_code,
                    "title": title,
                    "content_length": len(resp.content),
                    "technologies": [],
                })
            except Exception:
                continue

        return results