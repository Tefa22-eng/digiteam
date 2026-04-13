# modules/passive/subdomain_enum.py
"""
Subdomain Enumeration Module
Uses multiple sources to discover subdomains.
"""

import json
import re
from typing import Dict, Any, List, Set

from core.base_module import BaseModule
from utils.helpers import run_command, is_tool_installed

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class SubdomainEnumModule(BaseModule):
    """Discover subdomains using multiple sources and tools."""

    def __init__(self, target: str, config):
        super().__init__(target, config, module_name="Subdomain Enumeration")

    @property
    def description(self) -> str:
        return "Multi-source subdomain discovery"

    @property
    def category(self) -> str:
        return "passive"

    def _run(self) -> Dict[str, Any]:
        self.logger.info(f"Enumerating subdomains for {self.target}")

        all_subdomains: Set[str] = set()
        sources_used = []

        # Source 1: subfinder
        subs = self._from_subfinder()
        if subs:
            all_subdomains.update(subs)
            sources_used.append("subfinder")

        # Source 2: crt.sh (Certificate Transparency)
        subs = self._from_crtsh()
        if subs:
            all_subdomains.update(subs)
            sources_used.append("crt.sh")

        # Source 3: HackerTarget
        subs = self._from_hackertarget()
        if subs:
            all_subdomains.update(subs)
            sources_used.append("hackertarget")

        # Source 4: ThreatCrowd
        subs = self._from_threatcrowd()
        if subs:
            all_subdomains.update(subs)
            sources_used.append("threatcrowd")

        # Source 5: BufferOver
        subs = self._from_bufferover()
        if subs:
            all_subdomains.update(subs)
            sources_used.append("bufferover")

        # Clean and validate
        cleaned = self._clean_subdomains(all_subdomains)

        self.logger.info(
            f"Found {len(cleaned)} unique subdomains from {len(sources_used)} sources"
        )

        return {
            "subdomains": sorted(cleaned),
            "total_count": len(cleaned),
            "sources": sources_used,
        }

    def _from_subfinder(self) -> List[str]:
        """Use subfinder tool for subdomain discovery."""
        if not is_tool_installed("subfinder"):
            self.logger.debug("subfinder not installed, skipping")
            return []

        timeout = self.config.get("tools.subfinder.timeout", 300)
        cmd = ["subfinder", "-d", self.target, "-silent", "-all"]

        code, stdout, stderr = run_command(cmd, timeout=timeout)
        if code == 0 and stdout:
            return [
                line.strip()
                for line in stdout.strip().split("\n")
                if line.strip()
            ]
        return []

    def _from_crtsh(self) -> List[str]:
        """Query crt.sh for certificate transparency logs."""
        if not REQUESTS_AVAILABLE:
            return []
        try:
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            resp = requests.get(url, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                subs = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    for n in name.split("\n"):
                        n = n.strip().lower()
                        if n and "*" not in n:
                            subs.add(n)
                return list(subs)
        except Exception as e:
            self.logger.debug(f"crt.sh query failed: {e}")
        return []

    def _from_hackertarget(self) -> List[str]:
        """Query HackerTarget API."""
        if not REQUESTS_AVAILABLE:
            return []
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.target}"
            resp = requests.get(url, timeout=20)
            if resp.status_code == 200 and "error" not in resp.text.lower():
                subs = []
                for line in resp.text.strip().split("\n"):
                    if "," in line:
                        subs.append(line.split(",")[0].strip())
                return subs
        except Exception as e:
            self.logger.debug(f"HackerTarget query failed: {e}")
        return []

    def _from_threatcrowd(self) -> List[str]:
        """Query ThreatCrowd API."""
        if not REQUESTS_AVAILABLE:
            return []
        try:
            url = (
                f"https://www.threatcrowd.org/searchApi/v2/domain/report/"
                f"?domain={self.target}"
            )
            resp = requests.get(url, timeout=20)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("subdomains", [])
        except Exception as e:
            self.logger.debug(f"ThreatCrowd query failed: {e}")
        return []

    def _from_bufferover(self) -> List[str]:
        """Query BufferOver DNS API."""
        if not REQUESTS_AVAILABLE:
            return []
        try:
            url = f"https://dns.bufferover.run/dns?q=.{self.target}"
            resp = requests.get(url, timeout=20)
            if resp.status_code == 200:
                data = resp.json()
                subs = set()
                for record in data.get("FDNS_A", []) or []:
                    if "," in record:
                        subs.add(record.split(",")[1].strip())
                for record in data.get("RDNS", []) or []:
                    if "," in record:
                        subs.add(record.split(",")[1].strip())
                return list(subs)
        except Exception as e:
            self.logger.debug(f"BufferOver query failed: {e}")
        return []

    def _clean_subdomains(self, subdomains: Set[str]) -> List[str]:
        """Clean, validate, and deduplicate subdomains."""
        cleaned = set()
        for sub in subdomains:
            sub = sub.strip().lower().rstrip(".")
            # Must end with the target domain
            if sub and sub.endswith(self.target):
                # Basic validation
                if re.match(r'^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$', sub):
                    cleaned.add(sub)
        return sorted(cleaned)