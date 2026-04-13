# modules/passive/wayback_urls.py
"""
Wayback URLs Module
Discovers historical URLs from the Wayback Machine and GAU.
"""

from typing import Dict, Any, Set

from core.base_module import BaseModule
from utils.helpers import run_command, is_tool_installed

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class WaybackModule(BaseModule):
    """Collect historical URLs from Wayback Machine and other archives."""

    def __init__(self, target: str, config):
        super().__init__(target, config, module_name="Wayback URLs")

    @property
    def description(self) -> str:
        return "Historical URL discovery from web archives"

    @property
    def category(self) -> str:
        return "passive"

    def _run(self) -> Dict[str, Any]:
        self.logger.info(f"Collecting wayback URLs for {self.target}")

        all_urls: Set[str] = set()
        sources_used = []

        # waybackurls tool
        urls = self._from_waybackurls()
        if urls:
            all_urls.update(urls)
            sources_used.append("waybackurls")

        # gau tool
        urls = self._from_gau()
        if urls:
            all_urls.update(urls)
            sources_used.append("gau")

        # Wayback Machine CDX API
        urls = self._from_cdx_api()
        if urls:
            all_urls.update(urls)
            sources_used.append("cdx_api")

        # Categorize URLs
        categorized = self._categorize_urls(all_urls)

        return {
            "urls": sorted(all_urls)[:2000],  # Limit to 2000
            "total_count": len(all_urls),
            "sources": sources_used,
            "categories": categorized,
            "endpoints": sorted(all_urls)[:500],
        }

    def _from_waybackurls(self) -> Set[str]:
        if not is_tool_installed("waybackurls"):
            self.logger.debug("waybackurls not installed")
            return set()

        timeout = self.config.get("tools.waybackurls.timeout", 300)
        cmd = ["waybackurls", self.target]
        code, stdout, _ = run_command(cmd, timeout=timeout)

        if code == 0 and stdout:
            return {
                line.strip() for line in stdout.split("\n") if line.strip()
            }
        return set()

    def _from_gau(self) -> Set[str]:
        if not is_tool_installed("gau"):
            self.logger.debug("gau not installed")
            return set()

        timeout = self.config.get("tools.gau.timeout", 300)
        cmd = ["gau", "--subs", self.target]
        code, stdout, _ = run_command(cmd, timeout=timeout)

        if code == 0 and stdout:
            return {
                line.strip() for line in stdout.split("\n") if line.strip()
            }
        return set()

    def _from_cdx_api(self) -> Set[str]:
        if not REQUESTS_AVAILABLE:
            return set()

        urls = set()
        try:
            api_url = (
                f"https://web.archive.org/cdx/search/cdx"
                f"?url=*.{self.target}/*&output=json&fl=original"
                f"&collapse=urlkey&limit=5000"
            )
            resp = requests.get(api_url, timeout=60)
            if resp.status_code == 200:
                data = resp.json()
                for row in data[1:]:  # Skip header
                    if row:
                        urls.add(row[0])
        except Exception as e:
            self.logger.debug(f"CDX API query failed: {e}")

        return urls

    def _categorize_urls(self, urls: Set[str]) -> dict:
        """Categorize URLs by type for analysis."""
        categories = {
            "js_files": [],
            "api_endpoints": [],
            "parameters": [],
            "sensitive_files": [],
            "forms": [],
        }

        sensitive_extensions = [
            ".env", ".git", ".svn", ".bak", ".sql", ".log",
            ".conf", ".config", ".xml", ".json", ".yml", ".yaml",
            ".php~", ".swp", ".old", ".backup",
        ]

        for url in urls:
            url_lower = url.lower()
            if url_lower.endswith(".js"):
                categories["js_files"].append(url)
            elif "/api/" in url_lower or "/v1/" in url_lower or "/v2/" in url_lower:
                categories["api_endpoints"].append(url)
            elif "?" in url and "=" in url:
                categories["parameters"].append(url)
            elif any(url_lower.endswith(ext) for ext in sensitive_extensions):
                categories["sensitive_files"].append(url)

        # Limit each category
        for key in categories:
            categories[key] = categories[key][:200]

        return categories