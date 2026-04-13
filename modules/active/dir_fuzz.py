# modules/active/dir_fuzz.py
"""
Directory Fuzzing Module
Discovers hidden directories and files using ffuf.
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


class DirFuzzModule(BaseModule):
    """Discover directories and files via fuzzing."""

    def __init__(self, target: str, config):
        super().__init__(target, config, module_name="Directory Fuzzing")

    @property
    def description(self) -> str:
        return "Hidden directory and file discovery"

    @property
    def category(self) -> str:
        return "active"

    def pre_check(self) -> bool:
        if not is_tool_installed("ffuf"):
            self.result.warnings.append(
                "ffuf not installed. Using built-in wordlist check."
            )
        return True

    def _run(self) -> Dict[str, Any]:
        self.logger.info(f"Fuzzing directories on {self.target}")

        results = []

        if is_tool_installed("ffuf"):
            results = self._fuzz_with_ffuf()
        else:
            results = self._fuzz_builtin()

        return {
            "directories": results,
            "endpoints": [r.get("url", "") for r in results],
            "total_found": len(results),
        }

    def _fuzz_with_ffuf(self) -> List[dict]:
        """Use ffuf for directory discovery."""
        timeout = self.config.get("tools.ffuf.timeout", 600)
        wordlist = self.config.get(
            "tools.ffuf.wordlist",
            "/usr/share/wordlists/dirb/common.txt",
        )
        rate = self.config.get("tools.ffuf.rate_limit", 100)

        target_url = f"https://{self.target}/FUZZ"

        cmd = [
            "ffuf",
            "-u", target_url,
            "-w", wordlist,
            "-mc", "200,204,301,302,307,401,403,405",
            "-rate", str(rate),
            "-json",
            "-s",
            "-t", "50",
        ]

        code, stdout, _ = run_command(cmd, timeout=timeout)

        results = []
        if code == 0 and stdout:
            try:
                data = json.loads(stdout)
                for entry in data.get("results", []):
                    results.append({
                        "url": entry.get("url", ""),
                        "status": entry.get("status", 0),
                        "length": entry.get("length", 0),
                        "words": entry.get("words", 0),
                        "input": entry.get("input", {}).get("FUZZ", ""),
                    })
            except json.JSONDecodeError:
                # ffuf might output line-by-line JSON
                for line in stdout.strip().split("\n"):
                    try:
                        entry = json.loads(line)
                        results.append({
                            "url": entry.get("url", ""),
                            "status": entry.get("status", 0),
                            "length": entry.get("length", 0),
                        })
                    except json.JSONDecodeError:
                        continue

        return results

    def _fuzz_builtin(self) -> List[dict]:
        """Fallback: Check common directories with requests."""
        if not REQUESTS_AVAILABLE:
            return []

        common_paths = [
            "admin", "login", "dashboard", "api", "wp-admin",
            "wp-login.php", ".git", ".env", "robots.txt",
            "sitemap.xml", ".htaccess", "backup", "config",
            "server-status", "info.php", "phpinfo.php",
            "test", "debug", "console", "swagger",
            "api/v1", "api/v2", "graphql", ".well-known",
        ]

        results = []
        for path in common_paths:
            for scheme in ["https", "http"]:
                url = f"{scheme}://{self.target}/{path}"
                try:
                    resp = requests.get(
                        url,
                        timeout=5,
                        allow_redirects=False,
                        verify=False,
                        headers={"User-Agent": self.config.get(
                            "general.user_agent", "DIGI-TEAM/2.0"
                        )},
                    )
                    if resp.status_code in (200, 204, 301, 302, 307, 401, 403):
                        results.append({
                            "url": url,
                            "status": resp.status_code,
                            "length": len(resp.content),
                        })
                    break  # If HTTPS works, don't try HTTP
                except requests.exceptions.SSLError:
                    continue
                except Exception:
                    break

        return results