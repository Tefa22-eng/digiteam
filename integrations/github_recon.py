# integrations/github_recon.py
"""
GitHub Reconnaissance Module
Searches GitHub for leaked secrets, config files, and exposed code
related to the target domain.
API Docs: https://docs.github.com/en/rest/search
"""

import re
import time
from typing import Dict, Any, List

from core.base_module import BaseModule

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from utils.logger import setup_logger

logger = setup_logger("digiteam.integration.github")

GITHUB_API = "https://api.github.com"


class GitHubReconModule(BaseModule):
    """Search GitHub for sensitive data related to the target domain."""

    # Dork templates — {target} is replaced with the domain
    SEARCH_DORKS = [
        '"{target}" password',
        '"{target}" secret',
        '"{target}" api_key',
        '"{target}" apikey',
        '"{target}" access_token',
        '"{target}" AWS_SECRET',
        '"{target}" private_key',
        '"{target}" jdbc:',
        '"{target}" smtp',
        '"{target}" authorization: bearer',
        '"{target}" filename:.env',
        '"{target}" filename:.git-credentials',
        '"{target}" filename:wp-config.php',
        '"{target}" filename:configuration.php',
        '"{target}" filename:id_rsa',
        '"{target}" filename:.htpasswd',
        '"{target}" filename:shadow',
        '"{target}" extension:sql',
        '"{target}" extension:pem',
    ]

    def __init__(self, target: str, config):
        super().__init__(target, config, module_name="GitHub Recon")
        self._token = ""

    @property
    def description(self) -> str:
        return "GitHub code search for leaked secrets and sensitive files"

    @property
    def category(self) -> str:
        return "passive"

    def pre_check(self) -> bool:
        if not REQUESTS_AVAILABLE:
            self.result.warnings.append("requests library not available")
            return False

        if not self.config.has_api_key("github_token"):
            self.result.warnings.append(
                "GitHub token not configured. "
                "Set github_token in config.yaml or GITHUB_TOKEN env var."
            )
            return False

        self._token = self.config.get("api_keys.github_token", "")
        return True

    def _headers(self) -> dict:
        return {
            "Authorization": f"token {self._token}",
            "Accept": "application/vnd.github.v3.text-match+json",
            "User-Agent": self.config.get(
                "general.user_agent", "DIGI-TEAM/2.0"
            ),
        }

    def _run(self) -> Dict[str, Any]:
        self.logger.info(f"Searching GitHub for {self.target}")

        result = {
            "findings": [],
            "repositories": [],
            "total_results": 0,
            "dorks_searched": 0,
            "vulnerabilities": [],
        }

        repos_seen = set()

        for dork_template in self.SEARCH_DORKS:
            query = dork_template.replace("{target}", self.target)
            findings = self._search_code(query)

            if findings:
                for finding in findings:
                    result["findings"].append(finding)

                    repo_full = finding.get("repository", "")
                    if repo_full and repo_full not in repos_seen:
                        repos_seen.add(repo_full)
                        result["repositories"].append(repo_full)

                    # Flag as vulnerability indicator
                    result["vulnerabilities"].append({
                        "severity": self._assess_severity(dork_template),
                        "title": f"GitHub Exposure: {finding.get('path', '')}",
                        "detail": (
                            f"Repo: {repo_full} | "
                            f"Query: {query} | "
                            f"Match: {finding.get('text_match', '')[:150]}"
                        ),
                    })

            result["dorks_searched"] += 1

            # GitHub rate limit: 10 search requests/minute for authenticated
            time.sleep(3)

        result["total_results"] = len(result["findings"])

        self.logger.info(
            f"GitHub recon found {result['total_results']} results "
            f"across {len(result['repositories'])} repositories"
        )

        return result

    def _search_code(self, query: str) -> List[dict]:
        """Execute a GitHub code search query."""
        try:
            url = f"{GITHUB_API}/search/code"
            params = {
                "q": query,
                "per_page": 10,
                "sort": "indexed",
                "order": "desc",
            }

            resp = requests.get(
                url,
                headers=self._headers(),
                params=params,
                timeout=15,
            )

            if resp.status_code == 200:
                data = resp.json()
                results = []

                for item in data.get("items", []):
                    text_matches = ""
                    for tm in item.get("text_matches", []):
                        text_matches += tm.get("fragment", "") + " "

                    results.append({
                        "path": item.get("path", ""),
                        "repository": item.get("repository", {}).get(
                            "full_name", ""
                        ),
                        "html_url": item.get("html_url", ""),
                        "score": item.get("score", 0),
                        "text_match": text_matches.strip()[:300],
                        "query": query,
                    })

                return results

            elif resp.status_code == 403:
                remaining = resp.headers.get("X-RateLimit-Remaining", "?")
                reset = resp.headers.get("X-RateLimit-Reset", "?")
                self.logger.warning(
                    f"GitHub rate limited. Remaining: {remaining}, "
                    f"Reset: {reset}"
                )
                time.sleep(10)
                return []

            elif resp.status_code == 401:
                self.logger.error("GitHub: invalid token")
                self.result.errors.append("GitHub token rejected (401)")
                return []

            elif resp.status_code == 422:
                self.logger.debug(f"GitHub: unprocessable query — {query}")
                return []

            else:
                self.logger.debug(
                    f"GitHub search returned {resp.status_code} for: {query}"
                )
                return []

        except Exception as e:
            self.logger.error(f"GitHub code search failed: {e}")
            return []

    @staticmethod
    def _assess_severity(dork: str) -> str:
        """Assess finding severity based on the search dork used."""
        high_keywords = [
            "password", "secret", "private_key", "id_rsa",
            "AWS_SECRET", "access_token", ".git-credentials",
            "shadow", ".htpasswd",
        ]
        medium_keywords = [
            "api_key", "apikey", "jdbc:", "smtp", "bearer",
            "wp-config", "configuration.php",
        ]

        dork_lower = dork.lower()
        for kw in high_keywords:
            if kw.lower() in dork_lower:
                return "high"
        for kw in medium_keywords:
            if kw.lower() in dork_lower:
                return "medium"
        return "low"