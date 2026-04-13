# integrations/builtwith_api.py
"""
BuiltWith API Integration
Queries BuiltWith for detailed technology profiling.
API Docs: https://api.builtwith.com/
"""

from typing import Dict, Any, List

from core.base_module import BaseModule

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from utils.logger import setup_logger

logger = setup_logger("digiteam.integration.builtwith")

BW_BASE = "https://api.builtwith.com"


class BuiltWithModule(BaseModule):
    """Query BuiltWith for comprehensive technology profiling."""

    def __init__(self, target: str, config):
        super().__init__(target, config, module_name="BuiltWith Tech Profile")
        self._api_key = ""

    @property
    def description(self) -> str:
        return "BuiltWith technology stack profiling"

    @property
    def category(self) -> str:
        return "passive"

    def pre_check(self) -> bool:
        if not REQUESTS_AVAILABLE:
            self.result.warnings.append("requests library not available")
            return False

        if not self.config.has_api_key("builtwith"):
            self.result.warnings.append(
                "BuiltWith API key not configured. "
                "Set builtwith in config.yaml or BUILTWITH_API_KEY env var."
            )
            return False

        self._api_key = self.config.get("api_keys.builtwith", "")
        return True

    def _run(self) -> Dict[str, Any]:
        self.logger.info(f"Querying BuiltWith for {self.target}")

        result = {
            "technologies": [],
            "technology_groups": {},
            "meta": {},
            "spend": {},
            "social_profiles": [],
        }

        # ── Free API (v21) ───────────────────────────────────
        free_data = self._query_free_api()
        if free_data:
            result.update(free_data)

        # ── Detailed API (v21) ───────────────────────────────
        detailed = self._query_detailed_api()
        if detailed:
            # Merge technologies without overwriting free results
            existing_names = {t.get("name", "") for t in result["technologies"]}
            for tech in detailed.get("technologies", []):
                if tech.get("name", "") not in existing_names:
                    result["technologies"].append(tech)
            if detailed.get("technology_groups"):
                result["technology_groups"].update(
                    detailed["technology_groups"]
                )

        self.logger.info(
            f"BuiltWith detected {len(result['technologies'])} technologies"
        )

        return result

    # ─────────────────────────────────────────────────────────
    def _query_free_api(self) -> dict:
        """Query BuiltWith Free / Lookup API."""
        try:
            url = f"{BW_BASE}/free1/api.json"
            params = {
                "KEY": self._api_key,
                "LOOKUP": self.target,
            }

            resp = requests.get(url, params=params, timeout=20)

            if resp.status_code == 200:
                data = resp.json()

                technologies = []
                groups = {}

                for group in data.get("groups", []):
                    group_name = group.get("name", "Unknown")
                    group_cats = group.get("categories", [])

                    group_techs = []
                    for cat in group_cats:
                        cat_name = cat.get("name", "")
                        for live in cat.get("live", []):
                            tech = {
                                "name": live.get("Name", ""),
                                "description": live.get("Description", ""),
                                "link": live.get("Link", ""),
                                "tag": live.get("Tag", ""),
                                "category": cat_name,
                                "group": group_name,
                                "first_detected": live.get(
                                    "FirstDetected", ""
                                ),
                                "last_detected": live.get(
                                    "LastDetected", ""
                                ),
                            }
                            technologies.append(tech)
                            group_techs.append(tech["name"])

                    if group_techs:
                        groups[group_name] = group_techs

                meta = {}
                lookup_data = data.get("Results", [{}])
                if lookup_data:
                    first = lookup_data[0] if isinstance(lookup_data, list) else lookup_data
                    meta = {
                        "domain": first.get("Lookup", self.target),
                        "first_indexed": first.get("FirstIndexed", ""),
                        "last_indexed": first.get("LastIndexed", ""),
                    }

                return {
                    "technologies": technologies,
                    "technology_groups": groups,
                    "meta": meta,
                }

            elif resp.status_code == 401:
                self.logger.error("BuiltWith: invalid API key")
                self.result.errors.append("BuiltWith API key rejected (401)")
            elif resp.status_code == 403:
                self.logger.warning("BuiltWith: forbidden — quota exceeded?")
                self.result.warnings.append("BuiltWith API quota may be exceeded")
            else:
                self.logger.warning(
                    f"BuiltWith free API returned {resp.status_code}"
                )

            return {}

        except Exception as e:
            self.logger.error(f"BuiltWith free API failed: {e}")
            return {}

    # ─────────────────────────────────────────────────────────
    def _query_detailed_api(self) -> dict:
        """Query BuiltWith detailed / pro API endpoint."""
        try:
            url = f"{BW_BASE}/v21/api.json"
            params = {
                "KEY": self._api_key,
                "LOOKUP": self.target,
                "NOMETA": "no",
                "NOLIVE": "no",
                "NOATTR": "no",
            }

            resp = requests.get(url, params=params, timeout=30)

            if resp.status_code == 200:
                data = resp.json()

                technologies = []
                groups = {}

                results = data.get("Results", [])
                for res in results:
                    paths = res.get("Result", {}).get("Paths", [])
                    for path in paths:
                        for tech_group in path.get("Technologies", []):
                            tech = {
                                "name": tech_group.get("Name", ""),
                                "description": tech_group.get(
                                    "Description", ""
                                ),
                                "link": tech_group.get("Link", ""),
                                "tag": tech_group.get("Tag", ""),
                                "category": tech_group.get(
                                    "Categories", [""]
                                )[0]
                                if tech_group.get("Categories")
                                else "",
                                "is_premium": tech_group.get(
                                    "IsPremium", ""
                                ),
                            }
                            technologies.append(tech)

                    # Spending data
                    spend = res.get("Result", {}).get("SpendPaths", [])
                    social = res.get("Result", {}).get("Social", [])

                return {
                    "technologies": technologies,
                    "technology_groups": groups,
                }

            # Non-200 is OK — the free API might have already worked
            return {}

        except Exception as e:
            self.logger.debug(f"BuiltWith detailed API failed: {e}")
            return {}