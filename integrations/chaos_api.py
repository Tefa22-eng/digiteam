# integrations/chaos_api.py
"""
ProjectDiscovery Chaos API Integration
Queries the Chaos dataset for subdomain discovery.
API Docs: https://chaos.projectdiscovery.io/#/docs
"""

from typing import Dict, Any, List

from core.base_module import BaseModule

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from utils.logger import setup_logger

logger = setup_logger("digiteam.integration.chaos")

CHAOS_BASE = "https://dns.projectdiscovery.io/dns"


class ChaosModule(BaseModule):
    """Query ProjectDiscovery Chaos for subdomain data."""

    def __init__(self, target: str, config):
        super().__init__(target, config, module_name="Chaos (PD) Subdomains")
        self._api_key = ""

    @property
    def description(self) -> str:
        return "ProjectDiscovery Chaos subdomain dataset"

    @property
    def category(self) -> str:
        return "passive"

    def pre_check(self) -> bool:
        if not REQUESTS_AVAILABLE:
            self.result.warnings.append("requests library not available")
            return False

        if not self.config.has_api_key("chaos"):
            self.result.warnings.append(
                "Chaos API key not configured. "
                "Set chaos in config.yaml or CHAOS_API_KEY env var."
            )
            return False

        self._api_key = self.config.get("api_keys.chaos", "")
        return True

    def _headers(self) -> dict:
        return {
            "Authorization": self._api_key,
            "Accept": "application/json",
        }

    def _run(self) -> Dict[str, Any]:
        self.logger.info(f"Querying Chaos for {self.target}")

        result = {
            "subdomains": [],
            "total_count": 0,
            "source": "chaos-projectdiscovery",
            "is_program": False,
        }

        # ── Check if domain is in Chaos dataset ──────────────
        is_indexed = self._check_domain()
        result["is_program"] = is_indexed

        # ── Fetch subdomains ─────────────────────────────────
        subdomains = self._get_subdomains()
        if subdomains:
            result["subdomains"] = sorted(subdomains)
            result["total_count"] = len(subdomains)

        self.logger.info(
            f"Chaos found {result['total_count']} subdomains for {self.target}"
        )

        return result

    def _check_domain(self) -> bool:
        """Check if the domain exists in the Chaos dataset."""
        try:
            url = f"{CHAOS_BASE}/{self.target}"
            resp = requests.get(
                url, headers=self._headers(), timeout=15
            )
            return resp.status_code == 200
        except Exception:
            return False

    def _get_subdomains(self) -> List[str]:
        """GET /dns/{domain}/subdomains"""
        try:
            url = f"{CHAOS_BASE}/{self.target}/subdomains"
            resp = requests.get(
                url, headers=self._headers(), timeout=30
            )

            if resp.status_code == 200:
                data = resp.json()
                raw_subs = data.get("subdomains", [])
                full_subs = []
                for sub in raw_subs:
                    sub = sub.strip().lower()
                    if sub:
                        if sub == self.target:
                            full_subs.append(sub)
                        elif not sub.endswith(f".{self.target}"):
                            full_subs.append(f"{sub}.{self.target}")
                        else:
                            full_subs.append(sub)
                return full_subs

            elif resp.status_code == 401:
                self.logger.error("Chaos: invalid API key")
                self.result.errors.append("Chaos API key rejected (401)")
            elif resp.status_code == 404:
                self.logger.info(
                    f"{self.target} not found in Chaos dataset"
                )
                self.result.warnings.append(
                    f"{self.target} not indexed in Chaos"
                )
            elif resp.status_code == 429:
                self.logger.warning("Chaos rate limit hit")
                self.result.warnings.append("Chaos API rate limit reached")
            else:
                self.logger.warning(
                    f"Chaos returned {resp.status_code}: {resp.text[:200]}"
                )

            return []

        except Exception as e:
            self.logger.error(f"Chaos subdomains query failed: {e}")
            return []