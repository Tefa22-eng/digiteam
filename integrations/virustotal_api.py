# integrations/virustotal_api.py
"""
VirusTotal API Integration
Queries VirusTotal for domain intelligence.
"""

from typing import Dict, Any

from core.base_module import BaseModule

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class VirusTotalModule(BaseModule):
    """Query VirusTotal for domain intelligence and reputation."""

    def __init__(self, target: str, config):
        super().__init__(target, config, module_name="VirusTotal Intelligence")

    @property
    def description(self) -> str:
        return "VirusTotal domain intelligence and reputation"

    @property
    def category(self) -> str:
        return "passive"

    def pre_check(self) -> bool:
        if not self.config.has_api_key("virustotal"):
            self.result.warnings.append("VirusTotal API key not configured")
            return False
        return REQUESTS_AVAILABLE

    def _run(self) -> Dict[str, Any]:
        self.logger.info(f"Querying VirusTotal for {self.target}")

        api_key = self.config.get("api_keys.virustotal")
        headers = {"x-apikey": api_key}

        result = {
            "domain_info": {},
            "subdomains": [],
            "detections": [],
            "categories": [],
            "reputation": 0,
        }

        # Get domain report
        domain_data = self._get_domain_report(headers)
        if domain_data:
            result["domain_info"] = domain_data

        # Get subdomains
        subs = self._get_subdomains(headers)
        if subs:
            result["subdomains"] = subs

        return result

    def _get_domain_report(self, headers: dict) -> dict:
        """Get domain report from VirusTotal."""
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{self.target}"
            resp = requests.get(url, headers=headers, timeout=30)

            if resp.status_code == 200:
                data = resp.json().get("data", {})
                attrs = data.get("attributes", {})

                last_analysis = attrs.get("last_analysis_stats", {})
                categories = attrs.get("categories", {})

                return {
                    "registrar": attrs.get("registrar", ""),
                    "creation_date": attrs.get("creation_date", ""),
                    "reputation": attrs.get("reputation", 0),
                    "last_analysis_stats": last_analysis,
                    "categories": list(categories.values()),
                    "whois": attrs.get("whois", "")[:500],
                    "last_dns_records": attrs.get(
                        "last_dns_records", []
                    )[:20],
                    "total_votes": attrs.get("total_votes", {}),
                    "popularity_ranks": attrs.get("popularity_ranks", {}),
                }
            else:
                self.logger.warning(
                    f"VT domain report returned {resp.status_code}"
                )
                return {}
        except Exception as e:
            self.logger.error(f"VT domain report failed: {e}")
            return {}

    def _get_subdomains(self, headers: dict) -> list:
        """Get subdomains from VirusTotal."""
        try:
            url = (
                f"https://www.virustotal.com/api/v3/domains/"
                f"{self.target}/subdomains?limit=100"
            )
            resp = requests.get(url, headers=headers, timeout=30)

            if resp.status_code == 200:
                data = resp.json().get("data", [])
                return [
                    item.get("id", "")
                    for item in data
                    if item.get("id")
                ]
            return []
        except Exception as e:
            self.logger.error(f"VT subdomains query failed: {e}")
            return []