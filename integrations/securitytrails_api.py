# integrations/securitytrails_api.py
"""
SecurityTrails API Integration
Queries SecurityTrails for domain intelligence, subdomains,
DNS history, and associated domains.
API Docs: https://securitytrails.com/corp/apidocs
"""

from typing import Dict, Any, List

from core.base_module import BaseModule

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from utils.logger import setup_logger

logger = setup_logger("digiteam.integration.securitytrails")

ST_BASE = "https://api.securitytrails.com/v1"


class SecurityTrailsModule(BaseModule):
    """Query SecurityTrails for deep domain intelligence."""

    def __init__(self, target: str, config):
        super().__init__(target, config, module_name="SecurityTrails Intel")
        self._api_key = ""

    @property
    def description(self) -> str:
        return "SecurityTrails domain intel, subdomains, DNS history"

    @property
    def category(self) -> str:
        return "passive"

    def pre_check(self) -> bool:
        if not REQUESTS_AVAILABLE:
            self.result.warnings.append("requests library not available")
            return False

        if not self.config.has_api_key("securitytrails"):
            self.result.warnings.append(
                "SecurityTrails API key not configured. "
                "Set securitytrails in config.yaml or "
                "SECURITYTRAILS_API_KEY env var."
            )
            return False

        self._api_key = self.config.get("api_keys.securitytrails", "")
        return True

    def _headers(self) -> dict:
        return {
            "APIKEY": self._api_key,
            "Accept": "application/json",
        }

    def _run(self) -> Dict[str, Any]:
        self.logger.info(f"Querying SecurityTrails for {self.target}")

        result = {
            "domain_info": {},
            "subdomains": [],
            "dns_history": {},
            "associated_domains": [],
            "whois_info": {},
            "tags": [],
        }

        # ── Domain details ───────────────────────────────────
        domain_data = self._get_domain_details()
        if domain_data:
            result["domain_info"] = domain_data

        # ── Subdomains ───────────────────────────────────────
        subs = self._get_subdomains()
        if subs:
            result["subdomains"] = subs

        # ── DNS history ──────────────────────────────────────
        dns_hist = self._get_dns_history()
        if dns_hist:
            result["dns_history"] = dns_hist

        # ── Associated / related domains ─────────────────────
        associated = self._get_associated_domains()
        if associated:
            result["associated_domains"] = associated

        # ── WHOIS info ───────────────────────────────────────
        whois_data = self._get_whois()
        if whois_data:
            result["whois_info"] = whois_data

        self.logger.info(
            f"SecurityTrails found {len(result['subdomains'])} subdomains"
        )

        return result

    # ─────────────────────────────────────────────────────────
    def _get_domain_details(self) -> dict:
        """GET /v1/domain/{domain}"""
        try:
            url = f"{ST_BASE}/domain/{self.target}"
            resp = requests.get(url, headers=self._headers(), timeout=20)

            if resp.status_code == 200:
                data = resp.json()
                return {
                    "hostname": data.get("hostname", ""),
                    "alexa_rank": data.get("alexa_rank"),
                    "apex_domain": data.get("apex_domain", ""),
                    "current_dns": self._parse_current_dns(
                        data.get("current_dns", {})
                    ),
                    "subdomain_count": data.get("subdomain_count", 0),
                }
            elif resp.status_code == 429:
                self.logger.warning("SecurityTrails rate limit hit")
                self.result.warnings.append("SecurityTrails rate limit reached")
            elif resp.status_code == 401:
                self.logger.error("SecurityTrails: invalid API key")
                self.result.errors.append("SecurityTrails API key rejected")
            else:
                self.logger.warning(
                    f"SecurityTrails domain returned {resp.status_code}"
                )
            return {}
        except Exception as e:
            self.logger.error(f"SecurityTrails domain detail failed: {e}")
            return {}

    def _parse_current_dns(self, dns_data: dict) -> dict:
        """Parse current DNS records from SecurityTrails response."""
        parsed = {}
        for rtype, info in dns_data.items():
            if isinstance(info, dict) and "values" in info:
                parsed[rtype.upper()] = [
                    v.get("ip", v.get("value", str(v)))
                    for v in info["values"]
                ]
            elif isinstance(info, list):
                parsed[rtype.upper()] = info
        return parsed

    # ─────────────────────────────────────────────────────────
    def _get_subdomains(self) -> List[str]:
        """GET /v1/domain/{domain}/subdomains"""
        try:
            url = f"{ST_BASE}/domain/{self.target}/subdomains"
            params = {"children_only": "false", "include_inactive": "true"}
            resp = requests.get(
                url, headers=self._headers(), params=params, timeout=30
            )

            if resp.status_code == 200:
                data = resp.json()
                subs = []
                for sub in data.get("subdomains", []):
                    full = f"{sub}.{self.target}"
                    subs.append(full)
                return sorted(subs)
            return []
        except Exception as e:
            self.logger.error(f"SecurityTrails subdomains failed: {e}")
            return []

    # ─────────────────────────────────────────────────────────
    def _get_dns_history(self) -> dict:
        """GET /v1/history/{domain}/dns/{type}  for A and AAAA"""
        history = {}
        for rtype in ["a", "aaaa", "mx", "ns"]:
            try:
                url = f"{ST_BASE}/history/{self.target}/dns/{rtype}"
                resp = requests.get(
                    url, headers=self._headers(), timeout=20
                )
                if resp.status_code == 200:
                    data = resp.json()
                    records = []
                    for record in data.get("records", [])[:50]:
                        records.append({
                            "values": [
                                v.get("ip", v.get("value", ""))
                                for v in record.get("values", [])
                            ],
                            "first_seen": record.get("first_seen", ""),
                            "last_seen": record.get("last_seen", ""),
                            "organizations": record.get("organizations", []),
                        })
                    if records:
                        history[rtype.upper()] = records
            except Exception as e:
                self.logger.debug(f"DNS history {rtype} failed: {e}")
                continue
        return history

    # ─────────────────────────────────────────────────────────
    def _get_associated_domains(self) -> List[str]:
        """GET /v1/domain/{domain}/associated"""
        try:
            url = f"{ST_BASE}/domain/{self.target}/associated"
            resp = requests.get(
                url, headers=self._headers(), timeout=20
            )
            if resp.status_code == 200:
                data = resp.json()
                return [
                    rec.get("hostname", "")
                    for rec in data.get("records", [])
                    if rec.get("hostname")
                ][:100]
            return []
        except Exception as e:
            self.logger.error(f"SecurityTrails associated domains failed: {e}")
            return []

    # ─────────────────────────────────────────────────────────
    def _get_whois(self) -> dict:
        """GET /v1/domain/{domain}/whois"""
        try:
            url = f"{ST_BASE}/domain/{self.target}/whois"
            resp = requests.get(
                url, headers=self._headers(), timeout=20
            )
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "registrar": data.get("registrar", ""),
                    "created_date": data.get("createdDate", ""),
                    "updated_date": data.get("updatedDate", ""),
                    "expires_date": data.get("expiresDate", ""),
                    "nameservers": data.get("nameServers", []),
                    "status": data.get("status", []),
                    "contacts": data.get("contacts", {}),
                }
            return {}
        except Exception as e:
            self.logger.debug(f"SecurityTrails WHOIS failed: {e}")
            return {}