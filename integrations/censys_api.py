# integrations/censys_api.py
"""
Censys API Integration
Uses the unified Censys API token (NOT legacy id/secret).
Token format: censys_XXXXX_XXXXXXXXXXXXXXXXXXXXXXXXXXXXX
Auth method: Bearer token in Authorization header.
"""

from typing import Dict, Any, List

from core.base_module import BaseModule

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from utils.logger import setup_logger

logger = setup_logger("digiteam.integration.censys")

CENSYS_V2_BASE = "https://search.censys.io/api/v2"


class CensysModule(BaseModule):
    """Query Censys using the unified API token for host and cert data."""

    def __init__(self, target: str, config):
        super().__init__(target, config, module_name="Censys Intelligence")
        self._token = ""

    @property
    def description(self) -> str:
        return "Censys certificate and host intelligence (token auth)"

    @property
    def category(self) -> str:
        return "passive"

    def pre_check(self) -> bool:
        if not REQUESTS_AVAILABLE:
            self.result.warnings.append("requests library not available")
            return False

        if not self.config.has_api_key("censys_token"):
            self.result.warnings.append(
                "Censys API token not configured. "
                "Set censys_token in config.yaml or CENSYS_API_TOKEN env var."
            )
            return False

        self._token = self.config.get("api_keys.censys_token", "")
        return True

    def _headers(self) -> dict:
        """Build authorization headers using Bearer token."""
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "User-Agent": self.config.get(
                "general.user_agent", "DIGI-TEAM/2.0"
            ),
        }

    def _run(self) -> Dict[str, Any]:
        self.logger.info(f"Querying Censys for {self.target}")

        result = {
            "certificates": [],
            "hosts": [],
            "subdomains": [],
            "open_ports": [],
            "services": [],
        }

        # ── Search certificates ──────────────────────────────
        cert_data = self._search_certificates()
        if cert_data:
            result["certificates"] = cert_data.get("certificates", [])
            result["subdomains"] = cert_data.get("subdomains", [])

        # ── Search hosts ─────────────────────────────────────
        host_data = self._search_hosts()
        if host_data:
            result["hosts"] = host_data.get("hosts", [])
            result["open_ports"] = host_data.get("open_ports", [])
            result["services"] = host_data.get("services", [])

        self.logger.info(
            f"Censys found {len(result['subdomains'])} subdomains, "
            f"{len(result['hosts'])} hosts, "
            f"{len(result['open_ports'])} open ports"
        )

        return result

    # ──────────────────────────────────────────────────────────
    #  Certificate Search
    # ──────────────────────────────────────────────────────────
    def _search_certificates(self) -> dict:
        """Search Censys certificate database with Bearer token."""
        try:
            url = f"{CENSYS_V2_BASE}/certificates/search"
            params = {
                "q": f"names: {self.target}",
                "per_page": 100,
            }

            resp = requests.get(
                url,
                params=params,
                headers=self._headers(),
                timeout=30,
            )

            if resp.status_code == 401:
                self.logger.error("Censys: 401 Unauthorized — check your API token")
                self.result.errors.append("Censys API token rejected (401)")
                return {}

            if resp.status_code == 403:
                self.logger.error("Censys: 403 Forbidden — token may lack permissions")
                self.result.errors.append("Censys API token insufficient permissions (403)")
                return {}

            if resp.status_code == 429:
                self.logger.warning("Censys: rate limit hit")
                self.result.warnings.append("Censys API rate limit reached")
                return {}

            if resp.status_code != 200:
                self.logger.warning(
                    f"Censys cert search returned {resp.status_code}: "
                    f"{resp.text[:300]}"
                )
                return {}

            data = resp.json()
            certs = []
            subs = set()

            for hit in data.get("result", {}).get("hits", []):
                cert_info = {
                    "fingerprint": hit.get("fingerprint_sha256", ""),
                    "issuer_dn": hit.get("parsed", {}).get("issuer_dn", ""),
                    "subject_dn": hit.get("parsed", {}).get("subject_dn", ""),
                    "names": hit.get("names", []),
                    "validity": {
                        "start": hit.get("parsed", {}).get(
                            "validity_period", {}
                        ).get("not_before", ""),
                        "end": hit.get("parsed", {}).get(
                            "validity_period", {}
                        ).get("not_after", ""),
                    },
                }
                certs.append(cert_info)

                for name in hit.get("names", []):
                    name = name.strip().lower()
                    if (
                        name.endswith(self.target)
                        and "*" not in name
                        and name != self.target
                    ):
                        subs.add(name)

            return {
                "certificates": certs,
                "subdomains": sorted(list(subs)),
            }

        except requests.exceptions.Timeout:
            self.logger.warning("Censys certificate search timed out")
            return {}
        except Exception as e:
            self.logger.error(f"Censys certificate search failed: {e}")
            return {}

    # ──────────────────────────────────────────────────────────
    #  Host Search
    # ──────────────────────────────────────────────────────────
    def _search_hosts(self) -> dict:
        """Search Censys hosts/services database with Bearer token."""
        try:
            url = f"{CENSYS_V2_BASE}/hosts/search"
            params = {
                "q": self.target,
                "per_page": 50,
            }

            resp = requests.get(
                url,
                params=params,
                headers=self._headers(),
                timeout=30,
            )

            if resp.status_code not in (200,):
                self.logger.warning(
                    f"Censys host search returned {resp.status_code}"
                )
                return {}

            data = resp.json()
            hosts = []
            open_ports = []
            services = []

            for hit in data.get("result", {}).get("hits", []):
                ip = hit.get("ip", "")

                host_entry = {
                    "ip": ip,
                    "services_count": len(hit.get("services", [])),
                    "location": {
                        "country": hit.get("location", {}).get(
                            "country", ""
                        ),
                        "city": hit.get("location", {}).get("city", ""),
                    },
                    "autonomous_system": {
                        "asn": hit.get("autonomous_system", {}).get(
                            "asn", ""
                        ),
                        "name": hit.get("autonomous_system", {}).get(
                            "name", ""
                        ),
                        "bgp_prefix": hit.get("autonomous_system", {}).get(
                            "bgp_prefix", ""
                        ),
                    },
                    "operating_system": hit.get("operating_system", {}).get(
                        "product", ""
                    ),
                }
                hosts.append(host_entry)

                for svc in hit.get("services", []):
                    port = svc.get("port", 0)
                    proto = svc.get("transport_protocol", "tcp")
                    svc_name = svc.get("service_name", "unknown")
                    extended = svc.get("extended_service_name", "")

                    open_ports.append({
                        "host": ip,
                        "port": port,
                        "service": svc_name,
                        "version": extended,
                        "protocol": proto,
                    })

                    services.append({
                        "ip": ip,
                        "port": port,
                        "service": svc_name,
                        "extended": extended,
                        "banner": svc.get("banner", "")[:200],
                    })

            return {
                "hosts": hosts,
                "open_ports": open_ports,
                "services": services,
            }

        except requests.exceptions.Timeout:
            self.logger.warning("Censys host search timed out")
            return {}
        except Exception as e:
            self.logger.error(f"Censys host search failed: {e}")
            return {}

    # ──────────────────────────────────────────────────────────
    #  Specific Host Lookup (bonus utility)
    # ──────────────────────────────────────────────────────────
    def _lookup_host(self, ip: str) -> dict:
        """Look up a specific IP in Censys."""
        try:
            url = f"{CENSYS_V2_BASE}/hosts/{ip}"
            resp = requests.get(
                url,
                headers=self._headers(),
                timeout=20,
            )
            if resp.status_code == 200:
                return resp.json().get("result", {})
            return {}
        except Exception as e:
            self.logger.debug(f"Censys host lookup failed for {ip}: {e}")
            return {}