# integrations/shodan_api.py
"""
Shodan API Integration
Queries Shodan for host intelligence.
"""

from typing import Dict, Any

from core.base_module import BaseModule

try:
    import shodan as shodan_lib
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class ShodanModule(BaseModule):
    """Query Shodan for host and service intelligence."""

    def __init__(self, target: str, config):
        super().__init__(target, config, module_name="Shodan Intelligence")

    @property
    def description(self) -> str:
        return "Shodan host and service intelligence"

    @property
    def category(self) -> str:
        return "passive"

    def pre_check(self) -> bool:
        if not self.config.has_api_key("shodan"):
            self.result.warnings.append("Shodan API key not configured")
            self.logger.warning("Shodan API key not found in config")
            return False
        return True

    def _run(self) -> Dict[str, Any]:
        self.logger.info(f"Querying Shodan for {self.target}")

        api_key = self.config.get("api_keys.shodan")

        if SHODAN_AVAILABLE:
            return self._query_with_library(api_key)
        elif REQUESTS_AVAILABLE:
            return self._query_with_requests(api_key)
        else:
            return {"error": "No HTTP library available"}

    def _query_with_library(self, api_key: str) -> dict:
        """Use the official shodan library."""
        try:
            api = shodan_lib.Shodan(api_key)

            # Search for the domain
            results = api.search(f"hostname:{self.target}")

            hosts = []
            ports = []
            vulns = []

            for match in results.get("matches", []):
                host_info = {
                    "ip": match.get("ip_str", ""),
                    "port": match.get("port", 0),
                    "org": match.get("org", ""),
                    "os": match.get("os", ""),
                    "product": match.get("product", ""),
                    "version": match.get("version", ""),
                    "hostnames": match.get("hostnames", []),
                }
                hosts.append(host_info)
                ports.append({
                    "host": match.get("ip_str", ""),
                    "port": match.get("port", 0),
                    "service": match.get("product", ""),
                    "version": match.get("version", ""),
                })

                for v in match.get("vulns", []):
                    vulns.append({
                        "severity": "high",
                        "title": f"CVE: {v}",
                        "detail": f"Found on {match.get('ip_str')}:{match.get('port')}",
                    })

            return {
                "hosts": hosts,
                "ports": ports,
                "open_ports": ports,
                "total_results": results.get("total", 0),
                "vulnerabilities": vulns,
            }
        except shodan_lib.APIError as e:
            self.logger.error(f"Shodan API error: {e}")
            return {"error": str(e)}

    def _query_with_requests(self, api_key: str) -> dict:
        """Fallback: use requests to query Shodan API."""
        try:
            # First resolve the domain
            import socket
            ip = socket.gethostbyname(self.target)

            url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
            resp = requests.get(url, timeout=30)

            if resp.status_code == 200:
                data = resp.json()
                ports = []
                for item in data.get("data", []):
                    ports.append({
                        "host": ip,
                        "port": item.get("port", 0),
                        "service": item.get("product", ""),
                        "version": item.get("version", ""),
                    })

                return {
                    "ip": ip,
                    "ports": ports,
                    "open_ports": ports,
                    "os": data.get("os", ""),
                    "org": data.get("org", ""),
                    "isp": data.get("isp", ""),
                    "hostnames": data.get("hostnames", []),
                    "vulnerabilities": [
                        {"severity": "high", "title": f"CVE: {v}", "detail": ""}
                        for v in data.get("vulns", [])
                    ],
                }
            elif resp.status_code == 404:
                return {"info": "No Shodan data found for this host"}
            else:
                return {"error": f"Shodan API returned {resp.status_code}"}
        except Exception as e:
            self.logger.error(f"Shodan request failed: {e}")
            return {"error": str(e)}