# modules/passive/asn_intel.py
"""
ASN & IP Intelligence Module
Gathers ASN information and IP intelligence for the target.
"""

import socket
from typing import Dict, Any

from core.base_module import BaseModule

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class ASNIntelModule(BaseModule):
    """Gather ASN and IP intelligence information."""

    def __init__(self, target: str, config):
        super().__init__(target, config, module_name="ASN Intelligence")

    @property
    def description(self) -> str:
        return "ASN and IP intelligence gathering"

    @property
    def category(self) -> str:
        return "passive"

    def pre_check(self) -> bool:
        return REQUESTS_AVAILABLE

    def _run(self) -> Dict[str, Any]:
        self.logger.info(f"Gathering ASN intelligence for {self.target}")

        # Resolve IP
        try:
            ip = socket.gethostbyname(self.target)
        except socket.gaierror:
            return {"error": f"Could not resolve {self.target}"}

        result = {
            "ip_address": ip,
            "asn": {},
            "geolocation": {},
            "ip_ranges": [],
            "reverse_dns": "",
        }

        # BGPView API
        asn_data = self._query_bgpview(ip)
        if asn_data:
            result["asn"] = asn_data

        # ip-api for geolocation
        geo_data = self._query_ipapi(ip)
        if geo_data:
            result["geolocation"] = geo_data

        # Reverse DNS
        try:
            result["reverse_dns"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            result["reverse_dns"] = ""

        return result

    def _query_bgpview(self, ip: str) -> dict:
        try:
            resp = requests.get(
                f"https://api.bgpview.io/ip/{ip}",
                timeout=15,
                headers={"Accept": "application/json"},
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                prefixes = data.get("rir_allocation", {})
                ptr = data.get("ptr_record", "")

                asn_info = {}
                if data.get("prefixes"):
                    prefix = data["prefixes"][0]
                    asn_obj = prefix.get("asn", {})
                    asn_info = {
                        "asn": asn_obj.get("asn", ""),
                        "name": asn_obj.get("name", ""),
                        "description": asn_obj.get("description", ""),
                        "country_code": asn_obj.get("country_code", ""),
                        "prefix": prefix.get("prefix", ""),
                        "cidr": prefix.get("cidr", ""),
                    }
                return asn_info
        except Exception as e:
            self.logger.debug(f"BGPView query failed: {e}")
        return {}

    def _query_ipapi(self, ip: str) -> dict:
        try:
            resp = requests.get(
                f"http://ip-api.com/json/{ip}",
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "country": data.get("country", ""),
                    "region": data.get("regionName", ""),
                    "city": data.get("city", ""),
                    "isp": data.get("isp", ""),
                    "org": data.get("org", ""),
                    "as": data.get("as", ""),
                    "lat": data.get("lat", ""),
                    "lon": data.get("lon", ""),
                }
        except Exception as e:
            self.logger.debug(f"ip-api query failed: {e}")
        return {}