# modules/passive/dns_enum.py
"""
DNS Enumeration Module
Performs comprehensive DNS record lookups.
"""

import socket
from typing import Dict, Any, List

from core.base_module import BaseModule

try:
    import dns.resolver
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class DNSEnumModule(BaseModule):
    """Enumerate DNS records for the target domain."""

    RECORD_TYPES = [
        "A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA",
    ]

    def __init__(self, target: str, config):
        super().__init__(target, config, module_name="DNS Enumeration")

    @property
    def description(self) -> str:
        return "Comprehensive DNS record enumeration"

    @property
    def category(self) -> str:
        return "passive"

    def pre_check(self) -> bool:
        if not DNS_AVAILABLE:
            self.logger.warning(
                "dnspython not installed. Install with: pip install dnspython"
            )
            self.result.warnings.append("dnspython library not available")
            return False
        return True

    def _run(self) -> Dict[str, Any]:
        self.logger.info(f"Running DNS enumeration for {self.target}")

        records = {}
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.config.timeout
        resolver.lifetime = self.config.timeout

        for rtype in self.RECORD_TYPES:
            try:
                answers = resolver.resolve(self.target, rtype)
                records[rtype] = [str(r) for r in answers]
                self.logger.debug(
                    f"Found {len(records[rtype])} {rtype} records"
                )
            except dns.resolver.NoAnswer:
                records[rtype] = []
            except dns.resolver.NXDOMAIN:
                self.logger.warning(f"Domain {self.target} does not exist")
                records[rtype] = []
                break
            except dns.resolver.NoNameservers:
                records[rtype] = []
            except Exception as e:
                records[rtype] = []
                self.logger.debug(f"Error resolving {rtype}: {e}")

        # Check for zone transfer
        zone_transfer_possible = self._check_zone_transfer()

        # Extract IP addresses for subdomain tracking
        ip_addresses = records.get("A", []) + records.get("AAAA", [])

        # Security checks
        security_issues = []
        txt_records = records.get("TXT", [])

        has_spf = any("v=spf1" in r for r in txt_records)
        has_dmarc = False
        try:
            dmarc = resolver.resolve(f"_dmarc.{self.target}", "TXT")
            has_dmarc = True
            records["DMARC"] = [str(r) for r in dmarc]
        except Exception:
            records["DMARC"] = []

        if not has_spf:
            security_issues.append({
                "severity": "medium",
                "title": "Missing SPF Record",
                "detail": "No SPF record found. Domain may be vulnerable to email spoofing.",
            })
        if not has_dmarc:
            security_issues.append({
                "severity": "medium",
                "title": "Missing DMARC Record",
                "detail": "No DMARC record found. Email authentication not enforced.",
            })

        if zone_transfer_possible:
            security_issues.append({
                "severity": "high",
                "title": "DNS Zone Transfer Possible",
                "detail": "Zone transfer (AXFR) is allowed on one or more name servers.",
            })

        return {
            "records": records,
            "ip_addresses": ip_addresses,
            "zone_transfer": zone_transfer_possible,
            "security_issues": security_issues,
        }

    def _check_zone_transfer(self) -> bool:
        """Attempt zone transfer on all nameservers."""
        try:
            import dns.zone
            import dns.query

            ns_records = dns.resolver.resolve(self.target, "NS")
            for ns in ns_records:
                ns_str = str(ns).rstrip(".")
                try:
                    dns.zone.from_xfr(
                        dns.query.xfr(ns_str, self.target, lifetime=10)
                    )
                    self.logger.warning(
                        f"Zone transfer successful on {ns_str}!"
                    )
                    return True
                except Exception:
                    continue
        except Exception:
            pass
        return False