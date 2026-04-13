# modules/passive/whois_lookup.py
"""
WHOIS Lookup Module
Performs WHOIS queries to gather domain registration information.
Uses multiple fallback methods to ensure reliability on all platforms.
"""

import socket
import re
import subprocess
import sys
from typing import Dict, Any, Optional

from core.base_module import BaseModule

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Try python-whois but don't depend on it
WHOIS_LIB = None
try:
    import whois as python_whois
    WHOIS_LIB = "python-whois"
except ImportError:
    pass

if WHOIS_LIB is None:
    try:
        import whois as whois_alt
        WHOIS_LIB = "whois"
    except ImportError:
        pass


class WhoisModule(BaseModule):
    """
    Gather domain registration information via WHOIS.

    Uses three fallback strategies:
      1. WHOIS API (api.whois.rar.vn / whoisjson.com) — most reliable
      2. python-whois library — works on Linux, often fails on Windows
      3. Raw socket WHOIS query — universal fallback
    """

    def __init__(self, target: str, config):
        super().__init__(target, config, module_name="WHOIS Lookup")

    @property
    def description(self) -> str:
        return "Domain WHOIS registration information lookup"

    @property
    def category(self) -> str:
        return "passive"

    def pre_check(self) -> bool:
        # Always return True — we have multiple fallbacks
        return True

    def _run(self) -> Dict[str, Any]:
        self.logger.info(f"Running WHOIS lookup for {self.target}")

        # ── Strategy 1: Free WHOIS APIs (most reliable on Windows) ──
        data = self._whois_via_api()
        if data and data.get("domain_name"):
            self.logger.info("WHOIS data obtained via API")
            data["source"] = "api"
            data["security_issues"] = self._check_security(data)
            return data

        # ── Strategy 2: python-whois library ─────────────────────────
        data = self._whois_via_library()
        if data and data.get("domain_name"):
            self.logger.info("WHOIS data obtained via python-whois library")
            data["source"] = "library"
            data["security_issues"] = self._check_security(data)
            return data

        # ── Strategy 3: Raw socket WHOIS ─────────────────────────────
        data = self._whois_via_socket()
        if data and data.get("domain_name"):
            self.logger.info("WHOIS data obtained via raw socket")
            data["source"] = "socket"
            data["security_issues"] = self._check_security(data)
            return data

        # ── Strategy 4: System whois command (Linux/Mac) ─────────────
        if sys.platform != "win32":
            data = self._whois_via_command()
            if data and data.get("domain_name"):
                self.logger.info("WHOIS data obtained via system command")
                data["source"] = "command"
                data["security_issues"] = self._check_security(data)
                return data

        # All methods failed
        self.result.warnings.append(
            "All WHOIS methods failed. Domain may have WHOIS privacy "
            "or rate limiting is active."
        )
        return {
            "domain_name": self.target,
            "error": "Could not retrieve WHOIS data after trying 4 methods",
            "source": "none",
            "security_issues": [],
        }

    # ═══════════════════════════════════════════════════════════
    #  Strategy 1: WHOIS via free APIs
    # ═══════════════════════════════════════════════════════════
    def _whois_via_api(self) -> dict:
        """Query free WHOIS APIs — works perfectly on Windows."""
        if not REQUESTS_AVAILABLE:
            return {}

        # Try multiple free WHOIS API services
        apis = [
            self._api_whoisjson,
            self._api_rdap,
            self._api_ip2whois,
        ]

        for api_func in apis:
            try:
                result = api_func()
                if result and result.get("domain_name"):
                    return result
            except Exception as e:
                self.logger.debug(f"WHOIS API method failed: {e}")
                continue

        return {}

    def _api_rdap(self) -> dict:
        """Query RDAP (Registration Data Access Protocol) — the modern WHOIS."""
        try:
            # First get the RDAP server for the TLD
            tld = self.target.split(".")[-1]
            bootstrap_url = "https://data.iana.org/rdap/dns.json"

            resp = requests.get(bootstrap_url, timeout=10)
            if resp.status_code != 200:
                return {}

            rdap_data = resp.json()
            rdap_server = None

            for service in rdap_data.get("services", []):
                tlds = service[0]
                urls = service[1]
                if tld.lower() in [t.lower() for t in tlds]:
                    rdap_server = urls[0].rstrip("/")
                    break

            if not rdap_server:
                return {}

            # Query RDAP
            url = f"{rdap_server}/domain/{self.target}"
            resp = requests.get(
                url,
                timeout=15,
                headers={"Accept": "application/rdap+json"},
            )

            if resp.status_code != 200:
                return {}

            data = resp.json()

            # Parse RDAP response
            result = {
                "domain_name": data.get("ldhName", self.target),
                "status": data.get("status", []),
                "registrar": "",
                "creation_date": "",
                "expiration_date": "",
                "updated_date": "",
                "name_servers": [],
                "dnssec": "",
                "registrant": "",
                "emails": [],
                "country": "",
            }

            # Extract events
            for event in data.get("events", []):
                action = event.get("eventAction", "")
                date = event.get("eventDate", "")
                if action == "registration":
                    result["creation_date"] = date
                elif action == "expiration":
                    result["expiration_date"] = date
                elif action == "last changed":
                    result["updated_date"] = date

            # Extract entities
            for entity in data.get("entities", []):
                roles = entity.get("roles", [])
                vcard = entity.get("vcardArray", [None, []])[1] if entity.get("vcardArray") else []

                if "registrar" in roles:
                    # Find fn (formatted name)
                    for field in vcard:
                        if isinstance(field, list) and len(field) >= 4:
                            if field[0] == "fn":
                                result["registrar"] = field[3]
                            elif field[0] == "email":
                                result["emails"].append(field[3])

                if "registrant" in roles:
                    for field in vcard:
                        if isinstance(field, list) and len(field) >= 4:
                            if field[0] == "fn":
                                result["registrant"] = field[3]
                            elif field[0] == "adr":
                                # Extract country from address
                                adr = field[3] if isinstance(field[3], dict) else {}
                                result["country"] = adr.get("cc", "")

            # Extract nameservers
            for ns in data.get("nameservers", []):
                ns_name = ns.get("ldhName", "")
                if ns_name:
                    result["name_servers"].append(ns_name.lower())

            # DNSSEC
            secureDNS = data.get("secureDNS", {})
            if secureDNS.get("delegationSigned"):
                result["dnssec"] = "signedDelegation"
            else:
                result["dnssec"] = "unsigned"

            return result

        except Exception as e:
            self.logger.debug(f"RDAP query failed: {e}")
            return {}

    def _api_whoisjson(self) -> dict:
        """Query whoisjson.com free API."""
        try:
            url = f"https://whoisjson.com/whois.json?domain={self.target}"
            resp = requests.get(url, timeout=15)

            if resp.status_code == 200:
                data = resp.json()
                return {
                    "domain_name": data.get("domain_name", self.target),
                    "registrar": data.get("registrar", ""),
                    "creation_date": data.get("creation_date", ""),
                    "expiration_date": data.get("expiration_date", ""),
                    "updated_date": data.get("updated_date", ""),
                    "name_servers": data.get("name_servers", []),
                    "registrant": data.get("registrant", ""),
                    "emails": data.get("emails", []),
                    "country": data.get("registrant_country", ""),
                    "status": data.get("status", []),
                    "dnssec": data.get("dnssec", ""),
                }
            return {}
        except Exception as e:
            self.logger.debug(f"whoisjson API failed: {e}")
            return {}

    def _api_ip2whois(self) -> dict:
        """Query ip2whois.com free API (no key needed for basic)."""
        try:
            url = (
                f"https://www.ip2whois.com/api/v2"
                f"?domain={self.target}&format=json"
            )
            resp = requests.get(url, timeout=15)

            if resp.status_code == 200:
                data = resp.json()
                if data.get("domain"):
                    return {
                        "domain_name": data.get("domain", self.target),
                        "registrar": data.get("registrar", {}).get("name", ""),
                        "creation_date": data.get("create_date", ""),
                        "expiration_date": data.get("expire_date", ""),
                        "updated_date": data.get("update_date", ""),
                        "name_servers": data.get("nameservers", []),
                        "registrant": data.get("registrant", {}).get(
                            "organization", ""
                        ),
                        "emails": [
                            data.get("registrant", {}).get("email", ""),
                            data.get("admin", {}).get("email", ""),
                            data.get("tech", {}).get("email", ""),
                        ],
                        "country": data.get("registrant", {}).get(
                            "country", ""
                        ),
                        "status": data.get("status", []),
                        "dnssec": data.get("dnssec", ""),
                    }
            return {}
        except Exception as e:
            self.logger.debug(f"ip2whois API failed: {e}")
            return {}

    # ═══════════════════════════════════════════════════════════
    #  Strategy 2: python-whois library
    # ═══════════════════════════════════════════════════════════
    def _whois_via_library(self) -> dict:
        """Use python-whois library (may fail on Windows)."""
        if WHOIS_LIB is None:
            self.logger.debug("No whois library installed")
            return {}

        try:
            if WHOIS_LIB == "python-whois":
                import whois as python_whois
                w = python_whois.whois(self.target)
            else:
                import whois as whois_alt
                w = whois_alt.whois(self.target)

            return {
                "domain_name": self._normalize(w.domain_name),
                "registrar": self._normalize(w.registrar),
                "creation_date": str(self._normalize(w.creation_date)),
                "expiration_date": str(self._normalize(w.expiration_date)),
                "updated_date": str(self._normalize(w.updated_date)),
                "name_servers": self._normalize_list(w.name_servers),
                "registrant": self._normalize(
                    getattr(w, "org", "") or getattr(w, "name", "") or ""
                ),
                "emails": self._normalize_list(
                    w.emails if hasattr(w, "emails") and w.emails else []
                ),
                "country": self._normalize(
                    getattr(w, "country", "")
                    or getattr(w, "registrant_country", "")
                    or ""
                ),
                "status": self._normalize_list(w.status) if w.status else [],
                "dnssec": self._normalize(
                    getattr(w, "dnssec", "") or ""
                ),
            }
        except Exception as e:
            self.logger.debug(f"python-whois library failed: {e}")
            return {}

    # ═══════════════════════════════════════════════════════════
    #  Strategy 3: Raw socket WHOIS
    # ═══════════════════════════════════════════════════════════
    def _whois_via_socket(self) -> dict:
        """Direct socket connection to WHOIS servers."""
        try:
            tld = self.target.split(".")[-1].lower()

            # Map TLDs to WHOIS servers
            whois_servers = {
                "com": "whois.verisign-grs.com",
                "net": "whois.verisign-grs.com",
                "org": "whois.pir.org",
                "info": "whois.afilias.net",
                "io": "whois.nic.io",
                "co": "whois.nic.co",
                "me": "whois.nic.me",
                "dev": "whois.nic.google",
                "app": "whois.nic.google",
                "xyz": "whois.nic.xyz",
                "online": "whois.nic.online",
                "site": "whois.nic.site",
                "tech": "whois.nic.tech",
                "cloud": "whois.nic.cloud",
                "ai": "whois.nic.ai",
                "us": "whois.nic.us",
                "uk": "whois.nic.uk",
                "de": "whois.denic.de",
                "fr": "whois.nic.fr",
                "nl": "whois.sidn.nl",
                "eu": "whois.eu",
                "ru": "whois.tcinet.ru",
                "jp": "whois.jprs.jp",
                "cn": "whois.cnnic.cn",
                "au": "whois.auda.org.au",
                "ca": "whois.cira.ca",
                "in": "whois.registry.in",
                "br": "whois.registro.br",
            }

            server = whois_servers.get(tld, f"whois.nic.{tld}")

            # Connect and query
            raw_text = self._raw_whois_query(server, self.target)
            if not raw_text:
                return {}

            # Some registries (e.g., VeriSign) return a referral
            referral = self._extract_referral(raw_text)
            if referral and referral != server:
                detailed = self._raw_whois_query(referral, self.target)
                if detailed:
                    raw_text = detailed

            # Parse the raw WHOIS text
            return self._parse_raw_whois(raw_text)

        except Exception as e:
            self.logger.debug(f"Raw socket WHOIS failed: {e}")
            return {}

    def _raw_whois_query(
        self, server: str, domain: str, port: int = 43
    ) -> str:
        """Send a raw WHOIS query to a server."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((server, port))
            sock.send(f"{domain}\r\n".encode("utf-8"))

            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break

            sock.close()

            # Try utf-8 first, then latin-1
            try:
                return response.decode("utf-8")
            except UnicodeDecodeError:
                return response.decode("latin-1", errors="replace")

        except Exception as e:
            self.logger.debug(f"Socket query to {server} failed: {e}")
            return ""

    def _extract_referral(self, text: str) -> Optional[str]:
        """Extract referral WHOIS server from response."""
        patterns = [
            r"Registrar WHOIS Server:\s*(.+)",
            r"Whois Server:\s*(.+)",
            r"refer:\s*(.+)",
            r"ReferralServer:\s*whois://(.+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                server = match.group(1).strip().rstrip(".")
                # Remove protocol prefix if present
                server = server.replace("whois://", "").replace("rwhois://", "")
                if server and "." in server:
                    return server
        return None

    def _parse_raw_whois(self, text: str) -> dict:
        """Parse raw WHOIS text into structured data."""
        result = {
            "domain_name": self.target,
            "registrar": "",
            "creation_date": "",
            "expiration_date": "",
            "updated_date": "",
            "name_servers": [],
            "registrant": "",
            "emails": [],
            "country": "",
            "status": [],
            "dnssec": "",
            "raw_text": text[:3000],
        }

        # Field extraction patterns
        field_map = {
            "registrar": [
                r"Registrar:\s*(.+)",
                r"Sponsoring Registrar:\s*(.+)",
                r"registrar:\s*(.+)",
            ],
            "creation_date": [
                r"Creation Date:\s*(.+)",
                r"Created Date:\s*(.+)",
                r"created:\s*(.+)",
                r"Registration Date:\s*(.+)",
                r"Created On:\s*(.+)",
                r"Domain Registration Date:\s*(.+)",
            ],
            "expiration_date": [
                r"Expir(?:y|ation) Date:\s*(.+)",
                r"Registry Expiry Date:\s*(.+)",
                r"paid-till:\s*(.+)",
                r"Expiration Date:\s*(.+)",
                r"Domain Expiration Date:\s*(.+)",
                r"expires:\s*(.+)",
            ],
            "updated_date": [
                r"Updated Date:\s*(.+)",
                r"Last Modified:\s*(.+)",
                r"last-updated:\s*(.+)",
                r"Last Updated On:\s*(.+)",
                r"changed:\s*(.+)",
            ],
            "registrant": [
                r"Registrant Organization:\s*(.+)",
                r"Registrant Name:\s*(.+)",
                r"org:\s*(.+)",
                r"Organization:\s*(.+)",
            ],
            "country": [
                r"Registrant Country:\s*(.+)",
                r"country:\s*(.+)",
            ],
            "dnssec": [
                r"DNSSEC:\s*(.+)",
                r"dnssec:\s*(.+)",
            ],
        }

        for field, patterns in field_map.items():
            for pattern in patterns:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    result[field] = match.group(1).strip()
                    break

        # Extract name servers
        ns_patterns = [
            r"Name Server:\s*(.+)",
            r"nserver:\s*(.+)",
            r"nameserver:\s*(.+)",
            r"DNS:\s*(.+)",
        ]
        for pattern in ns_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                for ns in matches:
                    ns_clean = ns.strip().lower().rstrip(".")
                    if ns_clean and ns_clean not in result["name_servers"]:
                        result["name_servers"].append(ns_clean)
                break

        # Extract domain status
        status_patterns = [
            r"Domain Status:\s*(.+)",
            r"Status:\s*(.+)",
            r"state:\s*(.+)",
        ]
        for pattern in status_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                for status in matches:
                    s = status.strip().split()[0]  # Take first word
                    if s and s not in result["status"]:
                        result["status"].append(s)

        # Extract emails
        email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        emails_found = re.findall(email_pattern, text)
        result["emails"] = list(set(
            e.lower() for e in emails_found
            if not e.endswith((".example.com", ".iana.org"))
        ))[:10]

        # Remove raw_text from final output (it's verbose)
        del result["raw_text"]

        return result

    # ═══════════════════════════════════════════════════════════
    #  Strategy 4: System whois command (Linux/Mac only)
    # ═══════════════════════════════════════════════════════════
    def _whois_via_command(self) -> dict:
        """Use system whois command (not available on Windows)."""
        try:
            proc = subprocess.run(
                ["whois", self.target],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if proc.returncode == 0 and proc.stdout:
                return self._parse_raw_whois(proc.stdout)
            return {}
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            self.logger.debug(f"System whois command failed: {e}")
            return {}

    # ═══════════════════════════════════════════════════════════
    #  Security checks
    # ═══════════════════════════════════════════════════════════
    def _check_security(self, data: dict) -> list:
        """Check WHOIS data for security-relevant findings."""
        issues = []

        # DNSSEC check
        dnssec = str(data.get("dnssec", "")).lower()
        if dnssec and ("unsigned" in dnssec or "no" in dnssec):
            issues.append({
                "severity": "low",
                "title": "DNSSEC Not Enabled",
                "detail": (
                    f"Domain {self.target} does not have DNSSEC enabled. "
                    f"This makes it vulnerable to DNS spoofing attacks."
                ),
            })

        # Expiration check
        exp_date = str(data.get("expiration_date", ""))
        if exp_date:
            try:
                from datetime import datetime
                # Try common date formats
                for fmt in [
                    "%Y-%m-%dT%H:%M:%SZ",
                    "%Y-%m-%dT%H:%M:%S%z",
                    "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%d",
                    "%d-%b-%Y",
                ]:
                    try:
                        exp = datetime.strptime(
                            exp_date.split("+")[0].split(".")[0].strip(),
                            fmt,
                        )
                        days_left = (exp - datetime.now()).days
                        if days_left < 0:
                            issues.append({
                                "severity": "high",
                                "title": "Domain Expired",
                                "detail": (
                                    f"Domain {self.target} expired "
                                    f"{abs(days_left)} days ago!"
                                ),
                            })
                        elif days_left < 30:
                            issues.append({
                                "severity": "medium",
                                "title": "Domain Expiring Soon",
                                "detail": (
                                    f"Domain {self.target} expires in "
                                    f"{days_left} days."
                                ),
                            })
                        break
                    except ValueError:
                        continue
            except Exception:
                pass

        # Privacy / redacted check
        registrant = str(data.get("registrant", "")).lower()
        if any(
            kw in registrant
            for kw in [
                "redacted", "privacy", "proxy", "whoisguard",
                "domains by proxy", "contact privacy",
                "withheld", "data protected",
            ]
        ):
            issues.append({
                "severity": "info",
                "title": "WHOIS Privacy Enabled",
                "detail": (
                    f"Domain {self.target} uses WHOIS privacy protection. "
                    f"Registrant: {data.get('registrant', 'N/A')}"
                ),
            })

        return issues

    # ═══════════════════════════════════════════════════════════
    #  Helpers
    # ═══════════════════════════════════════════════════════════
    @staticmethod
    def _normalize(value):
        """Normalize a WHOIS field value."""
        if isinstance(value, list):
            return value[0] if value else ""
        return value or ""

    @staticmethod
    def _normalize_list(value):
        """Normalize a WHOIS list field."""
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(v).lower().strip() for v in value if v]
        return []