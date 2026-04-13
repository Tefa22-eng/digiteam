# modules/passive/cert_transparency.py
"""
Certificate Transparency Module
Queries CT logs for SSL certificate information.
"""

from typing import Dict, Any

from core.base_module import BaseModule

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import ssl
    import socket
    SSL_AVAILABLE = True
except ImportError:
    SSL_AVAILABLE = False


class CertTransparencyModule(BaseModule):
    """Analyze SSL certificates and CT log data."""

    def __init__(self, target: str, config):
        super().__init__(target, config, module_name="Certificate Transparency")

    @property
    def description(self) -> str:
        return "SSL certificate and CT log analysis"

    @property
    def category(self) -> str:
        return "passive"

    def pre_check(self) -> bool:
        return REQUESTS_AVAILABLE or SSL_AVAILABLE

    def _run(self) -> Dict[str, Any]:
        self.logger.info(f"Analyzing certificates for {self.target}")

        result = {
            "certificates": [],
            "subdomains": [],
            "issuers": [],
            "security_issues": [],
        }

        # Get certificate info directly
        cert_info = self._get_ssl_certificate()
        if cert_info:
            result["certificates"].append(cert_info)
            if cert_info.get("san"):
                result["subdomains"].extend(cert_info["san"])
            if cert_info.get("issuer"):
                result["issuers"].append(cert_info["issuer"])

            # Check for issues
            if cert_info.get("expired"):
                result["security_issues"].append({
                    "severity": "high",
                    "title": "Expired SSL Certificate",
                    "detail": f"Certificate for {self.target} has expired",
                })
            if cert_info.get("self_signed"):
                result["security_issues"].append({
                    "severity": "medium",
                    "title": "Self-Signed Certificate",
                    "detail": f"Certificate for {self.target} is self-signed",
                })

        # Query CT logs via crt.sh
        ct_subs = self._query_ct_logs()
        if ct_subs:
            result["subdomains"].extend(ct_subs)

        result["subdomains"] = sorted(list(set(result["subdomains"])))

        return result

    def _get_ssl_certificate(self) -> dict:
        """Get SSL certificate information from the target."""
        if not SSL_AVAILABLE:
            return {}

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection(
                (self.target, 443), timeout=10
            ) as sock:
                with context.wrap_socket(
                    sock, server_hostname=self.target
                ) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if not cert:
                        # Try with verification disabled
                        cert_bin = ssock.getpeercert(binary_form=True)
                        return {"raw_available": bool(cert_bin)}

                    # Parse Subject Alternative Names
                    san = []
                    for type_name, value in cert.get("subjectAltName", []):
                        if type_name == "DNS":
                            san.append(value)

                    # Parse subject
                    subject = dict(
                        x[0] for x in cert.get("subject", ())
                    )

                    # Parse issuer
                    issuer = dict(
                        x[0] for x in cert.get("issuer", ())
                    )

                    return {
                        "subject": subject.get("commonName", ""),
                        "issuer": issuer.get("organizationName", ""),
                        "issuer_cn": issuer.get("commonName", ""),
                        "serial_number": cert.get("serialNumber", ""),
                        "not_before": cert.get("notBefore", ""),
                        "not_after": cert.get("notAfter", ""),
                        "san": san,
                        "version": cert.get("version", ""),
                        "expired": False,
                        "self_signed": (
                            subject.get("commonName") ==
                            issuer.get("commonName")
                        ),
                    }
        except ssl.SSLCertVerificationError:
            return {"error": "Certificate verification failed", "expired": True}
        except Exception as e:
            self.logger.debug(f"SSL certificate fetch failed: {e}")
            return {}

    def _query_ct_logs(self) -> list:
        """Query certificate transparency logs."""
        if not REQUESTS_AVAILABLE:
            return []

        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            resp = requests.get(url, timeout=30)
            if resp.status_code == 200:
                for entry in resp.json():
                    name = entry.get("name_value", "")
                    for n in name.split("\n"):
                        n = n.strip().lower()
                        if n and "*" not in n and n.endswith(self.target):
                            subdomains.add(n)
        except Exception as e:
            self.logger.debug(f"CT log query failed: {e}")

        return list(subdomains)