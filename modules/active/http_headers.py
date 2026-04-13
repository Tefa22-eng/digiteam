# modules/active/http_headers.py
"""
HTTP Headers Analysis Module
Analyzes HTTP response headers for security misconfigurations.
"""

from typing import Dict, Any, List

from core.base_module import BaseModule

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class HTTPHeadersModule(BaseModule):
    """Analyze HTTP security headers."""

    SECURITY_HEADERS = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Permissions-Policy",
        "Feature-Policy",
        "Cross-Origin-Embedder-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Resource-Policy",
    ]

    INFO_HEADERS = [
        "Server",
        "X-Powered-By",
        "X-AspNet-Version",
        "X-Generator",
        "Via",
    ]

    def __init__(self, target: str, config):
        super().__init__(target, config, module_name="HTTP Headers Analysis")

    @property
    def description(self) -> str:
        return "HTTP security header analysis"

    @property
    def category(self) -> str:
        return "active"

    def pre_check(self) -> bool:
        return REQUESTS_AVAILABLE

    def _run(self) -> Dict[str, Any]:
        self.logger.info(f"Analyzing HTTP headers for {self.target}")

        headers_data = {}
        security_issues = []
        technologies = []

        for scheme in ["https", "http"]:
            url = f"{scheme}://{self.target}"
            try:
                resp = requests.get(
                    url,
                    timeout=10,
                    allow_redirects=True,
                    verify=False,
                    headers={"User-Agent": self.config.get(
                        "general.user_agent", "DIGI-TEAM/2.0"
                    )},
                )

                headers_data = dict(resp.headers)

                # Check missing security headers
                for header in self.SECURITY_HEADERS:
                    if header.lower() not in {
                        k.lower() for k in resp.headers
                    }:
                        severity = "medium" if header in [
                            "Strict-Transport-Security",
                            "Content-Security-Policy",
                        ] else "low"
                        security_issues.append({
                            "severity": severity,
                            "title": f"Missing {header}",
                            "detail": f"The {header} header is not set on {url}",
                        })

                # Check information disclosure headers
                for header in self.INFO_HEADERS:
                    for resp_header, value in resp.headers.items():
                        if resp_header.lower() == header.lower():
                            technologies.append(f"{header}: {value}")
                            security_issues.append({
                                "severity": "low",
                                "title": f"Information Disclosure: {header}",
                                "detail": f"{header} reveals: {value}",
                            })

                # Check cookie security
                for cookie in resp.cookies:
                    issues = []
                    if not cookie.secure:
                        issues.append("missing Secure flag")
                    if "httponly" not in str(
                        cookie._rest
                    ).lower() and not getattr(
                        cookie, "has_nonstandard_attr", lambda x: False
                    )("httponly"):
                        issues.append("missing HttpOnly flag")

                    if issues:
                        security_issues.append({
                            "severity": "medium",
                            "title": f"Insecure Cookie: {cookie.name}",
                            "detail": f"Cookie '{cookie.name}' has {', '.join(issues)}",
                        })

                break  # Use HTTPS if it works
            except requests.exceptions.SSLError:
                continue
            except Exception as e:
                self.logger.debug(f"Failed to fetch {url}: {e}")
                continue

        return {
            "headers": headers_data,
            "security_issues": security_issues,
            "technologies": technologies,
            "missing_security_headers": [
                h for h in self.SECURITY_HEADERS
                if h.lower() not in {k.lower() for k in headers_data}
            ],
        }