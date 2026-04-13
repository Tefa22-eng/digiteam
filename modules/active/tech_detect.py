# modules/active/tech_detect.py
"""
Technology Detection Module
Identifies technologies, frameworks, and CMS used by the target.
"""

import re
from typing import Dict, Any, List

from core.base_module import BaseModule

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class TechDetectModule(BaseModule):
    """Detect technologies and frameworks used by the target."""

    # Signature database for technology detection
    SIGNATURES = {
        "WordPress": {
            "headers": ["x-powered-by: wp"],
            "body": [
                "wp-content", "wp-includes", "wp-json",
                'name="generator" content="WordPress',
            ],
        },
        "Drupal": {
            "headers": ["x-generator: drupal", "x-drupal"],
            "body": ["Drupal.settings", "sites/default/files"],
        },
        "Joomla": {
            "headers": [],
            "body": ["/media/system/js/", 'name="generator" content="Joomla'],
        },
        "React": {
            "headers": [],
            "body": ["__NEXT_DATA__", "react-root", "_reactRootContainer"],
        },
        "Angular": {
            "headers": [],
            "body": ["ng-version", "ng-app", "angular.min.js"],
        },
        "Vue.js": {
            "headers": [],
            "body": ["__vue__", "vue.min.js", "vue.js"],
        },
        "jQuery": {
            "headers": [],
            "body": ["jquery.min.js", "jquery.js", "jQuery"],
        },
        "Bootstrap": {
            "headers": [],
            "body": ["bootstrap.min.css", "bootstrap.min.js"],
        },
        "Nginx": {
            "headers": ["server: nginx"],
            "body": [],
        },
        "Apache": {
            "headers": ["server: apache"],
            "body": [],
        },
        "CloudFlare": {
            "headers": ["server: cloudflare", "cf-ray"],
            "body": [],
        },
        "AWS": {
            "headers": ["x-amz", "server: amazons3", "server: awselb"],
            "body": [],
        },
        "PHP": {
            "headers": ["x-powered-by: php"],
            "body": [],
        },
        "ASP.NET": {
            "headers": ["x-powered-by: asp.net", "x-aspnet-version"],
            "body": ["__VIEWSTATE", "__EVENTVALIDATION"],
        },
        "Express.js": {
            "headers": ["x-powered-by: express"],
            "body": [],
        },
        "Laravel": {
            "headers": [],
            "body": ["laravel_session", "csrf-token"],
        },
        "Django": {
            "headers": [],
            "body": ["csrfmiddlewaretoken", "django"],
        },
        "Next.js": {
            "headers": ["x-powered-by: next.js"],
            "body": ["__NEXT_DATA__", "_next/static"],
        },
        "Varnish": {
            "headers": ["via: varnish", "x-varnish"],
            "body": [],
        },
    }

    def __init__(self, target: str, config):
        super().__init__(target, config, module_name="Technology Detection")

    @property
    def description(self) -> str:
        return "Web technology and framework detection"

    @property
    def category(self) -> str:
        return "active"

    def pre_check(self) -> bool:
        return REQUESTS_AVAILABLE

    def _run(self) -> Dict[str, Any]:
        self.logger.info(f"Detecting technologies on {self.target}")

        detected = []
        raw_headers = {}
        meta_info = {}

        for scheme in ["https", "http"]:
            url = f"{scheme}://{self.target}"
            try:
                resp = requests.get(
                    url,
                    timeout=15,
                    allow_redirects=True,
                    verify=False,
                    headers={"User-Agent": self.config.get(
                        "general.user_agent", "DIGI-TEAM/2.0"
                    )},
                )

                raw_headers = dict(resp.headers)
                body = resp.text[:50000]  # Limit body analysis
                headers_lower = {
                    k.lower(): v.lower() for k, v in resp.headers.items()
                }

                # Check signatures
                for tech, sigs in self.SIGNATURES.items():
                    found = False

                    # Header checks
                    for h_sig in sigs["headers"]:
                        parts = h_sig.split(": ", 1)
                        if len(parts) == 2:
                            h_name, h_value = parts
                            if h_name in headers_lower and h_value in headers_lower[h_name]:
                                found = True
                                break
                        else:
                            for h_val in headers_lower.values():
                                if h_sig in h_val:
                                    found = True
                                    break

                    # Body checks
                    if not found:
                        for b_sig in sigs["body"]:
                            if b_sig.lower() in body.lower():
                                found = True
                                break

                    if found:
                        detected.append(tech)

                # Extract meta generator
                gen_match = re.search(
                    r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)',
                    body,
                    re.IGNORECASE,
                )
                if gen_match:
                    meta_info["generator"] = gen_match.group(1)
                    if gen_match.group(1) not in detected:
                        detected.append(gen_match.group(1))

                # Check powered-by
                powered = resp.headers.get("X-Powered-By", "")
                if powered and powered not in detected:
                    detected.append(powered)

                # Server header
                server = resp.headers.get("Server", "")
                if server:
                    meta_info["server"] = server

                break  # Success, don't try HTTP
            except requests.exceptions.SSLError:
                continue
            except Exception as e:
                self.logger.debug(f"Tech detection failed for {url}: {e}")
                continue

        return {
            "technologies": sorted(list(set(detected))),
            "server_info": meta_info,
            "headers_summary": {
                k: v for k, v in raw_headers.items()
                if k.lower() in [
                    "server", "x-powered-by", "x-generator",
                    "x-aspnet-version", "x-framework",
                ]
            },
        }