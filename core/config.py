# core/config.py
"""
Configuration management for DIGI TEAM.
Handles loading, validation, and access to configuration values
including API keys and tool settings.
"""

import os
import yaml
from pathlib import Path
from typing import Any
from utils.logger import setup_logger

logger = setup_logger("digiteam.config")

DEFAULT_CONFIG = {
    "general": {
        "threads": 10,
        "timeout": 30,
        "output_dir": "reports",
        "json_only": False,
        "user_agent": "DIGI-TEAM-Recon/2.0",
    },
    "api_keys": {
        "shodan": "",
        "censys_token": "",
        "virustotal": "",
        "securitytrails": "",
        "chaos": "",
        "github_token": "",
        "builtwith": "",
    },
    "tools": {
        "subfinder": {
            "enabled": True,
            "path": "subfinder",
            "timeout": 300,
        },
        "httpx": {
            "enabled": True,
            "path": "httpx",
            "timeout": 300,
            "rate_limit": 150,
        },
        "naabu": {
            "enabled": True,
            "path": "naabu",
            "timeout": 600,
            "top_ports": 1000,
        },
        "nmap": {
            "enabled": True,
            "path": "nmap",
            "timeout": 900,
            "arguments": "-sV -sC",
        },
        "ffuf": {
            "enabled": True,
            "path": "ffuf",
            "timeout": 600,
            "wordlist": "/usr/share/wordlists/dirb/common.txt",
            "rate_limit": 100,
        },
        "waybackurls": {
            "enabled": True,
            "path": "waybackurls",
            "timeout": 300,
        },
        "gau": {
            "enabled": True,
            "path": "gau",
            "timeout": 300,
        },
        "gowitness": {
            "enabled": True,
            "path": "gowitness",
            "timeout": 600,
        },
    },
    "modules": {
        "passive": {
            "whois": True,
            "dns": True,
            "subdomains": True,
            "cert_transparency": True,
            "shodan": True,
            "censys": True,
            "virustotal": True,
            "securitytrails": True,
            "chaos": True,
            "github_recon": True,
            "builtwith": True,
            "wayback": True,
            "asn": True,
        },
        "active": {
            "live_hosts": True,
            "port_scan": True,
            "dir_fuzz": True,
            "http_headers": True,
            "tech_detect": True,
            "screenshots": True,
        },
    },
}


class ConfigManager:
    """Manages application configuration with file-based persistence."""

    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = Path(config_path)
        self._config = {}
        self._load_config()

    def _load_config(self):
        """Load configuration from YAML file, falling back to defaults."""
        if self.config_path.exists():
            try:
                with open(self.config_path, "r") as f:
                    file_config = yaml.safe_load(f) or {}
                self._config = self._deep_merge(DEFAULT_CONFIG, file_config)
                logger.info(f"Configuration loaded from {self.config_path}")
            except yaml.YAMLError as e:
                logger.warning(
                    f"Failed to parse config file: {e}. Using defaults."
                )
                self._config = DEFAULT_CONFIG.copy()
        else:
            logger.info(
                "No config file found. Using defaults and creating template."
            )
            self._config = DEFAULT_CONFIG.copy()
            self._save_default_config()

        self._load_env_overrides()

    def _deep_merge(self, base: dict, override: dict) -> dict:
        """Deep merge two dictionaries, with override taking precedence."""
        result = base.copy()
        for key, value in override.items():
            if (
                key in result
                and isinstance(result[key], dict)
                and isinstance(value, dict)
            ):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    def _load_env_overrides(self):
        """Override API keys from environment variables if present."""
        env_mappings = {
            "SHODAN_API_KEY": "api_keys.shodan",
            "CENSYS_API_TOKEN": "api_keys.censys_token",
            "VIRUSTOTAL_API_KEY": "api_keys.virustotal",
            "SECURITYTRAILS_API_KEY": "api_keys.securitytrails",
            "CHAOS_API_KEY": "api_keys.chaos",
            "GITHUB_TOKEN": "api_keys.github_token",
            "BUILTWITH_API_KEY": "api_keys.builtwith",
        }

        for env_var, config_path in env_mappings.items():
            value = os.environ.get(env_var)
            if value:
                self.set(config_path, value)
                logger.debug(f"Loaded {env_var} from environment")

    def _save_default_config(self):
        """Save a default config template to disk."""
        try:
            with open(self.config_path, "w") as f:
                yaml.dump(
                    DEFAULT_CONFIG,
                    f,
                    default_flow_style=False,
                    sort_keys=False,
                )
            logger.info(f"Default config saved to {self.config_path}")
        except IOError as e:
            logger.warning(f"Could not save default config: {e}")

    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get a config value using dot-notation path.
        Example: config.get("api_keys.shodan")
        """
        keys = key_path.split(".")
        value = self._config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value

    def set(self, key_path: str, value: Any):
        """Set a config value using dot-notation path."""
        keys = key_path.split(".")
        config = self._config
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        config[keys[-1]] = value

    def has_api_key(self, service: str) -> bool:
        """Check if an API key is configured for a given service."""
        key = self.get(f"api_keys.{service}", "")
        return bool(key and key.strip() and not key.startswith("your_"))

    def is_module_enabled(self, recon_type: str, module_name: str) -> bool:
        """Check if a specific module is enabled."""
        return self.get(f"modules.{recon_type}.{module_name}", False)

    def is_tool_enabled(self, tool_name: str) -> bool:
        """Check if an external tool integration is enabled."""
        return self.get(f"tools.{tool_name}.enabled", False)

    def get_all_api_keys_status(self) -> dict:
        """Return a summary of which API keys are configured."""
        services = [
            "shodan", "censys_token", "virustotal",
            "securitytrails", "chaos", "github_token", "builtwith",
        ]
        return {svc: self.has_api_key(svc) for svc in services}

    @property
    def threads(self) -> int:
        return self.get("general.threads", 10)

    @property
    def timeout(self) -> int:
        return self.get("general.timeout", 30)

    @property
    def output_dir(self) -> str:
        return self.get("general.output_dir", "reports")