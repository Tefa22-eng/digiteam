# modules/active/screenshot.py
"""
Screenshot Collection Module
Takes screenshots of discovered live hosts.
"""

import json
from pathlib import Path
from typing import Dict, Any

from core.base_module import BaseModule
from utils.helpers import run_command, is_tool_installed


class ScreenshotModule(BaseModule):
    """Capture screenshots of web targets."""

    def __init__(self, target: str, config):
        super().__init__(target, config, module_name="Screenshot Capture")

    @property
    def description(self) -> str:
        return "Visual screenshot capture of live hosts"

    @property
    def category(self) -> str:
        return "active"

    def pre_check(self) -> bool:
        if not is_tool_installed("gowitness"):
            self.result.warnings.append(
                "gowitness not installed. Screenshots will be skipped."
            )
            self.logger.warning("gowitness not found")
            return False
        return True

    def _run(self) -> Dict[str, Any]:
        self.logger.info(f"Taking screenshots for {self.target}")

        output_dir = Path(self.config.output_dir) / "screenshots"
        output_dir.mkdir(parents=True, exist_ok=True)

        timeout = self.config.get("tools.gowitness.timeout", 600)

        urls = [
            f"https://{self.target}",
            f"http://{self.target}",
        ]

        screenshots = []
        for url in urls:
            cmd = [
                "gowitness", "single",
                "--url", url,
                "--screenshot-path", str(output_dir),
                "--timeout", "10",
            ]

            code, stdout, stderr = run_command(cmd, timeout=60)
            if code == 0:
                screenshots.append({
                    "url": url,
                    "status": "captured",
                    "output_dir": str(output_dir),
                })
                self.logger.info(f"Screenshot captured: {url}")
            else:
                screenshots.append({
                    "url": url,
                    "status": "failed",
                    "error": stderr[:200] if stderr else "Unknown error",
                })

        return {
            "screenshots": screenshots,
            "output_directory": str(output_dir),
            "total_captured": sum(
                1 for s in screenshots if s["status"] == "captured"
            ),
        }