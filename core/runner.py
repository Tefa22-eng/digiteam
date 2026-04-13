# core/runner.py
"""
Core reconnaissance runner.
Orchestrates module execution with threading, progress tracking,
result aggregation, reporting, and post-processing.
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich import box

from core.base_module import BaseModule, ModuleResult, ModuleStatus
from core.config import ConfigManager
from core.report_engine import ReportEngine
from core.post_processor import PostProcessor
from utils.logger import setup_logger

# ── Passive modules ──────────────────────────────────────────────
from modules.passive.whois_lookup import WhoisModule
from modules.passive.dns_enum import DNSEnumModule
from modules.passive.subdomain_enum import SubdomainEnumModule
from modules.passive.cert_transparency import CertTransparencyModule
from modules.passive.wayback_urls import WaybackModule
from modules.passive.asn_intel import ASNIntelModule

# ── Active modules ───────────────────────────────────────────────
from modules.active.live_hosts import LiveHostsModule
from modules.active.port_scan import PortScanModule
from modules.active.dir_fuzz import DirFuzzModule
from modules.active.http_headers import HTTPHeadersModule
from modules.active.tech_detect import TechDetectModule
from modules.active.screenshot import ScreenshotModule

# ── API-backed passive modules ───────────────────────────────────
from integrations.shodan_api import ShodanModule
from integrations.censys_api import CensysModule
from integrations.virustotal_api import VirusTotalModule
from integrations.securitytrails_api import SecurityTrailsModule
from integrations.chaos_api import ChaosModule
from integrations.github_recon import GitHubReconModule
from integrations.builtwith_api import BuiltWithModule

console = Console()
logger = setup_logger("digiteam.runner")

STATUS_ICONS = {
    ModuleStatus.PENDING:   "[dim]⏳ Pending[/]",
    ModuleStatus.RUNNING:   "[bold yellow]⚡ Running[/]",
    ModuleStatus.COMPLETED: "[bold green]✓ Completed[/]",
    ModuleStatus.FAILED:    "[bold red]✗ Failed[/]",
    ModuleStatus.SKIPPED:   "[dim yellow]⊘ Skipped[/]",
}


class ReconRunner:
    """
    Main orchestrator for all reconnaissance operations.
    Manages module loading, parallel execution, live progress display,
    report generation, and post-processing.
    """

    def __init__(self, target: str, mode: int, config: ConfigManager):
        self.target = target
        self.mode = mode
        self.config = config
        self.results: Dict[str, ModuleResult] = {}
        self.modules: List[BaseModule] = []
        self._report_json_path: str = ""
        self._report_output_dir: str = ""

    # ══════════════════════════════════════════════════════════
    #  Module loading
    # ══════════════════════════════════════════════════════════

    def _get_passive_modules(self) -> List[BaseModule]:
        modules = []

        core_modules = {
            "whois":             WhoisModule,
            "dns":               DNSEnumModule,
            "subdomains":        SubdomainEnumModule,
            "cert_transparency": CertTransparencyModule,
            "wayback":           WaybackModule,
            "asn":               ASNIntelModule,
        }

        api_modules = {
            "shodan":          ShodanModule,
            "censys":          CensysModule,
            "virustotal":      VirusTotalModule,
            "securitytrails":  SecurityTrailsModule,
            "chaos":           ChaosModule,
            "github_recon":    GitHubReconModule,
            "builtwith":       BuiltWithModule,
        }

        for name, cls in core_modules.items():
            if self.config.is_module_enabled("passive", name):
                modules.append(cls(target=self.target, config=self.config))
                logger.debug(f"Loaded passive module: {name}")

        for name, cls in api_modules.items():
            if self.config.is_module_enabled("passive", name):
                modules.append(cls(target=self.target, config=self.config))
                logger.debug(f"Loaded API module: {name}")

        return modules

    def _get_active_modules(self) -> List[BaseModule]:
        modules = []
        module_map = {
            "live_hosts":   LiveHostsModule,
            "port_scan":    PortScanModule,
            "dir_fuzz":     DirFuzzModule,
            "http_headers": HTTPHeadersModule,
            "tech_detect":  TechDetectModule,
            "screenshots":  ScreenshotModule,
        }

        for name, cls in module_map.items():
            if self.config.is_module_enabled("active", name):
                modules.append(cls(target=self.target, config=self.config))
                logger.debug(f"Loaded active module: {name}")

        return modules

    def _load_modules(self):
        if self.mode in (1, 3):
            self.modules.extend(self._get_passive_modules())
        if self.mode in (2, 3):
            self.modules.extend(self._get_active_modules())
        logger.info(f"Loaded {len(self.modules)} modules")

    # ══════════════════════════════════════════════════════════
    #  Display helpers
    # ══════════════════════════════════════════════════════════

    def _build_status_table(self) -> Table:
        table = Table(
            title="Module Execution Status",
            box=box.ROUNDED,
            border_style="cyan",
            title_style="bold magenta",
            show_header=True,
            header_style="bold white",
            padding=(0, 1),
        )
        table.add_column("Module",   style="bold white", width=30)
        table.add_column("Category", style="dim cyan",   width=12)
        table.add_column("Status",                       width=20)
        table.add_column("Time",     style="dim white",  width=10, justify="right")

        for module in self.modules:
            name   = module.module_name
            result = self.results.get(name, module.result)
            status = STATUS_ICONS.get(result.status, str(result.status))
            t = (
                f"{result.execution_time:.1f}s"
                if result.execution_time > 0
                else "-"
            )
            table.add_row(name, module.category, status, t)

        return table

    def _build_api_key_table(self) -> Table:
        table = Table(
            title="API Key Status",
            box=box.SIMPLE,
            border_style="dim",
            title_style="bold cyan",
            show_header=True,
            header_style="bold white",
        )
        table.add_column("Service", style="white", width=20)
        table.add_column("Status",                 width=15)

        display_names = {
            "shodan":          "Shodan",
            "censys_token":    "Censys",
            "virustotal":      "VirusTotal",
            "securitytrails":  "SecurityTrails",
            "chaos":           "Chaos (PD)",
            "github_token":    "GitHub",
            "builtwith":       "BuiltWith",
        }

        for key, configured in self.config.get_all_api_keys_status().items():
            name = display_names.get(key, key)
            if configured:
                table.add_row(name, "[bold green]✓ Active[/]")
            else:
                table.add_row(name, "[dim red]✗ Missing[/]")

        return table

    # ══════════════════════════════════════════════════════════
    #  Execution
    # ══════════════════════════════════════════════════════════

    def _execute_module(self, module: BaseModule) -> ModuleResult:
        result = module.execute()
        self.results[module.module_name] = result
        return result

    def execute(self):
        """Full pipeline: load → execute → report → post-process."""
        self._load_modules()

        if not self.modules:
            console.print(
                "[bold red]✗ No modules to execute. "
                "Check your configuration.[/]"
            )
            return

        mode_names = {1: "Passive", 2: "Active", 3: "Full"}
        console.print(
            Panel(
                f"[bold white]Target:[/]  {self.target}\n"
                f"[bold white]Mode:[/]    {mode_names[self.mode]} Reconnaissance\n"
                f"[bold white]Modules:[/] {len(self.modules)}\n"
                f"[bold white]Threads:[/] {self.config.threads}",
                title="[bold cyan]Scan Configuration[/]",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )

        console.print(self._build_api_key_table())
        console.print()

        for module in self.modules:
            self.results[module.module_name] = module.result

        start_time = time.time()

        with Live(
            self._build_status_table(),
            console=console,
            refresh_per_second=4,
        ) as live:
            max_workers = min(self.config.threads, len(self.modules))
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_module = {
                    executor.submit(self._execute_module, mod): mod
                    for mod in self.modules
                }
                for future in as_completed(future_to_module):
                    mod = future_to_module[future]
                    try:
                        future.result()
                    except Exception as e:
                        self.results[mod.module_name].status = (
                            ModuleStatus.FAILED
                        )
                        self.results[mod.module_name].errors.append(str(e))
                        logger.error(
                            f"Unhandled error in {mod.module_name}: {e}"
                        )
                    live.update(self._build_status_table())

        total_time = time.time() - start_time

        self._print_summary(total_time)
        self._generate_reports(total_time)
        self._run_post_processing()

        console.print(
            f"\n[bold green]✓ All done! "
            f"Results saved to: [white]{self._report_output_dir}[/][/]\n"
        )

    # ══════════════════════════════════════════════════════════
    #  Summary + Reports
    # ══════════════════════════════════════════════════════════

    def _print_summary(self, total_time: float):
        completed = sum(
            1 for r in self.results.values()
            if r.status == ModuleStatus.COMPLETED
        )
        failed = sum(
            1 for r in self.results.values()
            if r.status == ModuleStatus.FAILED
        )
        skipped = sum(
            1 for r in self.results.values()
            if r.status == ModuleStatus.SKIPPED
        )

        console.print()
        t = Table(
            title="Scan Summary",
            box=box.ROUNDED,
            border_style="green",
            title_style="bold green",
        )
        t.add_column("Metric", style="bold white")
        t.add_column("Value",  style="bold cyan", justify="right")
        t.add_row("Total Modules", str(len(self.modules)))
        t.add_row("Completed",     f"[green]{completed}[/]")
        t.add_row("Failed",        f"[red]{failed}[/]")
        t.add_row("Skipped",       f"[yellow]{skipped}[/]")
        t.add_row("Total Time",    f"{total_time:.1f}s")
        console.print(t)

    def _generate_reports(self, total_time: float):
        console.print("\n[bold cyan]>> Generating reports...[/]")

        engine = ReportEngine(
            target=self.target,
            results=self.results,
            config=self.config,
            total_time=total_time,
        )

        json_path = engine.generate_json()
        self._report_json_path  = json_path
        self._report_output_dir = str(engine.output_dir)
        console.print(f"  [green]✓[/] JSON report: [bold]{json_path}[/]")

        if not self.config.get("general.json_only", False):
            html_path = engine.generate_html()
            console.print(f"  [green]✓[/] HTML report: [bold]{html_path}[/]")

    # ══════════════════════════════════════════════════════════
    #  Post-processing
    # ══════════════════════════════════════════════════════════

    def _run_post_processing(self):
        """
        Extract all subdomains + URLs from report.json,
        probe them with httpx, and write 4 filtered .txt files.
        """
        if not self._report_json_path:
            logger.warning("No JSON report path — skipping post-processing")
            return

        processor = PostProcessor(
            report_json_path=self._report_json_path,
            output_dir=self._report_output_dir,
            config=self.config,
        )
        processor.run()