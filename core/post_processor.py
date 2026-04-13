# core/post_processor.py
"""
Post-processing engine for DIGI TEAM.
Reads report.json, extracts subdomains and URLs,
probes them with httpx, and writes 4 clean output files:
  - all_subdomains.txt
  - alive_subdomains.txt
  - all_urls.txt
  - alive_urls.txt
"""

import json
import os
import re
import subprocess
import tempfile
import urllib.parse
from pathlib import Path
from typing import List, Set, Dict

from rich.console import Console
from rich.table import Table
from rich import box

from utils.logger import setup_logger

console = Console()
logger = setup_logger("digiteam.postprocessor")


class PostProcessor:
    """
    Reads report.json and produces 4 plain-text files:
      all_subdomains.txt   — every subdomain found by any module
      alive_subdomains.txt — only httpx-confirmed alive subdomains
      all_urls.txt         — every URL / endpoint found
      alive_urls.txt       — only httpx-confirmed alive URLs
    """

    def __init__(
        self,
        report_json_path: str,
        output_dir: str,
        config=None,
    ):
        self.report_json_path = Path(report_json_path)
        self.output_dir       = Path(output_dir)
        self.config           = config
        self.report_data: dict = {}

    # ══════════════════════════════════════════════════════════
    #  Load report
    # ══════════════════════════════════════════════════════════

    def load_report(self) -> bool:
        try:
            with open(self.report_json_path, "r", encoding="utf-8") as f:
                self.report_data = json.load(f)
            logger.info(f"Loaded report: {self.report_json_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load report: {e}")
            console.print(f"  [red]✗ Cannot load report.json: {e}[/]")
            return False

    # ══════════════════════════════════════════════════════════
    #  Extract subdomains
    # ══════════════════════════════════════════════════════════

    def extract_subdomains(self) -> List[str]:
        """
        Walk every field in report.json that can contain subdomains
        and return a sorted, deduplicated list of bare hostnames.
        """
        subs: Set[str] = set()
        summary = self.report_data.get("summary", {})

        # summary.subdomains
        for s in summary.get("subdomains", []):
            if isinstance(s, str) and s.strip():
                subs.add(s.strip().lower())

        # summary.live_hosts
        for host in summary.get("live_hosts", []):
            h = ""
            if isinstance(host, dict):
                h = host.get("host", "") or host.get("url", "")
            elif isinstance(host, str):
                h = host
            if h:
                extracted = self._host_from_url(h)
                if extracted:
                    subs.add(extracted)

        # every module's data block
        for mod_data in self.report_data.get("modules", {}).values():
            data = mod_data.get("data", {})
            if not data:
                continue

            # subdomains list
            for s in data.get("subdomains", []):
                if isinstance(s, str) and s.strip():
                    subs.add(s.strip().lower())

            # associated_domains (SecurityTrails)
            for s in data.get("associated_domains", []):
                if isinstance(s, str) and s.strip():
                    subs.add(s.strip().lower())

            # hostnames inside host objects (Shodan / Censys)
            for host in data.get("hosts", []):
                if isinstance(host, dict):
                    for hn in host.get("hostnames", []):
                        if isinstance(hn, str) and hn.strip():
                            subs.add(hn.strip().lower())

        cleaned = sorted(
            s for s in subs
            if s and "." in s and not s.startswith(".")
        )
        logger.info(f"Extracted {len(cleaned)} unique subdomains")
        return cleaned

    # ══════════════════════════════════════════════════════════
    #  Extract URLs
    # ══════════════════════════════════════════════════════════

    def extract_urls(self) -> List[str]:
        """
        Walk every field in report.json that can contain URLs
        and return a sorted, deduplicated list of full HTTP URLs.
        """
        urls: Set[str] = set()
        summary = self.report_data.get("summary", {})

        # summary.endpoints
        for ep in summary.get("endpoints", []):
            if isinstance(ep, str) and ep.strip().startswith("http"):
                urls.add(ep.strip())

        # summary.live_hosts
        for host in summary.get("live_hosts", []):
            if isinstance(host, dict):
                u = host.get("url", "")
            else:
                u = str(host)
            if u and u.strip().startswith("http"):
                urls.add(u.strip())

        # every module's data block
        for mod_data in self.report_data.get("modules", {}).values():
            data = mod_data.get("data", {})
            if not data:
                continue

            # urls / endpoints lists
            for key in ("urls", "endpoints"):
                val = data.get(key, [])
                if isinstance(val, list):
                    for u in val:
                        if isinstance(u, str) and u.strip().startswith("http"):
                            urls.add(u.strip())

            # directories (dir-fuzz results)
            for d in data.get("directories", []):
                if isinstance(d, dict):
                    u = d.get("url", "")
                elif isinstance(d, str):
                    u = d
                else:
                    u = ""
                if u and u.strip().startswith("http"):
                    urls.add(u.strip())

            # wayback categories — may be dict OR list
            categories = data.get("categories", {})
            if isinstance(categories, dict):
                for cat_urls in categories.values():
                    if isinstance(cat_urls, list):
                        for u in cat_urls:
                            if isinstance(u, str) and u.strip().startswith("http"):
                                urls.add(u.strip())
            elif isinstance(categories, list):
                for u in categories:
                    if isinstance(u, str) and u.strip().startswith("http"):
                        urls.add(u.strip())

        cleaned = sorted(urls)
        logger.info(f"Extracted {len(cleaned)} unique URLs")
        return cleaned

    # ══════════════════════════════════════════════════════════
    #  httpx binary discovery
    # ══════════════════════════════════════════════════════════

    def _find_httpx(self) -> str:
        """
        Find the httpx binary.
        Checks PATH first, then common Go install locations
        on both Windows and Linux/Mac.
        """
        import shutil

        # 1. PATH
        found = shutil.which("httpx")
        if found:
            logger.debug(f"httpx found in PATH: {found}")
            return found

        # 2. Common Go bin directories
        home     = Path.home()
        username = os.environ.get("USERNAME", os.environ.get("USER", ""))

        candidates = [
            # Windows
            home / "go" / "bin" / "httpx.exe",
            Path(f"C:/Users/{username}/go/bin/httpx.exe"),
            Path(f"C:/Users/{username}/AppData/Local/go/bin/httpx.exe"),
            # Linux / Mac
            home / "go" / "bin" / "httpx",
            Path("/usr/local/bin/httpx"),
            Path("/usr/bin/httpx"),
            Path(f"/home/{username}/go/bin/httpx"),
            Path("/root/go/bin/httpx"),
        ]

        for candidate in candidates:
            if candidate.exists():
                logger.debug(f"httpx found at: {candidate}")
                return str(candidate)

        logger.error("httpx binary not found anywhere")
        return ""

    # ══════════════════════════════════════════════════════════
    #  httpx probing
    # ══════════════════════════════════════════════════════════

    def probe_with_httpx(
        self,
        targets: List[str],
        label: str = "targets",
    ) -> List[str]:
        """
        Probe a list of hostnames or URLs with httpx.
        Uses a temp input file and Popen with CREATE_NO_WINDOW
        so it works correctly on Windows.
        Returns a sorted list of alive URLs.
        """
        if not targets:
            logger.warning(f"No {label} to probe")
            return []

        httpx_bin = self._find_httpx()
        if not httpx_bin:
            console.print(
                "  [red]✗ httpx not found.[/] "
                "[dim]Install: go install "
                "github.com/projectdiscovery/httpx/cmd/httpx@latest[/]"
            )
            console.print(
                r"  [dim]Then: setx PATH "
                r'"%PATH%;%USERPROFILE%\go\bin" (restart terminal)[/]'
            )
            return []

        # Write targets to a temp file
        tmp_path = ""
        try:
            tmp_fd, tmp_path = tempfile.mkstemp(
                suffix=".txt", prefix="dt_httpx_"
            )
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
                fh.write("\n".join(targets) + "\n")

            logger.info(
                f"httpx input written to {tmp_path} "
                f"({len(targets)} {label})"
            )

            # Build flags
            rate    = 150
            threads = 50
            if self.config:
                rate    = int(self.config.get("tools.httpx.rate_limit", 150))
                threads = min(int(self.config.threads) * 5, 100)

            # Cap to safe values on Windows
            threads = min(threads, 50)
            rate    = min(rate, 150)

            cmd = [
                httpx_bin,
                "-l",           tmp_path,
                "-silent",
                "-no-color",
                "-timeout",     "10",
                "-rate-limit",  str(rate),
                "-threads",     str(threads),
                "-retries",     "1",
                "-follow-redirects",
            ]

            logger.info(f"Running: {' '.join(cmd)}")

            # Give httpx enough wall time
            proc_timeout = max(120, len(targets) // 5 + 60)

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                # Prevents a black console window on Windows
                creationflags=(
                    subprocess.CREATE_NO_WINDOW
                    if os.name == "nt"
                    else 0
                ),
            )

            try:
                stdout_bytes, stderr_bytes = proc.communicate(
                    timeout=proc_timeout
                )
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout_bytes, stderr_bytes = proc.communicate()
                logger.warning(
                    f"httpx timed out after {proc_timeout}s for {label}"
                )
                console.print(
                    f"  [yellow]⚠ httpx timed out "
                    f"(>{proc_timeout}s) — partial results only[/]"
                )

            stdout_text = stdout_bytes.decode("utf-8", errors="replace")
            stderr_text = stderr_bytes.decode("utf-8", errors="replace")

            logger.debug(f"httpx returncode : {proc.returncode}")
            logger.debug(
                f"httpx stderr     : "
                f"{stderr_text[:300] if stderr_text else 'none'}"
            )
            logger.debug(f"httpx stdout len : {len(stdout_text)} chars")

            # Parse — each alive host is one URL per line
            alive: List[str] = []
            ansi_escape = re.compile(r"\x1b\[[0-9;]*m")

            for line in stdout_text.splitlines():
                line = ansi_escape.sub("", line).strip()
                if line.startswith("http://") or line.startswith("https://"):
                    alive.append(line)

            if proc.returncode != 0 and not alive:
                logger.warning(
                    f"httpx exited {proc.returncode}: "
                    f"{stderr_text[:200]}"
                )

            alive = sorted(set(alive))
            logger.info(
                f"httpx: {len(alive)} alive / {len(targets)} {label}"
            )
            return alive

        except FileNotFoundError:
            logger.error(f"Cannot execute httpx binary: {httpx_bin}")
            console.print(f"  [red]✗ Cannot run httpx: {httpx_bin}[/]")
            return []
        except Exception as e:
            logger.error(f"Unexpected httpx error: {e}")
            console.print(f"  [red]✗ httpx error: {e}[/]")
            return []
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    # ══════════════════════════════════════════════════════════
    #  Write helpers
    # ══════════════════════════════════════════════════════════

    def _write_txt(self, path: Path, lines: List[str]):
        """Write a list of strings (one per line) to a UTF-8 text file."""
        with open(path, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(line + "\n")
        logger.info(f"Wrote {len(lines)} lines → {path.name}")

    # ══════════════════════════════════════════════════════════
    #  URL deduplication
    # ══════════════════════════════════════════════════════════

    @staticmethod
    def _dedupe_urls(urls: List[str], max_count: int = 5000) -> List[str]:
        """
        Collapse URLs to unique (scheme + host + path) combinations,
        discarding query strings.  This prevents httpx from probing
        10 000+ parameterised Wayback variants of the same page.
        """
        seen:   Set[str]  = set()
        result: List[str] = []

        for url in urls:
            try:
                p   = urllib.parse.urlparse(url)
                key = f"{p.scheme}://{p.netloc}{p.path}".rstrip("/").lower()
                if key not in seen:
                    seen.add(key)
                    result.append(f"{p.scheme}://{p.netloc}{p.path}")
            except Exception:
                if url not in seen:
                    seen.add(url)
                    result.append(url)

        if len(result) > max_count:
            logger.warning(
                f"URL list capped: {len(result)} → {max_count}"
            )
            result = result[:max_count]

        return result

    # ══════════════════════════════════════════════════════════
    #  Hostname extraction
    # ══════════════════════════════════════════════════════════

    @staticmethod
    def _host_from_url(url: str) -> str:
        """Return bare hostname from a URL or plain hostname string."""
        url = url.strip()
        for prefix in ("https://", "http://", "ftp://"):
            if url.lower().startswith(prefix):
                url = url[len(prefix):]
                break
        return (
            url.split("/")[0]
               .split(":")[0]
               .split("?")[0]
               .lower()
               .strip()
        )

    # ══════════════════════════════════════════════════════════
    #  Main pipeline
    # ══════════════════════════════════════════════════════════

    def run(self):
        """
        Full post-processing pipeline:
          1. Load report.json
          2. Extract subdomains + URLs
          3. Write all_subdomains.txt and all_urls.txt immediately
          4. Probe with httpx
          5. Write alive_subdomains.txt and alive_urls.txt
          6. Print results table
        """
        console.print(
            "\n[bold cyan]>> Post-Processing: "
            "Probing alive targets with httpx...[/]\n"
        )

        if not self.load_report():
            return

        # ── Step 1: Extract ──────────────────────────────────
        all_subs = self.extract_subdomains()
        all_urls = self.extract_urls()

        console.print(
            f"  [dim]>[/] Extracted "
            f"[bold cyan]{len(all_subs)}[/] subdomains and "
            f"[bold cyan]{len(all_urls)}[/] URLs from report"
        )

        # ── Step 2: Write all_*.txt right away ───────────────
        subs_all_path = self.output_dir / "all_subdomains.txt"
        urls_all_path = self.output_dir / "all_urls.txt"
        self._write_txt(subs_all_path, all_subs)
        self._write_txt(urls_all_path, all_urls)

        console.print(
            f"  [green]✓[/] Written: [bold]{subs_all_path.name}[/] "
            f"({len(all_subs)} lines)"
        )
        console.print(
            f"  [green]✓[/] Written: [bold]{urls_all_path.name}[/] "
            f"({len(all_urls)} lines)"
        )

        # ── Step 3: Probe subdomains ──────────────────────────
        console.print(
            f"\n  [yellow]Probing {len(all_subs)} subdomains "
            f"with httpx...[/]"
        )
        alive_subs = self.probe_with_httpx(all_subs, "subdomains")
        console.print(
            f"  [green]>[/] Alive subdomains: "
            f"[bold green]{len(alive_subs)}[/] / {len(all_subs)}"
        )

        # ── Step 4: Deduplicate and probe URLs ────────────────
        deduped = self._dedupe_urls(all_urls, max_count=5000)
        console.print(
            f"\n  [yellow]Probing {len(deduped)} URLs with httpx "
            f"(deduped from {len(all_urls)})...[/]"
        )
        alive_urls = self.probe_with_httpx(deduped, "URLs")
        console.print(
            f"  [green]>[/] Alive URLs: "
            f"[bold green]{len(alive_urls)}[/] / {len(deduped)}"
        )

        # ── Step 5: Write alive_*.txt ─────────────────────────
        subs_alive_path = self.output_dir / "alive_subdomains.txt"
        urls_alive_path = self.output_dir / "alive_urls.txt"
        self._write_txt(subs_alive_path, sorted(alive_subs))
        self._write_txt(urls_alive_path, sorted(alive_urls))

        console.print(
            f"  [green]✓[/] Written: [bold]{subs_alive_path.name}[/] "
            f"({len(alive_subs)} lines)"
        )
        console.print(
            f"  [green]✓[/] Written: [bold]{urls_alive_path.name}[/] "
            f"({len(alive_urls)} lines)"
        )

        # ── Step 6: Results table ─────────────────────────────
        console.print()
        table = Table(
            title="Filtered Output Files",
            box=box.ROUNDED,
            border_style="green",
            title_style="bold green",
            show_header=True,
            header_style="bold white",
        )
        table.add_column("File",        style="bold white",  min_width=25)
        table.add_column("Description", style="dim white",   min_width=38)
        table.add_column("Lines",       style="bold cyan",   width=8,
                         justify="right")

        table.add_row(
            "all_subdomains.txt",
            "Every subdomain discovered",
            str(len(all_subs)),
        )
        table.add_row(
            "alive_subdomains.txt",
            "Alive subdomains (httpx verified)",
            f"[green]{len(alive_subs)}[/]",
        )
        table.add_row(
            "all_urls.txt",
            "Every URL / endpoint discovered",
            str(len(all_urls)),
        )
        table.add_row(
            "alive_urls.txt",
            "Alive URLs (httpx verified)",
            f"[green]{len(alive_urls)}[/]",
        )

        console.print(table)
        console.print(
            f"\n  [dim]Output location:[/] [bold]{self.output_dir}[/]"
        )