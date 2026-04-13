# core/report_engine.py
"""
Report generation engine.
Creates professional JSON and HTML reports from scan results.
"""

import json
import time
from pathlib import Path
from typing import Dict
from datetime import datetime

from core.base_module import ModuleResult
from core.config import ConfigManager
from utils.logger import setup_logger

logger = setup_logger("digiteam.report")


class ReportEngine:
    """Generates structured JSON and formatted HTML reports."""

    def __init__(
        self,
        target: str,
        results: Dict[str, ModuleResult],
        config: ConfigManager,
        total_time: float,
    ):
        self.target = target
        self.results = results
        self.config = config
        self.total_time = total_time
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.output_dir = Path(config.output_dir) / f"{target}_{self.timestamp}"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _build_report_data(self) -> dict:
        """Build the complete report data structure."""
        report = {
            "meta": {
                "tool": "DIGI TEAM",
                "version": "2.0.0",
                "target": self.target,
                "scan_date": datetime.now().isoformat(),
                "total_execution_time": round(self.total_time, 2),
                "modules_executed": len(self.results),
            },
            "summary": {
                "subdomains": [],
                "open_ports": [],
                "technologies": [],
                "endpoints": [],
                "live_hosts": [],
                "vulnerability_indicators": [],
            },
            "modules": {},
        }

        for name, result in self.results.items():
            report["modules"][name] = result.to_dict()

            data = result.data
            if not data:
                continue

            # Aggregate subdomains
            if "subdomains" in data:
                existing = set(report["summary"]["subdomains"])
                for s in data["subdomains"]:
                    if s not in existing:
                        report["summary"]["subdomains"].append(s)
                        existing.add(s)

            # Aggregate open ports
            if "ports" in data:
                report["summary"]["open_ports"].extend(data["ports"])
            if "open_ports" in data:
                report["summary"]["open_ports"].extend(data["open_ports"])

            # Aggregate technologies
            if "technologies" in data:
                existing = set(report["summary"]["technologies"])
                for t in data["technologies"]:
                    t_name = t if isinstance(t, str) else str(t.get("name", t))
                    if t_name not in existing:
                        report["summary"]["technologies"].append(t_name)
                        existing.add(t_name)

            # Aggregate endpoints
            if "endpoints" in data:
                report["summary"]["endpoints"].extend(data["endpoints"])
            if "urls" in data:
                report["summary"]["endpoints"].extend(data["urls"])

            # Aggregate live hosts
            if "live_hosts" in data:
                report["summary"]["live_hosts"].extend(data["live_hosts"])

            # Aggregate vulnerability indicators
            if "vulnerabilities" in data:
                report["summary"]["vulnerability_indicators"].extend(
                    data["vulnerabilities"]
                )
            if "security_issues" in data:
                report["summary"]["vulnerability_indicators"].extend(
                    data["security_issues"]
                )

        # Deduplicate
        report["summary"]["subdomains"] = sorted(
            list(set(report["summary"]["subdomains"]))
        )
        report["summary"]["endpoints"] = sorted(
            list(set(report["summary"]["endpoints"]))
        )[:500]
        report["summary"]["live_hosts"] = list(
            {json.dumps(h, default=str): h for h in report["summary"]["live_hosts"]}.values()
        )
        report["summary"]["technologies"] = sorted(
            list(set(report["summary"]["technologies"]))
        )

        return report

    def generate_json(self) -> str:
        """Generate JSON report."""
        report = self._build_report_data()
        json_path = self.output_dir / "report.json"

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str, ensure_ascii=False)

        logger.info(f"JSON report generated: {json_path}")
        return str(json_path)

    def generate_html(self) -> str:
        """Generate beautiful HTML report."""
        report = self._build_report_data()
        html_path = self.output_dir / "report.html"

        html = self._render_html(report)

        # ── KEY FIX: always write with utf-8 encoding ──
        with open(html_path, "w", encoding="utf-8", errors="replace") as f:
            f.write(html)

        logger.info(f"HTML report generated: {html_path}")
        return str(html_path)

    def _render_html(self, report: dict) -> str:
        """Render the HTML report from data."""
        meta = report["meta"]
        summary = report["summary"]
        modules = report["modules"]

        # ── Subdomains table rows ────────────────────────────
        subdomains_rows = ""
        for i, sub in enumerate(summary["subdomains"][:200], 1):
            subdomains_rows += (
                f"<tr><td>{i}</td><td>{self._esc(sub)}</td></tr>\n"
            )

        # ── Open ports table rows ────────────────────────────
        ports_rows = ""
        for p in summary["open_ports"][:100]:
            if isinstance(p, dict):
                ports_rows += (
                    f"<tr>"
                    f"<td>{self._esc(str(p.get('host', '')))}</td>"
                    f"<td>{self._esc(str(p.get('port', '')))}</td>"
                    f"<td>{self._esc(str(p.get('service', '')))}</td>"
                    f"<td>{self._esc(str(p.get('version', '')))}</td>"
                    f"</tr>\n"
                )
            else:
                ports_rows += (
                    f"<tr><td>-</td><td>{self._esc(str(p))}</td>"
                    f"<td>-</td><td>-</td></tr>\n"
                )

        # ── Technologies badges ──────────────────────────────
        tech_items = ""
        for t in summary["technologies"]:
            tech_items += (
                f'<span class="badge">{self._esc(str(t))}</span>\n'
            )

        # ── Live hosts table rows ────────────────────────────
        live_rows = ""
        for i, host in enumerate(summary["live_hosts"][:100], 1):
            if isinstance(host, dict):
                live_rows += (
                    f"<tr>"
                    f"<td>{i}</td>"
                    f"<td>{self._esc(str(host.get('url', '')))}</td>"
                    f"<td>{self._esc(str(host.get('status_code', '')))}</td>"
                    f"<td>{self._esc(str(host.get('title', '')))}</td>"
                    f"</tr>\n"
                )
            else:
                live_rows += (
                    f"<tr><td>{i}</td><td>{self._esc(str(host))}</td>"
                    f"<td>-</td><td>-</td></tr>\n"
                )

        # ── Vulnerability indicator rows ─────────────────────
        vuln_rows = ""
        for v in summary["vulnerability_indicators"][:50]:
            if isinstance(v, dict):
                severity = str(v.get("severity", "info")).lower()
                sev_class = {
                    "critical": "sev-critical",
                    "high": "sev-high",
                    "medium": "sev-medium",
                    "low": "sev-low",
                }.get(severity, "sev-info")
                vuln_rows += (
                    f'<tr>'
                    f'<td class="{sev_class}">'
                    f"{self._esc(str(v.get('severity', 'Info')).upper())}</td>"
                    f"<td>{self._esc(str(v.get('title', '')))}</td>"
                    f"<td>{self._esc(str(v.get('detail', '')))}</td>"
                    f"</tr>\n"
                )
            else:
                vuln_rows += (
                    f'<tr><td class="sev-info">INFO</td>'
                    f"<td>{self._esc(str(v))}</td><td>-</td></tr>\n"
                )

        # ── Module execution rows ────────────────────────────
        module_rows = ""
        for name, mod in modules.items():
            status = mod["status"]
            status_class = {
                "completed": "status-completed",
                "failed": "status-failed",
                "skipped": "status-skipped",
            }.get(status, "status-pending")
            errors = "; ".join(mod.get("errors", [])) or "-"
            warnings = "; ".join(mod.get("warnings", [])) or "-"
            module_rows += (
                f"<tr>"
                f"<td>{self._esc(name)}</td>"
                f'<td class="{status_class}">{self._esc(status.upper())}</td>'
                f"<td>{mod.get('execution_time', 0):.1f}s</td>"
                f"<td>{self._esc(errors[:100])}</td>"
                f"</tr>\n"
            )

        # ── Endpoints preview ────────────────────────────────
        endpoint_count = len(summary["endpoints"])
        endpoints_preview = ""
        for ep in summary["endpoints"][:50]:
            endpoints_preview += f"<li>{self._esc(str(ep))}</li>\n"

        # ── Count stats ──────────────────────────────────────
        completed_count = sum(
            1 for m in modules.values() if m["status"] == "completed"
        )
        failed_count = sum(
            1 for m in modules.values() if m["status"] == "failed"
        )
        skipped_count = sum(
            1 for m in modules.values() if m["status"] == "skipped"
        )

        # ──────────────────────────────────────────────────────
        #  HTML TEMPLATE — uses HTML entities for icons instead
        #  of emoji to avoid Windows cp1252 encoding issues
        # ──────────────────────────────────────────────────────
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DIGI TEAM Report - {self._esc(meta['target'])}</title>
<style>
    :root {{
        --bg: #0d1117;
        --card: #161b22;
        --border: #30363d;
        --text: #c9d1d9;
        --text-dim: #8b949e;
        --accent: #58a6ff;
        --green: #3fb950;
        --red: #f85149;
        --yellow: #d29922;
        --orange: #db6d28;
        --purple: #bc8cff;
    }}
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI',
                     Helvetica, Arial, sans-serif;
        background: var(--bg);
        color: var(--text);
        line-height: 1.6;
        padding: 2rem;
    }}
    .container {{ max-width: 1200px; margin: 0 auto; }}

    /* ── Header ─────────────────────────────────────── */
    .header {{
        text-align: center;
        padding: 2rem;
        border: 1px solid var(--border);
        border-radius: 12px;
        background: var(--card);
        margin-bottom: 2rem;
    }}
    .header h1 {{
        color: var(--accent);
        font-size: 2.5rem;
        letter-spacing: 2px;
    }}
    .header .subtitle {{
        color: var(--text-dim);
        font-size: 1.1rem;
        margin-top: .5rem;
    }}

    /* ── Stat Cards ─────────────────────────────────── */
    .meta-grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
        gap: 1rem;
        margin: 1.5rem 0;
    }}
    .meta-card {{
        background: var(--bg);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 1rem;
        text-align: center;
    }}
    .meta-card .value {{
        font-size: 1.8rem;
        font-weight: bold;
        color: var(--accent);
    }}
    .meta-card .label {{
        color: var(--text-dim);
        font-size: .85rem;
        margin-top: .25rem;
    }}

    /* ── Sections ───────────────────────────────────── */
    .section {{
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 1.5rem;
        margin-bottom: 1.5rem;
    }}
    .section h2 {{
        color: var(--accent);
        margin-bottom: 1rem;
        padding-bottom: .5rem;
        border-bottom: 1px solid var(--border);
        font-size: 1.3rem;
    }}

    /* ── Tables ─────────────────────────────────────── */
    table {{
        width: 100%;
        border-collapse: collapse;
        font-size: .9rem;
    }}
    th, td {{
        padding: .6rem .8rem;
        text-align: left;
        border-bottom: 1px solid var(--border);
    }}
    th {{
        color: var(--accent);
        font-weight: 600;
        background: rgba(88,166,255,0.05);
    }}
    tr:hover {{
        background: rgba(88,166,255,0.04);
    }}

    /* ── Badges ─────────────────────────────────────── */
    .badge {{
        display: inline-block;
        padding: .25rem .6rem;
        margin: .2rem;
        border-radius: 12px;
        font-size: .8rem;
        background: rgba(88,166,255,0.15);
        color: var(--accent);
        border: 1px solid rgba(88,166,255,0.3);
    }}

    /* ── Status indicators ──────────────────────────── */
    .status-completed {{ color: var(--green); font-weight: bold; }}
    .status-failed    {{ color: var(--red);   font-weight: bold; }}
    .status-skipped   {{ color: var(--yellow); font-weight: bold; }}
    .status-pending   {{ color: var(--text-dim); }}

    /* ── Severity indicators ────────────────────────── */
    .sev-critical {{ color: #ff0040; font-weight: bold; }}
    .sev-high     {{ color: var(--red);    font-weight: bold; }}
    .sev-medium   {{ color: var(--orange); font-weight: bold; }}
    .sev-low      {{ color: var(--yellow); }}
    .sev-info     {{ color: var(--accent); }}

    /* ── Endpoints list ─────────────────────────────── */
    .endpoint-list {{
        max-height: 400px;
        overflow-y: auto;
        list-style: none;
        padding: 0;
    }}
    .endpoint-list li {{
        padding: .3rem .5rem;
        border-bottom: 1px solid var(--border);
        font-size: .85rem;
        word-break: break-all;
        font-family: 'Consolas', 'Monaco', monospace;
    }}
    .endpoint-list li:hover {{
        background: rgba(88,166,255,0.04);
    }}

    /* ── Scan summary bar ───────────────────────────── */
    .scan-stats {{
        display: flex;
        gap: 1.5rem;
        justify-content: center;
        margin-top: 1rem;
        flex-wrap: wrap;
    }}
    .scan-stat {{
        font-size: .9rem;
    }}
    .scan-stat .num {{ font-weight: bold; }}

    /* ── Footer ─────────────────────────────────────── */
    .footer {{
        text-align: center;
        color: var(--text-dim);
        padding: 2rem 0;
        font-size: .85rem;
    }}

    /* ── Responsive ─────────────────────────────────── */
    @media (max-width: 768px) {{
        body {{ padding: .5rem; }}
        .header h1 {{ font-size: 1.5rem; }}
        .meta-grid {{ grid-template-columns: repeat(2, 1fr); }}
        table {{ font-size: .8rem; }}
        th, td {{ padding: .4rem; }}
    }}
</style>
</head>
<body>
<div class="container">

    <!-- ═══════════════ HEADER ═══════════════ -->
    <div class="header">
        <h1>&#x1F50E; DIGI TEAM</h1>
        <div class="subtitle">Elite Reconnaissance Report</div>

        <div class="meta-grid">
            <div class="meta-card">
                <div class="value">{self._esc(meta['target'])}</div>
                <div class="label">Target Domain</div>
            </div>
            <div class="meta-card">
                <div class="value">{len(summary['subdomains'])}</div>
                <div class="label">Subdomains</div>
            </div>
            <div class="meta-card">
                <div class="value">{len(summary['open_ports'])}</div>
                <div class="label">Open Ports</div>
            </div>
            <div class="meta-card">
                <div class="value">{len(summary['technologies'])}</div>
                <div class="label">Technologies</div>
            </div>
            <div class="meta-card">
                <div class="value">{len(summary['live_hosts'])}</div>
                <div class="label">Live Hosts</div>
            </div>
            <div class="meta-card">
                <div class="value">{len(summary['vulnerability_indicators'])}</div>
                <div class="label">Findings</div>
            </div>
            <div class="meta-card">
                <div class="value">{meta['total_execution_time']}s</div>
                <div class="label">Scan Duration</div>
            </div>
        </div>

        <div class="subtitle">
            Scan Date: {self._esc(meta['scan_date'])}
        </div>
        <div class="scan-stats">
            <span class="scan-stat">
                Modules: <span class="num">{meta['modules_executed']}</span>
            </span>
            <span class="scan-stat">
                Completed: <span class="num status-completed">{completed_count}</span>
            </span>
            <span class="scan-stat">
                Failed: <span class="num status-failed">{failed_count}</span>
            </span>
            <span class="scan-stat">
                Skipped: <span class="num status-skipped">{skipped_count}</span>
            </span>
        </div>
    </div>

    <!-- ═══════════════ MODULE STATUS ═══════════════ -->
    <div class="section">
        <h2>&#x2699; Module Execution Summary</h2>
        <table>
            <thead>
                <tr>
                    <th>Module</th>
                    <th>Status</th>
                    <th>Time</th>
                    <th>Errors</th>
                </tr>
            </thead>
            <tbody>
                {module_rows}
            </tbody>
        </table>
    </div>

    <!-- ═══════════════ SUBDOMAINS ═══════════════ -->
    <div class="section">
        <h2>&#x1F310; Subdomains ({len(summary['subdomains'])})</h2>
        <table>
            <thead>
                <tr><th>#</th><th>Subdomain</th></tr>
            </thead>
            <tbody>
                {subdomains_rows if subdomains_rows else '<tr><td colspan="2">No subdomains discovered</td></tr>'}
            </tbody>
        </table>
    </div>

    <!-- ═══════════════ OPEN PORTS ═══════════════ -->
    <div class="section">
        <h2>&#x1F50C; Open Ports ({len(summary['open_ports'])})</h2>
        <table>
            <thead>
                <tr>
                    <th>Host</th>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Version</th>
                </tr>
            </thead>
            <tbody>
                {ports_rows if ports_rows else '<tr><td colspan="4">No ports discovered</td></tr>'}
            </tbody>
        </table>
    </div>

    <!-- ═══════════════ LIVE HOSTS ═══════════════ -->
    <div class="section">
        <h2>&#x1F5A5; Live Hosts ({len(summary['live_hosts'])})</h2>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>URL</th>
                    <th>Status</th>
                    <th>Title</th>
                </tr>
            </thead>
            <tbody>
                {live_rows if live_rows else '<tr><td colspan="4">No live hosts detected</td></tr>'}
            </tbody>
        </table>
    </div>

    <!-- ═══════════════ TECHNOLOGIES ═══════════════ -->
    <div class="section">
        <h2>&#x1F6E0; Technologies Detected ({len(summary['technologies'])})</h2>
        <div style="padding: .5rem 0;">
            {tech_items if tech_items else '<p style="color: var(--text-dim);">No technologies detected</p>'}
        </div>
    </div>

    <!-- ═══════════════ ENDPOINTS ═══════════════ -->
    <div class="section">
        <h2>&#x1F517; Endpoints ({endpoint_count})</h2>
        <ul class="endpoint-list">
            {endpoints_preview if endpoints_preview else '<li>No endpoints discovered</li>'}
        </ul>
        {f'<p style="color: var(--text-dim); margin-top: .5rem; font-size: .85rem;">Showing first 50 of {endpoint_count} endpoints. See JSON report for full list.</p>' if endpoint_count > 50 else ''}
    </div>

    <!-- ═══════════════ VULNERABILITIES ═══════════════ -->
    <div class="section">
        <h2>&#x26A0; Vulnerability Indicators ({len(summary['vulnerability_indicators'])})</h2>
        <table>
            <thead>
                <tr>
                    <th style="width:100px;">Severity</th>
                    <th>Finding</th>
                    <th>Detail</th>
                </tr>
            </thead>
            <tbody>
                {vuln_rows if vuln_rows else '<tr><td colspan="3">No vulnerability indicators found</td></tr>'}
            </tbody>
        </table>
    </div>

    <!-- ═══════════════ FOOTER ═══════════════ -->
    <div class="footer">
        <p>
            Generated by <strong>DIGI TEAM v2.0.0</strong>
            - Elite Reconnaissance Framework
        </p>
        <p style="margin-top: .25rem;">
            Report generated: {self._esc(meta['scan_date'])}
            | Target: {self._esc(meta['target'])}
            | Duration: {meta['total_execution_time']}s
        </p>
    </div>

</div>
</body>
</html>"""
        return html

    @staticmethod
    def _esc(text: str) -> str:
        """Escape HTML characters."""
        if not isinstance(text, str):
            text = str(text)
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;")
        )