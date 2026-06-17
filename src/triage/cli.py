"""
memory-forensics-triage CLI

Entry point: `triage` (or `python -m triage.cli`)

Usage examples
--------------
  triage --dump /path/to/mem.raw
  triage --dump mem.raw --output json --out-dir /tmp/reports/
  triage --dump mem.raw --ioc-db /custom/iocs/ --verbose
"""
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import click

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default paths (relative to this file so the package is self-contained)
# ---------------------------------------------------------------------------
_SRC_DIR = Path(__file__).parent
_PROJECT_ROOT = _SRC_DIR.parent.parent
_DEFAULT_IOC_DB = _PROJECT_ROOT / "data" / "iocs"
_TEMPLATE_DIR = _PROJECT_ROOT / "templates"
_AUDIT_LOG = _PROJECT_ROOT / "triage_audit.jsonl"


# ---------------------------------------------------------------------------
# CLI definition
# ---------------------------------------------------------------------------

@click.command(name="triage")
@click.option(
    "--dump", "-d",
    required=True,
    type=click.Path(exists=True, readable=True, path_type=Path),
    help="Path to the memory dump file (.raw, .mem, .vmem, …)",
)
@click.option(
    "--output", "-o",
    type=click.Choice(["html", "json"], case_sensitive=False),
    default="html",
    show_default=True,
    help="Report output format.",
)
@click.option(
    "--ioc-db",
    type=click.Path(file_okay=False, path_type=Path),
    default=str(_DEFAULT_IOC_DB),
    show_default=True,
    help="Directory containing IOC YAML files.",
)
@click.option(
    "--out-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=".",
    show_default=True,
    help="Directory to write the report into.",
)
@click.option(
    "--profile",
    default=None,
    help="Optional Volatility OS profile hint (e.g. Win10x64_19041).",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Enable verbose/debug logging.",
)
def main(dump, output, ioc_db, out_dir, profile, verbose):
    """
    Automated memory forensics triage tool.

    Wraps Volatility 3, runs 12 plugins in parallel, scans output against
    an IOC database, and generates an HTML or JSON triage report.
    """
    # ---- Logging setup ----
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # ---- Audit log ----
    from triage.audit_log import get_audit_logger, log_event
    audit = get_audit_logger(str(_AUDIT_LOG))
    log_event(audit, "triage_started", dump=str(dump), output_format=output, ioc_db=str(ioc_db))

    click.echo("")
    click.echo("=" * 64)
    click.echo("  Memory Forensics Triage Tool  |  Volatility 3")
    click.echo("=" * 64)
    click.echo(f"  Dump      : {dump}")
    click.echo(f"  Format    : {output.upper()}")
    click.echo(f"  IOC DB    : {ioc_db}")
    click.echo(f"  Profile   : {profile or 'auto-detect'}")
    click.echo("=" * 64)
    click.echo("")

    dump_path = str(dump.resolve())

    # ---- Step 1: Validate dump ----
    click.echo("[1/5] Validating memory dump …")
    from triage.validator import validate_dump
    validation = validate_dump(dump_path)

    if not validation["valid"]:
        click.secho(
            f"  ERROR: Dump validation failed — {validation['error']}",
            fg="red",
            err=True,
        )
        log_event(audit, "validation_failed", error=validation["error"])
        sys.exit(1)

    detected_profile = profile or validation.get("os_profile") or "unknown"
    click.echo(f"  OK — OS profile detected: {detected_profile}")

    # ---- Step 2: Run plugins ----
    click.echo("\n[2/5] Running 12 Volatility 3 plugins in parallel (max 6 workers) …")
    from triage.orchestrator import run_all_plugins
    plugin_results, total_duration = run_all_plugins(
        dump_path, verbose=verbose, profile=profile
    )

    ok_count = sum(1 for r in plugin_results.values() if r["error"] is None)
    err_count = sum(1 for r in plugin_results.values() if r["error"] is not None)
    click.echo(f"  Done — {ok_count}/12 plugins succeeded, {err_count} errors, total {total_duration:.1f}s")
    if err_count and verbose:
        for name, res in plugin_results.items():
            if res["error"]:
                click.echo(f"    WARN: {name}: {res['error']}", err=True)

    # ---- Step 3: IOC scan ----
    click.echo("\n[3/5] Scanning output against IOC database …")
    from triage.ioc_scanner import scan
    ioc_matches = scan(plugin_results, str(ioc_db))
    click.echo(f"  Done — {len(ioc_matches)} IOC match(es) found")

    # ---- Step 4: Risk scoring ----
    click.echo("\n[4/5] Scoring process risk …")
    from triage.risk_scorer import score_processes, overall_verdict
    scored = score_processes(plugin_results, ioc_matches)
    verdict, overall_score = overall_verdict(scored)

    click.echo(f"  Done — {len(scored)} processes scored")

    # Determine process count from pslist/psscan
    proc_count = len(plugin_results.get("pslist", {}).get("rows", []))
    if not proc_count:
        proc_count = len(plugin_results.get("psscan", {}).get("rows", []))

    # Build report_data dict
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    net_rows = (
        plugin_results.get("netscan", {}).get("rows", [])
        + plugin_results.get("netstat", {}).get("rows", [])
    )
    kernel_modules = plugin_results.get("modscan", {}).get("rows", [])

    plugin_errors = {
        name: res["error"]
        for name, res in plugin_results.items()
        if res["error"]
    }

    report_data = {
        "dump_path": dump_path,
        "dump_filename": Path(dump_path).name,
        "analysis_timestamp": timestamp,
        "duration_s": total_duration,
        "verdict": verdict,
        "overall_score": overall_score,
        "process_count": proc_count,
        "suspect_processes": scored,
        "network_connections": net_rows,
        "ioc_matches": ioc_matches,
        "kernel_modules": kernel_modules,
        "plugin_results": plugin_results,
        "plugin_errors": plugin_errors,
    }

    # ---- Step 5: Generate report ----
    click.echo("\n[5/5] Generating report …")
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = Path(dump_path).stem
    report_ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if output == "html":
        from triage.report_html import generate_html_report
        report_file = out_dir / f"triage_{stem}_{report_ts}.html"
        generate_html_report(report_data, str(report_file), template_dir=str(_TEMPLATE_DIR))
    else:
        from triage.report_json import generate_json_report
        report_file = out_dir / f"triage_{stem}_{report_ts}.json"
        generate_json_report(report_data, str(report_file))

    log_event(
        audit,
        "triage_complete",
        verdict=verdict,
        score=overall_score,
        ioc_matches=len(ioc_matches),
        report=str(report_file),
    )

    # ---- Final verdict banner ----
    click.echo("")
    click.echo("=" * 64)
    verdict_colors = {"Compromised": "red", "Suspicious": "yellow", "Clean": "green"}
    click.secho(
        f"  VERDICT: {verdict}  (overall risk score: {overall_score}/100)",
        fg=verdict_colors.get(verdict, "white"),
        bold=True,
    )
    if scored:
        click.echo(f"  Top suspect: {scored[0]['name']} (PID {scored[0]['pid']}) — {scored[0]['risk_score']}/100")
    click.echo(f"  Report     : {report_file}")
    click.echo("=" * 64)
    click.echo("")

    # Exit code encodes verdict
    if verdict == "Compromised":
        sys.exit(2)
    elif verdict == "Suspicious":
        sys.exit(1)
    # Clean → 0


if __name__ == "__main__":
    main()
