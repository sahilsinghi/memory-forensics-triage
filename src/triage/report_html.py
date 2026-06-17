"""Generate polished HTML triage report using Jinja2 template."""
import logging
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger(__name__)

# Default template directory (relative to this file → ../../templates/)
_DEFAULT_TEMPLATE_DIR = Path(__file__).parent.parent.parent / "templates"


def generate_html_report(
    report_data: dict,
    output_path: str,
    template_dir: str = None,
) -> None:
    """
    Render the Jinja2 template and write the HTML report to *output_path*.

    Args:
        report_data:   Dict produced by cli.py containing all analysis results.
        output_path:   Destination file path for the HTML report.
        template_dir:  Path to directory containing report.html.j2.
                       Defaults to <project_root>/templates/.
    """
    tdir = Path(template_dir) if template_dir else _DEFAULT_TEMPLATE_DIR

    if not tdir.exists():
        raise FileNotFoundError(f"Template directory not found: {tdir}")

    env = Environment(
        loader=FileSystemLoader(str(tdir)),
        autoescape=select_autoescape(["html", "xml"]),
    )

    # Add custom filters
    env.filters["severity_color"] = _severity_color
    env.filters["verdict_color"] = _verdict_color
    env.filters["score_color"] = _score_color

    template = env.get_template("report.html.j2")
    html = template.render(**report_data)

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding="utf-8")

    logger.info("HTML report written to %s", output_path)


# ---------------------------------------------------------------------------
# Jinja2 custom filters
# ---------------------------------------------------------------------------

def _severity_color(severity: str) -> str:
    return {
        "critical": "bg-red-100 text-red-800 border-red-300",
        "high": "bg-orange-100 text-orange-800 border-orange-300",
        "medium": "bg-yellow-100 text-yellow-800 border-yellow-300",
        "low": "bg-blue-100 text-blue-800 border-blue-300",
    }.get(str(severity).lower(), "bg-gray-100 text-gray-800 border-gray-300")


def _verdict_color(verdict: str) -> str:
    return {
        "Compromised": "bg-red-600",
        "Suspicious": "bg-amber-500",
        "Clean": "bg-green-600",
    }.get(verdict, "bg-gray-500")


def _score_color(score: int) -> str:
    try:
        s = int(score)
    except (TypeError, ValueError):
        return "text-gray-600"
    if s >= 70:
        return "text-red-600 font-bold"
    if s >= 30:
        return "text-amber-600 font-semibold"
    return "text-green-600"
