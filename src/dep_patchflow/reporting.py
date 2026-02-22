"""Write upgrade_summary.json and upgrade_summary.md to out/."""

import json
from pathlib import Path

from .models import UpgradePlan


def write_reports(plan: UpgradePlan, out_dir: str | Path = "out") -> tuple[Path, Path]:
    """Generate upgrade plan reports in JSON and Markdown formats.

    Creates two output files:
    - upgrade_summary.json: Machine-readable JSON with full plan data
    - upgrade_summary.md: Human-readable Markdown report with tables

    Args:
        plan: UpgradePlan object containing upgrades and skipped items
        out_dir: Output directory (default: "out")

    Returns:
        Tuple of (json_path, md_path) Path objects

    Note:
        - Creates output directory if it doesn't exist
        - JSON includes serialized model data with enum values converted to strings
        - Markdown includes summary statistics and formatted tables
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    json_path = out / "upgrade_summary.json"
    payload = {
        "summary": plan.summary(),
        "upgrades": [u.model_dump() for u in plan.upgrades],
        "skipped": [s.model_dump() for s in plan.skipped],
    }
    for u in payload["upgrades"]:
        u["ecosystem"] = u["ecosystem"].value if hasattr(u["ecosystem"], "value") else u["ecosystem"]
    for s in payload["skipped"]:
        s["ecosystem"] = s["ecosystem"].value if hasattr(s["ecosystem"], "value") else s["ecosystem"]
        if s.get("severity"):
            s["severity"] = s["severity"].value if hasattr(s["severity"], "value") else s["severity"]
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    md_path = out / "upgrade_summary.md"
    md_lines = [
        "# Dependency Upgrade Summary",
        "",
        f"Generated: {plan.generated_at.isoformat()}",
        "",
        "## Summary",
        "",
        f"- **Upgrades:** {len(plan.upgrades)}",
        f"- **Skipped:** {len(plan.skipped)}",
        "",
    ]
    if plan.snyk_report_path:
        md_lines.append(f"- **Snyk report:** `{plan.snyk_report_path}`")
    if plan.config_path:
        md_lines.append(f"- **Config:** `{plan.config_path}`")
    md_lines.extend(["", "## Snyk recommended vs Artifactory available", ""])
    md_lines.append("Upgrades below were chosen only from versions that exist in Artifactory.")
    md_lines.append("")
    md_lines.append("| Package | From | To | Ecosystem | Reason |")
    md_lines.append("|---------|------|-----|----------|--------|")
    for u in plan.upgrades:
        md_lines.append(f"| {u.package} | {u.from_version} | {u.to_version} | {u.ecosystem.value} | {u.reason} |")
    md_lines.extend(["", "## Skipped dependencies", ""])
    md_lines.append("| Package | From | Ecosystem | Reason |")
    md_lines.append("|---------|------|----------|--------|")
    for s in plan.skipped:
        md_lines.append(f"| {s.package} | {s.from_version or '-'} | {s.ecosystem.value} | {s.reason} |")
    md_path.write_text("\n".join(md_lines), encoding="utf-8")

    return json_path, md_path
