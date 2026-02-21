"""CLI entry: dep-patchflow plan | apply."""

import logging
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .config import Settings
from .patchwork_runner import apply_manifest_updates, run_patchwork
from .planner import build_plan
from .reporting import write_reports
from .snyk_parser import parse_snyk_json

app = typer.Typer(
    name="dep-patchflow",
    help="Snyk-based dependency upgrades gated by Artifactory, with Patchwork integration.",
)
console = Console()


DEFAULTS_YML = "defaults.yml"


def _load_config(config_path: str | None) -> tuple[Settings, str | None]:
    """Load from --config if given, else from defaults.yml in cwd. Returns (settings, path_used)."""
    path = None
    if config_path and Path(config_path).exists():
        path = Path(config_path)
    elif Path(DEFAULTS_YML).exists():
        path = Path(DEFAULTS_YML)
    if path is not None:
        return Settings.from_yaml(path), str(path)
    return Settings(), None


@app.command()
def plan(
    snyk_report: Path = typer.Argument(..., help="Path to Snyk JSON report (snyk test --json)"),
    config: Path = typer.Option(None, "--config", "-c", help="Path to config (default: defaults.yml)"),
) -> None:
    """Parse Snyk report, resolve versions via Artifactory, output upgrade plan (JSON + MD)."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    settings, config_used = _load_config(str(config) if config else None)

    if not snyk_report.exists():
        console.print(f"[red]Snyk report not found: {snyk_report}[/red]")
        raise typer.Exit(1)

    findings = parse_snyk_json(snyk_report)
    if not findings:
        console.print("[yellow]No findings in Snyk report (or parse failed).[/yellow]")
    plan_result = build_plan(
        findings,
        settings,
        snyk_report_path=str(snyk_report),
        config_path=config_used,
    )
    json_path, md_path = write_reports(plan_result)
    console.print("[green]Plan generated.[/green]")
    table = Table(title="Upgrade plan summary")
    table.add_column("Package", style="cyan")
    table.add_column("From", style="yellow")
    table.add_column("To", style="green")
    table.add_column("Ecosystem")
    table.add_column("Reason")
    for u in plan_result.upgrades:
        table.add_row(u.package, u.from_version, u.to_version, u.ecosystem.value, u.reason)
    console.print(table)
    if plan_result.skipped:
        console.print(f"\n[dim]Skipped: {len(plan_result.skipped)}[/dim]")
    console.print(f"\nOutput: [bold]{json_path}[/bold], [bold]{md_path}[/bold]")


@app.command()
def apply(
    snyk_report: Path = typer.Argument(..., help="Path to Snyk JSON report"),
    config: Path = typer.Option(None, "--config", "-c", help="Path to config.yml"),
    project_dir: Path = typer.Option(Path("."), "--project-dir", "-d", help="Project root (for manifests + Patchwork)"),
    run_patchwork_cli: bool = typer.Option(True, "--patchwork/--no-patchwork", help="Run Patchwork after applying manifest updates"),
) -> None:
    """Apply upgrade plan: update requirements.txt/package.json, then optionally run Patchwork."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    settings, config_used = _load_config(str(config) if config else None)
    policy = settings.get_policy()
    dry = policy.dry_run

    if not snyk_report.exists():
        console.print(f"[red]Snyk report not found: {snyk_report}[/red]")
        raise typer.Exit(1)

    findings = parse_snyk_json(snyk_report)
    plan_result = build_plan(
        findings,
        settings,
        snyk_report_path=str(snyk_report),
        config_path=config_used,
    )
    json_path, md_path = write_reports(plan_result)
    console.print(f"Plan written to [bold]{json_path}[/bold], [bold]{md_path}[/bold]")

    if dry:
        console.print("[yellow]Dry run: not modifying files or running Patchwork.[/yellow]")
        return

    modified = apply_manifest_updates(plan_result, project_dir)
    if modified:
        console.print(f"[green]Updated: {', '.join(modified)}[/green]")
    else:
        console.print("[dim]No manifest files updated (none found or no Python/Node upgrades).[/dim]")

    if run_patchwork_cli and plan_result.upgrades:
        console.print("Running Patchwork DependencyUpgrade...")
        result = run_patchwork(settings, plan_result, project_dir=project_dir, dry_run=False)
        if result is not None and getattr(result, "returncode", -1) != 0:
            console.print("[yellow]Patchwork exited with non-zero code. Check logs.[/yellow]")
    elif run_patchwork_cli and not plan_result.upgrades:
        console.print("[dim]No upgrades in plan; skipping Patchwork.[/dim]")
    console.print("Done.")


if __name__ == "__main__":
    app()
