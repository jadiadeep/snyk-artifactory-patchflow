"""Patchwork integration: update default.yml with API key, run Patchwork for upgrades/autofix."""

import logging
import os
import subprocess
from pathlib import Path

import yaml

from .config import Settings
from .models import UpgradePlan

logger = logging.getLogger(__name__)


def update_patchwork_default_yml(
    default_yml_path: str | Path,
    openai_api_key: str | None = None,
) -> None:
    """
    Safely update Patchwork default.yml to set OpenAI key from env/config.
    Never writes secrets from code; only injects from argument (which should come from env).
    """
    path = Path(default_yml_path)
    key = openai_api_key or os.environ.get("OPENAI_API_KEY", "").strip()
    if not key:
        logger.warning("No OPENAI_API_KEY set; Patchwork may fail for LLM steps")
        return
    if not path.exists():
        logger.warning("Patchwork default.yml not found at %s; skipping update", path)
        return
    data = yaml.safe_load(path.read_text()) or {}
    # Patchwork accepts openai_api_key in defaults
    data["openai_api_key"] = key
    path.write_text(yaml.dump(data, default_flow_style=False, allow_unicode=True), encoding="utf-8")
    logger.info("Updated %s with openai_api_key from config/env", path)


def generate_patchflow_instructions(plan: UpgradePlan) -> str:
    """Generate a patchflow instruction file content for dependency upgrades (for documentation/CLI)."""
    lines = [
        "# Patchflow: dependency upgrades (dep-patchflow plan)",
        "",
        "## Upgrades to apply",
        "",
    ]
    for u in plan.upgrades:
        lines.append(f"- {u.ecosystem.value}: {u.package} {u.from_version} -> {u.to_version}  # {u.reason}")
    lines.extend(["", "## Skipped", ""])
    for s in plan.skipped:
        lines.append(f"- {s.package} ({s.from_version or '?'}): {s.reason}")
    return "\n".join(lines)


def _run_patchwork_cmd(
    patchflow: str,
    key: str,
    cwd: Path,
    timeout: int = 600,
) -> subprocess.CompletedProcess | None:
    """Run a single Patchwork patchflow (DependencyUpgrade or AutoFix)."""
    cmd = ["patchwork", patchflow, f"openai_api_key={key}"]
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.stdout:
            logger.info("Patchwork %s stdout: %s", patchflow, result.stdout[:2000])
        if result.stderr:
            logger.warning("Patchwork %s stderr: %s", patchflow, result.stderr[:2000])
        if result.returncode != 0:
            logger.error("Patchwork %s exited with code %s", patchflow, result.returncode)
        return result
    except FileNotFoundError:
        logger.error(
            "patchwork CLI not found. Install with: pip install 'patchwork-cli[security]'"
        )
        return None
    except subprocess.TimeoutExpired:
        logger.error("Patchwork %s timed out after %ss", patchflow, timeout)
        return None
    except Exception as e:
        logger.exception("Patchwork %s run failed: %s", patchflow, e)
        return None


def run_patchwork(
    settings: Settings,
    plan: UpgradePlan,
    project_dir: str | Path | None = None,
    dry_run: bool = False,
) -> list[subprocess.CompletedProcess | None]:
    """
    Run Patchwork DependencyUpgrade and AutoFix (both required for apply).
    See: https://github.com/patched-codes/patchwork (DependencyUpgrade, AutoFix).
    - DependencyUpgrade: dependency upgrade flow (aligns with our Artifactory-gated plan).
    - AutoFix: vulnerability/code fixes (e.g. Semgrep-based).
    If dry_run: do not execute, return [].
    """
    if dry_run:
        logger.info("Dry run: skipping Patchwork execution")
        return []
    key = settings.openai_api_key or os.environ.get("OPENAI_API_KEY", "").strip()
    if not key:
        logger.warning("OPENAI_API_KEY not set; Patchwork LLM steps will fail")
    cwd = Path(project_dir or ".")
    default_yml = getattr(settings, "patchwork_default_yml_path", "default.yml")
    if Path(default_yml).exists():
        update_patchwork_default_yml(default_yml, key)

    results: list[subprocess.CompletedProcess | None] = []
    # 1) DependencyUpgrade (dependency upgrades)
    results.append(_run_patchwork_cmd("DependencyUpgrade", key, cwd))
    # 2) AutoFix (vulnerability/code fixes)
    results.append(_run_patchwork_cmd("AutoFix", key, cwd))
    return results


def apply_manifest_updates(plan: UpgradePlan, project_dir: str | Path) -> list[str]:
    """
    Apply upgrade plan to requirements.txt and package.json in project_dir.
    Returns list of modified file paths.
    """
    project_dir = Path(project_dir)
    modified: list[str] = []
    py_upgrades = {u.package: u.to_version for u in plan.upgrades if u.ecosystem.value == "python"}
    node_upgrades = {u.package: u.to_version for u in plan.upgrades if u.ecosystem.value == "node"}

    req_txt = project_dir / "requirements.txt"
    if py_upgrades and req_txt.exists():
        lines = req_txt.read_text(encoding="utf-8", errors="replace").splitlines()
        new_lines = []
        changed = False
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                new_lines.append(line)
                continue
            # Match package==version or package>=version etc.
            pkg = stripped.split("[")[0].split("==")[0].split(">=")[0].split("~=")[0].strip().lower()
            for name, ver in py_upgrades.items():
                if name.lower() == pkg:
                    new_lines.append(f"{name}=={ver}")
                    changed = True
                    break
            else:
                new_lines.append(line)
        if changed:
            req_txt.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
            modified.append(str(req_txt))

    pkg_json = project_dir / "package.json"
    if node_upgrades and pkg_json.exists():
        import json as _json
        data = _json.loads(pkg_json.read_text(encoding="utf-8", errors="replace"))
        deps = data.get("dependencies") or {}
        dev = data.get("devDependencies") or {}
        changed = False
        for name, ver in node_upgrades.items():
            if name in deps:
                deps[name] = f"^{ver}"  # caret for semver
                changed = True
            if name in dev:
                dev[name] = f"^{ver}"
                changed = True
        if changed:
            data["dependencies"] = deps
            data["devDependencies"] = dev
            pkg_json.write_text(_json.dumps(data, indent=2) + "\n", encoding="utf-8")
            modified.append(str(pkg_json))

    return modified
