"""Parse Snyk test --json output into normalized Finding list."""

import json
import logging
from pathlib import Path

from .models import Ecosystem, Finding, Severity

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}
PKG_MANAGER_TO_ECOSYSTEM = {
    "pip": Ecosystem.PYTHON,
    "poetry": Ecosystem.PYTHON,
    "pipenv": Ecosystem.PYTHON,
    "npm": Ecosystem.NODE,
    "yarn": Ecosystem.NODE,
    "pnpm": Ecosystem.NODE,
}


def _normalize_severity(s: str | None) -> Severity:
    """Normalize severity string to Severity enum.

    Args:
        s: Severity string from Snyk report (e.g., "high", "critical")

    Returns:
        Severity enum value, defaults to MEDIUM if unknown or None
    """
    if not s:
        return Severity.MEDIUM
    key = str(s).lower().strip()
    return SEVERITY_MAP.get(key, Severity.MEDIUM)


def _ecosystem_from_package_manager(pm: str | None, language: str | None) -> Ecosystem:
    """Determine ecosystem from package manager or language.

    Args:
        pm: Package manager name (e.g., "pip", "npm", "yarn")
        language: Programming language (e.g., "python", "javascript")

    Returns:
        Ecosystem enum value, defaults to PYTHON if unknown
    """
    if pm:
        pm_lower = str(pm).lower()
        if pm_lower in PKG_MANAGER_TO_ECOSYSTEM:
            return PKG_MANAGER_TO_ECOSYSTEM[pm_lower]
    if language:
        lang = str(language).lower()
        if lang == "python":
            return Ecosystem.PYTHON
        if lang in ("node", "javascript", "nodejs"):
            return Ecosystem.NODE
    return Ecosystem.PYTHON  # fallback


def _extract_fix_versions(vuln: dict) -> list[str]:
    """Extract fix versions from Snyk vulnerability data.

    Snyk reports can have fix versions in multiple formats:
    - upgradePath: Array of package@version strings
    - fixedIn: Version string or array
    - fixVersion: Version string
    - patchedVersions: Array of version strings

    Args:
        vuln: Vulnerability dictionary from Snyk JSON

    Returns:
        List of version strings that fix the vulnerability (deduplicated, ordered)
    """
    fix_versions: list[str] = []
    # upgradePath can be array of package@version; last is often the fix
    path = vuln.get("upgradePath")
    if isinstance(path, list) and path:
        for item in path:
            if isinstance(item, str) and "@" in item:
                _, ver = item.rsplit("@", 1)
                if ver and ver.lower() not in ("false", "null"):
                    fix_versions.append(ver.strip())
            elif isinstance(item, str) and item and item.lower() not in ("false", "null"):
                fix_versions.append(item.strip())
    if not fix_versions and isinstance(path, str) and "@" in path:
        _, ver = path.rsplit("@", 1)
        if ver:
            fix_versions.append(ver.strip())
    # Some reports have upgradePath with single version string
    if not fix_versions and isinstance(path, str) and path and " " not in path:
        fix_versions.append(path.strip())
    # Alternative keys
    for key in ("fixedIn", "fixVersion", "patchedVersions"):
        val = vuln.get(key)
        if isinstance(val, list):
            fix_versions.extend(str(v) for v in val if v)
        elif isinstance(val, str) and val:
            fix_versions.append(val.strip())
    return list(dict.fromkeys(fix_versions))  # preserve order, dedupe


def parse_snyk_json(path: str | Path) -> list[Finding]:
    """Parse Snyk JSON report into normalized Finding objects.

    Parses the output from `snyk test --json` and converts it into a list of
    normalized Finding objects. Handles various Snyk report formats and
    deduplicates findings by (ecosystem, package_name, installed_version).

    Args:
        path: Path to Snyk JSON report file

    Returns:
        List of Finding objects (empty list if file not found or invalid JSON)

    Note:
        - Logs warnings for missing files or invalid JSON
        - Skips vulnerabilities without package names
        - Deduplicates findings keeping the first occurrence
    """
    path = Path(path)
    if not path.exists():
        logger.warning("Snyk report file not found: %s", path)
        return []
    raw = path.read_text(encoding="utf-8", errors="replace")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        logger.exception("Invalid JSON in Snyk report: %s", e)
        return []

    findings: list[Finding] = []
    # Top-level vulnerabilities array (snyk test --json)
    vulns = data.get("vulnerabilities") or data.get("vulnerability") or []
    if not isinstance(vulns, list):
        vulns = [vulns] if vulns else []

    package_manager = data.get("packageManager") or data.get("package_manager")
    language = data.get("language")

    for v in vulns:
        if not isinstance(v, dict):
            logger.debug("Skipping non-dict vulnerability entry")
            continue
        pkg = v.get("packageName") or v.get("moduleName") or v.get("package")
        if isinstance(pkg, dict):
            pkg = pkg.get("name") or pkg.get("packageName") or ""
        pkg = (pkg or "").strip()
        if not pkg:
            logger.debug("Skipping vuln with no package name: %s", v.get("id"))
            continue

        version = v.get("version") or v.get("installedVersion") or ""
        if isinstance(version, list):
            version = version[0] if version else ""
        version = (version or "").strip()

        severity = _normalize_severity(v.get("severity"))
        ecosystem = _ecosystem_from_package_manager(
            v.get("packageManager") or package_manager,
            v.get("language") or language,
        )
        fix_versions = _extract_fix_versions(v)
        findings.append(
            Finding(
                ecosystem=ecosystem,
                package_name=pkg,
                installed_version=version or None,
                severity=severity,
                fix_versions=fix_versions,
                raw=v,
            )
        )

    # Dedupe by (ecosystem, package_name, installed_version); keep first
    seen: set[tuple[str, str, str]] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.ecosystem.value, f.package_name, f.installed_version or "")
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)

    logger.info("Parsed %d unique findings from %s", len(unique), path)
    return unique
