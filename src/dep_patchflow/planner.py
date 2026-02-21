"""Build UpgradePlan from findings + Artifactory + policy."""

import logging
from pathlib import Path

from .artifactory import list_versions
from .config import PolicySettings, Settings
from .models import Ecosystem, Finding, Severity, SkippedItem, UpgradeItem, UpgradePlan
from .version_policy import choose_best_version, filter_prereleases

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


def _severity_at_least(severity: Severity, min_severity: str) -> bool:
    min_val = SEVERITY_ORDER.get(Severity(min_severity), 0)
    return SEVERITY_ORDER.get(severity, 0) >= min_val


def build_plan(
    findings: list[Finding],
    settings: Settings,
    policy: PolicySettings | None = None,
    snyk_report_path: str | None = None,
    config_path: str | None = None,
) -> UpgradePlan:
    """
    Resolve target versions using Artifactory and policy; produce UpgradePlan.
    Enforces max_upgrades_per_run and min_severity.
    """
    policy = policy or settings.get_policy()
    upgrades: list[UpgradeItem] = []
    skipped: list[SkippedItem] = []

    # Sort by severity (critical first), then by package name
    ordered = sorted(
        findings,
        key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.package_name),
    )

    for f in ordered:
        if len(upgrades) >= policy.max_upgrades_per_run:
            skipped.append(
                SkippedItem(
                    package=f.package_name,
                    from_version=f.installed_version,
                    ecosystem=f.ecosystem,
                    reason=f"max_upgrades_per_run ({policy.max_upgrades_per_run}) reached",
                    severity=f.severity,
                )
            )
            continue
        if not _severity_at_least(f.severity, policy.min_severity):
            skipped.append(
                SkippedItem(
                    package=f.package_name,
                    from_version=f.installed_version,
                    ecosystem=f.ecosystem,
                    reason=f"severity {f.severity.value} below min_severity {policy.min_severity}",
                    severity=f.severity,
                )
            )
            continue

        af_versions = list_versions(f.package_name, f.ecosystem, settings)
        selected, reason = choose_best_version(
            f.installed_version or "0",
            f.fix_versions,
            af_versions,
            allow_major=policy.allow_major,
            prefer_stable_only=policy.prefer_stable_only,
            ecosystem=f.ecosystem,
        )
        if selected is None:
            skipped.append(
                SkippedItem(
                    package=f.package_name,
                    from_version=f.installed_version,
                    ecosystem=f.ecosystem,
                    reason=reason,
                    severity=f.severity,
                )
            )
            continue
        from_ver = f.installed_version or "unknown"
        if from_ver == selected:
            skipped.append(
                SkippedItem(
                    package=f.package_name,
                    from_version=from_ver,
                    ecosystem=f.ecosystem,
                    reason="already at chosen version",
                    severity=f.severity,
                )
            )
            continue
        upgrades.append(
            UpgradeItem(
                package=f.package_name,
                from_version=from_ver,
                to_version=selected,
                ecosystem=f.ecosystem,
                reason=reason,
            )
        )

    return UpgradePlan(
        upgrades=upgrades,
        skipped=skipped,
        snyk_report_path=snyk_report_path,
        config_path=config_path,
    )
