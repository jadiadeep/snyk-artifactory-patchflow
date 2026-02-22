"""Pydantic models for findings, upgrade plans, and reporting.

This module defines the core data structures used throughout the application:
- Ecosystem: Supported package ecosystems (Python, Node.js)
- Severity: Vulnerability severity levels
- Finding: Normalized vulnerability finding from Snyk reports
- UpgradeItem: A single planned dependency upgrade
- SkippedItem: A finding that was skipped (with reason)
- UpgradePlan: Complete upgrade plan with upgrades and skipped items
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Ecosystem(str, Enum):
    """Supported package ecosystems for dependency management."""

    PYTHON = "python"
    NODE = "node"


class Severity(str, Enum):
    """Vulnerability severity levels as defined by Snyk."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    """Normalized vulnerability finding from Snyk (or other source).

    Represents a single vulnerability finding parsed from a Snyk JSON report.
    All findings are normalized to this format regardless of source format.

    Attributes:
        ecosystem: Package ecosystem (Python or Node.js)
        package_name: Name of the vulnerable package
        installed_version: Currently installed version (may be None)
        severity: Vulnerability severity level
        fix_versions: List of versions that fix this vulnerability (from Snyk)
        raw: Original raw data from Snyk report (excluded from serialization)
    """

    ecosystem: Ecosystem
    package_name: str
    installed_version: str | None = None
    severity: Severity
    fix_versions: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict, exclude=True)

    def __hash__(self) -> int:
        """Generate hash for deduplication based on ecosystem, package name, and version."""
        return hash((self.ecosystem, self.package_name, self.installed_version or ""))


class UpgradeItem(BaseModel):
    """A single planned dependency upgrade.

    Represents one package that will be upgraded as part of the upgrade plan.

    Attributes:
        package: Package name to upgrade
        from_version: Current version
        to_version: Target version (must exist in Artifactory)
        ecosystem: Package ecosystem
        reason: Explanation of why this version was chosen
    """

    package: str
    from_version: str
    to_version: str
    ecosystem: Ecosystem
    reason: str


class SkippedItem(BaseModel):
    """A finding that was not upgraded (with reason).

    Represents a vulnerability that was identified but not included in the upgrade plan,
    along with the reason why it was skipped.

    Attributes:
        package: Package name that was skipped
        from_version: Current version (may be None if unknown)
        ecosystem: Package ecosystem
        reason: Explanation of why this was skipped
        severity: Vulnerability severity (optional, for reporting)
    """

    package: str
    from_version: str | None
    ecosystem: Ecosystem
    reason: str
    severity: Severity | None = None


class UpgradePlan(BaseModel):
    """Full upgrade plan: upgrades to apply and items skipped.

    This is the main output of the planning phase. It contains:
    - List of upgrades to apply (with versions verified in Artifactory)
    - List of items that were skipped (with reasons)
    - Metadata about when/how the plan was generated

    Attributes:
        upgrades: List of packages to upgrade
        skipped: List of packages that were skipped
        generated_at: Timestamp when plan was generated
        snyk_report_path: Path to the Snyk report used (for reference)
        config_path: Path to config file used (for reference)
    """

    upgrades: list[UpgradeItem] = Field(default_factory=list)
    skipped: list[SkippedItem] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    snyk_report_path: str | None = None
    config_path: str | None = None

    def summary(self) -> dict[str, Any]:
        """Generate a summary dictionary of the upgrade plan.

        Returns:
            Dictionary containing counts, timestamps, and paths for reporting.
        """
        return {
            "upgrades_count": len(self.upgrades),
            "skipped_count": len(self.skipped),
            "generated_at": self.generated_at.isoformat(),
            "snyk_report_path": self.snyk_report_path,
            "config_path": self.config_path,
        }
