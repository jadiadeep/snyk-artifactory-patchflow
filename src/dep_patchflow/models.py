"""Pydantic models for findings, upgrade plans, and reporting."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Ecosystem(str, Enum):
    PYTHON = "python"
    NODE = "node"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    """Normalized vulnerability finding from Snyk (or other source)."""

    ecosystem: Ecosystem
    package_name: str
    installed_version: str | None = None
    severity: Severity
    fix_versions: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict, exclude=True)

    def __hash__(self) -> int:
        return hash((self.ecosystem, self.package_name, self.installed_version or ""))


class UpgradeItem(BaseModel):
    """A single planned upgrade."""

    package: str
    from_version: str
    to_version: str
    ecosystem: Ecosystem
    reason: str


class SkippedItem(BaseModel):
    """A finding that was not upgraded (with reason)."""

    package: str
    from_version: str | None
    ecosystem: Ecosystem
    reason: str
    severity: Severity | None = None


class UpgradePlan(BaseModel):
    """Full upgrade plan: upgrades to apply and items skipped."""

    upgrades: list[UpgradeItem] = Field(default_factory=list)
    skipped: list[SkippedItem] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    snyk_report_path: str | None = None
    config_path: str | None = None

    def summary(self) -> dict[str, Any]:
        return {
            "upgrades_count": len(self.upgrades),
            "skipped_count": len(self.skipped),
            "generated_at": self.generated_at.isoformat(),
            "snyk_report_path": self.snyk_report_path,
            "config_path": self.config_path,
        }
