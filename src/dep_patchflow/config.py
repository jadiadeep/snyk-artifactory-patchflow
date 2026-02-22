"""Pydantic settings: env + optional config file. No secrets in code."""

from pathlib import Path
from typing import Literal

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class PolicySettings(BaseSettings):
    """Version and run policy settings.

    Controls upgrade behavior such as severity thresholds, major version upgrades,
    and maximum number of upgrades per run.
    """

    allow_major: bool = False
    min_severity: Literal["low", "medium", "high", "critical"] = "medium"
    max_upgrades_per_run: int = Field(ge=1, le=500, default=20)
    prefer_stable_only: bool = True
    dry_run: bool = False


class Settings(BaseSettings):
    """Main application settings loaded from environment variables and config files.

    Supports loading from:
    - Environment variables (with UPPER_SNAKE_CASE names)
    - .env file
    - YAML config file (via from_yaml class method)

    Environment variables take precedence over config file values.
    """

    model_config = SettingsConfigDict(
        env_prefix="",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Artifactory
    artifactory_base_url: str = Field(default="", alias="ARTIFACTORY_BASE_URL")
    artifactory_token: str = Field(default="", alias="ARTIFACTORY_TOKEN")
    artifactory_username: str = Field(default="", alias="ARTIFACTORY_USERNAME")
    artifactory_password: str = Field(default="", alias="ARTIFACTORY_PASSWORD")
    artifactory_repo_pypi: str = Field(default="pypi-remote", alias="ARTIFACTORY_REPO_PYPI")
    artifactory_repo_npm: str = Field(default="npm-remote", alias="ARTIFACTORY_REPO_NPM")
    artifactory_version_method: Literal["aql", "metadata"] = Field(
        default="aql", alias="ARTIFACTORY_VERSION_METHOD"
    )

    # Snyk (optional when using file report)
    snyk_token: str = Field(default="", alias="SNYK_TOKEN")

    # Patchwork / LLM
    openai_api_key: str = Field(default="", alias="OPENAI_API_KEY")
    patchwork_default_yml_path: str = Field(
        default="default.yml", alias="PATCHWORK_DEFAULT_YML_PATH"
    )

    # Policy (nested in YAML; env override via POLICY_ALLOW_MAJOR etc.)
    policy_allow_major: bool | None = Field(default=None, alias="POLICY_ALLOW_MAJOR")
    policy_min_severity: Literal["low", "medium", "high", "critical"] | None = Field(
        default=None, alias="POLICY_MIN_SEVERITY"
    )
    policy_max_upgrades_per_run: int | None = Field(
        default=None, alias="POLICY_MAX_UPGRADES_PER_RUN"
    )
    policy_prefer_stable_only: bool | None = Field(
        default=None, alias="POLICY_PREFER_STABLE_ONLY"
    )
    policy_dry_run: bool | None = Field(default=None, alias="POLICY_DRY_RUN")

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Settings":
        """Load settings from config file; env vars override (pydantic-settings merge)."""
        path = Path(path)
        if not path.exists():
            return cls()
        data = yaml.safe_load(path.read_text()) or {}
        policy = data.pop("policy", None) or {}
        for k, v in policy.items():
            key = f"policy_{k}"
            if key not in data and v is not None:
                data[key] = v
        import os
        for k, v in list(data.items()):
            if isinstance(v, str) and v.startswith("${") and v.endswith("}"):
                var = v[2:-1].strip()
                data[k] = os.environ.get(var, v)
        return cls(**{k: v for k, v in data.items() if k in cls.model_fields})

    def get_policy(self) -> PolicySettings:
        """Build PolicySettings from current settings.

        Converts policy_* fields to PolicySettings object, using defaults
        for any None values. Environment variables override YAML config.

        Returns:
            PolicySettings object with all policy values resolved
        """
        return PolicySettings(
            allow_major=self.policy_allow_major if self.policy_allow_major is not None else False,
            min_severity=self.policy_min_severity or "medium",
            max_upgrades_per_run=self.policy_max_upgrades_per_run or 20,
            prefer_stable_only=self.policy_prefer_stable_only if self.policy_prefer_stable_only is not None else True,
            dry_run=self.policy_dry_run if self.policy_dry_run is not None else False,
        )
