"""Tests for version selection policy."""

import pytest

from dep_patchflow.models import Ecosystem
from dep_patchflow.version_policy import (
    choose_best_version,
    filter_prereleases,
)


def test_filter_prereleases_python() -> None:
    versions = ["1.0.0", "2.0.0rc1", "1.1.0b0", "3.0.0"]
    out = filter_prereleases(versions, Ecosystem.PYTHON)
    assert "1.0.0" in out
    assert "3.0.0" in out
    assert "2.0.0rc1" not in out
    assert "1.1.0b0" not in out


def test_choose_best_snyk_in_artifactory() -> None:
    selected, reason = choose_best_version(
        "1.0.0",
        ["2.0.0", "1.2.0"],
        ["1.1.0", "1.2.0", "2.0.0"],
        allow_major=False,
        prefer_stable_only=True,
        ecosystem=Ecosystem.PYTHON,
    )
    assert selected == "1.2.0"
    assert "Snyk" in reason


def test_choose_best_no_major() -> None:
    selected, reason = choose_best_version(
        "1.0.0",
        ["2.0.0"],
        ["1.1.0", "2.0.0"],
        allow_major=False,
        prefer_stable_only=True,
        ecosystem=Ecosystem.PYTHON,
    )
    assert selected == "1.1.0"
    assert "Artifactory" in reason


def test_choose_best_empty_artifactory() -> None:
    selected, reason = choose_best_version(
        "1.0.0",
        ["2.0.0"],
        [],
        allow_major=True,
        prefer_stable_only=True,
        ecosystem=Ecosystem.PYTHON,
    )
    assert selected is None
    assert "Artifactory" in reason


def test_choose_best_major_allowed() -> None:
    selected, reason = choose_best_version(
        "1.0.0",
        ["2.0.0"],
        ["1.0.0", "2.0.0"],
        allow_major=True,
        prefer_stable_only=True,
        ecosystem=Ecosystem.PYTHON,
    )
    assert selected == "2.0.0"
