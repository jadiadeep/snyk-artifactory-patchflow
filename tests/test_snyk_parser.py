"""Tests for Snyk JSON parser."""

import json
import tempfile
from pathlib import Path

import pytest

from dep_patchflow.models import Ecosystem, Severity
from dep_patchflow.snyk_parser import parse_snyk_json


def test_parse_snyk_minimal() -> None:
    data = {
        "vulnerabilities": [
            {
                "packageName": "requests",
                "version": "2.25.0",
                "severity": "high",
                "upgradePath": ["requests@2.28.0"],
            }
        ],
        "packageManager": "pip",
    }
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        f.write(json.dumps(data).encode())
        path = f.name
    try:
        findings = parse_snyk_json(path)
        assert len(findings) == 1
        f = findings[0]
        assert f.package_name == "requests"
        assert f.installed_version == "2.25.0"
        assert f.severity == Severity.HIGH
        assert f.ecosystem == Ecosystem.PYTHON
        assert "2.28.0" in f.fix_versions
    finally:
        Path(path).unlink(missing_ok=True)


def test_parse_snyk_upgrade_path_array() -> None:
    data = {
        "vulnerabilities": [
            {
                "moduleName": "axios",
                "version": "0.21.0",
                "severity": "critical",
                "upgradePath": ["axios@0.21.1", "axios@1.6.0"],
            }
        ],
        "packageManager": "npm",
    }
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        f.write(json.dumps(data).encode())
        path = f.name
    try:
        findings = parse_snyk_json(path)
        assert len(findings) == 1
        f = findings[0]
        assert f.package_name == "axios"
        assert f.ecosystem == Ecosystem.NODE
        assert f.severity == Severity.CRITICAL
        assert "0.21.1" in f.fix_versions
        assert "1.6.0" in f.fix_versions
    finally:
        Path(path).unlink(missing_ok=True)


def test_parse_snyk_dedupe() -> None:
    data = {
        "vulnerabilities": [
            {"packageName": "foo", "version": "1.0", "severity": "medium"},
            {"packageName": "foo", "version": "1.0", "severity": "high"},
        ],
        "packageManager": "pip",
    }
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        f.write(json.dumps(data).encode())
        path = f.name
    try:
        findings = parse_snyk_json(path)
        assert len(findings) == 1
    finally:
        Path(path).unlink(missing_ok=True)


def test_parse_nonexistent() -> None:
    findings = parse_snyk_json(Path("/nonexistent/snyk.json"))
    assert findings == []


def test_parse_invalid_json() -> None:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        f.write(b"not json")
        path = f.name
    try:
        findings = parse_snyk_json(path)
        assert findings == []
    finally:
        Path(path).unlink(missing_ok=True)
