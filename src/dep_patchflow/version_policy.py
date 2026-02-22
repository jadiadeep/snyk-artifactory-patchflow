"""Version selection policy: filter pre-releases, choose best version from Snyk + Artifactory."""

import logging
from typing import Tuple

from packaging.version import Version as PyVersion

from .models import Ecosystem

logger = logging.getLogger(__name__)


def filter_prereleases(versions: list[str], ecosystem: Ecosystem) -> list[str]:
    """Filter out pre-release versions, keeping only stable releases.

    Removes versions containing pre-release identifiers like:
    - dev, alpha, a0, beta, b0, rc, pre
    - Post releases (e.g., 1.0.0.post1) are kept for Python

    Args:
        versions: List of version strings to filter
        ecosystem: Package ecosystem (affects post-release handling)

    Returns:
        List containing only stable version strings
    """
    out: list[str] = []
    for v in versions:
        v_lower = v.lower()
        if any(
            x in v_lower
            for x in ("dev", "alpha", "a0", "beta", "b0", "rc", "pre", "post", "-")
        ):
            # Allow post releases like 1.0.0.post1 if we want; for prefer_stable_only we skip
            if ecosystem == Ecosystem.PYTHON and ".post" in v_lower and v_lower.count("-") == 0:
                out.append(v)
                continue
            continue
        out.append(v)
    return out


def _parse_python_version(v: str) -> PyVersion | None:
    """Parse Python version string using PEP 440 rules.

    Args:
        v: Version string to parse

    Returns:
        PyVersion object if valid, None otherwise
    """
    try:
        return PyVersion(v)
    except Exception:
        return None


def _python_cmp(v1: str, v2: str) -> int:
    """Compare two Python version strings.

    Args:
        v1: First version string
        v2: Second version string

    Returns:
        -1 if v1 < v2, 0 if equal, 1 if v1 > v2
        Invalid versions are treated as less than valid versions
    """
    p1, p2 = _parse_python_version(v1), _parse_python_version(v2)
    if p1 is None and p2 is None:
        return 0
    if p1 is None:
        return 1
    if p2 is None:
        return -1
    if p1 < p2:
        return -1
    if p1 > p2:
        return 1
    return 0


def _node_cmp(v1: str, v2: str) -> int:
    try:
        import semver
        ver1 = semver.VersionInfo.parse(v1.lstrip("v"))
        ver2 = semver.VersionInfo.parse(v2.lstrip("v"))
        if ver1 < ver2:
            return -1
        if ver1 > ver2:
            return 1
        return 0
    except Exception:
        return 0


def _is_major_upgrade(installed: str, candidate: str, ecosystem: Ecosystem) -> bool:
    """Check if candidate version is a major upgrade from installed version.

    Args:
        installed: Currently installed version
        candidate: Candidate version to check
        ecosystem: Package ecosystem (affects version parsing)

    Returns:
        True if candidate is a major version upgrade, False otherwise
        Returns True if version parsing fails (conservative approach)
    """
    if ecosystem == Ecosystem.PYTHON:
        p1, p2 = _parse_python_version(installed), _parse_python_version(candidate)
        if p1 is None or p2 is None:
            return True  # Conservative: assume major upgrade if parsing fails
        return p1.major != p2.major
    try:
        import semver
        v1 = semver.VersionInfo.parse(installed.lstrip("v"))
        v2 = semver.VersionInfo.parse(candidate.lstrip("v"))
        return v1.major != v2.major
    except Exception:
        return True  # Conservative: assume major upgrade if parsing fails


def choose_best_version(
    installed_version: str,
    snyk_fix_versions: list[str],
    artifactory_versions: list[str],
    allow_major: bool,
    prefer_stable_only: bool,
    ecosystem: Ecosystem,
) -> Tuple[str | None, str]:
    """Select the best upgrade version from available options.

    This function implements the core version selection logic:
    1. All versions must exist in Artifactory (tool can only use what's available)
    2. Prefer Snyk's recommended fix versions if available in Artifactory
    3. If Snyk's version not available, use latest available in Artifactory
    4. Respect policy constraints (allow_major, prefer_stable_only)

    Args:
        installed_version: Currently installed version (or "0" if unknown)
        snyk_fix_versions: List of versions Snyk recommends to fix the vulnerability
        artifactory_versions: List of versions available in Artifactory
        allow_major: Whether to allow major version upgrades
        prefer_stable_only: Whether to filter out pre-release versions
        ecosystem: Package ecosystem (PYTHON or NODE)

    Returns:
        Tuple of (selected_version, reason_string)
        - selected_version: Best version to upgrade to, or None if no suitable version
        - reason: Human-readable explanation of why this version was chosen

    Example:
        If Snyk recommends 3.9 but Artifactory only has up to 3.7,
        this function will return 3.7 with reason explaining that Snyk's
        version wasn't available, so latest in Artifactory was used.
    """
    installed = (installed_version or "0").strip()
    cmp_fn = _python_cmp if ecosystem == Ecosystem.PYTHON else _node_cmp
    af_set = set(artifactory_versions)
    if not af_set:
        return None, "No versions available in Artifactory"

    candidates = list(af_set)
    if prefer_stable_only:
        candidates = filter_prereleases(candidates, ecosystem)
    if not candidates:
        return None, "No stable versions in Artifactory after filtering pre-releases"

    # Sort ascending so "latest" = last element
    if ecosystem == Ecosystem.PYTHON:
        candidates.sort(key=lambda x: (_parse_python_version(x) or PyVersion("0")))
    else:
        try:
            import semver
            candidates.sort(key=lambda x: semver.VersionInfo.parse(x.lstrip("v")))
        except Exception:
            candidates.sort()

    # 1) Prefer Snyk fix versions that exist in Artifactory (use smallest that fixes)
    snyk_in_af = [s for s in snyk_fix_versions if s in af_set and (not prefer_stable_only or s in candidates)]
    if ecosystem == Ecosystem.PYTHON:
        snyk_in_af.sort(key=lambda x: (_parse_python_version(x) or PyVersion("0")))
    else:
        try:
            import semver
            snyk_in_af.sort(key=lambda x: semver.VersionInfo.parse(x.lstrip("v")))
        except Exception:
            snyk_in_af.sort()
    for snyk_ver in snyk_in_af:
        if not allow_major and _is_major_upgrade(installed, snyk_ver, ecosystem):
            continue
        return snyk_ver, "Snyk fix version available in Artifactory"

    # 2) Snyk's requested version(s) not in Artifactory → use latest available in Artifactory
    #    so the tool can actually download the package (e.g. Snyk says 3.9, Artifactory has 3.7 → use 3.7)
    for c in reversed(candidates):
        if allow_major:
            return c, "Latest in Artifactory (Snyk requested version not available)"
        if not _is_major_upgrade(installed, c, ecosystem):
            return c, "Latest in Artifactory (Snyk requested version not available)"
    return None, "No suitable version (major upgrade disallowed or no candidate)"
