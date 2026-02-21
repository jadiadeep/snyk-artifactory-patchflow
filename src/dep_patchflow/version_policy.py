"""Version selection policy: filter pre-releases, choose best version from Snyk + Artifactory."""

import logging
from typing import Tuple

from packaging.version import Version as PyVersion

from .models import Ecosystem

logger = logging.getLogger(__name__)


def filter_prereleases(versions: list[str], ecosystem: Ecosystem) -> list[str]:
    """Return only stable versions (no dev, alpha, beta, rc, post)."""
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
    try:
        return PyVersion(v)
    except Exception:
        return None


def _python_cmp(v1: str, v2: str) -> int:
    """Return -1 if v1 < v2, 0 if equal, 1 if v1 > v2."""
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
    if ecosystem == Ecosystem.PYTHON:
        p1, p2 = _parse_python_version(installed), _parse_python_version(candidate)
        if p1 is None or p2 is None:
            return True
        return p1.major != p2.major
    try:
        import semver
        v1 = semver.VersionInfo.parse(installed.lstrip("v"))
        v2 = semver.VersionInfo.parse(candidate.lstrip("v"))
        return v1.major != v2.major
    except Exception:
        return True


def choose_best_version(
    installed_version: str,
    snyk_fix_versions: list[str],
    artifactory_versions: list[str],
    allow_major: bool,
    prefer_stable_only: bool,
    ecosystem: Ecosystem,
) -> Tuple[str | None, str]:
    """
    Select the best upgrade version. All versions must exist in Artifactory (tool can only use what's there).
    - If Snyk's requested fix version exists in Artifactory → use it (prefer smallest Snyk fix that's available).
    - If Snyk's requested version is NOT in Artifactory → use the latest available in Artifactory
      (e.g. Snyk asks for 3.9 but Artifactory has only up to 3.7 → use 3.7 so the tool can actually download it).
    - Respect allow_major and prefer_stable_only.
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
