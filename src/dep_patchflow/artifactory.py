"""JFrog Artifactory client: list available package versions (AQL or metadata)."""

import logging
from typing import Any

import httpx
from packaging.version import Version as PyVersion

from .config import Settings
from .models import Ecosystem

logger = logging.getLogger(__name__)

# In-memory cache: (ecosystem, package_name) -> list[str] of versions
_version_cache: dict[tuple[str, str], list[str]] = {}
_cache_miss_reasons: dict[tuple[str, str], str] = {}


def _sort_python(versions: list[str]) -> list[str]:
    parsed: list[tuple[PyVersion, str]] = []
    for v in versions:
        try:
            parsed.append((PyVersion(v), v))
        except Exception:
            parsed.append((PyVersion("0"), v))
    parsed.sort(key=lambda x: x[0])
    return [v for _, v in parsed]


def _sort_node(versions: list[str]) -> list[str]:
    try:
        import semver
        parsed: list[tuple[tuple[int, int, int], str]] = []
        for v in versions:
            try:
                ver = semver.VersionInfo.parse(v.lstrip("v"))
                parsed.append(((ver.major, ver.minor, ver.patch), v))
            except Exception:
                parsed.append(((0, 0, 0), v))
        parsed.sort(key=lambda x: x[0])
        return [v for _, v in parsed]
    except Exception:
        return sorted(versions)


def _auth_headers(settings: Settings) -> dict[str, str]:
    if settings.artifactory_token:
        return {"Authorization": f"Bearer {settings.artifactory_token}"}
    if settings.artifactory_username and settings.artifactory_password:
        import base64
        cred = base64.b64encode(
            f"{settings.artifactory_username}:{settings.artifactory_password}".encode()
        ).decode()
        return {"Authorization": f"Basic {cred}"}
    return {}


def list_versions_aql(
    client: httpx.Client,
    base_url: str,
    repo: str,
    ecosystem: Ecosystem,
    package_name: str,
) -> list[str]:
    """
    List versions via Artifactory AQL.
    PyPI: repo path typically stores items like package_name/version/
    NPM: repo path typically stores package_name/-/package_name-version.tgz
    """
    if ecosystem == Ecosystem.PYTHON:
        # AQL: find items in repo where path contains package name
        # Common layout: repo/pypi/packagename/version/filename
        aql = {
            "repo": repo,
            "path": {"$match": f"*{package_name}*"},
            "name": {"$match": "*.whl"},
        }
        # Alternative: name might be packagename-version.whl
        # We'll collect "path" and extract version from path
    else:
        aql = {
            "repo": repo,
            "path": {"$match": f"*{package_name}*"},
            "name": {"$match": "*.tgz"},
        }

    url = f"{base_url.rstrip('/')}/api/search/aql"
    body = "items.find(" + __aql_dict_to_query(aql) + ").include(\"path\",\"name\")"
    try:
        resp = client.post(url, content=body, headers={"Content-Type": "text/plain"})
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        logger.debug("AQL request failed for %s/%s: %s", ecosystem.value, package_name, e)
        return []

    results = data.get("results") or []
    versions: set[str] = set()
    for r in results:
        path = (r.get("path") or "") + "/" + (r.get("name") or "")
        # PyPI: path like pypi/requests/2.28.0/requests-2.28.0.whl -> 2.28.0
        # NPM: path like npm/axios/-/axios-1.6.0.tgz -> 1.6.0
        parts = path.replace("\\", "/").split("/")
        for i, part in enumerate(parts):
            if part == package_name and i + 1 < len(parts):
                cand = parts[i + 1]
                if cand != "-" and not cand.endswith(".whl") and not cand.endswith(".tgz"):
                    versions.add(cand)
            # npm: package_name-1.2.3.tgz
            if package_name in part and ".tgz" in part:
                rest = part.replace(f"{package_name}-", "").replace(".tgz", "").strip()
                if rest and rest[0].isdigit():
                    versions.add(rest)
        # Try version from path segment that looks like semver/pep440
        for part in parts:
            if part and part[0].isdigit() and "." in part and package_name.lower() in path.lower():
                versions.add(part)
    out = list(versions)
    if ecosystem == Ecosystem.PYTHON:
        return _sort_python(out)
    return _sort_node(out)


def __aql_dict_to_query(d: dict) -> str:
    parts = []
    for k, v in d.items():
        if isinstance(v, dict) and "$match" in v:
            parts.append(f'"{k}":{{"$match":"{v["$match"]}"}}')
        else:
            parts.append(f'"{k}":"{v}"')
    return "{" + ",".join(parts) + "}"


def list_versions_metadata(
    client: httpx.Client,
    base_url: str,
    repo: str,
    ecosystem: Ecosystem,
    package_name: str,
) -> list[str]:
    """
    List versions via repository metadata / folder browsing.
    PyPI: GET /artifactory/repo/pypi/packagename/ -> parse index or simple list
    NPM: GET /artifactory/repo/package_name -> parse package metadata
    """
    base = base_url.rstrip("/")
    if ecosystem == Ecosystem.PYTHON:
        # Many Artifactory PyPI setups: /repo/api/pypi/<repo>/packages/<name>/versions
        url = f"{base}/api/pypi/{repo}/packages/{package_name}/versions"
        try:
            resp = client.get(url)
            if resp.status_code == 404:
                url2 = f"{base}/{repo}/pypi/{package_name}/"
                resp = client.get(url2)
            resp.raise_for_status()
            data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
            if isinstance(data, list):
                vers = data
            elif isinstance(data, dict) and "versions" in data:
                vers = data["versions"]
            else:
                vers = []
            return _sort_python([str(v) for v in vers])
        except Exception as e:
            logger.debug("Metadata request failed for pypi %s: %s", package_name, e)
            return []
    else:
        # NPM: /artifactory/repo/package_name or /api/npm/npm-repo/package_name
        url = f"{base}/api/npm/npms/{repo}/{package_name}"
        try:
            resp = client.get(url)
            if resp.status_code != 200:
                url2 = f"{base}/{repo}/{package_name}"
                resp = client.get(url2)
            resp.raise_for_status()
            data = resp.json()
            versions = data.get("versions") or data.get("version") or {}
            if isinstance(versions, dict):
                return _sort_node(list(versions.keys()))
            if isinstance(versions, list):
                return _sort_node([str(v) for v in versions])
            return []
        except Exception as e:
            logger.debug("Metadata request failed for npm %s: %s", package_name, e)
            return []


def list_versions(
    package_name: str,
    ecosystem: Ecosystem,
    settings: Settings,
    use_cache: bool = True,
) -> list[str]:
    """
    Return sorted list of versions available in Artifactory for the given package.
    Uses in-memory cache by default. Returns [] on failure and records reason in _cache_miss_reasons.
    """
    cache_key = (ecosystem.value, package_name)
    if use_cache and cache_key in _version_cache:
        return _version_cache[cache_key]
    if use_cache and cache_key in _cache_miss_reasons:
        logger.debug("Cache miss reason for %s: %s", cache_key, _cache_miss_reasons[cache_key])
        return []

    if not settings.artifactory_base_url:
        _cache_miss_reasons[cache_key] = "ARTIFACTORY_BASE_URL not set"
        return []

    repo = settings.artifactory_repo_pypi if ecosystem == Ecosystem.PYTHON else settings.artifactory_repo_npm
    headers = _auth_headers(settings)
    versions: list[str] = []

    with httpx.Client(timeout=30.0, headers=headers) as client:
        if getattr(settings, "artifactory_version_method", "aql") == "metadata":
            versions = list_versions_metadata(
                client, settings.artifactory_base_url, repo, ecosystem, package_name
            )
        else:
            versions = list_versions_aql(
                client, settings.artifactory_base_url, repo, ecosystem, package_name
            )

    if not versions:
        _cache_miss_reasons[cache_key] = "No versions returned (check repo layout or AQL)"
    else:
        _version_cache[cache_key] = versions
    return versions


def clear_cache() -> None:
    """Clear in-memory version cache (e.g. for tests)."""
    global _version_cache, _cache_miss_reasons
    _version_cache = {}
    _cache_miss_reasons = {}
