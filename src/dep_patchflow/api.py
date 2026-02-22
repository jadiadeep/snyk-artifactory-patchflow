"""Optional FastAPI: POST /scan-report, POST /apply, GET /health."""

import logging
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .config import Settings
from .patchwork_runner import apply_manifest_updates, run_patchwork
from .planner import build_plan
from .reporting import write_reports
from .snyk_parser import parse_snyk_json

logger = logging.getLogger(__name__)

app = FastAPI(
    title="dep-patchflow API",
    description="Snyk report → upgrade plan (Artifactory-gated) and apply with Patchwork",
    version="0.1.0",
)

# Load config once at startup (override via env)
_settings: Settings | None = None


def get_settings() -> Settings:
    """Get or create global Settings instance.

    Uses singleton pattern to load settings once at startup.
    Settings can be overridden via environment variables.

    Returns:
        Settings object loaded from environment variables
    """
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


class ScanReportResponse(BaseModel):
    plan_summary: dict
    upgrades_count: int
    skipped_count: int
    output_json_path: str | None
    output_md_path: str | None


class ApplyResponse(BaseModel):
    success: bool
    message: str
    modified_files: list[str]
    patchwork_run: bool


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "dep-patchflow"}


@app.post("/scan-report", response_model=ScanReportResponse)
async def scan_report(
    file: UploadFile = File(..., description="Snyk JSON report file"),
    config_path: str | None = None,
) -> ScanReportResponse:
    """Upload Snyk JSON report and generate upgrade plan.

    Parses the uploaded Snyk report, queries Artifactory for available versions,
    and generates an upgrade plan. Does not apply changes.

    Args:
        file: Uploaded Snyk JSON report file
        config_path: Optional path to config file (overrides default settings)

    Returns:
        ScanReportResponse with plan summary and output file paths

    Raises:
        HTTPException: If file is not JSON or processing fails
    """
    if not file.filename or not file.filename.endswith(".json"):
        raise HTTPException(400, "Expected a .json file (Snyk test --json output)")
    content = await file.read()
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        settings = get_settings()
        if config_path and Path(config_path).exists():
            settings = Settings.from_yaml(config_path)
        findings = parse_snyk_json(path)
        plan = build_plan(findings, settings)
        out_dir = Path("out")
        json_path, md_path = write_reports(plan, out_dir=out_dir)
        return ScanReportResponse(
            plan_summary=plan.summary(),
            upgrades_count=len(plan.upgrades),
            skipped_count=len(plan.skipped),
            output_json_path=str(json_path),
            output_md_path=str(md_path),
        )
    finally:
        Path(path).unlink(missing_ok=True)


@app.post("/apply", response_model=ApplyResponse)
async def apply(
    file: UploadFile = File(..., description="Snyk JSON report file"),
    project_dir: str = ".",
    run_patchwork: bool = True,
) -> ApplyResponse:
    """Apply upgrade plan: update manifests, optionally run Patchwork."""
    if not file.filename or not file.filename.endswith(".json"):
        raise HTTPException(400, "Expected a .json file")
    content = await file.read()
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        settings = get_settings()
        findings = parse_snyk_json(path)
        plan = build_plan(findings, settings)
        write_reports(plan, out_dir="out")
        modified = apply_manifest_updates(plan, Path(project_dir))
        pw_ran = False
        if run_patchwork:
            results = run_patchwork(settings, plan, project_dir=project_dir, dry_run=False)
            pw_ran = len(results) > 0
        return ApplyResponse(
            success=True,
            message="Plan applied",
            modified_files=modified,
            patchwork_run=pw_ran,
        )
    finally:
        Path(path).unlink(missing_ok=True)


def serve(host: str = "0.0.0.0", port: int = 8000) -> None:
    """Start FastAPI server with uvicorn.

    Args:
        host: Host to bind to (default: "0.0.0.0" for all interfaces)
        port: Port to listen on (default: 8000)
    """
    import uvicorn
    uvicorn.run("dep_patchflow.api:app", host=host, port=port, reload=False)
