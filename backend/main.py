"""
BABCOM GRC Platform — FastAPI Backend  v2.1
════════════════════════════════════════════════════════════════════════════
All API endpoints the React frontend consumes.

Endpoints
─────────
GET  /api/health               Backend health check
POST /api/run                  Start assessment (GitHub + local path)
GET  /api/status               Poll running assessment progress
POST /api/upload               Upload evidence files directly from browser
GET  /api/report               Full compliance report
GET  /api/report/summary       Score + risk level only
GET  /api/report/controls      All control results (filterable)
GET  /api/report/controls/{id} Single control detail
GET  /api/report/evidence      Canonical evidence store
GET  /api/report/risks         Risk register entries
GET  /api/report/export        Download PDF compliance report
GET  /api/sources              Files loaded in last run
GET  /api/frameworks           Available framework definitions
GET  /api/scheduler/status     Next scheduled run time
POST /api/scheduler/run-now    Trigger immediate scheduled run
GET  /api/docs                 Interactive API documentation (built-in)
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, BackgroundTasks, HTTPException, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from engine.runner          import GRCRunner
from engine.scheduler       import start_scheduler, stop_scheduler, get_next_run, set_result_callback
from connectors.github_connector import GitHubConnector
from connectors.local_connector  import LocalConnector

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
log = logging.getLogger(__name__)


# ── Shared state ──────────────────────────────────────────────────────────────
_state: dict = {
    "last_report": None,
    "running":     False,
    "progress":    [],
    "sources":     [],
}

# Default config used by the scheduler (updated on each /api/run call)
_last_run_config: dict = {
    "github_repo":          "adarshray416/GRC",
    "github_token":         None,
    "local_path":           r"D:\files\backend\evidence_store\evidence",
    "controls_frameworks":  ["ISO27001", "SOC2", "GDPR"],
    "alert_threshold":      80,
    "schedule_hour":        2,
    "schedule_minute":      0,
}


# ── Lifespan (startup / shutdown) ────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("BABCOM GRC Backend starting…")
    # Wire scheduler so it can push results into _state
    set_result_callback(lambda r: _state.update({"last_report": r}))
    start_scheduler(_last_run_config)
    yield
    stop_scheduler()
    log.info("BABCOM GRC Backend stopped")


app = FastAPI(
    title       = "BABCOM GRC API",
    description = "Compliance automation backend — ISO 27001 / SOC 2 / GDPR",
    version     = "2.1.0",
    lifespan    = lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins  = ["*"],
    allow_methods  = ["*"],
    allow_headers  = ["*"],
)


# ── Request / Response models ─────────────────────────────────────────────────
class RunRequest(BaseModel):
    github_repo:           str       = "adarshray416/GRC"
    github_token:          Optional[str] = None
    local_path:            str       = r"D:\files\backend\evidence_store\evidence"
    controls_frameworks:   List[str] = ["ISO27001", "SOC2", "GDPR"]
    alert_threshold:       int       = 80


# ── Progress helper ───────────────────────────────────────────────────────────
def _log(msg: str):
    _state["progress"].append(msg)
    log.info(msg)


# ── Core pipeline (runs in background) ───────────────────────────────────────
async def _run_pipeline(req: RunRequest):
    _state["running"]  = True
    _state["progress"] = []
    _state["sources"]  = []

    evidence_index: List[dict] = []

    # 1 — GitHub
    _log(f"Connecting to GitHub: {req.github_repo}…")
    try:
        gh = GitHubConnector(
            repo  = req.github_repo,
            token = req.github_token or os.getenv("GITHUB_TOKEN"),
        )
        files = gh.fetch_all()
        evidence_index.extend(files)
        _state["sources"].extend(files)
        _log(f"GitHub: {len(files)} file(s) found in {req.github_repo}")
    except Exception as e:
        _log(f"[WARN] GitHub: {e}")

    # 2 — Local path
    _log(f"Scanning local path: {req.local_path}…")
    try:
        lc    = LocalConnector(base_path=req.local_path)
        files = lc.fetch_all()
        evidence_index.extend(files)
        _state["sources"].extend(files)
        _log(f"Local: {len(files)} file(s) found")
    except Exception as e:
        _log(f"[WARN] Local: {e}")

    # 3 — Previously uploaded files (from /api/upload)
    upload_dir = _get_upload_dir()
    if upload_dir and Path(upload_dir).exists():
        try:
            from connectors.local_connector import LocalConnector as LC
            up_files = LC(base_path=upload_dir).fetch_all()
            for f in up_files:
                f["source"] = f"upload:{f['file']}"
            evidence_index.extend(up_files)
            _state["sources"].extend(up_files)
            _log(f"Uploaded files: {len(up_files)} file(s)")
        except Exception as e:
            _log(f"[WARN] Upload dir: {e}")

    if not evidence_index:
        _log("[ERROR] No evidence files found from any source.")
        _state["running"] = False
        return

    # 4 — Run GRC engine
    _log(f"Running GRC engine across {req.controls_frameworks}…")
    try:
        runner = GRCRunner(
            evidence_index = evidence_index,
            frameworks     = req.controls_frameworks,
        )
        report = runner.run(progress_cb=_log)
        _state["last_report"] = report
        # Update scheduler config with latest settings
        _last_run_config.update({
            "github_repo":         req.github_repo,
            "github_token":        req.github_token,
            "local_path":          req.local_path,
            "controls_frameworks": req.controls_frameworks,
            "alert_threshold":     req.alert_threshold,
        })
        _log(f"Assessment complete — score: {report['summary']['overall_score']}%  "
             f"risk: {report['summary']['risk_level']}")
    except Exception as e:
        _log(f"[ERROR] Engine: {e}")
        log.exception("Pipeline error")

    _state["running"] = False


# ── Upload directory management ───────────────────────────────────────────────
_upload_dir: Optional[str] = None

def _get_upload_dir() -> str:
    global _upload_dir
    if not _upload_dir:
        _upload_dir = tempfile.mkdtemp(prefix="grc_uploads_")
    return _upload_dir


# ═══════════════════════════════════════════════════════════════════════════════
# API ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

# ── Health ────────────────────────────────────────────────────────────────────
@app.get("/api/health", tags=["System"])
def health():
    """Simple health check — returns immediately if the backend is running."""
    return {"status": "ok", "version": "2.1.0"}


# ── Run assessment ────────────────────────────────────────────────────────────
@app.post("/api/run", tags=["Assessment"])
async def run_assessment(req: RunRequest, background_tasks: BackgroundTasks):
    """
    Start a GRC assessment.
    Scrapes GitHub repo + local path, then runs the full evaluation pipeline.
    Poll /api/status for progress.
    """
    if _state["running"]:
        raise HTTPException(status_code=409, detail="Assessment already running — wait for it to finish.")
    _state["progress"] = []
    background_tasks.add_task(_run_pipeline, req)
    return {"message": "Assessment started", "sources": ["github", "local", "uploads"]}


# ── Status polling ────────────────────────────────────────────────────────────
@app.get("/api/status", tags=["Assessment"])
def get_status():
    """
    Poll this endpoint while an assessment is running.
    Returns progress log lines and whether a report is available.
    """
    return {
        "running":    _state["running"],
        "progress":   _state["progress"],
        "has_report": _state["last_report"] is not None,
    }


# ── File upload ───────────────────────────────────────────────────────────────
@app.post("/api/upload", tags=["Evidence"])
async def upload_files(files: List[UploadFile] = File(...)):
    """
    Upload evidence files directly from the browser.
    Uploaded files are included in the next assessment run automatically.

    Accepts: .txt  .pdf  .csv  .log  .json  .md
    """
    upload_dir  = _get_upload_dir()
    saved       = []
    rejected    = []
    allowed_ext = {".txt", ".pdf", ".csv", ".log", ".json", ".md"}

    for uf in files:
        ext = Path(uf.filename).suffix.lower()
        if ext not in allowed_ext:
            rejected.append(uf.filename)
            continue
        dest = Path(upload_dir) / uf.filename
        content = await uf.read()
        dest.write_bytes(content)
        saved.append({
            "file": uf.filename,
            "size": len(content),
            "path": str(dest),
        })

    return {
        "saved":    saved,
        "rejected": rejected,
        "message":  f"{len(saved)} file(s) saved. They will be included in the next Run Assessment.",
    }


@app.delete("/api/upload", tags=["Evidence"])
def clear_uploads():
    """Clear all previously uploaded files."""
    upload_dir = _get_upload_dir()
    count = 0
    for f in Path(upload_dir).glob("*"):
        if f.is_file():
            f.unlink()
            count += 1
    return {"message": f"Cleared {count} uploaded file(s)"}


@app.get("/api/upload", tags=["Evidence"])
def list_uploads():
    """List currently uploaded files waiting to be assessed."""
    upload_dir = _get_upload_dir()
    files = [
        {"file": f.name, "size": f.stat().st_size}
        for f in Path(upload_dir).glob("*") if f.is_file()
    ]
    return {"files": files, "count": len(files)}


# ── Report ────────────────────────────────────────────────────────────────────
def _require_report():
    if not _state["last_report"]:
        raise HTTPException(
            status_code=404,
            detail="No report yet. POST /api/run to start an assessment first."
        )
    return _state["last_report"]


@app.get("/api/report", tags=["Report"])
def get_report():
    """Full compliance report (JSON). Includes all controls, evidence, sources."""
    return _require_report()


@app.get("/api/report/summary", tags=["Report"])
def get_summary():
    """Score, risk level, and per-framework breakdown only."""
    return _require_report()["summary"]


@app.get("/api/report/controls", tags=["Report"])
def get_controls(
    framework: Optional[str] = Query(None, description="Filter by framework, e.g. ISO27001"),
    status:    Optional[str] = Query(None, description="Filter by status: pass/partial/fail/missing"),
):
    """
    All control results.
    Optionally filter by framework (ISO27001, SOC2, GDPR) or status.
    """
    controls = _require_report()["controls"]
    if framework:
        controls = [c for c in controls if c.get("framework", "").upper() == framework.upper()]
    if status:
        controls = [c for c in controls if c.get("status") == status]
    return controls


@app.get("/api/report/controls/{control_id}", tags=["Report"])
def get_control(control_id: str):
    """Full detail for a single control including all check results."""
    report = _require_report()
    for c in report["controls"]:
        if c["control_id"] == control_id:
            return c
    raise HTTPException(status_code=404, detail=f"Control '{control_id}' not found.")


@app.get("/api/report/evidence", tags=["Report"])
def get_evidence():
    """Canonical evidence store — extracted structured data from all files."""
    return _require_report().get("evidence_store", {})


@app.get("/api/report/risks", tags=["Report"])
def get_risks():
    """Risk register entries extracted from all risk evidence files."""
    store = _require_report().get("evidence_store", {})
    risks = store.get("risk", [])
    return {
        "count":  len(risks),
        "risks":  risks,
        "high_critical": [r for r in risks if r.get("impact") in ("critical", "high")],
        "untreated":     [r for r in risks if r.get("status") != "approved"],
    }


@app.get("/api/report/export", tags=["Report"])
def export_pdf():
    """
    Download the compliance report as a PDF file.
    Requires: pip install reportlab
    """
    report = _require_report()
    try:
        from engine.pdf_report import generate_pdf_report
        pdf_bytes = generate_pdf_report(report)
        return StreamingResponse(
            iter([pdf_bytes]),
            media_type = "application/pdf",
            headers    = {
                "Content-Disposition": "attachment; filename=grc_compliance_report.pdf",
                "Content-Length":      str(len(pdf_bytes)),
            }
        )
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="PDF export requires reportlab. Run: pip install reportlab"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")


# ── Sources ───────────────────────────────────────────────────────────────────
@app.get("/api/sources", tags=["Evidence"])
def get_sources():
    """Files loaded during the last assessment run."""
    return {
        "sources": _state["sources"],
        "count":   len(_state["sources"]),
    }


# ── Frameworks ────────────────────────────────────────────────────────────────
@app.get("/api/frameworks", tags=["Configuration"])
def get_frameworks():
    """Available compliance frameworks and their control counts."""
    report   = _state["last_report"]
    by_fw    = report["summary"]["by_framework"] if report else {}
    controls = report["controls"]               if report else []

    frameworks = []
    for fw_id, name in [("ISO27001","ISO 27001:2022"), ("SOC2","SOC 2 Type II"), ("GDPR","GDPR")]:
        fw_controls = [c for c in controls if c.get("framework") == fw_id]
        d = by_fw.get(fw_id, {})
        frameworks.append({
            "id":       fw_id,
            "name":     name,
            "controls": len(fw_controls) or sum(1 for _ in []),
            "score":    d.get("score"),
            "pass":     d.get("pass"),
            "fail":     d.get("fail"),
        })
    return frameworks


# ── Scheduler ─────────────────────────────────────────────────────────────────
@app.get("/api/scheduler/status", tags=["Scheduler"])
def scheduler_status():
    """Next scheduled assessment run time."""
    return {
        "enabled":   True,
        "next_run":  get_next_run(),
        "schedule":  f"Daily at {_last_run_config.get('schedule_hour',2):02d}:"
                     f"{_last_run_config.get('schedule_minute',0):02d} UTC",
    }


@app.post("/api/scheduler/run-now", tags=["Scheduler"])
async def scheduler_run_now(background_tasks: BackgroundTasks):
    """Trigger an immediate assessment using the last configured sources."""
    if _state["running"]:
        raise HTTPException(status_code=409, detail="Assessment already running.")
    req = RunRequest(
        github_repo          = _last_run_config.get("github_repo", "adarshray416/GRC"),
        github_token         = _last_run_config.get("github_token"),
        local_path           = _last_run_config.get("local_path", r"D:\files\backend\evidence_store\evidence"),
        controls_frameworks  = _last_run_config.get("controls_frameworks", ["ISO27001"]),
    )
    background_tasks.add_task(_run_pipeline, req)
    return {"message": "Immediate assessment triggered"}
