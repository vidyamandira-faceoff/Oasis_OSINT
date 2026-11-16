import re
from pathlib import Path
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import List, Optional

from core.config import BASE_DIR
from services.recon_username.backend.service import (
    execute_recon_task,
    get_recon_status,
    get_latest_findings,
    get_search_history,
    ensure_report_file,
    REPORTS_DIR
)

router = APIRouter()
templates = Jinja2Templates(directory=str(BASE_DIR))

class ReconRunRequest(BaseModel):
    target: str
    scope: Optional[str] = "standard"  # "quick", "standard", "deep"
    category: Optional[str] = "all"    # "all", "coding", "social", "business", etc.
    timeout: Optional[int] = 6
    force: Optional[bool] = False
    id_type: Optional[str] = "username"
    enrich: Optional[bool] = False
    with_domains: Optional[bool] = False
    recursive: Optional[bool] = False
    tor: Optional[bool] = False

from core.security import get_session_from_request
from core.database import record_execution, get_service_history_for_user
from roles.accounts import is_admin_user

@router.get("/services/recon-username")
async def page_view(request: Request, target: Optional[str] = None):
    session = get_session_from_request(request)
    if not session or not session.get("authenticated"):
        return RedirectResponse(url="/login", status_code=302)
    target_prefix = "/role_admin" if session.get("is_admin") else "/role_user"
    url = f"{target_prefix}/services/recon-username"
    if target:
        import urllib.parse
        url += f"?target={urllib.parse.quote_plus(target)}"
    return RedirectResponse(url=url, status_code=302)

@router.post("/api/recon_username/run")
async def run_task(req: ReconRunRequest, request: Request):
    target = req.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target identifier cannot be blank.")
    
    # Safe validation allowing handles, numerical IDs (Gaia/Steam/VK), and dots/dashes
    if not re.match(r'^[a-zA-Z0-9_\-\.:]{1,100}$', target):
        raise HTTPException(status_code=400, detail="Invalid target format. Use alphanumeric characters, numbers, dots, underscores, or hyphens.")
        
    result = execute_recon_task(
        target=target,
        scope=req.scope or "standard",
        category=req.category or "all",
        timeout=req.timeout or 6,
        force=bool(req.force),
        id_type=req.id_type or "username",
        enrich=bool(req.enrich),
        with_domains=bool(req.with_domains),
        recursive=bool(req.recursive if req.recursive is not None else True),
        tor=bool(req.tor)
    )

    # Record execution in relational database
    session = get_session_from_request(request)
    username = session.get("username", "admin") if session else "admin"
    try:
        record_execution(
            username=username,
            service_id="recon_username",
            service_name="Username Intelligence",
            tool_name="Maigret Async Engine",
            target=target,
            duration_seconds=float(result.get("duration", 4.2)),
            findings_count=int(result.get("count", 0)),
            findings_summary=f"Surveyed target '{target}' across public registries",
            status="Success",
            status_class="badge-status-success",
            report_path=f"services/recon_username/reports/report_{target}.json"
        )
    except Exception:
        pass

    return result

@router.get("/api/recon_username/status")
async def check_status(target: str):
    clean_target = target.strip()
    if not clean_target:
        raise HTTPException(status_code=400, detail="Target parameter required.")
    return get_recon_status(clean_target)

@router.get("/api/recon_username/results")
async def get_results(target: Optional[str] = None):
    clean_target = target.strip() if target else ""
    findings = get_latest_findings(clean_target)
    return {"target": clean_target, "findings": findings}

@router.get("/api/recon_username/history")
async def get_history(request: Request):
    session = get_session_from_request(request)
    username = session.get("username") if session else None
    is_admin = session.get("is_admin", False) if session else False
    db_history = get_service_history_for_user("recon_username", username=username, is_admin=is_admin)
    return {"history": db_history}

@router.get("/api/recon_username/download")
async def download_report(target: str, format: str = "json"):
    clean_target = target.strip()
    if not clean_target:
        raise HTTPException(status_code=400, detail="Target parameter required.")

    fmt = format.lower().strip()
    file_path = ensure_report_file(clean_target, fmt)
    if not file_path or not file_path.exists():
        raise HTTPException(status_code=404, detail="Requested report file does not exist and could not be generated.")

    media_map = {
        "csv": "text/csv",
        "html": "text/html",
        "md": "text/markdown",
        "txt": "text/plain",
        "json": "application/json"
    }
    media_type = media_map.get(fmt, "application/octet-stream")
    ext_map = {"csv": "csv", "html": "html", "md": "md", "txt": "txt", "json": "json"}
    ext = ext_map.get(fmt, "dat")
    filename = f"recon_{clean_target}_report.{ext}"

    return FileResponse(
        path=str(file_path),
        media_type=media_type,
        filename=filename
    )

@router.get("/api/recon_username/view-html")
async def view_html_dossier(target: str):
    clean_target = target.strip()
    if not clean_target:
        raise HTTPException(status_code=400, detail="Target parameter required.")
    
    html_path = ensure_report_file(clean_target, "html")
    if not html_path or not html_path.exists():
        raise HTTPException(status_code=404, detail="HTML dossier not found for this target.")
    
    content = html_path.read_text(encoding="utf-8")
    content = re.sub(r'(?i)maigret', 'OASIS Reconnaissance Engine', content)
    return HTMLResponse(content=content)
