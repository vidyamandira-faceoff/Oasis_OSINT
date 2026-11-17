import re
from pathlib import Path
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from typing import Optional

from core.config import BASE_DIR
from services.phone_intelligence.backend.service import (
    execute_phone_task,
    get_phone_status,
    get_phone_history,
    ensure_phone_report_file,
    NATIVE_PHONE_ENDPOINT,
    REPORTS_DIR
)

router = APIRouter()
templates = Jinja2Templates(directory=str(BASE_DIR))

class PhoneRunRequest(BaseModel):
    target: str = Field(min_length=3, max_length=50)
    country: Optional[str] = "IN"
    force: Optional[bool] = False

from core.security import get_session_from_request
from core.database import record_execution, get_service_history_for_user
from roles.accounts import is_admin_user

@router.get("/services/phone-intelligence")
@router.get("/services/recon-phone")
async def page_view(request: Request, target: Optional[str] = None):
    session = get_session_from_request(request)
    if not session or not session.get("authenticated"):
        return RedirectResponse(url="/login", status_code=302)
    target_prefix = "/role_admin" if session.get("is_admin") else "/role_user"
    url = f"{target_prefix}/services/phone-intelligence"
    if target:
        import urllib.parse
        url += f"?target={urllib.parse.quote_plus(target)}"
    return RedirectResponse(url=url, status_code=302)

@router.post("/api/phone_intelligence/run")
async def run_task(req: PhoneRunRequest, request: Request):
    clean_target = req.target.strip()
    if not clean_target:
        raise HTTPException(status_code=400, detail="Target phone number cannot be blank.")

    try:
        result = execute_phone_task(
            target=clean_target,
            default_country=req.country or "IN",
            force=bool(req.force)
        )
        session = get_session_from_request(request)
        username = session.get("username", "admin") if session else "admin"
        try:
            record_execution(
                username=username,
                service_id="phone_intelligence",
                service_name="Phone Number Intelligence",
                tool_name="Libphonenumber Carrier Engine",
                target=clean_target,
                duration_seconds=float(result.get("duration", 0.8)),
                findings_count=1,
                findings_summary=f"Carrier & format analysis on {clean_target}",
                status="Success",
                status_class="badge-status-success",
                report_path=f"services/phone_intelligence/reports/report_{clean_target}_simple.json"
            )
        except Exception:
            pass
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Phone intelligence execution failed: {str(e)}")

@router.get("/api/phone_intelligence/status")
async def check_status(target: str):
    clean_target = target.strip()
    if not clean_target:
        raise HTTPException(status_code=400, detail="Target parameter required.")
    return get_phone_status(clean_target)

@router.get("/api/phone_intelligence/history")
async def get_history(request: Request):
    session = get_session_from_request(request)
    username = session.get("username") if session else None
    is_admin = session.get("is_admin", False) if session else False
    db_history = get_service_history_for_user("phone_intelligence", username=username, is_admin=is_admin)
    return {"history": db_history}

@router.get("/api/phone_intelligence/native-endpoint")
async def get_native_endpoint():
    return {"endpoint": NATIVE_PHONE_ENDPOINT}

@router.get("/api/phone_intelligence/download")
async def download_report(target: str, format: str = "json"):
    clean_target = target.strip()
    if not clean_target:
        raise HTTPException(status_code=400, detail="Target parameter required.")

    fmt = format.lower().strip()
    file_path = ensure_phone_report_file(clean_target, fmt)
    if not file_path or not file_path.exists():
        raise HTTPException(status_code=404, detail="Requested report file does not exist and could not be generated.")

    media_map = {
        "csv": "text/csv",
        "json": "application/json",
        "md": "text/markdown",
        "txt": "text/plain"
    }
    media_type = media_map.get(fmt, "text/plain")
    filename = f"phone_intelligence_{clean_target}.{fmt}"

    return FileResponse(
        path=str(file_path),
        media_type=media_type,
        filename=filename,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )
