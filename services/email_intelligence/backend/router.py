from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from typing import Optional, List
from pathlib import Path

from services.email_intelligence.backend.engine_worker import parse_target_emails, is_valid_email
from services.email_intelligence.backend.service import (
    execute_email_recon,
    get_email_status,
    ensure_email_report_file,
    get_recent_email_scans,
    execute_mailbox_discovery,
    get_mailbox_status,
    ensure_mailbox_report_file,
    get_recent_mailbox_scans
)

router = APIRouter()

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR))

class EmailRunRequest(BaseModel):
    target: str = Field(min_length=3, max_length=1500)
    force: Optional[bool] = False
    timeout: Optional[int] = 10
    no_password_recovery: Optional[bool] = False

class MailboxRunRequest(BaseModel):
    username: str = Field(min_length=2, max_length=150)
    force: Optional[bool] = False
    timeout: Optional[int] = 10

from core.security import get_session_from_request
from core.database import record_execution, get_service_history_for_user
from roles.accounts import is_admin_user

@router.get("/services/email-intelligence")
async def page_view(request: Request, target: Optional[str] = None):
    session = get_session_from_request(request)
    if not session or not session.get("authenticated"):
        return RedirectResponse(url="/login", status_code=302)
    target_prefix = "/role_admin" if session.get("is_admin") else "/role_user"
    url = f"{target_prefix}/services/email-intelligence"
    if target:
        import urllib.parse
        url += f"?target={urllib.parse.quote_plus(target)}"
    return RedirectResponse(url=url, status_code=302)

@router.post("/api/email_intelligence/run")
async def run_email_task(req: EmailRunRequest, request: Request):
    raw_target = req.target.strip()
    if not raw_target:
        raise HTTPException(status_code=400, detail="Target email address cannot be blank.")
    
    parsed = parse_target_emails(raw_target)
    if not parsed:
        raise HTTPException(status_code=400, detail="No valid email address found in input.")

    session = get_session_from_request(request)
    username = session.get("username", "admin") if session else "admin"

    # Single target
    if len(parsed) == 1:
        target = parsed[0]
        try:
            result = execute_email_recon(
                email=target,
                force=bool(req.force),
                timeout=req.timeout or 10,
                no_password_recovery=bool(req.no_password_recovery)
            )
            result["batch"] = False
            result["parsed_targets"] = parsed

            # Record in relational database
            try:
                findings_cnt = len(result.get("findings", []))
                record_execution(
                    username=username,
                    service_id="email_intelligence",
                    service_name="Email Intelligence",
                    tool_name="Holehe 124 Platform Footprint",
                    target=target,
                    duration_seconds=float(result.get("duration", 8.0)),
                    findings_count=findings_cnt,
                    findings_summary=f"{findings_cnt} verified platforms identified",
                    status="Success",
                    status_class="badge-status-success",
                    report_path=f"services/email_intelligence/reports/email_{target}.json"
                )
            except Exception:
                pass

            return result
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed dispatching email intelligence task: {e}")

    # Multiple targets (Batch Mode)
    try:
        first_target = parsed[0]
        first_result = execute_email_recon(
            email=first_target,
            force=bool(req.force),
            timeout=req.timeout or 10,
            no_password_recovery=bool(req.no_password_recovery)
        )

        try:
            record_execution(
                username=username,
                service_id="email_intelligence",
                service_name="Email Intelligence",
                tool_name="Holehe Batch Footprint",
                target=f"{first_target} (+{len(parsed)-1} queued)",
                duration_seconds=float(first_result.get("duration", 8.0)),
                findings_count=len(first_result.get("findings", [])),
                findings_summary=f"Batch execution: {len(parsed)} targets queued",
                status="Success",
                status_class="badge-status-success"
            )
        except Exception:
            pass

        return {
            "status": "BATCH_DISPATCHED",
            "batch": True,
            "total_targets": len(parsed),
            "parsed_targets": parsed,
            "current_target": first_target,
            "first_result": first_result,
            "no_password_recovery": bool(req.no_password_recovery),
            "progress_msg": f"Batch initialized with {len(parsed)} target emails. Processing '{first_target}' first."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed initializing batch email recon: {e}")

@router.get("/api/email_intelligence/status")
async def check_email_status(target: str):
    clean_target = target.strip()
    if not clean_target:
        raise HTTPException(status_code=400, detail="Target email parameter is required.")
    return get_email_status(clean_target)

@router.get("/api/email_intelligence/history")
async def fetch_email_history(request: Request):
    session = get_session_from_request(request)
    username = session.get("username") if session else None
    is_admin = session.get("is_admin", False) if session else False
    db_history = get_service_history_for_user("email_intelligence", username=username, is_admin=is_admin)
    return {"history": db_history}

@router.get("/api/email_intelligence/download")
async def download_email_report(target: str, format: str = "json"):
    clean_target = target.strip()
    if not clean_target:
        raise HTTPException(status_code=400, detail="Target email parameter is required.")

    fmt = format.lower().strip()
    file_path = ensure_email_report_file(clean_target, fmt)
    if not file_path or not file_path.exists():
        raise HTTPException(status_code=404, detail="Requested OASIS Email Intelligence report does not exist.")

    media_map = {
        "csv": "text/csv",
        "json": "application/json",
        "md": "text/markdown",
        "txt": "text/plain"
    }
    media_type = media_map.get(fmt, "application/octet-stream")
    clean_file_key = clean_target.replace('@', '_at_')
    filename = f"OASIS_email_{clean_file_key}_dossier.{fmt}"

    return FileResponse(
        path=str(file_path),
        media_type=media_type,
        filename=filename,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


# ============================================================================
# Mailbox Discovery Endpoints (OASIS Mailbox Engine)
# ============================================================================

@router.post("/api/email_intelligence/mailbox/run")
async def run_mailbox_task(req: MailboxRunRequest, request: Request):
    raw_user = req.username.strip()
    if not raw_user:
        raise HTTPException(status_code=400, detail="Target username/handle cannot be blank.")
    
    try:
        result = execute_mailbox_discovery(
            username=raw_user,
            force=bool(req.force),
            timeout=req.timeout or 10
        )
        session = get_session_from_request(request)
        username = session.get("username", "admin") if session else "admin"
        try:
            record_execution(
                username=username,
                service_id="email_intelligence",
                service_name="Email Intelligence",
                tool_name="Mailbox Deliverability Engine",
                target=raw_user,
                duration_seconds=float(result.get("duration", 4.5)),
                findings_count=len(result.get("findings", [])),
                findings_summary=f"Checked 26 providers for handle '{raw_user}'",
                status="Success",
                status_class="badge-status-success",
                report_path=f"services/email_intelligence/reports/mailbox_{raw_user}.json"
            )
        except Exception:
            pass
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed dispatching mailbox discovery task: {e}")

@router.get("/api/email_intelligence/mailbox/status")
async def check_mailbox_status(username: str):
    clean_user = username.strip()
    if not clean_user:
        raise HTTPException(status_code=400, detail="Target username parameter is required.")
    return get_mailbox_status(clean_user)

@router.get("/api/email_intelligence/mailbox/history")
async def fetch_mailbox_history(request: Request):
    session = get_session_from_request(request)
    username = session.get("username") if session else None
    is_admin = session.get("is_admin", False) if session else False
    db_history = get_service_history_for_user("email_intelligence", username=username, is_admin=is_admin)
    if db_history:
        return {"history": db_history}
    return {"history": get_recent_mailbox_scans()}

@router.get("/api/email_intelligence/mailbox/download")
async def download_mailbox_report(username: str, format: str = "json"):
    clean_user = username.strip()
    if not clean_user:
        raise HTTPException(status_code=400, detail="Target username parameter is required.")

    fmt = format.lower().strip()
    file_path = ensure_mailbox_report_file(clean_user, fmt)
    if not file_path or not file_path.exists():
        raise HTTPException(status_code=404, detail="Requested OASIS Mailbox Discovery report does not exist.")

    media_map = {
        "csv": "text/csv",
        "json": "application/json",
        "md": "text/markdown",
        "txt": "text/plain"
    }
    media_type = media_map.get(fmt, "application/octet-stream")
    clean_key = clean_user.replace('@', '_at_')
    filename = f"OASIS_mailbox_{clean_key}_dossier.{fmt}"

    return FileResponse(
        path=str(file_path),
        media_type=media_type,
        filename=filename,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

