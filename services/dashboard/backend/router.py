from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from typing import Optional
from core.config import BASE_DIR
from core.security import get_session_from_request
from roles.accounts import get_user, is_admin_user

router = APIRouter()
templates = Jinja2Templates(directory=str(BASE_DIR))

@router.get("/dashboard")
async def dashboard_page(request: Request):
    session = get_session_from_request(request)
    if not session or not session.get("authenticated"):
        return RedirectResponse(url="/login", status_code=302)

    if session.get("is_admin"):
        return RedirectResponse(url="/role_admin/dashboard", status_code=302)
    return RedirectResponse(url="/role_user/dashboard", status_code=302)
