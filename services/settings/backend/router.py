from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from core.config import BASE_DIR, SERVICES_DIR, GATEWAY_PORT
from core.security import get_session_from_request

router = APIRouter()
templates = Jinja2Templates(directory=str(BASE_DIR))

@router.get("/settings")
async def settings_page(request: Request):
    session = get_session_from_request(request)
    if not session or not session.get("authenticated"):
        return RedirectResponse(url="/login", status_code=302)
    if session.get("is_admin"):
        return RedirectResponse(url="/role_admin/settings", status_code=302)
    return RedirectResponse(url="/role_user/dashboard", status_code=302)
