from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from core.config import BASE_DIR, SERVICES_DIR, GATEWAY_PORT
from roles.accounts import is_admin_user

router = APIRouter()
templates = Jinja2Templates(directory=str(BASE_DIR))

@router.get("/settings")
async def settings_page(request: Request):
    current_username = request.cookies.get("oasis_user") or "alex"
    if is_admin_user(current_username) or current_username.lower() == "admin":
        return RedirectResponse(url="/role_admin/settings", status_code=302)
    return RedirectResponse(url="/role_user/dashboard", status_code=302)
