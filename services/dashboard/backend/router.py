from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from typing import Optional
from core.config import BASE_DIR
from roles.accounts import get_user, is_admin_user

router = APIRouter()
templates = Jinja2Templates(directory=str(BASE_DIR))

@router.get("/dashboard")
async def dashboard_page(request: Request, role: Optional[str] = None, view: Optional[str] = None):
    current_username = request.cookies.get("oasis_user") or "alex"
    user_account = get_user(current_username)
    
    is_admin = False
    if role == "admin" or view == "admin" or current_username.lower() == "admin":
        is_admin = True
    elif user_account and user_account.get("role") == "admin":
        is_admin = True

    if is_admin:
        return RedirectResponse(url="/role_admin/dashboard", status_code=302)
    return RedirectResponse(url="/role_user/dashboard", status_code=302)
