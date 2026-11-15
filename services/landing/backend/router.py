from fastapi import APIRouter, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional
from core.config import BASE_DIR, APP_NAME, APP_VERSION
from roles.accounts import (
    authenticate_user,
    get_user,
    is_admin_user,
    ADMIN_ACCOUNT,
    SEED_USER_ACCOUNTS,
)

router = APIRouter()
templates = Jinja2Templates(directory=str(BASE_DIR))


class LoginPayload(BaseModel):
    username: str
    password: Optional[str] = ""
    remember: Optional[bool] = True


@router.get("/", response_class=HTMLResponse)
@router.get("/login", response_class=HTMLResponse)
async def landing_page(request: Request):
    """
    Renders the unified OASIS Landing Page featuring the integrated
    Station Terminal Authentication & Login Box Card for Admin and User roles.
    """
    current_username = request.cookies.get("oasis_user") or ""
    current_user_obj = get_user(current_username) if current_username else None

    return templates.TemplateResponse(
        request=request,
        name="services/landing/frontend/templates/landing.html",
        context={
            "page_title": f"{APP_NAME} — Strategic Intelligence Platform",
            "app_name": APP_NAME,
            "app_version": APP_VERSION,
            "current_user": current_username,
            "current_user_obj": current_user_obj,
            "admin_account": ADMIN_ACCOUNT,
            "seed_users": list(SEED_USER_ACCOUNTS.values()),
        }
    )


@router.post("/api/auth/login")
async def api_auth_login(payload: LoginPayload, response: Response):
    """
    Validates station credentials against seeded roles (Admin & User),
    sets authentication cookie, and returns role telemetry.
    """
    user_account = authenticate_user(payload.username, payload.password)
    
    if not user_account:
        return JSONResponse(
            status_code=401,
            content={
                "success": False,
                "message": "Authentication failed: invalid username or passkey."
            }
        )

    is_admin = user_account.get("role") == "admin"

    # Set authentication cookie (7 days if remember checked, else session)
    max_age = 7 * 24 * 3600 if payload.remember else None
    response.set_cookie(
        key="oasis_user",
        value=user_account["username"],
        max_age=max_age,
        path="/",
        httponly=False,
        samesite="lax"
    )

    redirect_target = "/role_admin/dashboard" if is_admin else "/role_user/dashboard"
    return {
        "success": True,
        "message": f"Authorized as {user_account['displayName']} ({user_account['role'].upper()}).",
        "user": user_account,
        "is_admin": is_admin,
        "redirect": redirect_target
    }


@router.get("/api/auth/session")
async def api_auth_session(request: Request):
    """
    Returns current authenticated session status and role (Admin or User).
    """
    user_cookie = request.cookies.get("oasis_user")
    if user_cookie:
        user_account = get_user(user_cookie) or {
            "username": user_cookie,
            "displayName": user_cookie.replace("_", " ").title(),
            "role": "user",
            "avatar": user_cookie[0].upper()
        }
        return {
            "authenticated": True,
            "user": user_account,
            "is_admin": user_account.get("role") == "admin"
        }
    return {"authenticated": False, "user": None, "is_admin": False}


@router.post("/api/auth/logout")
@router.get("/logout")
async def api_auth_logout(response: Response):
    """
    Clears station credentials and redirects back to the landing page.
    """
    response.delete_cookie(key="oasis_user", path="/")
    return RedirectResponse(url="/", status_code=302)
