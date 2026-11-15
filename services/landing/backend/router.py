import time
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
from core.security import (
    get_session_from_request,
    set_auth_cookies,
    clear_auth_cookies,
    decode_token,
    create_access_token,
    revoke_token,
    check_login_rate_limit,
    record_login_failure,
    record_login_success,
    is_any_osint_scan_running,
    ACCESS_TOKEN_EXPIRE_SECONDS,
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
    If the user has an active session, automatically redirects to their role dashboard
    to prevent unwanted landing page redirections.
    """
    session = get_session_from_request(request)
    if session and session.get("authenticated"):
        target_dash = "/role_admin/dashboard" if session.get("is_admin") else "/role_user/dashboard"
        return RedirectResponse(url=target_dash, status_code=302)

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
async def api_auth_login(payload: LoginPayload, request: Request, response: Response):
    """
    Validates station credentials with:
    1. Sliding-window brute force rate-limiting.
    2. Constant-time password verification.
    3. Cryptographic Access Token & Refresh Token issuance via secure HttpOnly cookies.
    """
    # 1. Brute-Force Rate Limiting Check
    allowed, retry_after = check_login_rate_limit(request, payload.username)
    if not allowed:
        return JSONResponse(
            status_code=429,
            headers={"Retry-After": str(retry_after)},
            content={
                "success": False,
                "message": f"Security Lockout: Too many failed login attempts. Please wait {retry_after} seconds before retrying.",
                "retry_after": retry_after,
            }
        )

    # 2. Credential Verification
    user_account = authenticate_user(payload.username, payload.password)
    if not user_account:
        record_login_failure(request, payload.username)
        return JSONResponse(
            status_code=401,
            content={
                "success": False,
                "message": "Authentication rejected: Invalid credentials provided."
            }
        )

    # 3. Successful Login: Clear Rate Limiting & Issue Tokens
    record_login_success(request, payload.username)
    is_admin = user_account.get("role") == "admin"
    redirect_target = "/role_admin/dashboard" if is_admin else "/role_user/dashboard"
    
    res = JSONResponse(content={
        "success": True,
        "message": f"Authorized as {user_account['displayName']} ({user_account['role'].upper()}).",
        "user": user_account,
        "is_admin": is_admin,
        "redirect": redirect_target,
        "expires_in": ACCESS_TOKEN_EXPIRE_SECONDS,
    })
    set_auth_cookies(res, user_account)
    res.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    res.headers["Pragma"] = "no-cache"
    return res


@router.post("/api/auth/refresh")
async def api_auth_refresh(request: Request):
    """
    Silent token refresh endpoint.
    Exchanges a valid HttpOnly refresh token for a newly issued access token.
    Allows active users and background tasks to maintain continuous station sessions.
    """
    refresh_token = request.cookies.get("oasis_refresh_token")
    if not refresh_token:
        return JSONResponse(
            status_code=401,
            content={"success": False, "message": "No refresh token available."}
        )

    payload = decode_token(refresh_token, is_refresh=True)
    if not payload:
        return JSONResponse(
            status_code=401,
            content={"success": False, "message": "Refresh token is invalid or expired."}
        )

    username = payload.get("sub") or payload.get("username")
    user_account = get_user(username) or {
        "username": username,
        "displayName": username.title() if username else "User",
        "role": payload.get("role", "user"),
        "avatar": username[0].upper() if username else "U",
    }

    res = JSONResponse(content={
        "success": True,
        "message": "Access token refreshed successfully.",
        "expires_in": ACCESS_TOKEN_EXPIRE_SECONDS,
    })
    set_auth_cookies(res, user_account)
    res.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    res.headers["Pragma"] = "no-cache"
    return res


@router.get("/api/auth/scan-status")
async def api_auth_scan_status(request: Request):
    """
    Diagnostics endpoint used by client-side idle watchers:
    Returns whether any OSINT crawler, scan, or background tool is currently running.
    Prevents idle auto-logout while tasks are actively executing.
    """
    has_active, active_tools = is_any_osint_scan_running()
    return {
        "has_active_scans": has_active,
        "active_count": len(active_tools),
        "active_tools": active_tools,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


@router.get("/api/auth/session")
async def api_auth_session(request: Request):
    """
    Returns current authenticated session status and role (Admin or User).
    Uses secure token decoding.
    """
    session = get_session_from_request(request)
    if session and session.get("authenticated"):
        user_account = get_user(session["username"]) or {
            "username": session["username"],
            "displayName": session.get("displayName", session["username"].title()),
            "role": session.get("role", "user"),
            "avatar": session.get("avatar", "U"),
        }
        return {
            "authenticated": True,
            "user": user_account,
            "is_admin": session.get("is_admin", False),
        }
    return {"authenticated": False, "user": None, "is_admin": False}


@router.post("/api/auth/logout")
@router.get("/logout")
async def api_auth_logout(request: Request):
    """
    Revokes access and refresh tokens and clears authentication cookies.
    """
    access_token = request.cookies.get("oasis_access_token")
    if access_token:
        revoke_token(access_token, is_refresh=False)
    
    refresh_token = request.cookies.get("oasis_refresh_token")
    if refresh_token:
        revoke_token(refresh_token, is_refresh=True)

    accept = request.headers.get("accept", "")
    content_type = request.headers.get("content-type", "")
    if "application/json" in accept or "application/json" in content_type:
        res = JSONResponse(
            status_code=200,
            content={"success": True, "message": "Signed out successfully.", "redirect": "/login"}
        )
    else:
        res = RedirectResponse(url="/login", status_code=302)

    clear_auth_cookies(res)
    res.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, post-check=0, pre-check=0"
    res.headers["Pragma"] = "no-cache"
    res.headers["Expires"] = "0"
    return res
