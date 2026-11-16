from pathlib import Path
from typing import Optional
from fastapi import APIRouter, Request, Query, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from core.config import BASE_DIR, SERVICES_DIR, GATEWAY_PORT
from core.security import get_session_from_request
from roles.accounts import get_user, is_admin_user
from roles.user.service import get_user_dashboard_data
from services.dashboard.backend.service import get_dashboard_summary
from services.notifications.backend.service import list_tool_notifications, get_stats
from services.changelog.backend.service import get_all_releases, get_latest_version

router = APIRouter(tags=["Role User"])
templates = Jinja2Templates(directory=str(BASE_DIR))


def _get_user_context(request: Request, active_view: str, extra: Optional[dict] = None) -> dict:
    session = get_session_from_request(request)
    if not session or not session.get("authenticated"):
        raise HTTPException(status_code=401, detail="Authentication required.")

    current_username = session["username"]
    user_account = get_user(current_username) or {
        "username": current_username,
        "displayName": session.get("displayName", current_username.title()),
        "role": session.get("role", "user"),
        "avatar": session.get("avatar", current_username[0].upper()),
    }
    ctx = {
        "request": request,
        "active_view": active_view,
        "role_prefix": "/role_user",
        "is_admin": False,
        "user_role": "USER",
        "user_name": user_account.get("displayName", "User"),
        "user_avatar": user_account.get("avatar", "U"),
        "user_account": user_account,
        "admin_data": None,
    }
    if extra:
        ctx.update(extra)
    return ctx


# -----------------------------------------------------------------------------
# User Page Views (role_user_******)
# -----------------------------------------------------------------------------
@router.get("/role_user/dashboard", response_class=HTMLResponse)
async def user_dashboard_page(request: Request):
    summary = get_dashboard_summary()
    context = _get_user_context(
        request,
        active_view="dashboard",
        extra={
            "page_title": "Oasis — Mission Control Dashboard",
            "summary": summary,
        }
    )
    return templates.TemplateResponse(
        request=request,
        name="roles/user/templates/role_user_dashboard.html",
        context=context
    )


@router.get("/role_user/services/recon-username", response_class=HTMLResponse)
async def user_recon_username_page(request: Request, target: Optional[str] = None):
    initial_target = target.strip() if target else ""
    context = _get_user_context(
        request,
        active_view="recon_username",
        extra={
            "page_title": "Username Intelligence & Identity Reconnaissance — Oasis",
            "initial_target": initial_target
        }
    )
    return templates.TemplateResponse(
        request=request,
        name="roles/user/templates/role_user_recon_username.html",
        context=context
    )


@router.get("/role_user/services/domain-intelligence", response_class=HTMLResponse)
@router.get("/role_user/services/recon-website-url", response_class=HTMLResponse)
@router.get("/role_user/services/recon-subdomains", response_class=HTMLResponse)
@router.get("/role_user/services/recon-web-browsers", response_class=HTMLResponse)
async def user_domain_intelligence_page(request: Request, target: Optional[str] = None):
    initial_target = target.strip() if target else ""
    context = _get_user_context(
        request,
        active_view="domain_intelligence",
        extra={
            "page_title": "Domain & Website Intelligence — Oasis",
            "initial_target": initial_target
        }
    )
    return templates.TemplateResponse(
        request=request,
        name="roles/user/templates/role_user_domain_intelligence.html",
        context=context
    )


@router.get("/role_user/services/social-media-intelligence", response_class=HTMLResponse)
@router.get("/role_user/services/social-media", response_class=HTMLResponse)
async def user_social_media_page(request: Request, target: Optional[str] = None, platform: Optional[str] = "all"):
    initial_target = target.strip() if target else ""
    context = _get_user_context(
        request,
        active_view="social_media_intelligence",
        extra={
            "page_title": "Social Media Intelligence & Account Analysis — Oasis",
            "initial_target": initial_target,
            "initial_platform": platform
        }
    )
    return templates.TemplateResponse(
        request=request,
        name="roles/user/templates/role_user_social_media.html",
        context=context
    )


@router.get("/role_user/services/phone-intelligence", response_class=HTMLResponse)
@router.get("/role_user/services/recon-phone", response_class=HTMLResponse)
async def user_phone_intelligence_page(request: Request, target: Optional[str] = None):
    initial_target = target.strip() if target else ""
    context = _get_user_context(
        request,
        active_view="phone_intelligence",
        extra={
            "page_title": "Phone Number Intelligence & Carrier Profiler — Oasis",
            "initial_target": initial_target
        }
    )
    return templates.TemplateResponse(
        request=request,
        name="roles/user/templates/role_user_phone_intelligence.html",
        context=context
    )


@router.get("/role_user/services/email-intelligence", response_class=HTMLResponse)
async def user_email_intelligence_page(request: Request, target: Optional[str] = None):
    initial_target = target.strip() if target else ""
    context = _get_user_context(
        request,
        active_view="email_intelligence",
        extra={
            "page_title": "Email Intelligence & Account Footprint — Oasis",
            "initial_target": initial_target
        }
    )
    return templates.TemplateResponse(
        request=request,
        name="roles/user/templates/role_user_email_intelligence.html",
        context=context
    )


@router.get("/role_user/services/ip-network-intelligence", response_class=HTMLResponse)
async def user_ip_network_page(request: Request, target: Optional[str] = None):
    initial_target = target.strip() if target else ""
    context = _get_user_context(
        request,
        active_view="ip_network_intelligence",
        extra={
            "page_title": "IP & Network Intelligence — Oasis",
            "initial_target": initial_target
        }
    )
    return templates.TemplateResponse(
        request=request,
        name="roles/user/templates/role_user_ip_network.html",
        context=context
    )


@router.get("/role_user/notifications", response_class=HTMLResponse)
async def user_notifications_page(request: Request, status: str = "ALL", tool: str = "ALL"):
    notifications = list_tool_notifications(status_filter=status, tool_filter=tool)
    stats = get_stats()
    context = _get_user_context(
        request,
        active_view="notifications",
        extra={
            "page_title": "OSINT Processing Notifications — Oasis",
            "notifications": notifications,
            "stats": stats,
            "current_status_filter": status.upper(),
            "current_tool_filter": tool.lower(),
        }
    )
    return templates.TemplateResponse(
        request=request,
        name="roles/user/templates/role_user_notifications.html",
        context=context
    )


@router.get("/role_user/settings")
async def user_settings_page():
    """Settings page is removed for normal users; automatically redirect to dashboard."""
    return RedirectResponse(url="/role_user/dashboard", status_code=302)


@router.get("/role_user/changelog", response_class=HTMLResponse)
async def user_changelog_page(request: Request):
    releases = get_all_releases()
    latest_version = get_latest_version()
    context = _get_user_context(
        request,
        active_view="changelog",
        extra={
            "page_title": "Platform Changelog & Releases — Oasis",
            "releases": releases,
            "total_releases": len(releases),
            "latest_version": latest_version,
        }
    )
    return templates.TemplateResponse(
        request=request,
        name="roles/user/templates/role_user_changelog.html",
        context=context
    )


# -----------------------------------------------------------------------------
# User API Profile Endpoint
# -----------------------------------------------------------------------------
@router.get("/api/user/profile")
async def get_user_profile(request: Request):
    """Returns standard user station metadata."""
    session = get_session_from_request(request)
    if not session or not session.get("authenticated"):
        raise HTTPException(status_code=401, detail="Authentication required.")
    current_user = session["username"]
    return {
        "success": True,
        "profile": get_user_dashboard_data(current_user)
    }
