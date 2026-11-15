from pathlib import Path
from typing import Optional
from fastapi import APIRouter, Request, Query, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from core.config import BASE_DIR, SERVICES_DIR, GATEWAY_PORT
from core.security import get_session_from_request
from roles.accounts import get_user, is_admin_user
from roles.admin.service import get_admin_dashboard_data
from services.dashboard.backend.service import get_dashboard_summary
from services.notifications.backend.service import list_tool_notifications, get_stats
from services.changelog.backend.service import get_all_releases, get_latest_version

router = APIRouter(tags=["Role Admin"])
templates = Jinja2Templates(directory=str(BASE_DIR))


def _get_admin_context(request: Request, active_view: str, extra: Optional[dict] = None) -> dict:
    session = get_session_from_request(request)
    if not session or not session.get("authenticated"):
        raise HTTPException(status_code=401, detail="Authentication required.")
    if not session.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin privileges required.")

    current_username = session["username"]
    user_account = get_user(current_username) or {
        "username": current_username,
        "displayName": session.get("displayName", "Admin"),
        "role": "admin",
        "avatar": session.get("avatar", "A"),
    }
    admin_data = get_admin_dashboard_data()
    ctx = {
        "request": request,
        "active_view": active_view,
        "role_prefix": "/role_admin",
        "is_admin": True,
        "user_role": "ADMIN",
        "user_name": user_account.get("displayName", "Admin"),
        "user_avatar": user_account.get("avatar", "A"),
        "user_account": user_account,
        "admin_data": admin_data,
    }
    if extra:
        ctx.update(extra)
    return ctx


# -----------------------------------------------------------------------------
# Admin Page Views (role_admin_******)
# -----------------------------------------------------------------------------
@router.get("/role_admin/dashboard", response_class=HTMLResponse)
async def admin_dashboard_page(request: Request):
    summary = get_dashboard_summary()
    context = _get_admin_context(
        request,
        active_view="dashboard",
        extra={
            "page_title": "Oasis — Admin Telemetry & Governance Dashboard",
            "summary": summary,
        }
    )
    return templates.TemplateResponse(
        request=request,
        name="roles/admin/templates/role_admin_dashboard.html",
        context=context
    )


@router.get("/role_admin/services/recon-username", response_class=HTMLResponse)
async def admin_recon_username_page(request: Request, target: Optional[str] = None):
    initial_target = target.strip() if target else ""
    context = _get_admin_context(
        request,
        active_view="recon_username",
        extra={
            "page_title": "Admin: Username Intelligence — Oasis",
            "initial_target": initial_target
        }
    )
    return templates.TemplateResponse(
        request=request,
        name="roles/admin/templates/role_admin_recon_username.html",
        context=context
    )


@router.get("/role_admin/services/domain-intelligence", response_class=HTMLResponse)
@router.get("/role_admin/services/recon-website-url", response_class=HTMLResponse)
@router.get("/role_admin/services/recon-subdomains", response_class=HTMLResponse)
@router.get("/role_admin/services/recon-web-browsers", response_class=HTMLResponse)
async def admin_domain_intelligence_page(request: Request, target: Optional[str] = None):
    initial_target = target.strip() if target else ""
    context = _get_admin_context(
        request,
        active_view="domain_intelligence",
        extra={
            "page_title": "Admin: Domain & Website Intelligence — Oasis",
            "initial_target": initial_target
        }
    )
    return templates.TemplateResponse(
        request=request,
        name="roles/admin/templates/role_admin_domain_intelligence.html",
        context=context
    )


@router.get("/role_admin/services/social-media-intelligence", response_class=HTMLResponse)
@router.get("/role_admin/services/social-media", response_class=HTMLResponse)
async def admin_social_media_page(request: Request, target: Optional[str] = None, platform: Optional[str] = "all"):
    initial_target = target.strip() if target else ""
    context = _get_admin_context(
        request,
        active_view="social_media_intelligence",
        extra={
            "page_title": "Admin: Social Media Intelligence — Oasis",
            "initial_target": initial_target,
            "initial_platform": platform
        }
    )
    return templates.TemplateResponse(
        request=request,
        name="roles/admin/templates/role_admin_social_media.html",
        context=context
    )


@router.get("/role_admin/services/phone-intelligence", response_class=HTMLResponse)
@router.get("/role_admin/services/recon-phone", response_class=HTMLResponse)
async def admin_phone_intelligence_page(request: Request, target: Optional[str] = None):
    initial_target = target.strip() if target else ""
    context = _get_admin_context(
        request,
        active_view="phone_intelligence",
        extra={
            "page_title": "Admin: Phone Number Intelligence — Oasis",
            "initial_target": initial_target
        }
    )
    return templates.TemplateResponse(
        request=request,
        name="roles/admin/templates/role_admin_phone_intelligence.html",
        context=context
    )


@router.get("/role_admin/services/email-intelligence", response_class=HTMLResponse)
async def admin_email_intelligence_page(request: Request, target: Optional[str] = None):
    initial_target = target.strip() if target else ""
    context = _get_admin_context(
        request,
        active_view="email_intelligence",
        extra={
            "page_title": "Admin: Email Intelligence — Oasis",
            "initial_target": initial_target
        }
    )
    return templates.TemplateResponse(
        request=request,
        name="roles/admin/templates/role_admin_email_intelligence.html",
        context=context
    )


@router.get("/role_admin/services/ip-network-intelligence", response_class=HTMLResponse)
async def admin_ip_network_page(request: Request, target: Optional[str] = None):
    initial_target = target.strip() if target else ""
    context = _get_admin_context(
        request,
        active_view="ip_network_intelligence",
        extra={
            "page_title": "Admin: IP & Network Intelligence — Oasis",
            "initial_target": initial_target
        }
    )
    return templates.TemplateResponse(
        request=request,
        name="roles/admin/templates/role_admin_ip_network.html",
        context=context
    )


@router.get("/role_admin/notifications", response_class=HTMLResponse)
async def admin_notifications_page(request: Request, status: str = "ALL", tool: str = "ALL"):
    notifications = list_tool_notifications(status_filter=status, tool_filter=tool)
    stats = get_stats()
    context = _get_admin_context(
        request,
        active_view="notifications",
        extra={
            "page_title": "Admin: OSINT Notifications & Audit — Oasis",
            "notifications": notifications,
            "stats": stats,
            "current_status_filter": status.upper(),
            "current_tool_filter": tool.lower(),
        }
    )
    return templates.TemplateResponse(
        request=request,
        name="roles/admin/templates/role_admin_notifications.html",
        context=context
    )


@router.get("/role_admin/settings", response_class=HTMLResponse)
async def admin_settings_page(request: Request):
    context = _get_admin_context(
        request,
        active_view="settings",
        extra={
            "page_title": "Admin: Settings & Environments — Oasis",
            "services_dir": str(SERVICES_DIR),
            "gateway_port": GATEWAY_PORT,
            "social_services_count": 4,
            "recon_services_count": 8,
            "total_tools_count": 36,
        }
    )
    return templates.TemplateResponse(
        request=request,
        name="roles/admin/templates/role_admin_settings.html",
        context=context
    )


@router.get("/role_admin/changelog", response_class=HTMLResponse)
async def admin_changelog_page(request: Request):
    releases = get_all_releases()
    latest_version = get_latest_version()
    context = _get_admin_context(
        request,
        active_view="changelog",
        extra={
            "page_title": "Admin: System Changelog — Oasis",
            "releases": releases,
            "latest_version": latest_version,
        }
    )
    return templates.TemplateResponse(
        request=request,
        name="roles/admin/templates/role_admin_changelog.html",
        context=context
    )


# -----------------------------------------------------------------------------
# Admin API Telemetry Endpoint
# -----------------------------------------------------------------------------
@router.get("/api/admin/telemetry")
async def get_admin_telemetry(request: Request):
    """Returns platform microservice & tool health telemetry for Admin role."""
    session = get_session_from_request(request)
    if not session or not session.get("authenticated"):
        raise HTTPException(status_code=401, detail="Authentication required.")
    if not session.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin privileges required.")
    data = get_admin_dashboard_data()
    return {
        "success": True,
        "is_admin": True,
        "data": data,
    }
