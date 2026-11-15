"""
Changelog API & Web Router for OASIS
"""

from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from core.config import BASE_DIR
from roles.accounts import is_admin_user
from services.changelog.backend.service import (
    get_all_releases,
    get_latest_version,
    get_changelog_markdown
)

router = APIRouter(tags=["Platform Changelog"])

templates = Jinja2Templates(directory=str(BASE_DIR))

@router.get("/changelog")
async def changelog_page(request: Request):
    """Redirects to role-specific changelog view."""
    current_username = request.cookies.get("oasis_user") or "alex"
    target_prefix = "/role_admin" if (is_admin_user(current_username) or current_username.lower() == "admin") else "/role_user"
    return RedirectResponse(url=f"{target_prefix}/changelog", status_code=302)

@router.get("/api/changelog")
async def get_changelog_api():
    """Returns structured JSON of all platform releases and changes."""
    return JSONResponse(content={
        "status": "success",
        "latest_version": get_latest_version(),
        "releases": get_all_releases()
    })

@router.get("/api/changelog/raw")
async def get_raw_changelog_markdown():
    """Returns raw CHANGELOG.md file content."""
    return PlainTextResponse(content=get_changelog_markdown(), media_type="text/markdown")
