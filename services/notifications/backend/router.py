from fastapi import APIRouter, Request, Query
from fastapi.templating import Jinja2Templates
from fastapi.responses import JSONResponse, RedirectResponse
from pathlib import Path
from core.config import BASE_DIR
from roles.accounts import is_admin_user
from services.notifications.backend.service import list_tool_notifications, get_stats, purge_completed_notifications

router = APIRouter(tags=["Notifications"])

templates = Jinja2Templates(directory=[
    str(BASE_DIR / "services" / "notifications" / "frontend" / "templates"),
    str(BASE_DIR / "shared" / "templates")
])

@router.get("/notifications")
async def notifications_page(request: Request, status: str = "ALL", tool: str = "ALL"):
    current_username = request.cookies.get("oasis_user") or "alex"
    target_prefix = "/role_admin" if (is_admin_user(current_username) or current_username.lower() == "admin") else "/role_user"
    return RedirectResponse(url=f"{target_prefix}/notifications", status_code=302)

@router.get("/api/notifications")
async def get_notifications_api(status: str = "ALL", tool: str = "ALL"):
    notifications = list_tool_notifications(status_filter=status, tool_filter=tool)
    stats = get_stats()
    return JSONResponse(content={
        "status": "success",
        "stats": stats,
        "notifications": notifications
    })

@router.post("/api/notifications/clear")
async def clear_notifications_api():
    result = purge_completed_notifications()
    return JSONResponse(content=result)
