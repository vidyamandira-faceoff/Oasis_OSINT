import time
from pathlib import Path
from fastapi import FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, JSONResponse

from core.config import (
    BASE_DIR,
    GATEWAY_PORT,
    APP_NAME,
    APP_VERSION
)
from core.process_manager import RUNNING_PROCESSES, terminate_all_tasks
from core.security import (
    decode_token,
    create_access_token,
    get_session_from_request,
    ACCESS_TOKEN_EXPIRE_SECONDS,
)
from roles.accounts import get_user

# Core Services Routers
from services.landing.backend.router import router as landing_router
from services.dashboard.backend.router import router as dashboard_router
from services.settings.backend.router import router as settings_router
from services.notifications.backend.router import router as notifications_router
from services.changelog.backend.router import router as changelog_router
# Roles Routers (Admin & Normal User)
from roles.admin.router import router as admin_api_router
from roles.user.router import router as user_api_router
# Active Intelligence Module Routers
from services.recon_username.backend.router import router as recon_username_router
from services.domain_intelligence.backend.router import router as domain_intelligence_router
from services.social_media_intelligence.backend.router import router as social_media_router
from services.phone_intelligence.backend.router import router as phone_intelligence_router
from services.email_intelligence.backend.router import router as email_intelligence_router
from services.ip_network_intelligence.backend.router import router as ip_network_router

app = FastAPI(
    title=APP_NAME,
    description="OASIS — Open-source OSINT Investigation Platform (V1 Demo Build)",
    version=APP_VERSION
)

# -----------------------------------------------------------------------------
# Security & Session Authentication Middleware
# -----------------------------------------------------------------------------
PUBLIC_EXACT_PATHS = {
    "/",
    "/login",
    "/logout",
    "/api/auth/login",
    "/api/auth/refresh",
    "/api/auth/session",
    "/api/auth/logout",
    "/api/status",
    "/favicon.ico",
}

@app.middleware("http")
async def security_and_session_middleware(request: Request, call_next):
    path = request.url.path

    # Check whether requested path is explicitly public or a static asset
    is_public = (
        path in PUBLIC_EXACT_PATHS
        or path.startswith("/static")
        or path.startswith("/api/auth/")
    )

    # Resolve cryptographic session
    session = get_session_from_request(request)

    # 1. Enforce authentication on all protected routes
    if not is_public:
        if not session or not session.get("authenticated"):
            # Unauthenticated API calls -> 401 Unauthorized
            if path.startswith("/api/"):
                return JSONResponse(
                    status_code=401,
                    content={"success": False, "detail": "Authentication required. Please sign in."},
                    headers={
                        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                        "Pragma": "no-cache",
                    }
                )
            # Unauthenticated Page requests -> 302 Redirect to /login
            return RedirectResponse(
                url="/login",
                status_code=302,
                headers={
                    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                    "Pragma": "no-cache",
                }
            )

        # 2. Enforce Admin Authorization for Admin routes
        if path.startswith("/role_admin") or path.startswith("/api/admin"):
            if not session.get("is_admin"):
                if path.startswith("/api/"):
                    return JSONResponse(
                        status_code=403,
                        content={"success": False, "detail": "Forbidden: Admin privileges required."},
                        headers={
                            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                            "Pragma": "no-cache",
                        }
                    )
                return RedirectResponse(
                    url="/role_user/dashboard",
                    status_code=302,
                    headers={
                        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                        "Pragma": "no-cache",
                    }
                )

    # Call downstream route handler
    response = await call_next(request)

    # 3. Transparent Token Refresh: If session was verified via refresh token, attach new access token
    if session and session.get("refreshed"):
        u = session.get("username")
        acc = get_user(u)
        if acc:
            token_payload = {
                "sub": acc["username"],
                "username": acc["username"],
                "displayName": acc.get("displayName", acc["username"].title()),
                "role": acc.get("role", "user"),
                "is_admin": acc.get("role") == "admin",
                "avatar": acc.get("avatar", acc["username"][0].upper()),
            }
            new_access_token = create_access_token(token_payload)
            response.set_cookie(
                key="oasis_access_token",
                value=new_access_token,
                max_age=ACCESS_TOKEN_EXPIRE_SECONDS,
                path="/",
                httponly=True,
                samesite="lax",
            )

    # 4. Security Hardening Headers (Defense against MitM, Clickjacking, MIME-Sniffing)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"

    # 5. Anti-Caching Headers on all protected views & APIs to defeat browser bfcache leaks after signout
    if not path.startswith("/static"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, post-check=0, pre-check=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

    return response

# -----------------------------------------------------------------------------
# Static Assets Mounts (Shared + Module Specific)
# -----------------------------------------------------------------------------
shared_static_dir = BASE_DIR / "shared" / "static"
if shared_static_dir.exists():
    app.mount("/static/shared", StaticFiles(directory=str(shared_static_dir)), name="shared_static")

services_dir = BASE_DIR / "services"
if services_dir.exists():
    for mod_dir in services_dir.iterdir():
        if mod_dir.is_dir():
            mod_static = mod_dir / "frontend" / "static"
            if mod_static.exists():
                app.mount(f"/static/services/{mod_dir.name}", StaticFiles(directory=str(mod_static)), name=f"{mod_dir.name}_static")

root_static_dir = BASE_DIR / "static"
if root_static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(root_static_dir)), name="root_static")

# -----------------------------------------------------------------------------
# Global Health & Status API
# -----------------------------------------------------------------------------
@app.get("/api/status")
async def get_system_status():
    return {
        "status": "operational",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "active_processes": len(RUNNING_PROCESSES),
        "active_modules": [
            "Username Intelligence",
            "Domain & Website Intelligence",
            "Social Media Intelligence",
            "Phone Number Intelligence",
            "Email Intelligence",
            "IP & Network Intelligence",
        ],
        "connected_engines": [
            "OASIS Username Intelligence Engine",
            "OASIS Domain & Website Intelligence Engine",
            "OASIS Instagram Flash Scraper (Chromium Headless)",
            "OASIS Email Intelligence Engine",
            "OASIS IP & Network Intelligence Engine",
            "Native Social Media Scraper Cluster",
            "Native Phone Number Intelligence Platform",
        ],
    }

@app.post("/api/tools/abort-all")
async def abort_all_tasks():
    return terminate_all_tasks()

# -----------------------------------------------------------------------------
# Microservice Routers Registration
# -----------------------------------------------------------------------------
# Core Platform Modules
app.include_router(landing_router)
app.include_router(dashboard_router)
app.include_router(settings_router)
app.include_router(notifications_router)
app.include_router(changelog_router)

# Role Governance Modules (Admin & Normal User)
app.include_router(admin_api_router)
app.include_router(user_api_router)

# Legacy view redirects (decommissioned /vault and /terminal)
@app.get("/vault")
async def redirect_vault():
    return RedirectResponse(url="/changelog", status_code=302)

@app.get("/terminal")
async def redirect_terminal():
    return RedirectResponse(url="/changelog", status_code=302)

# Intelligence Modules
app.include_router(recon_username_router)
app.include_router(domain_intelligence_router)
app.include_router(social_media_router)
app.include_router(phone_intelligence_router)
app.include_router(email_intelligence_router)
app.include_router(ip_network_router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=GATEWAY_PORT, reload=True)
