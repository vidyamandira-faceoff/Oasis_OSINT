import re
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
from core.database import (
    get_user_by_email,
    get_user_by_username,
    get_user_by_username_or_email,
    create_user,
    update_user_password,
    save_email_otp,
    verify_email_otp,
    is_email_verified_for_signup,
    is_otp_verified_for_reset,
    consume_verified_otp,
)
from core.mailer import generate_alphanumeric_otp, send_email_otp
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
    validate_password_strength,
    create_verification_token,
    verify_verification_token,
    ACCESS_TOKEN_EXPIRE_SECONDS,
)

router = APIRouter()
templates = Jinja2Templates(directory=str(BASE_DIR))


class LoginPayload(BaseModel):
    username: str
    password: Optional[str] = ""
    remember: Optional[bool] = True


class SendOtpPayload(BaseModel):
    email: str


class VerifyOtpPayload(BaseModel):
    email: str
    otp_code: str


class SignupCompletePayload(BaseModel):
    email: str
    username: str
    password: str
    confirm_password: str
    display_name: Optional[str] = ""
    verification_ticket: Optional[str] = ""


class ResetPasswordPayload(BaseModel):
    email: str
    password: str
    confirm_password: str
    verification_ticket: Optional[str] = ""



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
    safe_current_user_obj = {k: v for k, v in current_user_obj.items() if k != "password"} if current_user_obj else None
    safe_admin_account = {k: v for k, v in ADMIN_ACCOUNT.items() if k != "password"}
    safe_seed_users = [{k: v for k, v in u.items() if k != "password"} for u in SEED_USER_ACCOUNTS.values()]

    return templates.TemplateResponse(
        request=request,
        name="services/landing/frontend/templates/landing.html",
        context={
            "page_title": f"{APP_NAME} — Strategic Intelligence Platform",
            "app_name": APP_NAME,
            "app_version": APP_VERSION,
            "current_user": current_username,
            "current_user_obj": safe_current_user_obj,
            "admin_account": safe_admin_account,
            "seed_users": safe_seed_users,
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
    safe_user_account = {k: v for k, v in user_account.items() if k != "password"}
    
    res = JSONResponse(content={
        "success": True,
        "message": f"Authorized as {user_account['displayName']} ({user_account['role'].upper()}).",
        "user": safe_user_account,
        "role": user_account.get("role", "user"),
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
        safe_user_account = {k: v for k, v in user_account.items() if k != "password"}
        return {
            "authenticated": True,
            "user": safe_user_account,
            "role": safe_user_account.get("role", "user"),
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


# =============================================================================
# SIGN-UP MODULE ENDPOINTS (STAGED EMAIL OTP + USERNAME & PASSWORD)
# =============================================================================

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
USERNAME_REGEX = re.compile(r'^[a-zA-Z0-9_.]{3,24}$')


@router.post("/api/auth/signup/send-otp")
async def api_signup_send_otp(payload: SendOtpPayload):
    """
    Step 1 of Sign Up:
    Validates email format, ensures email is not already registered,
    and issues an 8-digit alphanumeric verification OTP valid for 5 minutes.
    """
    clean_email = (payload.email or "").strip().lower()
    if not clean_email or not EMAIL_REGEX.match(clean_email):
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": "Please provide a valid email address (e.g. analyst@example.com)."}
        )

    # Check if an account already exists with this email
    existing_user = get_user_by_email(clean_email)
    if existing_user:
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "message": "An account with this email address already exists. Please sign in or use passkey recovery."
            }
        )

    # Generate 8-digit alphanumeric OTP
    otp_code = generate_alphanumeric_otp(8)
    save_email_otp(clean_email, otp_code, purpose="signup", validity_seconds=300)
    _, send_msg = send_email_otp(clean_email, otp_code, purpose="signup", validity_minutes=5)

    return JSONResponse(
        status_code=200,
        content={
            "success": True,
            "message": f"8-digit verification code dispatched to {clean_email}. Valid for 5 minutes.",
            "expires_in": 300,
            "dev_otp": otp_code,  # For seamless local testing preview
        }
    )


@router.post("/api/auth/signup/verify-otp")
async def api_signup_verify_otp(payload: VerifyOtpPayload):
    """
    Step 1.2 of Sign Up:
    Validates the 8-digit alphanumeric OTP against the database within the 5-minute window.
    Returns a cryptographic verification ticket that unlocks Step 2 (username & password setup).
    """
    clean_email = (payload.email or "").strip().lower()
    clean_code = (payload.otp_code or "").strip().upper()

    if not clean_email or not clean_code:
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": "Email address and 8-digit verification code are required."}
        )

    is_verified, msg = verify_email_otp(clean_email, clean_code, purpose="signup")
    if not is_verified:
        return JSONResponse(status_code=400, content={"success": False, "message": msg})

    # Issue signed verification ticket
    ticket = create_verification_token(clean_email, purpose="signup", expires_in=900)
    return JSONResponse(
        status_code=200,
        content={
            "success": True,
            "message": "Email verified successfully! You may now configure your username and access passkey.",
            "verification_ticket": ticket,
        }
    )


@router.get("/api/auth/check-username")
async def api_check_username(username: str):
    """
    Validates username format and checks real-time database availability.
    """
    clean_user = (username or "").strip().lower()
    if not clean_user or not USERNAME_REGEX.match(clean_user):
        return {
            "available": False,
            "message": "Username must be 3–24 characters and contain only letters, numbers, periods, or underscores."
        }

    existing = get_user_by_username(clean_user)
    if existing:
        return {"available": False, "message": f"Username '{clean_user}' is already taken."}
    
    return {"available": True, "message": f"Username '{clean_user}' is available."}


@router.post("/api/auth/signup/complete")
async def api_signup_complete(payload: SignupCompletePayload, response: Response):
    """
    Step 2 of Sign Up:
    Only accessible AFTER email has been verified via OTP.
    Enforces standard password parameters, creates the user record, and issues station session cookies.
    """
    clean_email = (payload.email or "").strip().lower()
    clean_username = (payload.username or "").strip().lower()

    # 1. Verification Gate: Email must be proven verified
    ticket = payload.verification_ticket or ""
    is_ticket_valid = verify_verification_token(ticket, clean_email, purpose="signup") if ticket else False
    is_db_verified = is_email_verified_for_signup(clean_email)

    if not (is_ticket_valid or is_db_verified):
        return JSONResponse(
            status_code=403,
            content={
                "success": False,
                "message": "Email verification required. Until the email gets verified with an 8-digit OTP, registration cannot proceed."
            }
        )

    # 2. Username Validation
    if not clean_username or not USERNAME_REGEX.match(clean_username):
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "message": "Username must be 3–24 characters long and contain only letters, numbers, periods, or underscores."
            }
        )

    if get_user_by_username(clean_username):
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": f"Username '{clean_username}' is already in use. Please select another."}
        )

    # 3. Password Confirmation
    if payload.password != payload.confirm_password:
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": "Passwords do not match. Please re-enter confirm password."}
        )

    # 4. Standard Password Parameters & Security Validation
    is_pwd_valid, missing_rules, rules_dict = validate_password_strength(payload.password)
    if not is_pwd_valid:
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "message": "Password does not meet standard parameters: " + "; ".join(missing_rules),
                "rules": rules_dict,
                "missing": missing_rules
            }
        )

    # 5. Database User Creation
    display_name = (payload.display_name or "").strip() or clean_username.title()
    new_user = create_user(
        username=clean_username,
        email=clean_email,
        password=payload.password,
        display_name=display_name,
        role_name="user"
    )

    # 6. Consume and clear verified OTP
    consume_verified_otp(clean_email, purpose="signup")

    # 7. Auto-sign in the new user and issue session tokens
    res = JSONResponse(
        status_code=200,
        content={
            "success": True,
            "message": f"Station analyst account initialized. Welcome, {new_user['displayName']}!",
            "user": new_user,
            "is_admin": False,
            "redirect": "/role_user/dashboard",
            "expires_in": ACCESS_TOKEN_EXPIRE_SECONDS,
        }
    )
    set_auth_cookies(res, new_user)
    res.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    res.headers["Pragma"] = "no-cache"
    return res


# =============================================================================
# FORGOT PASSWORD MODULE ENDPOINTS (OTP VERIFICATION USING REGISTERED EMAIL)
# =============================================================================

@router.post("/api/auth/forgot-password/send-otp")
async def api_forgot_password_send_otp(payload: SendOtpPayload):
    """
    Step 1 of Forgot Password:
    Verifies the email is registered to a station account, generates an 8-digit alphanumeric
    OTP valid for 5 minutes, and dispatches it.
    """
    clean_email = (payload.email or "").strip().lower()
    if not clean_email or not EMAIL_REGEX.match(clean_email):
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": "Please provide a valid registered email address."}
        )

    user = get_user_by_email(clean_email)
    if not user:
        return JSONResponse(
            status_code=404,
            content={"success": False, "message": f"No registered station account found for email: {clean_email}."}
        )

    # Generate 8-digit alphanumeric OTP valid for 5 minutes
    otp_code = generate_alphanumeric_otp(8)
    save_email_otp(clean_email, otp_code, purpose="forgot_password", validity_seconds=300)
    _, send_msg = send_email_otp(clean_email, otp_code, purpose="forgot_password", validity_minutes=5)

    return JSONResponse(
        status_code=200,
        content={
            "success": True,
            "message": f"8-digit recovery code dispatched to {clean_email}. Valid for 5 minutes.",
            "expires_in": 300,
            "dev_otp": otp_code,
        }
    )


@router.post("/api/auth/forgot-password/verify-otp")
async def api_forgot_password_verify_otp(payload: VerifyOtpPayload):
    """
    Step 2 of Forgot Password:
    Validates the 8-digit alphanumeric recovery OTP.
    Returns a cryptographic verification ticket unlocking the new passkey entry fields.
    """
    clean_email = (payload.email or "").strip().lower()
    clean_code = (payload.otp_code or "").strip().upper()

    if not clean_email or not clean_code:
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": "Email address and 8-digit recovery code are required."}
        )

    is_verified, msg = verify_email_otp(clean_email, clean_code, purpose="forgot_password")
    if not is_verified:
        return JSONResponse(status_code=400, content={"success": False, "message": msg})

    # Issue signed verification ticket
    ticket = create_verification_token(clean_email, purpose="forgot_password", expires_in=900)
    return JSONResponse(
        status_code=200,
        content={
            "success": True,
            "message": "Identity verified. You may now set your new access passkey.",
            "verification_ticket": ticket,
        }
    )


@router.post("/api/auth/forgot-password/reset")
async def api_forgot_password_reset(payload: ResetPasswordPayload):
    """
    Step 3 of Forgot Password:
    Enforces OTP verification gate and standard password rules before updating the account passkey.
    """
    clean_email = (payload.email or "").strip().lower()

    # 1. Verification Gate
    ticket = payload.verification_ticket or ""
    is_ticket_valid = verify_verification_token(ticket, clean_email, purpose="forgot_password") if ticket else False
    is_db_verified = is_otp_verified_for_reset(clean_email)

    if not (is_ticket_valid or is_db_verified):
        return JSONResponse(
            status_code=403,
            content={
                "success": False,
                "message": "OTP verification required. Please verify the 8-digit code sent to your email before resetting your passkey."
            }
        )

    # 2. Password Matching
    if payload.password != payload.confirm_password:
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": "Passwords do not match. Please re-enter confirm password."}
        )

    # 3. Standard Password Parameters & Security Validation
    is_pwd_valid, missing_rules, rules_dict = validate_password_strength(payload.password)
    if not is_pwd_valid:
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "message": "Password does not meet standard parameters: " + "; ".join(missing_rules),
                "rules": rules_dict,
                "missing": missing_rules
            }
        )

    # 4. Update Password in Database
    updated = update_user_password(clean_email, payload.password)
    if not updated:
        return JSONResponse(
            status_code=404,
            content={"success": False, "message": "Unable to update passkey. User account not found."}
        )

    # 5. Clear verified OTP
    consume_verified_otp(clean_email, purpose="forgot_password")

    return JSONResponse(
        status_code=200,
        content={
            "success": True,
            "message": "Access passkey updated successfully. You can now authenticate with your new passkey.",
            "email": clean_email
        }
    )

