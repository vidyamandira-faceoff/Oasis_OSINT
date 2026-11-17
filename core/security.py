"""
OASIS Security & Authentication Governance Engine
Implements:
1. Cryptographically secure Access Tokens (15 min) and Refresh Tokens (7 days) via HMAC-SHA256.
2. Brute-force & credential-stuffing defense with IP/Account rate-limiting.
3. Constant-time timing-attack mitigation (hmac.compare_digest).
4. Revocation registry for instant session invalidation.
5. In-flight OSINT task and scan activity detection (protects against idle auto-logout).
"""

import os
import time
import json
import hmac
import base64
import hashlib
import secrets
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List
from fastapi import Request, Response

from core.config import BASE_DIR

# Persistent Secret Generation (survives restarts if stored in .oasis_secret)
SECRET_FILE = BASE_DIR / ".oasis_secret"
if SECRET_FILE.exists():
    try:
        with open(SECRET_FILE, "r") as f:
            _stored_secrets = json.load(f)
            JWT_SECRET_KEY = _stored_secrets.get("jwt_secret")
            REFRESH_SECRET_KEY = _stored_secrets.get("refresh_secret")
    except Exception:
        JWT_SECRET_KEY = None
        REFRESH_SECRET_KEY = None
else:
    JWT_SECRET_KEY = None
    REFRESH_SECRET_KEY = None

if not JWT_SECRET_KEY or not REFRESH_SECRET_KEY:
    JWT_SECRET_KEY = os.getenv("OASIS_JWT_SECRET") or secrets.token_hex(32)
    REFRESH_SECRET_KEY = os.getenv("OASIS_REFRESH_SECRET") or secrets.token_hex(32)
    try:
        with open(SECRET_FILE, "w") as f:
            json.dump({"jwt_secret": JWT_SECRET_KEY, "refresh_secret": REFRESH_SECRET_KEY}, f)
    except Exception:
        pass

# Token Expirations
ACCESS_TOKEN_EXPIRE_SECONDS = 15 * 60        # 15 minutes
REFRESH_TOKEN_EXPIRE_SECONDS = 7 * 24 * 3600  # 7 days
IDLE_TIMEOUT_SECONDS = 30 * 60               # 30 minutes idle threshold

# In-Memory Token Revocation Registry (jti set)
REVOKED_TOKENS = set()

# In-Memory Brute-Force Tracker
# Format: { key: [timestamp1, timestamp2, ...] }
_FAILED_LOGIN_ATTEMPTS: Dict[str, List[float]] = {}
MAX_USER_FAILED_ATTEMPTS = 5
MAX_IP_FAILED_ATTEMPTS = 25
LOCKOUT_WINDOW_SECONDS = 300  # 5 minutes window


# -----------------------------------------------------------------------------
# Cryptographic Password Hashing & Verification (PBKDF2-HMAC-SHA256)
# -----------------------------------------------------------------------------
PBKDF2_ITERATIONS = 100_000


def hash_password(password: str) -> str:
    """Hashes a password with PBKDF2-HMAC-SHA256 and a 16-byte random salt."""
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${dk.hex()}"


def verify_password(plain_password: str, stored_hash: str) -> bool:
    """
    Verifies a plain-text password against a PBKDF2 hash or legacy plaintext
    with constant-time comparison to prevent timing side-channel attacks.
    """
    if not plain_password or not stored_hash:
        return False
    try:
        if stored_hash.startswith("pbkdf2_sha256$"):
            parts = stored_hash.split("$")
            if len(parts) == 4:
                _, iter_str, salt, expected_hash = parts
                iterations = int(iter_str)
                dk = hashlib.pbkdf2_hmac(
                    "sha256",
                    plain_password.encode("utf-8"),
                    salt.encode("utf-8"),
                    iterations
                )
                return hmac.compare_digest(dk.hex(), expected_hash)
        # Constant-time fallback for legacy plain-text entries
        return hmac.compare_digest(plain_password, stored_hash)
    except Exception:
        return False


def strip_secrets(user: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Returns a copy of a user record without credential material."""
    if not user:
        return user
    return {k: v for k, v in user.items() if k != "password"}


# -----------------------------------------------------------------------------
# Development Mode
# -----------------------------------------------------------------------------
def is_dev_mode() -> bool:
    """
    True only when OASIS_DEV_MODE is explicitly enabled. Dev mode exposes
    convenience helpers (OTP preview, demo credential presets) that must never
    be active on a shared or production deployment.
    """
    return os.getenv("OASIS_DEV_MODE", "").strip().lower() in ("1", "true", "yes", "on")


# -----------------------------------------------------------------------------
# Credential-Change Session Invalidation
# -----------------------------------------------------------------------------
# username -> unix timestamp of the last password change. Any token issued
# before this moment is rejected, so a password reset signs out every session.
CREDENTIALS_CHANGED_AT: Dict[str, int] = {}


def invalidate_user_sessions(username: str) -> None:
    """Revokes all access/refresh tokens issued to `username` before now."""
    clean = (username or "").strip().lower()
    if clean:
        CREDENTIALS_CHANGED_AT[clean] = int(time.time())



# -----------------------------------------------------------------------------
# Base64URL Helpers
# -----------------------------------------------------------------------------
def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    padding = "=" * (4 - (len(s) % 4)) if len(s) % 4 != 0 else ""
    return base64.urlsafe_b64decode((s + padding).encode("utf-8"))


# -----------------------------------------------------------------------------
# Token Issuance & Verification (HMAC-SHA256 Standard JWT format)
# -----------------------------------------------------------------------------
def create_access_token(data: Dict[str, Any], expires_in: int = ACCESS_TOKEN_EXPIRE_SECONDS) -> str:
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        **data,
        "iat": now,
        "exp": now + expires_in,
        "jti": secrets.token_hex(16),
        "type": "access",
    }
    
    encoded_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    encoded_payload = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")
    
    signature = hmac.new(JWT_SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256).digest()
    encoded_signature = _b64url_encode(signature)
    
    return f"{encoded_header}.{encoded_payload}.{encoded_signature}"


def create_refresh_token(data: Dict[str, Any], expires_in: int = REFRESH_TOKEN_EXPIRE_SECONDS) -> str:
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": data.get("sub") or data.get("username"),
        "role": data.get("role", "user"),
        "iat": now,
        "exp": now + expires_in,
        "jti": secrets.token_hex(16),
        "type": "refresh",
    }
    
    encoded_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    encoded_payload = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")
    
    signature = hmac.new(REFRESH_SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256).digest()
    encoded_signature = _b64url_encode(signature)
    
    return f"{encoded_header}.{encoded_payload}.{encoded_signature}"


def decode_token(token: str, is_refresh: bool = False) -> Optional[Dict[str, Any]]:
    """
    Decodes and validates an HMAC-SHA256 signed token.
    Uses constant-time comparison to defeat timing attacks.
    """
    if not token or token.count(".") != 2:
        return None
    
    try:
        parts = token.split(".")
        header_raw = _b64url_decode(parts[0])
        payload_raw = _b64url_decode(parts[1])
        signature = _b64url_decode(parts[2])
        
        secret = REFRESH_SECRET_KEY if is_refresh else JWT_SECRET_KEY
        signing_input = f"{parts[0]}.{parts[1]}".encode("utf-8")
        expected_sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
        
        # Constant-time comparison defeats timing attacks
        if not hmac.compare_digest(signature, expected_sig):
            return None
        
        payload = json.loads(payload_raw.decode("utf-8"))
        
        # Expiry check
        now = int(time.time())
        if payload.get("exp", 0) < now:
            return None
        
        # Type check
        expected_type = "refresh" if is_refresh else "access"
        if payload.get("type") != expected_type:
            return None
        
        # Revocation check
        jti = payload.get("jti")
        if jti and jti in REVOKED_TOKENS:
            return None

        # Credential-change check: tokens issued before a password reset are void
        subject = str(payload.get("sub") or payload.get("username") or "").lower()
        changed_at = CREDENTIALS_CHANGED_AT.get(subject)
        if changed_at is not None and int(payload.get("iat", 0)) < changed_at:
            return None

        return payload
    except Exception:
        return None


def revoke_token(token_str: str, is_refresh: bool = False):
    """Adds a token's JTI to the revocation blacklist."""
    if not token_str or token_str.count(".") != 2:
        return
    try:
        parts = token_str.split(".")
        payload_raw = _b64url_decode(parts[1])
        payload = json.loads(payload_raw.decode("utf-8"))
        jti = payload.get("jti")
        if jti:
            REVOKED_TOKENS.add(jti)
    except Exception:
        pass


# -----------------------------------------------------------------------------
# Cookie Management Helpers
# -----------------------------------------------------------------------------
def set_auth_cookies(response: Response, user_account: Dict[str, Any]):
    """
    Sets secure HttpOnly access and refresh tokens, plus hydration cookie.
    """
    username = user_account["username"]
    role = user_account.get("role", "user")
    
    token_payload = {
        "sub": username,
        "username": username,
        "displayName": user_account.get("displayName", username.title()),
        "role": role,
        "is_admin": role == "admin",
        "avatar": user_account.get("avatar", username[0].upper()),
    }
    
    access_token = create_access_token(token_payload)
    refresh_token = create_refresh_token(token_payload)
    
    # 1. Access Token Cookie (HttpOnly, SameSite=Lax, 15 minutes)
    response.set_cookie(
        key="oasis_access_token",
        value=access_token,
        max_age=ACCESS_TOKEN_EXPIRE_SECONDS,
        path="/",
        httponly=True,
        samesite="lax",
    )
    
    # 2. Refresh Token Cookie (HttpOnly, SameSite=Lax, 7 days)
    response.set_cookie(
        key="oasis_refresh_token",
        value=refresh_token,
        max_age=REFRESH_TOKEN_EXPIRE_SECONDS,
        path="/",
        httponly=True,
        samesite="lax",
    )
    
    # 3. Client UI Hydration Cookie (readable by client JS for fast DOM header display)
    response.set_cookie(
        key="oasis_user",
        value=username,
        max_age=REFRESH_TOKEN_EXPIRE_SECONDS,
        path="/",
        httponly=False,
        samesite="lax",
    )
    
    return access_token, refresh_token


def clear_auth_cookies(response: Response):
    """Clears all authentication and session cookies immediately."""
    for cookie_name in ("oasis_access_token", "oasis_refresh_token"):
        response.delete_cookie(
            key=cookie_name,
            path="/",
            httponly=True,
            samesite="lax",
        )
        response.set_cookie(
            key=cookie_name,
            value="",
            max_age=0,
            expires=0,
            path="/",
            httponly=True,
            samesite="lax",
        )
    response.delete_cookie(
        key="oasis_user",
        path="/",
        httponly=False,
        samesite="lax",
    )
    response.set_cookie(
        key="oasis_user",
        value="",
        max_age=0,
        expires=0,
        path="/",
        httponly=False,
        samesite="lax",
    )


# -----------------------------------------------------------------------------
# Session Resolution from Request
# -----------------------------------------------------------------------------
def get_session_from_request(request: Request) -> Optional[Dict[str, Any]]:
    """
    Resolves the current authenticated user session:
    1. Checks the HttpOnly oasis_access_token.
    2. If expired or missing, checks HttpOnly oasis_refresh_token.
    3. If refresh token is valid, returns session marked with 'can_refresh': True.
    """
    access_token = request.cookies.get("oasis_access_token")
    if access_token:
        payload = decode_token(access_token, is_refresh=False)
        if payload:
            return {
                "authenticated": True,
                "username": payload.get("sub") or payload.get("username"),
                "displayName": payload.get("displayName", ""),
                "role": payload.get("role", "user"),
                "is_admin": payload.get("role") == "admin",
                "avatar": payload.get("avatar", "U"),
                "refreshed": False,
            }
    
    # Fallback to refresh token
    refresh_token = request.cookies.get("oasis_refresh_token")
    if refresh_token:
        r_payload = decode_token(refresh_token, is_refresh=True)
        if r_payload:
            from roles.accounts import get_user
            u = r_payload.get("sub")
            acc = get_user(u)
            if not acc:
                # Account was deleted or deactivated: refresh must not resurrect it
                return None
            return {
                "authenticated": True,
                "username": u,
                "displayName": acc.get("displayName", u.title()) if acc else u.title(),
                "role": r_payload.get("role", "user"),
                "is_admin": r_payload.get("role") == "admin",
                "avatar": acc.get("avatar", u[0].upper()) if acc else "U",
                "refreshed": True,
            }
    
    return None


# -----------------------------------------------------------------------------
# Brute-Force & Credential Stuffing Rate Limiter
# -----------------------------------------------------------------------------
def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


def check_login_rate_limit(request: Request, username: str) -> Tuple[bool, int]:
    """
    Checks if client IP or username has exceeded maximum failed login attempts.
    - Max 5 failed attempts per specific username.
    - Max 25 failed attempts per client IP.
    Returns: (is_allowed: bool, retry_after_seconds: int)
    """
    ip = get_client_ip(request)
    now = time.time()
    cutoff = now - LOCKOUT_WINDOW_SECONDS
    
    checks = [
        (f"user:{username.strip().lower()}", MAX_USER_FAILED_ATTEMPTS),
        (f"ip:{ip}", MAX_IP_FAILED_ATTEMPTS),
    ]
    
    for key, limit in checks:
        attempts = _FAILED_LOGIN_ATTEMPTS.get(key, [])
        recent = [t for t in attempts if t > cutoff]
        _FAILED_LOGIN_ATTEMPTS[key] = recent
        
        if len(recent) >= limit:
            oldest_in_window = recent[0]
            retry_after = int(LOCKOUT_WINDOW_SECONDS - (now - oldest_in_window)) + 1
            return False, max(1, retry_after)
            
    return True, 0


def record_login_failure(request: Request, username: str):
    ip = get_client_ip(request)
    now = time.time()
    for key in (f"ip:{ip}", f"user:{username.strip().lower()}"):
        if key not in _FAILED_LOGIN_ATTEMPTS:
            _FAILED_LOGIN_ATTEMPTS[key] = []
        _FAILED_LOGIN_ATTEMPTS[key].append(now)


def record_login_success(request: Request, username: str):
    ip = get_client_ip(request)
    _FAILED_LOGIN_ATTEMPTS.pop(f"ip:{ip}", None)
    _FAILED_LOGIN_ATTEMPTS.pop(f"user:{username.strip().lower()}", None)


# -----------------------------------------------------------------------------
# In-Flight OSINT Task / Scan Detection
# -----------------------------------------------------------------------------
def is_any_osint_scan_running() -> Tuple[bool, List[str]]:
    """
    Checks across all platform modules whether any background OSINT crawler,
    spider, reverse lookup, or intelligence engine is actively running.
    Prevents idle auto-logout when operations are underway.
    """
    active_tools: List[str] = []
    
    # 1. Core Process Manager handles
    try:
        from core.process_manager import RUNNING_PROCESSES
        for name, proc in list(RUNNING_PROCESSES.items()):
            if proc and proc.poll() is None:
                active_tools.append(f"Engine Process: {name.upper()}")
    except Exception:
        pass
    
    # 2. Recon Username module
    try:
        from services.recon_username.backend.service import _TASKS
        for target, task in list(_TASKS.items()):
            if task.get("status") in ("running", "queued"):
                active_tools.append(f"Username Recon ({target})")
    except Exception:
        pass

    # 3. Domain & Website Intelligence module
    try:
        from services.domain_intelligence.backend.service import _JOBS
        for job_id, job in list(_JOBS.items()):
            if job.get("status") in ("running", "queued"):
                active_tools.append(f"Domain Recon ({job.get('target', job_id)})")
    except Exception:
        pass

    # 4. Social Media Intelligence module
    try:
        from services.social_media_intelligence.backend.service import _TASKS, _IG_TASKS, _TW_TASKS, _LI_TASKS
        for pool in (_TASKS, _IG_TASKS, _TW_TASKS, _LI_TASKS):
            for target, task in list(pool.items()):
                if isinstance(task, dict) and task.get("status") in ("running", "queued"):
                    active_tools.append(f"Social Media Scan ({target})")
    except Exception:
        pass

    # 5. Phone Intelligence module
    try:
        from services.phone_intelligence.backend.service import _TASKS
        for target, task in list(_TASKS.items()):
            if task.get("status") in ("running", "queued"):
                active_tools.append(f"Phone Number Recon ({target})")
    except Exception:
        pass

    # 6. IP & Network Intelligence module
    try:
        from services.ip_network_intelligence.backend.service import _IP_TASKS
        for target, task in list(_IP_TASKS.items()):
            if task.get("status") in ("running", "queued"):
                active_tools.append(f"IP Network Scan ({target})")
    except Exception:
        pass

    has_active = len(active_tools) > 0
    return has_active, active_tools


# -----------------------------------------------------------------------------
# Password Standards & Verification Ticket Helpers
# -----------------------------------------------------------------------------
SPECIAL_CHARACTERS = set("!@#$%^&*()_+-=[]{}|;:,.<>?/~`'\"\\")

def validate_password_strength(password: str) -> Tuple[bool, List[str], Dict[str, bool]]:
    """
    Evaluates password compliance with standard enterprise security parameters:
    1. Minimum 8 characters in length
    2. At least one uppercase letter (A-Z)
    3. At least one lowercase letter (a-z)
    4. At least one numeric digit (0-9)
    5. At least one special symbol (!@#$%^&*...)
    Returns (is_valid, list_of_missing_rules, rules_dict).
    """
    pwd = password or ""
    rules = {
        "min_length": len(pwd) >= 8,
        "uppercase": any(c.isupper() for c in pwd),
        "lowercase": any(c.islower() for c in pwd),
        "number": any(c.isdigit() for c in pwd),
        "special": any(c in SPECIAL_CHARACTERS for c in pwd),
    }

    missing = []
    if not rules["min_length"]:
        missing.append("Minimum 8 characters in length")
    if not rules["uppercase"]:
        missing.append("At least one uppercase letter (A-Z)")
    if not rules["lowercase"]:
        missing.append("At least one lowercase letter (a-z)")
    if not rules["number"]:
        missing.append("At least one numeric digit (0-9)")
    if not rules["special"]:
        missing.append("At least one special symbol (!@#$%^&*...)")

    is_valid = len(missing) == 0
    return is_valid, missing, rules


def create_verification_token(email: str, purpose: str, expires_in: int = 900) -> str:
    """Creates a short-lived cryptographic ticket certifying email verification."""
    data = {
        "sub": email.strip().lower(),
        "purpose": purpose,
        "type": "email_verification_ticket",
    }
    return create_access_token(data, expires_in=expires_in)


def verify_verification_token(token: str, email: str, purpose: str) -> bool:
    """Verifies that the ticket is valid, signed, unexpired, and matches email & purpose."""
    payload = decode_token(token, is_refresh=False)
    if not payload:
        return False
    if payload.get("type") != "email_verification_ticket":
        return False
    if payload.get("sub") != email.strip().lower():
        return False
    if payload.get("purpose") != purpose:
        return False
    return True

