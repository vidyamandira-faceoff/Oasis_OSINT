"""
OASIS Seeded User & Admin Accounts Registry
Two platform roles: Admin and User.
Normal users have standard, equal access with simple, non-title based usernames.
"""

from typing import Dict, Any, Optional
from core.security import verify_password, strip_secrets, hash_password

try:
    from core.database import (
        get_user_by_username,
        get_user_by_email,
        get_user_by_username_or_email,
        get_user_credentials,
        update_user_last_login,
        get_all_users_with_roles
    )
    DB_AVAILABLE = True
except ImportError:
    get_user_by_username = None
    get_user_by_email = None
    get_user_by_username_or_email = None
    get_user_credentials = None
    update_user_last_login = None
    get_all_users_with_roles = None
    DB_AVAILABLE = False

# NOTE: The in-memory registry below is a bootstrap/offline fallback ONLY.
# It is consulted exclusively when the database layer cannot be imported.
# Whenever the database is available it is the single source of truth, so a
# password reset or account deactivation can never be bypassed with these
# default credentials.

# Single Admin Account
ADMIN_ACCOUNT: Dict[str, Any] = {
    "username": "admin",
    "email": "admin@oasis.live",
    "password": "admin123",
    "role": "admin",
    "displayName": "Admin",
    "avatar": "A",
    "can_view_telemetry": True,
    "can_manage_services": True,
}

# Seeded Normal User Accounts (simple, non-title based usernames)
SEED_USER_ACCOUNTS: Dict[str, Dict[str, Any]] = {
    "alex": {
        "username": "alex",
        "email": "alex@oasis.live",
        "password": "alex123",
        "role": "user",
        "displayName": "Alex",
        "avatar": "A",
        "can_view_telemetry": False,
        "can_manage_services": False,
    },
    "sam": {
        "username": "sam",
        "email": "sam@oasis.live",
        "password": "sam123",
        "role": "user",
        "displayName": "Sam",
        "avatar": "S",
        "can_view_telemetry": False,
        "can_manage_services": False,
    },
    "jordan": {
        "username": "jordan",
        "email": "jordan@oasis.live",
        "password": "jordan123",
        "role": "user",
        "displayName": "Jordan",
        "avatar": "J",
        "can_view_telemetry": False,
        "can_manage_services": False,
    },
}

ALL_USERS: Dict[str, Dict[str, Any]] = {
    ADMIN_ACCOUNT["username"]: ADMIN_ACCOUNT,
    **SEED_USER_ACCOUNTS,
}


_DUMMY_HASH = hash_password("oasis-timing-equaliser")


def _find_in_memory(clean_identifier: str) -> Optional[Dict[str, Any]]:
    for account in ALL_USERS.values():
        if account["username"].lower() == clean_identifier or account.get("email", "").lower() == clean_identifier:
            return account
    return None


def authenticate_user(username_or_email: str, password: Optional[str] = "") -> Optional[Dict[str, Any]]:
    """
    Validates username or email and password against the database accounts registry.
    Two roles: 'admin' and 'user'. Returns the user record WITHOUT credential material.
    """
    clean_identifier = (username_or_email or "").strip().lower()
    if not clean_identifier or not password:
        return None

    if DB_AVAILABLE:
        creds = get_user_credentials(clean_identifier)
        if not creds:
            # Equalise timing with a real PBKDF2 check to resist user enumeration
            verify_password(password, _DUMMY_HASH)
            return None
        db_user, stored_hash = creds
        if not verify_password(password, stored_hash):
            return None
        try:
            update_user_last_login(db_user["username"])
        except Exception:
            pass
        return strip_secrets(db_user)

    # Offline fallback (database layer unavailable)
    account = _find_in_memory(clean_identifier)
    if account and verify_password(password, account["password"]):
        return strip_secrets(account)
    return None


def get_user(username_or_email: str) -> Optional[Dict[str, Any]]:
    """Retrieves an active account by username or email, without credential material."""
    clean_identifier = (username_or_email or "").strip().lower()
    if DB_AVAILABLE:
        return strip_secrets(get_user_by_username_or_email(clean_identifier))
    return strip_secrets(_find_in_memory(clean_identifier))


def is_admin_user(username: str) -> bool:
    """Returns True if the user has the Admin role."""
    user = get_user(username)
    if user:
        return user.get("role") == "admin"
    return False
