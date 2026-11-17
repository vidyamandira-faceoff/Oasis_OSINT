"""
OASIS Seeded User & Admin Accounts Registry
Two platform roles: Admin and User.
Normal users have standard, equal access with simple, non-title based usernames.
"""

from typing import Dict, Any, Optional
import hmac
from core.security import verify_password

try:
    from core.database import (
        get_user_by_username,
        get_user_by_email,
        get_user_by_username_or_email,
        update_user_last_login,
        get_all_users_with_roles
    )
except ImportError:
    get_user_by_username = None
    get_user_by_email = None
    get_user_by_username_or_email = None
    update_user_last_login = None
    get_all_users_with_roles = None

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


def authenticate_user(username_or_email: str, password: Optional[str] = "") -> Optional[Dict[str, Any]]:
    """
    Validates username or email and password against the database accounts registry.
    Two roles: 'admin' and 'user'.
    """
    clean_identifier = (username_or_email or "").strip().lower()

    # Try database first with username or email
    if get_user_by_username_or_email:
        db_user = get_user_by_username_or_email(clean_identifier)
        if db_user:
            expected_pass = db_user.get("password", "")
            if password and verify_password(password, expected_pass):
                if update_user_last_login:
                    try:
                        update_user_last_login(db_user["username"])
                    except Exception:
                        pass
                return db_user

    # Fallback to in-memory registry
    for account in ALL_USERS.values():
        if account["username"].lower() == clean_identifier or account.get("email", "").lower() == clean_identifier:
            expected_pass = account["password"]
            if password and verify_password(password, expected_pass):
                return account

    return None


def get_user(username_or_email: str) -> Optional[Dict[str, Any]]:
    """Retrieves account details by username or email from database or fallback dictionary."""
    clean_identifier = (username_or_email or "").strip().lower()
    if get_user_by_username_or_email:
        db_user = get_user_by_username_or_email(clean_identifier)
        if db_user:
            return db_user
    for account in ALL_USERS.values():
        if account["username"].lower() == clean_identifier or account.get("email", "").lower() == clean_identifier:
            return account
    return None


def is_admin_user(username: str) -> bool:
    """Returns True if the user has the Admin role."""
    user = get_user(username)
    if user:
        return user.get("role") == "admin"
    return False
