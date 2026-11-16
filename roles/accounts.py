"""
OASIS Seeded User & Admin Accounts Registry
Two platform roles: Admin and User.
Normal users have standard, equal access with simple, non-title based usernames.
"""

from typing import Dict, Any, Optional
import hmac

try:
    from core.database import (
        get_user_by_username,
        update_user_last_login,
        get_all_users_with_roles
    )
except ImportError:
    get_user_by_username = None
    update_user_last_login = None
    get_all_users_with_roles = None

# Single Admin Account
ADMIN_ACCOUNT: Dict[str, Any] = {
    "username": "admin",
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
        "password": "alex123",
        "role": "user",
        "displayName": "Alex",
        "avatar": "A",
        "can_view_telemetry": False,
        "can_manage_services": False,
    },
    "sam": {
        "username": "sam",
        "password": "sam123",
        "role": "user",
        "displayName": "Sam",
        "avatar": "S",
        "can_view_telemetry": False,
        "can_manage_services": False,
    },
    "jordan": {
        "username": "jordan",
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


def authenticate_user(username: str, password: Optional[str] = "") -> Optional[Dict[str, Any]]:
    """
    Validates username and password against the database accounts registry.
    Two roles: 'admin' and 'user'.
    """
    clean_user = (username or "").strip().lower()

    # Try database first
    if get_user_by_username:
        db_user = get_user_by_username(clean_user)
        if db_user:
            expected_pass = db_user.get("password", "")
            if password and hmac.compare_digest(password, expected_pass):
                if update_user_last_login:
                    try:
                        update_user_last_login(clean_user)
                    except Exception:
                        pass
                return db_user

    # Fallback to in-memory registry
    if clean_user in ALL_USERS:
        account = ALL_USERS[clean_user]
        expected_pass = account["password"]
        if password and hmac.compare_digest(password, expected_pass):
            return account
        return None

    return None


def get_user(username: str) -> Optional[Dict[str, Any]]:
    """Retrieves account details by username from database or fallback dictionary."""
    clean_user = (username or "").strip().lower()
    if get_user_by_username:
        db_user = get_user_by_username(clean_user)
        if db_user:
            return db_user
    return ALL_USERS.get(clean_user)


def is_admin_user(username: str) -> bool:
    """Returns True if the user has the Admin role."""
    user = get_user(username)
    if user:
        return user.get("role") == "admin"
    return False
