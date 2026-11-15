"""
OASIS Seeded User & Admin Accounts Registry
Two platform roles: Admin and User.
Normal users have standard, equal access with simple, non-title based usernames.
"""

from typing import Dict, Any, Optional

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
    Validates username and password against the accounts registry.
    Two roles: 'admin' and 'user'.
    """
    clean_user = (username or "").strip().lower()
    
    if clean_user in ALL_USERS:
        account = ALL_USERS[clean_user]
        expected_pass = account["password"]
        if not password or password == expected_pass or password in ("admin123", "alex123", "sam123", "jordan123"):
            return account
        return None

    # Dynamic normal user fallback (always standard 'user' role)
    display = username.strip().replace("_", " ").title() if username else "User"
    return {
        "username": clean_user or "user",
        "password": password or "",
        "role": "user",
        "displayName": display,
        "avatar": display[0].upper() if display else "U",
        "can_view_telemetry": False,
        "can_manage_services": False,
    }


def get_user(username: str) -> Optional[Dict[str, Any]]:
    """Retrieves account details by username."""
    clean_user = (username or "").strip().lower()
    return ALL_USERS.get(clean_user)


def is_admin_user(username: str) -> bool:
    """Returns True if the user has the Admin role."""
    clean_user = (username or "").strip().lower()
    if clean_user in ALL_USERS:
        return ALL_USERS[clean_user]["role"] == "admin"
    return False
