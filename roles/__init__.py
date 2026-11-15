"""
OASIS Role-Based Access & Governance Package
Provides distinct roles (Admin vs. Normal User) with tailored dashboards,
tool mappings, and service health monitoring.
"""

from .accounts import (
    authenticate_user,
    get_user,
    is_admin_user,
    ALL_USERS,
    ADMIN_ACCOUNT,
    SEED_USER_ACCOUNTS,
)

__all__ = [
    "authenticate_user",
    "get_user",
    "is_admin_user",
    "ALL_USERS",
    "ADMIN_ACCOUNT",
    "SEED_USER_ACCOUNTS",
]

