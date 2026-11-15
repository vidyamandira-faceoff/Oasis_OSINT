"""
Normal User Service
Provides user-level scope and dashboard metadata.
"""

from typing import Dict, Any

def get_user_dashboard_data(username: str) -> Dict[str, Any]:
    """
    Returns user-level dashboard context for standard user access.
    """
    return {
        "user_role": "User",
        "station_access": "Operational Suite Active",
    }
