"""
OASIS Normal User Intelligence Service & Dynamic Frequency Governance
Directly backed by SQLite (service_executions). Zero dummy/mock data.
Tracks real user scan executions, computes real recency-weighted affinity rankings,
and dynamically serves the "Frequently Used Services & Modules" dashboard section.
"""

from datetime import datetime
from typing import Dict, Any, List, Optional
from core.database import init_db, get_db_connection

# Master registry of intelligence services available to normal users
AVAILABLE_MODULES: List[Dict[str, Any]] = [
    {
        "id": "recon_username",
        "name": "Username & Identity Intelligence",
        "route": "/role_user/services/recon-username",
        "category": "Identity Profiling",
        "specs": "3,000+ Global Online Platform Registries",
        "description": "Enumerate registered accounts across thousands of web platforms. Harvest profile biographies, avatars, verified handles, and cross-platform identity linkages.",
        "icon_type": "user",
        "accent_color": "#10b981",
        "badge_bg": "rgba(16, 185, 129, 0.12)",
        "badge_border": "rgba(16, 185, 129, 0.3)",
        "theme_tag": "Active Recon",
        "action_cta": "Launch Username Recon",
    },
    {
        "id": "domain_intelligence",
        "name": "Domain & Website Intelligence",
        "route": "/role_user/services/domain-intelligence",
        "category": "Infrastructure & Web",
        "specs": "Web Spidering • DNS Topology • Secret Scanning",
        "description": "Deep recursive crawling of web endpoints, automated DNS subdomain resolution, client-side JavaScript route extraction, and high-entropy secret detection.",
        "icon_type": "globe",
        "accent_color": "#0284c7",
        "badge_bg": "rgba(2, 132, 199, 0.12)",
        "badge_border": "rgba(2, 132, 199, 0.3)",
        "theme_tag": "Surface Spider",
        "action_cta": "Launch Domain Recon",
    },
    {
        "id": "email_intelligence",
        "name": "Email Intelligence & Footprint",
        "route": "/role_user/services/email-intelligence",
        "category": "Credential & Mailbox",
        "specs": "124 Platform Registries • 26 Mailbox Providers • Leaked Hints",
        "description": "Dual-engine email triage: 26-provider Mailbox Discovery by username plus 124-platform Reverse Account Footprinting with masked phone and recovery email harvesting.",
        "icon_type": "mail",
        "accent_color": "#6366f1",
        "badge_bg": "rgba(99, 102, 241, 0.12)",
        "badge_border": "rgba(99, 102, 241, 0.3)",
        "theme_tag": "Reverse Footprint",
        "action_cta": "Launch Email Recon",
    },
    {
        "id": "social_media",
        "name": "Social Media Intelligence",
        "route": "/role_user/services/social-media-intelligence",
        "category": "Social Graph & Timeline",
        "specs": "Instagram • X / Twitter • Facebook • LinkedIn",
        "description": "Dual-tier social intelligence: native in-app Flash recon for Instagram and Twitter with timeline and media harvesting, plus dedicated clusters for Facebook and LinkedIn.",
        "icon_type": "share",
        "accent_color": "#ec4899",
        "badge_bg": "rgba(236, 72, 153, 0.12)",
        "badge_border": "rgba(236, 72, 153, 0.3)",
        "theme_tag": "Flash Recon",
        "action_cta": "Launch Social Scrapers",
    },
    {
        "id": "ip_network",
        "name": "IP & Network Intelligence",
        "route": "/role_user/services/ip-network-intelligence",
        "category": "Perimeter & ASN",
        "specs": "GeoIP Coordinates • ASN/BGP Routing • Tactical Port Triage",
        "description": "Tactical perimeter reconnaissance: physical GeoIP coordinates, autonomous system (ASN) route origin, reverse DNS (PTR), 16-port non-intrusive triage, and TLS certificate decoding.",
        "icon_type": "server",
        "accent_color": "#0ea5e9",
        "badge_bg": "rgba(14, 165, 233, 0.12)",
        "badge_border": "rgba(14, 165, 233, 0.3)",
        "theme_tag": "Network Triage",
        "action_cta": "Launch Network Recon",
    },
    {
        "id": "phone_intelligence",
        "name": "Phone Number Intelligence",
        "route": "/role_user/services/phone-intelligence",
        "category": "Telecom & Carrier",
        "specs": "Carrier Resolution • Circle Mapping • Search Platform",
        "description": "Direct access to native telephone investigation intelligence for carrier network resolution, geographic telecom circle mapping, line type validation, and multi-source footprints.",
        "icon_type": "phone",
        "accent_color": "#059669",
        "badge_bg": "rgba(5, 150, 105, 0.12)",
        "badge_border": "rgba(5, 150, 105, 0.3)",
        "theme_tag": "Telecom Map",
        "action_cta": "Launch Phone Scraper",
    },
]

SERVICE_ALIASES: Dict[str, str] = {
    "recon_username": "recon_username",
    "domain_intelligence": "domain_intelligence",
    "social_media_intelligence": "social_media",
    "social_media": "social_media",
    "phone_intelligence": "phone_intelligence",
    "email_intelligence": "email_intelligence",
    "ip_network_intelligence": "ip_network",
    "ip_network": "ip_network",
}


def _format_time_ago(dt: datetime) -> str:
    diff_sec = (datetime.now() - dt).total_seconds()
    if diff_sec < 60:
        return "Just now"
    elif diff_sec < 3600:
        m = max(1, int(diff_sec // 60))
        return f"{m}m ago"
    elif diff_sec < 86400:
        h = max(1, int(diff_sec // 3600))
        return f"{h}h ago"
    elif diff_sec < 172800:
        return "Yesterday"
    else:
        d = max(2, int(diff_sec // 86400))
        return f"{d}d ago"


def record_user_service_usage(username: str, service_id: str) -> Dict[str, Any]:
    """
    Hook called when a user executes a service scan.
    The primary audit log is stored in SQLite `service_executions` table by core.database.record_execution.
    This hook queries the database and returns the up-to-date execution count for the service.
    """
    stats = get_user_service_execution_stats(username)
    canonical = SERVICE_ALIASES.get((service_id or "").strip().lower(), (service_id or "").strip().lower())
    return stats.get(canonical, {"scan_count": 0, "last_created_at": None})


def get_user_service_execution_stats(username: str) -> Dict[str, Dict[str, Any]]:
    """
    Queries SQLite `service_executions` for actual, real user scan execution counts and timestamps.
    Zero fake or seeded baseline data.
    """
    init_db()
    stats: Dict[str, Dict[str, Any]] = {}
    clean_user = (username or "").strip().lower()

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT service_id, COUNT(*) as scan_count, MAX(created_at) as last_created_at
            FROM service_executions
            WHERE LOWER(username) = ?
            GROUP BY service_id;
        """, (clean_user,))
        rows = cursor.fetchall()

        for row in rows:
            raw_id = (row["service_id"] or "").strip().lower()
            canonical_id = SERVICE_ALIASES.get(raw_id, raw_id)
            count = int(row["scan_count"] or 0)
            last_ts = row["last_created_at"]

            if canonical_id in stats:
                stats[canonical_id]["scan_count"] += count
                if last_ts and (not stats[canonical_id]["last_created_at"] or last_ts > stats[canonical_id]["last_created_at"]):
                    stats[canonical_id]["last_created_at"] = last_ts
            else:
                stats[canonical_id] = {
                    "scan_count": count,
                    "last_created_at": last_ts
                }

    return stats


def get_frequently_used_services(username: str) -> List[Dict[str, Any]]:
    """
    Computes 100% genuine dynamic frequency rankings directly from SQLite service_executions.
    Zero mock baseline, zero dummy seeds.
    Ranks services strictly by actual scans executed by the user.
    """
    stats = get_user_service_execution_stats(username)
    now = datetime.now()

    # Total real scans run by this user across all modules
    total_scans = sum(stats.get(m["id"], {}).get("scan_count", 0) for m in AVAILABLE_MODULES)

    scored_list = []
    for mod in AVAILABLE_MODULES:
        mid = mod["id"]
        mod_stat = stats.get(mid, {})
        real_scans = mod_stat.get("scan_count", 0)
        last_created_str = mod_stat.get("last_created_at")

        last_used_dt: Optional[datetime] = None
        if real_scans > 0 and last_created_str:
            try:
                last_used_dt = datetime.strptime(last_created_str, "%Y-%m-%d %H:%M:%S")
            except Exception:
                try:
                    last_used_dt = datetime.fromisoformat(last_created_str)
                except Exception:
                    last_used_dt = None

        if real_scans > 0 and last_used_dt:
            hours_ago = max(0.01, (now - last_used_dt).total_seconds() / 3600.0)
            recency_factor = max(0.1, 1.0 - (hours_ago / 168.0))
            score = round((real_scans * 10.0) + (recency_factor * 25.0), 2)
            time_ago_str = _format_time_ago(last_used_dt)
        else:
            score = 0.0
            time_ago_str = "No scans yet"

        pct = round((real_scans / total_scans) * 100) if total_scans > 0 else 0

        item = {
            **mod,
            "active_scans": real_scans,
            "launches": real_scans,
            "affinity_score": score,
            "last_used_dt": last_used_dt,
            "last_used_str": time_ago_str,
            "usage_percentage": pct,
        }
        scored_list.append(item)

    # Sort descending by affinity_score, secondary by real active_scans
    scored_list.sort(key=lambda x: (x["affinity_score"], x["active_scans"]), reverse=True)

    tier_labels = [
        "Primary Suite • High Casework Affinity",
        "High Frequency • Regular Casework",
        "Frequent • Active Recon",
        "Moderate Usage",
        "Specialized Recon",
        "Periodic Utility",
    ]

    for i, item in enumerate(scored_list, 1):
        item["rank"] = i
        if item["active_scans"] > 0:
            item["rank_badge"] = f"#{i} MOST FREQUENT" if i == 1 else f"#{i} FREQUENT"
            if i - 1 < len(tier_labels):
                item["frequency_tier"] = tier_labels[i - 1]
            else:
                item["frequency_tier"] = "Active Casework"
        else:
            item["rank_badge"] = "STANDBY"
            item["frequency_tier"] = "Standby • No Casework Executed"

    return scored_list


def get_user_dashboard_data(username: str) -> Dict[str, Any]:
    """
    Returns complete user dashboard metadata with dynamic frequently used services.
    Directly backed by SQLite service_executions. Zero mock/dummy data.
    """
    frequent_modules = get_frequently_used_services(username)
    total_scans = sum(m["active_scans"] for m in frequent_modules)
    top_module = frequent_modules[0] if (frequent_modules and frequent_modules[0]["active_scans"] > 0) else None

    return {
        "user_role": "User",
        "station_access": "Operational Suite Active",
        "frequently_used": frequent_modules,
        "total_launches": total_scans,
        "top_module_name": top_module["name"] if top_module else "Primary Intelligence Suites",
    }
