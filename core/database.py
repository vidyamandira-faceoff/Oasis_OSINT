"""
OASIS Relational Database Architecture
SQLite-backed persistence for Roles, Role-Wise Users, and Multi-User Service Execution History.
Powers the Live Usage Matrix, Admin Data Matrix, and User Profile Test History across services.
"""

import os
import json
import time
import sqlite3
import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

from core.config import BASE_DIR

DB_PATH = BASE_DIR / "oasis.sqlite3"


def get_db_connection() -> sqlite3.Connection:
    """Creates a thread-safe connection with dictionary rows and foreign keys enabled."""
    conn = sqlite3.connect(str(DB_PATH), timeout=15.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db() -> None:
    """Initializes tables, relational constraints, indices, and seeds initial data if missing."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # 1. Roles Relational Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                display_name TEXT NOT NULL,
                description TEXT,
                can_view_telemetry INTEGER DEFAULT 0,
                can_manage_services INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # 2. Users Relational Table (Foreign Key -> roles.id)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role_id INTEGER NOT NULL,
                display_name TEXT NOT NULL,
                avatar TEXT DEFAULT 'U',
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE RESTRICT
            );
        """)

        # 3. Service Executions / Test History Relational Table (Foreign Key -> users.id)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS service_executions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                user_role TEXT NOT NULL,
                service_id TEXT NOT NULL,
                service_name TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                target TEXT NOT NULL,
                duration_seconds REAL DEFAULT 0.0,
                findings_count INTEGER DEFAULT 0,
                findings_summary TEXT,
                status TEXT DEFAULT 'Success',
                status_class TEXT DEFAULT 'badge-status-success',
                report_path TEXT,
                metadata_json TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
        """)

        # Indices for high-velocity lookups
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_role_id ON users(role_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_executions_user_id ON service_executions(user_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_executions_service_id ON service_executions(service_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_executions_created_at ON service_executions(created_at);")

        conn.commit()

        # 4. Seed Roles if empty
        cursor.execute("SELECT COUNT(*) as count FROM roles;")
        if cursor.fetchone()["count"] == 0:
            cursor.executemany("""
                INSERT INTO roles (name, display_name, description, can_view_telemetry, can_manage_services)
                VALUES (?, ?, ?, ?, ?);
            """, [
                ("admin", "Administrator", "Full operational authority, live telemetry, security controls, and multi-user audit access", 1, 1),
                ("user", "Intelligence Analyst", "Standard intelligence investigation, search execution, and dossier export authority", 0, 0)
            ])
            conn.commit()

        # Retrieve Role IDs
        cursor.execute("SELECT id, name FROM roles;")
        role_map = {row["name"]: row["id"] for row in cursor.fetchall()}

        # 5. Seed Users if empty
        cursor.execute("SELECT COUNT(*) as count FROM users;")
        if cursor.fetchone()["count"] == 0:
            admin_role_id = role_map.get("admin", 1)
            user_role_id = role_map.get("user", 2)
            now_iso = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            cursor.executemany("""
                INSERT INTO users (username, password, role_id, display_name, avatar, is_active, last_login)
                VALUES (?, ?, ?, ?, ?, ?, ?);
            """, [
                ("admin", "admin123", admin_role_id, "Admin", "A", 1, now_iso),
                ("alex", "alex123", user_role_id, "Alex", "A", 1, now_iso),
                ("sam", "sam123", user_role_id, "Sam", "S", 1, now_iso),
                ("jordan", "jordan123", user_role_id, "Jordan", "J", 1, now_iso),
            ])
            conn.commit()

        # Retrieve User Map: username -> {id, role_name}
        cursor.execute("""
            SELECT u.id, u.username, r.name as role_name 
            FROM users u 
            JOIN roles r ON u.role_id = r.id;
        """)
        user_map = {row["username"]: {"id": row["id"], "role": row["role_name"]} for row in cursor.fetchall()}

        # 6. Seed Initial Multi-User Test History if executions table is empty
        cursor.execute("SELECT COUNT(*) as count FROM service_executions;")
        if cursor.fetchone()["count"] == 0:
            now = datetime.datetime.now()

            initial_executions = [
                # Alex's test runs
                (
                    user_map["alex"]["id"], "alex", user_map["alex"]["role"],
                    "recon_username", "Username Intelligence", "Maigret Async Engine",
                    "oushnikbhaduri", 4.2, 128, "128 verified endpoints", "Success", "badge-status-success",
                    "services/recon_username/reports/report_oushnikbhaduri.json",
                    (now - datetime.timedelta(minutes=6)).strftime("%Y-%m-%d %H:%M:%S")
                ),
                (
                    user_map["alex"]["id"], "alex", user_map["alex"]["role"],
                    "email_intelligence", "Email Intelligence", "Holehe 124 Platform Footprint",
                    "test@gmail.com", 12.1, 24, "24 verified accounts", "Success", "badge-status-success",
                    "services/email_intelligence/reports/email_test_at_gmail.com.json",
                    (now - datetime.timedelta(minutes=42)).strftime("%Y-%m-%d %H:%M:%S")
                ),
                (
                    user_map["alex"]["id"], "alex", user_map["alex"]["role"],
                    "domain_intelligence", "Domain & Website Intelligence", "Photon Surface Spider",
                    "example.com", 5.6, 38, "38 routes & endpoints mapped", "Success", "badge-status-success",
                    "services/domain_intelligence/reports/example.com.json",
                    (now - datetime.timedelta(hours=2, minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
                ),
                (
                    user_map["alex"]["id"], "alex", user_map["alex"]["role"],
                    "recon_username", "Username Intelligence", "Maigret Async Engine",
                    "atig", 3.9, 94, "94 profiles identified", "Success", "badge-status-success",
                    "services/recon_username/reports/report_atig.json",
                    (now - datetime.timedelta(hours=4, minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
                ),

                # Sam's test runs
                (
                    user_map["sam"]["id"], "sam", user_map["sam"]["role"],
                    "domain_intelligence", "Domain & Website Intelligence", "Photon Surface Spider",
                    "https://example.com", 7.8, 56, "42 routes, 14 subdomains", "Success", "badge-status-success",
                    "services/domain_intelligence/reports/example_https.json",
                    (now - datetime.timedelta(minutes=19)).strftime("%Y-%m-%d %H:%M:%S")
                ),
                (
                    user_map["sam"]["id"], "sam", user_map["sam"]["role"],
                    "social_media_intelligence", "Social Media Intelligence", "LinkedIn Workforce Scanner",
                    "google", 3.1, 15, "15 employee profiles, 3 synthesized emails", "Success", "badge-status-success",
                    "services/social_media_intelligence/reports/linkedin_google.json",
                    (now - datetime.timedelta(hours=1, minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
                ),
                (
                    user_map["sam"]["id"], "sam", user_map["sam"]["role"],
                    "ip_network_intelligence", "IP & Network Intelligence", "Tactical Port & ASN Triage",
                    "8.8.8.8", 1.8, 2, "AS15169 Google LLC, 2 open ports (DNS, HTTPS)", "Success", "badge-status-success",
                    "services/ip_network_intelligence/reports/ip_8.8.8.8.json",
                    (now - datetime.timedelta(hours=2, minutes=45)).strftime("%Y-%m-%d %H:%M:%S")
                ),
                (
                    user_map["sam"]["id"], "sam", user_map["sam"]["role"],
                    "social_media_intelligence", "Social Media Intelligence", "X / Twitter Flash Engine",
                    "target_profile_org", 9.4, 4, "Rate-limit mitigated (cached response)", "Mitigated", "badge-status-warning",
                    "services/social_media_intelligence/reports/twitter_target.json",
                    (now - datetime.timedelta(hours=3, minutes=30)).strftime("%Y-%m-%d %H:%M:%S")
                ),

                # Jordan's test runs
                (
                    user_map["jordan"]["id"], "jordan", user_map["jordan"]["role"],
                    "ip_network_intelligence", "IP & Network Intelligence", "BGP ASN & Port Triage",
                    "1.1.1.1", 1.4, 3, "AS13335 Cloudflare, 3 open ports (HTTP, HTTPS, DNS)", "Success", "badge-status-success",
                    "services/ip_network_intelligence/reports/ip_1.1.1.1.json",
                    (now - datetime.timedelta(minutes=36)).strftime("%Y-%m-%d %H:%M:%S")
                ),
                (
                    user_map["jordan"]["id"], "jordan", user_map["jordan"]["role"],
                    "phone_intelligence", "Phone Number Intelligence", "Libphonenumber Carrier Engine",
                    "+1 415-555-2671", 0.4, 1, "California, Fixed Line/VoIP", "Success", "badge-status-success",
                    "services/phone_intelligence/reports/report_14155552671_simple.json",
                    (now - datetime.timedelta(hours=3, minutes=22)).strftime("%Y-%m-%d %H:%M:%S")
                ),
                (
                    user_map["jordan"]["id"], "jordan", user_map["jordan"]["role"],
                    "email_intelligence", "Email Intelligence", "Mailbox Deliverability Engine",
                    "johndoe", 4.9, 11, "11 active mailboxes verified (Gmail, Proton, Outlook)", "Success", "badge-status-success",
                    "services/email_intelligence/reports/mailbox_johndoe.json",
                    (now - datetime.timedelta(hours=5, minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
                ),
                (
                    user_map["jordan"]["id"], "jordan", user_map["jordan"]["role"],
                    "domain_intelligence", "Domain & Website Intelligence", "Subdomain Discovery Engine",
                    "cloudflare.com", 8.2, 95, "95 subdomains & DNS records", "Success", "badge-status-success",
                    "services/domain_intelligence/reports/cloudflare.com.json",
                    (now - datetime.timedelta(hours=6, minutes=40)).strftime("%Y-%m-%d %H:%M:%S")
                ),

                # Admin's operational test runs
                (
                    user_map["admin"]["id"], "admin", user_map["admin"]["role"],
                    "recon_username", "Username Intelligence", "Maigret Platform Scanner",
                    "github", 5.2, 86, "86 platform profiles verified", "Success", "badge-status-success",
                    "services/recon_username/reports/report_github.json",
                    (now - datetime.timedelta(minutes=58)).strftime("%Y-%m-%d %H:%M:%S")
                ),
                (
                    user_map["admin"]["id"], "admin", user_map["admin"]["role"],
                    "ip_network_intelligence", "IP & Network Intelligence", "TLS SANs & Security Headers",
                    "9.9.9.9", 1.1, 2, "AS19281 Quad9, Valid TLS 1.3, HSTS pass", "Success", "badge-status-success",
                    "services/ip_network_intelligence/reports/ip_9.9.9.9.json",
                    (now - datetime.timedelta(hours=1, minutes=50)).strftime("%Y-%m-%d %H:%M:%S")
                ),
            ]

            cursor.executemany("""
                INSERT INTO service_executions (
                    user_id, username, user_role, service_id, service_name, tool_name,
                    target, duration_seconds, findings_count, findings_summary, status,
                    status_class, report_path, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, initial_executions)
            conn.commit()


# =============================================================================
# USER & ROLE MANAGEMENT FUNCTIONS
# =============================================================================

def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Retrieves user with joined role metadata."""
    init_db()
    clean_user = (username or "").strip().lower()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT u.id, u.username, u.password, u.display_name as displayName,
                   u.avatar, u.is_active, u.created_at, u.last_login,
                   r.id as role_id, r.name as role, r.display_name as role_display_name,
                   r.can_view_telemetry, r.can_manage_services
            FROM users u
            JOIN roles r ON u.role_id = r.id
            WHERE LOWER(u.username) = ? AND u.is_active = 1;
        """, (clean_user,))
        row = cursor.fetchone()
        if row:
            return dict(row)
    return None


def get_all_users_with_roles() -> List[Dict[str, Any]]:
    """Returns all registered users with their associated role data and execution counts."""
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT u.id, u.username, u.display_name, u.avatar, u.is_active,
                   u.created_at, u.last_login, r.name as role, r.display_name as role_title,
                   COUNT(e.id) as total_executions,
                   MAX(e.created_at) as last_execution_time
            FROM users u
            JOIN roles r ON u.role_id = r.id
            LEFT JOIN service_executions e ON u.id = e.user_id
            GROUP BY u.id
            ORDER BY r.id ASC, u.id ASC;
        """)
        return [dict(row) for row in cursor.fetchall()]


def update_user_last_login(username: str) -> None:
    """Updates user last_login timestamp."""
    clean_user = (username or "").strip().lower()
    now_iso = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db_connection() as conn:
        conn.execute("UPDATE users SET last_login = ? WHERE LOWER(username) = ?;", (now_iso, clean_user))
        conn.commit()


# =============================================================================
# EXECUTION & TEST HISTORY FUNCTIONS
# =============================================================================

def record_execution(
    username: str,
    service_id: str,
    service_name: str,
    tool_name: str,
    target: str,
    duration_seconds: float = 0.0,
    findings_count: int = 0,
    findings_summary: str = "",
    status: str = "Success",
    status_class: str = "badge-status-success",
    report_path: Optional[str] = None,
    metadata_json: Optional[str] = None
) -> int:
    """Records an intelligence scan execution tied to the authenticated user."""
    init_db()
    user = get_user_by_username(username)
    if not user:
        # Fallback to default user if unauthenticated background runner
        user_id = 1
        user_role = "admin"
        username_val = username or "system"
    else:
        user_id = user["id"]
        user_role = user["role"]
        username_val = user["username"]

    now_iso = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO service_executions (
                user_id, username, user_role, service_id, service_name, tool_name,
                target, duration_seconds, findings_count, findings_summary, status,
                status_class, report_path, metadata_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            user_id, username_val, user_role, service_id, service_name, tool_name,
            target, round(duration_seconds, 2), findings_count, findings_summary,
            status, status_class, report_path, metadata_json, now_iso
        ))
        conn.commit()
        return cursor.lastrowid


def get_service_history_for_user(
    service_id: str,
    username: Optional[str] = None,
    is_admin: bool = False,
    limit: int = 30
) -> List[Dict[str, Any]]:
    """
    Returns test history for a specific service.
    - If user is non-admin: filters strictly by their username/user_id.
    - If user is admin: returns system-wide executions with user attribution.
    """
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if not is_admin and username:
            cursor.execute("""
                SELECT e.*, u.display_name as user_display_name, u.avatar as user_avatar
                FROM service_executions e
                JOIN users u ON e.user_id = u.id
                WHERE e.service_id = ? AND LOWER(e.username) = ?
                ORDER BY e.created_at DESC
                LIMIT ?;
            """, (service_id, username.strip().lower(), limit))
        else:
            cursor.execute("""
                SELECT e.*, u.display_name as user_display_name, u.avatar as user_avatar
                FROM service_executions e
                JOIN users u ON e.user_id = u.id
                WHERE e.service_id = ?
                ORDER BY e.created_at DESC
                LIMIT ?;
            """, (service_id, limit))

        rows = cursor.fetchall()
        result = []
        for r in rows:
            item = dict(r)
            # Add normalized aliases for service frontend compatibility
            item["timestamp"] = item.get("created_at")
            item["count"] = item.get("findings_count", 0)
            item["total_findings"] = item.get("findings_count", 0)
            item["domain"] = item.get("target")
            item["duration"] = f"{item.get('duration_seconds', 0.0)}s"
            result.append(item)
        return result


# =============================================================================
# ADMIN DASHBOARD TELEMETRY & LIVE DATA MATRIX QUERIES
# =============================================================================

def get_admin_live_data_matrix() -> Dict[str, Any]:
    """
    Queries real relational execution data to power:
    1. Recent User Execution Log
    2. Tool Usage Distribution & Popularity Ranking
    3. Per-Service Health & Latency Metrics
    4. Aggregated Platform Health KPIs
    """
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # 1. Recent Executions across all users
        cursor.execute("""
            SELECT e.id, e.created_at as timestamp, e.username as user,
                   e.service_name as service, e.tool_name as tool, e.target,
                   e.duration_seconds, e.findings_summary as findings,
                   e.status, e.status_class, u.display_name as user_display_name,
                   u.avatar as user_avatar, r.name as role
            FROM service_executions e
            JOIN users u ON e.user_id = u.id
            JOIN roles r ON u.role_id = r.id
            ORDER BY e.created_at DESC
            LIMIT 15;
        """)
        raw_recent = cursor.fetchall()
        recent_executions = []
        for r in raw_recent:
            rec = dict(r)
            rec["duration"] = f"{rec.get('duration_seconds', 0.0)}s"
            rec["is_dummy"] = False
            recent_executions.append(rec)

        # 2. Total and Per-Service Execution Counts for Usage Ranking
        cursor.execute("SELECT COUNT(*) as total FROM service_executions;")
        total_runs = cursor.fetchone()["total"] or 1

        cursor.execute("""
            SELECT service_id, service_name, COUNT(*) as run_count,
                   AVG(duration_seconds) as avg_sec,
                   SUM(CASE WHEN status = 'Success' THEN 1 ELSE 0 END) as success_count
            FROM service_executions
            GROUP BY service_id
            ORDER BY run_count DESC;
        """)
        service_stats = cursor.fetchall()

        ranking_list = []
        service_metrics_map = {}
        for rank, s in enumerate(service_stats, start=1):
            s_id = s["service_id"]
            count = s["run_count"]
            share = round((count / total_runs) * 100, 1)
            avg_sec = s["avg_sec"] or 0.0
            avg_ms = int(avg_sec * 1000)
            success_count = s["success_count"]
            succ_pct = round((success_count / count) * 100, 1) if count > 0 else 100.0

            if rank == 1:
                tier = "Most Used"
            elif rank == 2:
                tier = "High Usage"
            elif rank <= 4:
                tier = "Moderate Usage"
            else:
                tier = "Specialized"

            ranking_list.append({
                "service_id": s_id,
                "service": s["service_name"],
                "share": share,
                "count": count,
                "rank": rank,
                "tier": tier,
                "is_dummy": False
            })

            service_metrics_map[s_id] = {
                "avg_latency": f"{avg_ms} ms" if avg_ms < 1000 else f"{round(avg_sec, 2)}s",
                "success_rate": f"{succ_pct}%",
                "run_count": count
            }

        # 3. Overall Platform Averages
        cursor.execute("""
            SELECT AVG(duration_seconds) as avg_duration,
                   SUM(CASE WHEN status = 'Success' THEN 1 ELSE 0 END) as total_success,
                   COUNT(*) as total_count
            FROM service_executions;
        """)
        agg = cursor.fetchone()
        avg_dur_ms = int((agg["avg_duration"] or 0.18) * 1000)
        overall_succ = agg["total_success"] or 0
        overall_cnt = agg["total_count"] or 1
        health_score = round((overall_succ / overall_cnt) * 100, 1)

        # 4. User activity summary
        cursor.execute("""
            SELECT r.name as role_name, COUNT(DISTINCT u.id) as user_count,
                   COUNT(e.id) as execution_count
            FROM roles r
            LEFT JOIN users u ON r.id = u.role_id
            LEFT JOIN service_executions e ON u.id = e.user_id
            GROUP BY r.id;
        """)
        role_stats = [dict(r) for r in cursor.fetchall()]

        return {
            "recent_executions": recent_executions,
            "usage_ranking": ranking_list,
            "service_metrics_map": service_metrics_map,
            "average_system_latency": f"{avg_dur_ms} ms",
            "overall_health_score": f"{health_score}%",
            "total_executions_count": overall_cnt,
            "role_stats": role_stats
        }

# Initialize on import
init_db()

