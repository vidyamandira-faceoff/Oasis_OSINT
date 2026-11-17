#!/usr/bin/env python3
"""
OASIS Database Migration Manager
Applies versioned SQL migrations, manages schema state, and sets up developer databases.

Usage:
    python migrations/migrate.py               # Apply pending migrations
    python migrations/migrate.py --status      # Check migration and schema status
    python migrations/migrate.py --seed        # Ensure demonstration test data is seeded
    python migrations/migrate.py --reset       # Drop and recreate schema (clean dev start)
"""

import sys
import os
import argparse
import sqlite3
from pathlib import Path

# Resolve Base Directory
BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "oasis.sqlite3"
MIGRATIONS_DIR = Path(__file__).resolve().parent


def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_tracking_table(conn: sqlite3.Connection) -> None:
    """Creates schema_migrations table to track applied migration files."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()


def get_applied_migrations(conn: sqlite3.Connection) -> set:
    init_tracking_table(conn)
    cursor = conn.cursor()
    cursor.execute("SELECT version FROM schema_migrations;")
    return {row["version"] for row in cursor.fetchall()}


def run_migrations(db_path: Path = DB_PATH, include_seed: bool = True) -> int:
    """Discovers and applies all pending .sql migration scripts."""
    print(f"[*] OASIS Database Migration Tool")
    print(f"[*] Target SQLite Database: {db_path}")

    conn = get_connection(db_path)
    init_tracking_table(conn)
    applied = get_applied_migrations(conn)

    sql_files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    if not sql_files:
        print("[!] No .sql migration files found in migrations/ directory.")
        return 0

    applied_count = 0
    for file_path in sql_files:
        version = file_path.stem
        # If user explicitly disabled seed, skip 002
        if not include_seed and "seed" in version.lower():
            continue

        if version in applied:
            continue

        print(f" -> Applying migration: {file_path.name} ...", end=" ", flush=True)
        try:
            sql_content = file_path.read_text(encoding="utf-8")
            # If migration attempts to add an existing column, bypass duplicate column error
            if "ADD COLUMN" in sql_content:
                cur = conn.cursor()
                cur.execute("PRAGMA table_info(users);")
                existing_cols = {r["name"] for r in cur.fetchall()}
                filtered_lines = []
                for line in sql_content.splitlines():
                    if "ADD COLUMN" in line:
                        parts = line.strip().split()
                        col_idx = parts.index("COLUMN") + 1 if "COLUMN" in parts else -1
                        col_name = parts[col_idx] if col_idx != -1 and col_idx < len(parts) else ""
                        if col_name and col_name in existing_cols:
                            continue
                    filtered_lines.append(line)
                sql_content = "\n".join(filtered_lines)

            conn.executescript(sql_content)
            conn.execute(
                "INSERT INTO schema_migrations (version, filename) VALUES (?, ?);",
                (version, file_path.name)
            )
            conn.commit()
            print("[OK]")
            applied_count += 1
        except Exception as e:
            conn.rollback()
            print(f"[FAILED]\n[!] Error applying {file_path.name}: {e}")
            sys.exit(1)

    if applied_count == 0:
        print("[*] Database is already up-to-date. No pending migrations.")
    else:
        print(f"[✔] Successfully applied {applied_count} migration(s).")

    conn.close()
    return applied_count


def reset_database(db_path: Path = DB_PATH) -> None:
    """Drops all tables and re-applies all migrations."""
    print(f"[!] Warning: Resetting database at {db_path}...")
    conn = get_connection(db_path)
    cursor = conn.cursor()

    # Disable foreign keys during drop
    cursor.execute("PRAGMA foreign_keys = OFF;")
    cursor.execute("SELECT name, type FROM sqlite_master WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%';")
    items = cursor.fetchall()

    for item in items:
        name = item["name"]
        item_type = item["type"].upper()
        cursor.execute(f"DROP {item_type} IF EXISTS {name};")

    conn.commit()
    conn.close()
    print("[✔] Dropped all existing tables.")
    run_migrations(db_path=db_path, include_seed=True)


def print_status(db_path: Path = DB_PATH) -> None:
    """Prints current database health, tables, rows, and applied migrations."""
    print("=" * 60)
    print(f"  OASIS Database & Schema Status")
    print("=" * 60)
    print(f"Database File: {db_path}")
    print(f"File Exists:   {db_path.exists()} ({db_path.stat().st_size if db_path.exists() else 0} bytes)")

    if not db_path.exists():
        print("[!] Database file has not been created yet. Run `python migrations/migrate.py`.")
        return

    conn = get_connection(db_path)
    init_tracking_table(conn)
    applied = get_applied_migrations(conn)

    print("\nApplied Migrations:")
    all_files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    for f in all_files:
        status = "[Applied]" if f.stem in applied else "[Pending]"
        print(f"  {status:10} {f.name}")

    print("\nRelational Tables & Data Counts:")
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;")
    tables = [r["name"] for r in cursor.fetchall()]

    for t in tables:
        cursor.execute(f"SELECT COUNT(*) as cnt FROM {t};")
        cnt = cursor.fetchone()["cnt"]
        print(f"  - {t:<22} : {cnt:>5} records")

    print("\nRegistered Platform Accounts:")
    try:
        cursor.execute("""
            SELECT u.id, u.username, u.display_name, r.name as role,
                   (SELECT COUNT(*) FROM service_executions WHERE user_id = u.id) as executions
            FROM users u
            JOIN roles r ON u.role_id = r.id;
        """)
        for u in cursor.fetchall():
            print(f"  - @{u['username']:<10} | Role: {u['role']:<6} | Name: {u['display_name']:<8} | Runs: {u['executions']}")
    except Exception:
        pass

    print("=" * 60)
    conn.close()


def main():
    parser = argparse.ArgumentParser(description="OASIS Database Migration Tool")
    parser.add_argument("--up", action="store_true", help="Apply pending migrations (default)")
    parser.add_argument("--status", action="store_true", help="Display schema and table row counts")
    parser.add_argument("--reset", action="store_true", help="Drop and recreate all tables from scratch")
    parser.add_argument("--no-seed", action="store_true", help="Skip seeding demonstration test records")
    args = parser.parse_args()

    if args.status:
        print_status()
    elif args.reset:
        reset_database()
        print_status()
    else:
        run_migrations(include_seed=not args.no_seed)
        if not args.up:
            print_status()


if __name__ == "__main__":
    main()

