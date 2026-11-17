-- ==============================================================================
-- OASIS OSINT Platform — Database Migration 001
-- Initial Relational Schema: Roles, Users, and Service Executions
-- Target: SQLite 3.x (with Foreign Key constraints)
-- ==============================================================================

PRAGMA foreign_keys = ON;

-- ------------------------------------------------------------------------------
-- 1. Roles Table
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    description TEXT,
    can_view_telemetry INTEGER DEFAULT 0,
    can_manage_services INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ------------------------------------------------------------------------------
-- 2. Users Table
-- ------------------------------------------------------------------------------
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

-- ------------------------------------------------------------------------------
-- 3. Service Executions / Investigation Test History Table
-- ------------------------------------------------------------------------------
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

-- ------------------------------------------------------------------------------
-- 4. High-Performance Indices
-- ------------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_role_id ON users(role_id);
CREATE INDEX IF NOT EXISTS idx_executions_user_id ON service_executions(user_id);
CREATE INDEX IF NOT EXISTS idx_executions_service_id ON service_executions(service_id);
CREATE INDEX IF NOT EXISTS idx_executions_created_at ON service_executions(created_at);

-- ------------------------------------------------------------------------------
-- 5. Seed Default Roles
-- ------------------------------------------------------------------------------
INSERT OR IGNORE INTO roles (id, name, display_name, description, can_view_telemetry, can_manage_services)
VALUES 
    (1, 'admin', 'Administrator', 'Full operational authority, live telemetry, security controls, and multi-user audit access', 1, 1),
    (2, 'user', 'Intelligence Analyst', 'Standard intelligence investigation, search execution, and dossier export authority', 0, 0);

-- ------------------------------------------------------------------------------
-- 6. Seed Default Platform Accounts
-- ------------------------------------------------------------------------------
INSERT OR IGNORE INTO users (id, username, password, role_id, display_name, avatar, is_active)
VALUES 
    (1, 'admin', 'admin123', 1, 'Admin', 'A', 1),
    (2, 'alex', 'alex123', 2, 'Alex', 'A', 1),
    (3, 'sam', 'sam123', 2, 'Sam', 'S', 1),
    (4, 'jordan', 'jordan123', 2, 'Jordan', 'J', 1);

