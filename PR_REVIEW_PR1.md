# Pull Request #1 Code Review: "New features and fixations"

**Repository:** `vidyamandira-faceoff/Oasis_OSINT`  
**PR Link:** [PR #1 — New features and fixations](https://github.com/vidyamandira-faceoff/Oasis_OSINT/pull/1)  
**Author:** `@Atig-Singh`  
**Reviewer:** Oasis OSINT Security & Architecture Review  
**Date:** November 17, 2026  
**Status:** ✅ **READY TO MERGE after second-round fixes** (see §5 and §6; the first-round “ready” verdict was premature)

---

## 1. Executive Summary

This pull request introduces an ambitious feature set to the Oasis OSINT platform:
- Authentication system with session cookies, JWT/HMAC tokens, sliding-window rate-limiting, and security response headers.
- Multi-user RBAC architecture separating **Admin** and **Standard User** roles.
- Modern landing page with interactive sign-in, user sign-up, and forgot password panels.
- SQLite-backed persistence layer with relational migrations (`roles`, `users`, `email_otps`, `service_executions`).
- Integration of the Photon web spider engine for domain reconnaissance.

While the design vision, UX direction, and authentication middleware are great additions, **this PR is NOT ready to merge in its current state**. It contains **two critical blockers** (a crashing database migration and plaintext password storage), **two high-severity data leakage vulnerabilities**, and a **severe maintenance liability** with over 25,000 lines of duplicated templates.

---

## 2. Review Verdict & Scorecard

| Category | Assessment | Impact |
| :--- | :---: | :--- |
| **Database Migrations** | 🔴 **CRITICAL** | Migration script fails and terminates with SQLite exception on clean installs |
| **Credential Security** | 🔴 **CRITICAL** | Passwords stored and verified in plaintext (no hashing) |
| **Secrets & OTP Leakage** | 🟠 **HIGH** | OTP verification codes leaked to system logs and notifications |
| **Documentation** | 🟠 **HIGH** | `OSINT_TOOLS_DOCUMENTATION.md` was inadvertently deleted |
| **Code Duplication** | 🟡 **MEDIUM-HIGH** | >25,000 lines of copy-pasted templates between Admin & User roles |
| **Repository Hygiene** | 🟡 **MEDIUM** | Entire third-party GitHub repository cloned into service directory |
| **UI / UX & Middleware** | 🟢 **GOOD** | Clean landing page UI, strict security headers, and token refresh flow |

---

## 3. Detailed Findings

### 🔴 Critical Issues (Must Fix Before Merge)

#### 1. SQL Migration 003 Fails on Clean Databases (`no such column: email`)
- **Location:** `migrations/003_add_user_email_and_otp.sql:24-27`
- **Issue:** Migration `001_initial_schema.sql` creates the `users` table without an `email` column:
  ```sql
  CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role_id INTEGER NOT NULL,
      ...
  );
  ```
  Migration `003_add_user_email_and_otp.sql` then attempts to execute:
  ```sql
  UPDATE users SET email = 'admin@oasis.live' WHERE username = 'admin' ...;
  ```
  without ever running `ALTER TABLE users ADD COLUMN email TEXT;`.
- **Result:** Running `python migrations/migrate.py` or `./oasis.sh` on a new installation immediately halts with:
  ```text
  [FAILED] Error applying 003_add_user_email_and_otp.sql: no such column: email
  ```
- **Fix:** Add the column migration to `migrations/003_add_user_email_and_otp.sql` prior to updating:
  ```sql
  ALTER TABLE users ADD COLUMN email TEXT;
  CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email);
  ```
  *(Or define `email TEXT UNIQUE` directly in `migrations/001_initial_schema.sql`).*

---

#### 2. Passwords Stored and Compared in Cleartext (No Cryptographic Hashing)
- **Locations:**
  - `core/database.py` (`init_db`, `create_user`, `update_user_password`)
  - `roles/accounts.py` (`ADMIN_ACCOUNT`, `SEED_USER_ACCOUNTS`, `authenticate_user`)
  - `migrations/001_initial_schema.sql:66-70`
- **Issue:**
  Passwords for both default accounts (`admin123`, `alex123`, `sam123`, `jordan123`) and newly created users (from the registration form) are stored directly as plain strings in SQLite.
  In `roles/accounts.py`:
  ```python
  expected_pass = db_user.get("password", "")
  if password and hmac.compare_digest(password, expected_pass):
      return db_user
  ```
  In `core/database.py`:
  ```python
  cursor.execute("""
      INSERT INTO users (username, email, password, role_id, display_name, ...)
      VALUES (?, ?, ?, ?, ?, ...);
  """, (clean_user, clean_email, password, role_id, clean_display, ...))
  ```
- **Impact:** Any database leak, unprivileged backup access, or compromised host allows immediate exposure of every user's credential.
- **Fix:**
  Use Python's built-in `hashlib.pbkdf2_hmac` (with a random salt) or `bcrypt` / `argon2` to hash passwords upon signup and password reset:
  ```python
  import hashlib
  import secrets

  def hash_password(password: str) -> str:
      salt = secrets.token_hex(16)
      key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100_000)
      return f"{salt}${key.hex()}"

  def verify_password(password: str, hashed: str) -> bool:
      try:
          salt, key = hashed.split("$")
          new_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100_000)
          return hmac.compare_digest(key, new_key.hex())
      except Exception:
          return False
  ```

---

### 🟠 High Severity Issues

#### 3. OTP Code Leaks to System Notifications & Application Logs
- **Location:** `core/mailer.py:118-138`
- **Issue:**
  When SMTP credentials are not configured (the default development environment), `send_email_otp()` logs the 8-digit OTP code to:
  1. `add_log("SecurityGateway", log_msg, "info")`
  2. `add_recon_notification(..., details=f"Code: {clean_code}...", metrics=f"OTP: {clean_code}...")`
- **Impact:** Because notifications and logs are visible across the platform, any user who can view notifications or logs can intercept OTP codes generated for other accounts (including the `admin` account during a password reset).
- **Fix:** In development fallback mode, log OTPs to server standard output only or mask the OTP in shared notification channels. Never broadcast verification codes to shared notification feeds.

#### 4. Account Objects with Passwords Passed to Template Context
- **Location:** `services/landing/backend/router.py:108-111`
- **Issue:**
  The landing page route passes `admin_account` and `seed_users` dictionaries (which contain the `"password"` field) into the Jinja2 template context:
  ```python
  "admin_account": ADMIN_ACCOUNT,
  "seed_users": list(SEED_USER_ACCOUNTS.values()),
  ```
- **Fix:** Strip the `password` field from any account dictionary before passing it to template contexts:
  ```python
  safe_admin = {k: v for k, v in ADMIN_ACCOUNT.items() if k != "password"}
  safe_users = [{k: v for k, v in u.items() if k != "password"} for u in SEED_USER_ACCOUNTS.values()]
  ```

#### 5. Deletion of OSINT Tools Documentation
- **Location:** `OSINT_TOOLS_DOCUMENTATION.md`
- **Issue:** The PR completely deleted `OSINT_TOOLS_DOCUMENTATION.md` (-288 lines), which contains the architecture, tool registry, and execution model documentation for the platform's 12 OSINT domains.
- **Fix:** Revert the deletion of `OSINT_TOOLS_DOCUMENTATION.md`.

---

### 🟡 Architectural & Code Quality Concerns

#### 6. Extreme Template Duplication (>25,000 Lines of Duplicated Code)
- **Locations:**
  - `roles/admin/templates/role_admin_*.html` (10 files, ~14,000 lines)
  - `roles/user/templates/role_user_*.html` (9 files, ~13,000 lines)
- **Issue:**
  The PR cloned every existing microservice HTML template twice (once for `role_admin_` and once for `role_user_`), with only minor diffs (e.g. `role_prefix` links and admin-only HUD blocks).
- **Maintenance Impact:** Any UI redesign, bug fix, or script update in any module will now require editing three separate templates (`services/<mod>/frontend/templates/`, `roles/admin/templates/`, `roles/user/templates/`).
- **Fix:**
  Reuse existing templates under `services/<mod>/frontend/templates/` with Jinja2 role conditionals:
  ```jinja2
  {% if is_admin %}
      {# Admin-only Controls & Telemetry #}
  {% endif %}
  ```
  Pass `is_admin`, `user_role`, and `role_prefix` through the standard template context rather than maintaining separate physical files.

#### 7. Vendor Directory Cloned Directly into Repository
- **Location:** `services/domain_intelligence/engine/`
- **Issue:**
  The author dumped an entire git clone of `s0md3v/Photon` directly into `services/domain_intelligence/engine/`, including Photon's `.travis.yml`, `.whitesource`, `.gitignore`, `Dockerfile`, `LICENSE.md`, and `README.md`.
- **Fix:**
  Clean up non-runtime assets (`.travis.yml`, `.whitesource`, `Dockerfile`, root `README.md`) or manage Photon as a standalone dependency / submodule, keeping only clean internal Python wrappers.

#### 8. Dual Database Schema Initialization Conflict
- **Locations:** `core/database.py:init_db()` vs `migrations/migrate.py`
- **Issue:**
  Both `core/database.py` and `migrations/migrate.py` contain table creation and seed scripts, but their schemas diverged (e.g. `init_db()` adds `email` while `001_initial_schema.sql` omits it).
- **Fix:** Standardize on one single source of truth: either let `migrate.py` manage the schema versions or have `init_db()` invoke the migration runner.

---

### 🟢 Strengths & Well-Executed Elements

1. **Security Response Headers:** Excellent defense-in-depth headers added in `server.py` (`X-Frame-Options`, `X-Content-Type-Options`, `Permissions-Policy`, anti-caching headers on protected routes).
2. **Brute Force Protection:** Sliding-window rate-limiting based on IP and username in `core/security.py`.
3. **In-Flight Task Detection:** `is_any_osint_scan_running()` intelligently prevents session auto-logout while long-running OSINT background scans are actively running.
4. **Parameterized SQL Queries:** Parameterized bindings (`?`, `?`) are used throughout `core/database.py`, protecting against SQL injection attacks.
5. **Modern Landing UI:** Great visual presentation, tabs, dark mode support, and clean aesthetic alignment.

---

## 4. Required Action Checklist Before Merge

- [x] **Fix Migration 003**: Added `ALTER TABLE users ADD COLUMN email TEXT;` and created unique index before `UPDATE users` statements; fortified `migrations/migrate.py` against duplicate column crashes. *(Resolved in commit `514c9ee`)*
- [x] **Hash Passwords with PBKDF2**: Implemented cryptographic PBKDF2-HMAC-SHA256 password hashing (100,000 iterations + 16-byte random salt) in `core/security.py`, `core/database.py`, and `roles/accounts.py`. Auto-migrates legacy plaintext passwords. *(Resolved in commit `514c9ee`)*
- [x] **Mask OTP Codes in Public Channels**: Masked OTP codes in telemetry logs and notifications in `core/mailer.py`. *(Resolved in commit `514c9ee`)*
- [x] **Sanitize Template Context & API Responses**: Stripped `"password"` keys from all template contexts and `/api/auth/` JSON responses in `services/landing/backend/router.py`. *(Resolved in commit `514c9ee`)*
- [x] **Restore Documentation**: Restored `OSINT_TOOLS_DOCUMENTATION.md` (288 lines). *(Resolved in commit `514c9ee`)*
- [x] **Clean Up Photon Dump**: Purged extraneous build and CI files (`.travis.yml`, `.whitesource`, `Dockerfile`, `MANIFEST.in`) from `services/domain_intelligence/engine/`. *(Resolved in commit `514c9ee`)*
- [ ] **Optional Template Deduplication**: Consider consolidating `roles/admin/templates/` and `roles/user/templates/` into modular Jinja2 components in a future refactor.

---

## 5. Resolution Status & Verdict After Fixes

**First-round status (commit `514c9ee`):** ❌ *Withdrawn.* The original findings were fixed, but re-testing the live auth flow uncovered two new critical issues (below), so the PR was not yet safe to merge.

---

## 6. Re-Review (Round 2) — New Findings & Resolution

| # | Severity | Finding | Resolution |
| :--- | :---: | :--- | :--- |
| 1 | 🔴 Critical | **Account takeover:** `/api/auth/signup/send-otp` and `/api/auth/forgot-password/send-otp` returned the OTP in the JSON response (`dev_otp`) unconditionally. Anyone knowing an email (e.g. `admin@oasis.live`) could reset the password and log in as admin — reproduced end-to-end. | `dev_otp` is returned only when `OASIS_DEV_MODE` is explicitly enabled **and** SMTP is not configured (`core/mailer.should_expose_dev_otp`). Full OTP is no longer printed to the console when SMTP delivery succeeded. |
| 2 | 🔴 Critical | **Default password could never be changed:** `authenticate_user` fell back to the hardcoded in-memory registry (`admin123`) whenever the DB check failed, so the old default still worked after a reset, and deactivated users could still log in. The login page also advertised `admin / admin123`. | In-memory registry is used **only** if the database layer cannot be imported. DB is the single source of truth; inactive users are rejected; refresh tokens of deactivated users no longer re-authenticate. Credential presets render only in dev mode. |
| 3 | 🟠 High | Password hash still leaked via signup response and role template contexts (`user_account`). | Public user getters no longer select `password`; a dedicated `get_user_credentials()` is used only for verification. `get_user`/`authenticate_user` return `strip_secrets()` copies. |
| 4 | 🟡 Medium | Migration `ADD COLUMN` workaround checked every statement against the `users` table only. | Replaced with a table-aware `ALTER TABLE <t> ADD COLUMN <c>` parser. |
| 5 | 🟡 Medium | `migrate.py` left seed passwords in plaintext; `init_db()` seeded users without emails. | `migrate.py` hashes plaintext passwords after migrating; `init_db()` seeds emails. |
| 6 | 🟡 Medium | Password reset did not invalidate existing sessions. | `update_user_password` revokes all tokens issued before the change (in-memory, consistent with the existing revocation list). |

**Also:** 17 regression tests added (`tests/test_auth_security.py`, run with `python -m unittest discover -s tests -v`) covering every item above; README documents `OASIS_DEV_MODE` / SMTP configuration, and broken `file:///home/...` links were fixed. All role pages smoke-tested (admin + user) with no credential material in output.

**Known limitations (non-blocking, follow-up):**
- Token revocation (logout & password-change) is in-memory and resets on server restart.
- Schema is still defined in both `init_db()` and `migrations/`; consolidate into one source of truth.
- Admin/User template duplication (~25k lines) — refactor into shared Jinja2 templates.
- Photon (`services/domain_intelligence/engine/`) is GPL-3.0; confirm licence compatibility.

**Final status:** ✅ **READY TO MERGE**

