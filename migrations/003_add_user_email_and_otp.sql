-- ==============================================================================
-- OASIS OSINT Platform — Database Migration 003
-- Add User Email and OTP Verification Registry
-- Target: SQLite 3.x
-- ==============================================================================

PRAGMA foreign_keys = ON;

-- 1. Create email_otps table for email verification & password recovery
CREATE TABLE IF NOT EXISTS email_otps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    otp_code TEXT NOT NULL,
    purpose TEXT NOT NULL, -- 'signup' or 'forgot_password'
    expires_at TIMESTAMP NOT NULL,
    verified INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_email_otps_email ON email_otps(email);
CREATE INDEX IF NOT EXISTS idx_email_otps_code ON email_otps(otp_code);
CREATE INDEX IF NOT EXISTS idx_email_otps_purpose ON email_otps(purpose);

-- 2. Update existing seeded users with canonical email addresses if null
UPDATE users SET email = 'admin@oasis.live' WHERE username = 'admin' AND (email IS NULL OR email = '');
UPDATE users SET email = 'alex@oasis.live' WHERE username = 'alex' AND (email IS NULL OR email = '');
UPDATE users SET email = 'sam@oasis.live' WHERE username = 'sam' AND (email IS NULL OR email = '');
UPDATE users SET email = 'jordan@oasis.live' WHERE username = 'jordan' AND (email IS NULL OR email = '');

