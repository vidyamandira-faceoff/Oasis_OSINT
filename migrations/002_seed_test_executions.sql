-- ==============================================================================
-- OASIS OSINT Platform — Database Migration 002
-- Seed Initial Investigation Test History for Multi-User Profiles & Admin Matrix
-- ==============================================================================

PRAGMA foreign_keys = ON;

-- Insert demonstration test runs for Alex, Sam, Jordan, and Admin if table is empty
INSERT OR IGNORE INTO service_executions (
    id, user_id, username, user_role, service_id, service_name, tool_name,
    target, duration_seconds, findings_count, findings_summary, status,
    status_class, report_path, created_at
) VALUES 
    -- Alex: Username Reconnaissance
    (1, 2, 'alex', 'user', 'recon_username', 'Username Intelligence', 'Maigret Async Engine',
     'octocat', 4.2, 128, '128 verified endpoints across public developer registries', 'Success',
     'badge-status-success', 'services/recon_username/reports/report_octocat.json',
     datetime('now', '-6 minutes')),

    -- Alex: Email Footprint
    (2, 2, 'alex', 'user', 'email_intelligence', 'Email Intelligence', 'Holehe 124 Platform Footprint',
     'test@gmail.com', 12.1, 24, '24 verified registered accounts identified', 'Success',
     'badge-status-success', 'services/email_intelligence/reports/email_test_at_gmail.com.json',
     datetime('now', '-42 minutes')),

    -- Alex: Domain Intelligence
    (3, 2, 'alex', 'user', 'domain_intelligence', 'Domain & Website Intelligence', 'Photon Surface Spider',
     'example.com', 5.6, 38, '38 routes & endpoints mapped', 'Success',
     'badge-status-success', 'services/domain_intelligence/reports/example.com.json',
     datetime('now', '-2 hours')),

    -- Sam: Domain & Website Spider
    (4, 3, 'sam', 'user', 'domain_intelligence', 'Domain & Website Intelligence', 'Photon Surface Spider',
     'https://example.com', 7.8, 56, '42 routes, 14 subdomains discovered', 'Success',
     'badge-status-success', 'services/domain_intelligence/reports/example_https.json',
     datetime('now', '-19 minutes')),

    -- Sam: Social Media Personnel
    (5, 3, 'sam', 'user', 'social_media_intelligence', 'Social Media Intelligence', 'LinkedIn Workforce Scanner',
     'google', 3.1, 15, '15 employee profiles, 3 synthesized emails', 'Success',
     'badge-status-success', 'services/social_media_intelligence/reports/linkedin_google.json',
     datetime('now', '-65 minutes')),

    -- Sam: IP & Network Perimeter
    (6, 3, 'sam', 'user', 'ip_network_intelligence', 'IP & Network Intelligence', 'Tactical Port & ASN Triage',
     '8.8.8.8', 1.8, 2, 'AS15169 Google LLC, 2 open ports (DNS, HTTPS)', 'Success',
     'badge-status-success', 'services/ip_network_intelligence/reports/ip_8.8.8.8.json',
     datetime('now', '-165 minutes')),

    -- Sam: Social Rate-Limit Mitigation
    (7, 3, 'sam', 'user', 'social_media_intelligence', 'Social Media Intelligence', 'X / Twitter Flash Engine',
     'target_profile_org', 9.4, 4, 'Rate-limit mitigated (cached response)', 'Mitigated',
     'badge-status-warning', 'services/social_media_intelligence/reports/twitter_target.json',
     datetime('now', '-210 minutes')),

    -- Jordan: IP Network BGP
    (8, 4, 'jordan', 'user', 'ip_network_intelligence', 'IP & Network Intelligence', 'BGP ASN & Port Triage',
     '1.1.1.1', 1.4, 3, 'AS13335 Cloudflare, 3 open ports (HTTP, HTTPS, DNS)', 'Success',
     'badge-status-success', 'services/ip_network_intelligence/reports/ip_1.1.1.1.json',
     datetime('now', '-36 minutes')),

    -- Jordan: Phone Intelligence
    (9, 4, 'jordan', 'user', 'phone_intelligence', 'Phone Number Intelligence', 'Libphonenumber Carrier Engine',
     '+1 415-555-2671', 0.4, 1, 'California, Fixed Line/VoIP (Valid carrier signature)', 'Success',
     'badge-status-success', 'services/phone_intelligence/reports/report_14155552671_simple.json',
     datetime('now', '-202 minutes')),

    -- Jordan: Mailbox Deliverability
    (10, 4, 'jordan', 'user', 'email_intelligence', 'Email Intelligence', 'Mailbox Deliverability Engine',
     'johndoe', 4.9, 11, '11 active mailboxes verified (Gmail, Proton, Outlook)', 'Success',
     'badge-status-success', 'services/email_intelligence/reports/mailbox_johndoe.json',
     datetime('now', '-310 minutes')),

    -- Admin: Username Registry Audit
    (11, 1, 'admin', 'admin', 'recon_username', 'Username Intelligence', 'Maigret Platform Scanner',
     'github', 5.2, 86, '86 platform profiles verified', 'Success',
     'badge-status-success', 'services/recon_username/reports/report_github.json',
     datetime('now', '-58 minutes')),

    -- Admin: IP & TLS Handshake
    (12, 1, 'admin', 'admin', 'ip_network_intelligence', 'IP & Network Intelligence', 'TLS SANs & Security Headers',
     '9.9.9.9', 1.1, 2, 'AS19281 Quad9, Valid TLS 1.3, HSTS pass', 'Success',
     'badge-status-success', 'services/ip_network_intelligence/reports/ip_9.9.9.9.json',
     datetime('now', '-110 minutes'));

