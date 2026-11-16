# Oasis — Modular Reconnaissance & Scraping Platform

Oasis is a modular, multi-service Intelligence, Scraping & Reconnaissance Platform featuring 12 dedicated capability domains with background multi-tool execution engines:

### Social Media Intelligence & Scraping
1. **Instagram Scraping & Recon** (`social_instagram`): Profile metadata, follower networks, media harvesting, and relationship analysis.
2. **LinkedIn Scraping & Recon** (`social_linkedin`): Workforce mapping, company intelligence, executive hierarchies, and corporate research.
3. **X (Twitter) Scraping & Recon** (`social_x`): Timeline harvesting, handle analysis, tweet frequency, and sentiment tracking.
4. **Reddit Scraping & Recon** (`social_reddit`): Subreddit scraping, user dossiers, comment extraction, and community intelligence.

### Reconnaissance & Footprinting
5. **Website URL Search & Recon** (`recon_website_url`): Deep recursive endpoint crawling, REST API extraction, and exposed secret auditing.
6. **Web Browsers & Technology Recon** (`recon_web_browsers`): Headless browser auditing, technology stack fingerprinter, and DOM security inspection.
7. **Email Address Scraping & Recon** (`recon_email`): Mailbox existence verification, corporate email patterns, MX checks, and breach intelligence.
8. **IP Addresses Intelligence** (`recon_ip`): Geolocation lookups, ASN BGP prefixes, reverse DNS PTRs, and routing infrastructure.
9. **Username Intelligence** (`recon_username`): Multi-platform profile availability checks (100+ platforms) and alias correlation.
10. **Phone Number Recon** (`recon_phone`): Carrier lookup, MCC/MNC network identification, line type validation, and HLR queries.
11. **Hostname & Subdomain Recon** (`recon_subdomains`): High-speed DNS bruteforce enumeration, Certificate Transparency log extraction, and zone checks.
12. **Bitcoin & Crypto Addresses** (`recon_crypto`): Blockchain ledger tracking, balance telemetry, UTXO flows, and wallet risk profiling.

---

## Architecture Overview

The system is structured as a decoupled full-stack application following modern microservices principles:
- **Central Gateway (`server.py`)**: Runs on port 5050, orchestrating requests, routing dedicated service pages, and dispatching background multi-tool tasks.
- **Dedicated Service Pages**: Each service is accessible via its own distinct URL route:
  - `/dashboard` &rarr; Mission Briefing & HUD
  - `/vault` &rarr; Target Intelligence Repository
  - `/terminal` &rarr; Live Subprocess Console Stream
  - `/notifications` &rarr; Processing Notifications & Telemetry
  - `/settings` &rarr; Configuration & Environment Paths
  - `/services/social-instagram` &rarr; Instagram Scraping
  - `/services/social-linkedin` &rarr; LinkedIn Scraping
  - `/services/social-x` &rarr; X Scraping & Recon
  - `/services/social-reddit` &rarr; Reddit Scraping
  - `/services/recon-website-url` &rarr; Website URL Recon
  - `/services/recon-web-browsers` &rarr; Web Browsers & Stack
  - `/services/recon-email` &rarr; Email Address Recon
  - `/services/recon-ip` &rarr; IP Address Intelligence
  - `/services/recon-username` &rarr; Username Recon
  - `/services/recon-phone` &rarr; Phone Number Recon
  - `/services/recon-subdomains` &rarr; Hostname & Subdomains
  - `/services/recon-crypto` &rarr; Bitcoin & Crypto Addresses

---

## Database Setup & Migrations for Developers

OASIS uses a relational SQLite database (`oasis.sqlite3`) with foreign key constraints, tracking platform roles, investigator accounts, and multi-user service test histories.

### Automatic Setup
When a developer runs the setup script, the database migrations and default accounts are set up automatically:
```bash
./setup_linux.sh
```

### Manual Migration CLI Commands
Developers can manage and inspect their local database state using the migration CLI tool or master script:

```bash
# 1. Apply all pending migrations and seed default schema
./oasis.sh migrate
# or directly with Python:
python migrations/migrate.py --up

# 2. Check current database health, tables, row counts, and accounts
./oasis.sh migrate --status
# or directly:
python migrations/migrate.py --status

# 3. Clean development reset (drops and recreates all tables with seed data)
./oasis.sh migrate --reset
# or directly:
python migrations/migrate.py --reset
```

### Migration Files Reference
* [`migrations/001_initial_schema.sql`](file:///home/atig/Desktop/Oasis_OSINT/migrations/001_initial_schema.sql): DDL creating `roles`, `users`, `service_executions`, and indexes with default Admin and Analyst accounts.
* [`migrations/002_seed_test_executions.sql`](file:///home/atig/Desktop/Oasis_OSINT/migrations/002_seed_test_executions.sql): Realistic multi-user investigation test runs across all 6 intelligence suites.
* [`migrations/migrate.py`](file:///home/atig/Desktop/Oasis_OSINT/migrations/migrate.py): Standalone migration runner and schema manager.
