"""
OASIS Email & OTP Verification Gateway
Manages cryptographic 8-digit alphanumeric OTP generation, 5-minute expiration windows,
SMTP email dispatch, and simulated development fallbacks.
"""

import os
import smtplib
import secrets
import string
import time
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Tuple, Optional
from dotenv import load_dotenv

from core.logger import add_log

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

# Alphanumeric character pool for 8-digit OTP (Clean uppercase & numbers)
OTP_CHARSET = string.ascii_uppercase + string.digits


def generate_alphanumeric_otp(length: int = 8) -> str:
    """Generates a cryptographically strong 8-digit alphanumeric OTP."""
    return "".join(secrets.choice(OTP_CHARSET) for _ in range(length))


def get_app_environment() -> str:
    """
    Returns 'development' or 'production'.
    Defaults to 'production' for safety unless explicitly marked as development.
    """
    raw = (os.getenv("OASIS_ENV") or os.getenv("APP_ENV") or os.getenv("ENVIRONMENT") or "").strip().lower()
    if raw in ("development", "dev", "local", "staging", "test", "testing"):
        return "development"
    if raw in ("production", "prod", "live"):
        return "production"
    from core.security import is_dev_mode
    if is_dev_mode():
        return "development"
    return "production"


def get_smtp_config() -> dict:
    """
    Resolves SMTP credentials dynamically according to the active environment:
    - In production: Uses production credentials (admin@foai.site / PROD_SMTP_*)
    - In development: Uses development credentials (faceoffonboarding@gmail.com / DEV_SMTP_*)
    Generic SMTP_* and OASIS_SMTP_* environment variables act as overrides.
    """
    env = get_app_environment()
    prefix = "PROD_SMTP_" if env == "production" else "DEV_SMTP_"

    # 1. Environment-specific keys (e.g. PROD_SMTP_USER or DEV_SMTP_USER)
    host = os.getenv(f"{prefix}HOST")
    port_str = os.getenv(f"{prefix}PORT")
    user = os.getenv(f"{prefix}USER")
    pwd = os.getenv(f"{prefix}PASSWORD") or os.getenv(f"{prefix}PASS")
    from_email = os.getenv(f"{prefix}FROM_EMAIL") or os.getenv(f"{prefix}FROM")

    # 2. General / standard SMTP environment variables
    host = host or os.getenv("OASIS_SMTP_HOST") or os.getenv("SMTP_HOST")
    port_str = port_str or os.getenv("OASIS_SMTP_PORT") or os.getenv("SMTP_PORT") or "587"
    user = user or os.getenv("OASIS_SMTP_USER") or os.getenv("SMTP_USER")
    pwd = pwd or os.getenv("OASIS_SMTP_PASS") or os.getenv("SMTP_PASS") or os.getenv("SMTP_PASSWORD")
    from_email = from_email or os.getenv("OASIS_SMTP_FROM") or os.getenv("SMTP_FROM") or os.getenv("SMTP_FROM_EMAIL")

    ssl_val = os.getenv(f"{prefix}SSL") or os.getenv("OASIS_SMTP_SSL") or os.getenv("SMTP_SSL") or "false"
    use_ssl = ssl_val.strip().lower() in ("true", "1", "yes")

    try:
        port = int(port_str)
    except (ValueError, TypeError):
        port = 587

    host = (host or "").strip()
    user = (user or "").strip()
    pwd = (pwd or "").strip()
    from_email = (from_email or "").strip() or user

    # Normalize Google App Password spaces if present
    if pwd and (("gmail.com" in host.lower()) or len(pwd.replace(" ", "")) == 16):
        pwd = pwd.replace(" ", "")

    return {
        "env": env,
        "host": host,
        "port": port,
        "user": user,
        "password": pwd,
        "from_email": from_email,
        "use_ssl": use_ssl,
    }


def is_smtp_configured() -> bool:
    """True when SMTP host and credentials are present for the active environment."""
    cfg = get_smtp_config()
    return bool(cfg.get("host") and cfg.get("user") and cfg.get("password"))


def should_expose_dev_otp() -> bool:
    """
    The OTP may be echoed back to the browser ONLY for local development:
    OASIS_DEV_MODE must be explicitly enabled AND no real mail transport may be
    configured. Returning the OTP otherwise lets anyone who knows an email
    address bypass verification and take over the account.
    """
    from core.security import is_dev_mode
    return is_dev_mode() and not is_smtp_configured()


def send_email_otp(
    recipient_email: str,
    otp_code: str,
    purpose: str = "signup",
    validity_minutes: int = 5
) -> Tuple[bool, str]:
    """
    Dispatches an 8-digit alphanumeric OTP to the recipient email.
    If SMTP server credentials are configured in the environment, delivers via real SMTP.
    Otherwise, logs to system telemetry, console, and internal notification channels.
    """
    clean_email = (recipient_email or "").strip().lower()
    clean_code = (otp_code or "").strip().upper()
    
    action_title = "Account Registration Verification" if purpose == "signup" else "Passkey Recovery Verification"
    action_desc = (
        "complete your station analyst registration" if purpose == "signup" 
        else "authorize a passkey reset for your account"
    )

    # Resolve active SMTP configuration
    smtp_cfg = get_smtp_config()
    smtp_host = smtp_cfg["host"]
    smtp_port = smtp_cfg["port"]
    smtp_user = smtp_cfg["user"]
    smtp_pass = smtp_cfg["password"]
    smtp_from = smtp_cfg["from_email"] or "auth@oasis.intelligence"
    use_ssl = smtp_cfg["use_ssl"]

    sent_via_smtp = False
    smtp_error = ""

    if smtp_host and smtp_user and smtp_pass:
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[{clean_code}] OASIS Station Security — {action_title}"
            msg["From"] = f"OASIS Intelligence Station <{smtp_from}>"
            msg["To"] = clean_email

            text_content = (
                f"OASIS Tactical Intelligence Terminal\n\n"
                f"Your 8-digit security verification code is: {clean_code}\n\n"
                f"This single-use code is valid for exactly {validity_minutes} minutes to {action_desc}.\n"
                f"If you did not request this verification, please disregard this transmission.\n"
            )

            html_content = f"""
            <div style="background-color: #0b0f19; color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 40px 20px; border-radius: 8px; max-width: 560px; margin: 0 auto; border: 1px solid #1e293b;">
                <div style="border-bottom: 1px solid #1e293b; padding-bottom: 16px; margin-bottom: 24px; display: flex; align-items: center; gap: 10px;">
                    <span style="display: inline-block; width: 10px; height: 10px; border-radius: 50%; background-color: #ea580c;"></span>
                    <span style="font-weight: 800; font-size: 18px; letter-spacing: 0.05em; color: #f97316;">OASIS STATION SECURITY</span>
                </div>
                <h2 style="font-size: 20px; color: #ffffff; margin-top: 0;">{action_title}</h2>
                <p style="color: #94a3b8; font-size: 14px; line-height: 1.6;">
                    A request was received to {action_desc} for email <strong style="color: #cbd5e1;">{clean_email}</strong>.
                    Enter the following 8-digit verification code into the station prompt:
                </p>
                <div style="background: #111827; border: 1px solid #334155; border-radius: 8px; padding: 20px; text-align: center; margin: 28px 0;">
                    <span style="font-family: 'JetBrains Mono', monospace, Consolas, Courier; font-size: 32px; font-weight: 700; letter-spacing: 6px; color: #38bdf8;">
                        {clean_code}
                    </span>
                    <div style="margin-top: 8px; font-size: 12px; color: #64748b;">
                        Valid for {validity_minutes} minutes &bull; Single-use security token
                    </div>
                </div>
                <p style="font-size: 12px; color: #64748b; line-height: 1.5; margin-top: 24px; border-top: 1px solid #1e293b; padding-top: 16px;">
                    Department of Computer Science &amp; Engineering &bull; Ramakrishna Mission Vidyamandira<br>
                    Autonomous OSINT Strategic Terminal Transmission.
                </p>
            </div>
            """

            msg.attach(MIMEText(text_content, "plain"))
            msg.attach(MIMEText(html_content, "html"))

            if use_ssl or smtp_port == 465:
                with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=15) as server:
                    server.login(smtp_user, smtp_pass)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
                    server.ehlo()
                    server.starttls()
                    server.ehlo()
                    server.login(smtp_user, smtp_pass)
                    server.send_message(msg)
            
            sent_via_smtp = True
        except Exception as e:
            smtp_error = str(e)
            add_log("Mailer", f"SMTP delivery failed: {smtp_error}. Falling back to terminal log.", "warning")

    # Log to system audit trail
    masked_code = clean_code[:2] + "••••" + clean_code[-2:]
    # Full code goes to the local console only when no email was delivered
    # (development without SMTP); otherwise only the masked form is printed.
    console_code = masked_code if sent_via_smtp else clean_code
    print(f"[AUTH OTP] {action_title} for {clean_email}: [{console_code}] (Expires in {validity_minutes}m)")
    add_log("SecurityGateway", f"[AUTH OTP] {action_title} for {clean_email} ({masked_code}, expires in {validity_minutes}m)", "info")

    # Add sanitized notification to internal registry without exposing plain OTP
    try:
        from core.notifications import add_recon_notification
        add_recon_notification(
            tool="Security Gateway",
            status="FINISHED",
            title=f"Verification OTP Generated",
            details=f"Single-use verification code generated for {clean_email} ({purpose}). Valid for {validity_minutes} minutes.",
            target=clean_email,
            metrics=f"{masked_code} • {validity_minutes}m Expiry",
            action_url="/login",
            action_label="Login Box"
        )
    except Exception:
        pass

    if sent_via_smtp:
        return True, f"8-digit verification code has been dispatched to {clean_email}."
    else:
        return True, f"8-digit verification code generated for {clean_email}."

