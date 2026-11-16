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
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Tuple, Optional

from core.logger import add_log

# Alphanumeric character pool for 8-digit OTP (Clean uppercase & numbers)
OTP_CHARSET = string.ascii_uppercase + string.digits


def generate_alphanumeric_otp(length: int = 8) -> str:
    """Generates a cryptographically strong 8-digit alphanumeric OTP."""
    return "".join(secrets.choice(OTP_CHARSET) for _ in range(length))


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

    # Check for SMTP configuration
    smtp_host = os.getenv("OASIS_SMTP_HOST") or os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("OASIS_SMTP_PORT") or os.getenv("SMTP_PORT") or 587)
    smtp_user = os.getenv("OASIS_SMTP_USER") or os.getenv("SMTP_USER")
    smtp_pass = os.getenv("OASIS_SMTP_PASS") or os.getenv("SMTP_PASS")
    smtp_from = os.getenv("OASIS_SMTP_FROM") or os.getenv("SMTP_FROM") or "auth@oasis.intelligence"
    use_ssl = os.getenv("OASIS_SMTP_SSL", "false").lower() in ("true", "1", "yes")

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
                with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10) as server:
                    server.login(smtp_user, smtp_pass)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                    server.starttls()
                    server.login(smtp_user, smtp_pass)
                    server.send_message(msg)
            
            sent_via_smtp = True
        except Exception as e:
            smtp_error = str(e)
            add_log("Mailer", f"SMTP delivery failed: {smtp_error}. Falling back to terminal log.", "warning")

    # Log to system audit trail
    log_msg = f"[AUTH OTP] {action_title} for {clean_email}: [{clean_code}] (Expires in {validity_minutes}m)"
    print(log_msg)
    add_log("SecurityGateway", log_msg, "info")

    # Add to internal notifications registry
    try:
        from core.notifications import add_recon_notification
        add_recon_notification(
            tool="Security Gateway",
            status="FINISHED",
            title=f"Verification OTP Generated",
            details=f"8-digit code issued for {clean_email} ({purpose}). Code: {clean_code} (Valid {validity_minutes}m).",
            target=clean_email,
            metrics=f"OTP: {clean_code} • {validity_minutes}m Expiry",
            action_url="/login",
            action_label="Login Box"
        )
    except Exception:
        pass

    if sent_via_smtp:
        return True, f"8-digit verification code has been dispatched to {clean_email}."
    else:
        return True, f"8-digit verification code generated for {clean_email}."

