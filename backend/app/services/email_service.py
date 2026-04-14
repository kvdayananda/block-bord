"""
Block Bord AI — Email Service
Sends high-risk detection alerts via SMTP.
Falls back to structured logging if SMTP is not configured.
"""
import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger("blockbord.email")


def send_high_risk_alert(email: str, url: str, result: dict) -> None:
    """
    Sends a high-risk detection alert to the user's email address.
    Gracefully falls back to console log if SMTP is not configured.
    """
    smtp_host = os.getenv("SMTP_HOST", "")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASS", "")
    from_email = os.getenv("SMTP_FROM", smtp_user)

    reasons = result.get("reasons", [])
    risk_score = result.get("risk_score", "?")
    category = result.get("category", "Unknown")

    subject = "⚠️ [Block Bord AI] High Risk Site Detected"
    body = (
        f"Block Bord AI has flagged the following URL as HIGH RISK:\n\n"
        f"URL: {url}\n"
        f"Risk Score: {risk_score}/100\n"
        f"Category: {category}\n\n"
        f"Security Red Flags:\n"
        + "\n".join(f"  • {r}" for r in reasons[:5])
        + "\n\nStay safe!\nThe Block Bord AI Team"
    )

    if smtp_host and smtp_user and smtp_pass:
        try:
            msg = MIMEText(body)
            msg["Subject"] = subject
            msg["From"] = from_email
            msg["To"] = email
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.sendmail(from_email, [email], msg.as_string())
            logger.info(f"High-risk alert sent to {email} for {url}")
        except Exception as e:
            logger.error(f"Failed to send alert email to {email}: {e}")
    else:
        # Fallback: structured log (no SMTP configured)
        logger.warning(
            f"[No SMTP] HIGH RISK alert for {email} | URL: {url} | Score: {risk_score}/100"
        )
