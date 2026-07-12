"""
Block Bord AI — Email Service
Provides transactional email capabilities (password reset, email verification) and high‑risk alerts. Falls back to structured logging when SMTP is not configured.
"""

from backend.app.config import settings
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger("blockbord.email")


def _smtp_send(msg: MIMEMultipart, recipient: str) -> None:
    """Low‑level helper to send a MIME message via configured SMTP."""
    smtp_host = settings.smtp_host
    smtp_port = settings.smtp_port
    smtp_user = settings.smtp_user
    smtp_pass = settings.smtp_pass
    from_addr = settings.smtp_from_email or settings.smtp_from or smtp_user
    from_name = getattr(settings, "smtp_from_name", "Block Bord AI")
    if smtp_host and smtp_user and smtp_pass:
        try:
            msg["From"] = f"{from_name} <{from_addr}>"
            msg["To"] = recipient
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.sendmail(from_addr, [recipient], msg.as_string())
            logger.info(f"Email sent to {recipient}: {msg['Subject']}")
        except Exception as e:
            logger.error(f"Failed to send email to {recipient}: {e}")
    else:
        logger.warning(f"[No SMTP] Email to {recipient} not sent. Subject: {msg['Subject']}")


def send_email(recipient: str, subject: str, html_body: str, text_body: str | None = None) -> None:
    """Public helper to send an email.
    If both html_body and text_body are provided, a multipart alternative is sent.
    """
    if text_body is None:
        # Simple text email
        msg = MIMEText(html_body, "plain", "utf-8")
    else:
        msg = MIMEMultipart("alternative")
        msg.attach(MIMEText(text_body, "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))
    msg["Subject"] = subject
    _smtp_send(msg, recipient)


def send_password_reset_email(email: str, reset_link: str) -> None:
    """Send a password‑reset email with a single CTA link."""
    subject = "[Block Bord AI] Password Reset Request"
    text = (
        f"Hello,\n\n"
        f"We received a request to reset the password for your Block Bord AI account.\n"
        f"If you did not request this, you can safely ignore this email.\n\n"
        f"To reset your password, please click the link below (or paste it into your browser):\n"
        f"{reset_link}\n\n"
        f"This link will expire in 24 hours.\n\n"
        f"Best regards,\nBlock Bord AI Team"
    )
    send_email(email, subject, text)


def send_verification_email(email: str, verification_link: str) -> None:
    """Send an email verification message."""
    subject = "[Block Bord AI] Verify Your Email Address"
    text = (
        f"Welcome to Block Bord AI!\n\n"
        f"Please verify your email address by clicking the link below (or pasting it into your browser):\n"
        f"{verification_link}\n\n"
        f"This link will expire in 24 hours.\n\n"
        f"If you did not sign up for an account, you can ignore this email.\n\n"
        f"Regards,\nBlock Bord AI Team"
    )
    send_email(email, subject, text)


def send_high_risk_alert(email: str, url: str, result: dict) -> None:
    """Existing high‑risk alert function retained for compatibility."""
    # Re‑use the generic send_email for consistency
    subject = "⚠️ [Block Bord AI] High Risk Site Detected"
    reasons = result.get("reasons", [])
    risk_score = result.get("risk_score", "?")
    category = result.get("category", "Unknown")
    body = (
        f"Block Bord AI has flagged the following URL as HIGH RISK:\n\n"
        f"URL: {url}\n"
        f"Risk Score: {risk_score}/100\n"
        f"Category: {category}\n\n"
        f"Security Red Flags:\n"
        + "\n".join(f"  • {r}" for r in reasons[:5])
        + "\n\nStay safe!\nThe Block Bord AI Team"
    )
    # Use plain‑text email
    send_email(email, subject, body)
