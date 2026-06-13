"""Email delivery channel - real SMTP when configured, honest no-op otherwise.

Scheduled reports and critical notifications can be delivered by email. Rather
than ship a fake "email sent" toast, this performs a real SMTP send when the
deployment provides SMTP settings, and reports `sent: false, reason:
not-configured` when it doesn't - the same honest seam as the enrichment /
integration adapters. Never raises (a mail failure must not break a request or
the engine tick).

Configure with env: SMTP_HOST, SMTP_PORT (587), SMTP_USER, SMTP_PASSWORD,
SMTP_FROM, SMTP_TLS (true).
"""
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def _cfg() -> dict:
    return {
        "host": os.environ.get("SMTP_HOST", ""),
        "port": int(os.environ.get("SMTP_PORT", "587") or "587"),
        "user": os.environ.get("SMTP_USER", ""),
        "password": os.environ.get("SMTP_PASSWORD", ""),
        "sender": os.environ.get("SMTP_FROM", os.environ.get("SMTP_USER", "")
                                  or "threatorbit@localhost"),
        "tls": os.environ.get("SMTP_TLS", "true").lower() != "false",
    }


def configured() -> bool:
    return bool(_cfg()["host"])


def status() -> dict:
    c = _cfg()
    return {"configured": bool(c["host"]), "host": c["host"] or None,
            "port": c["port"], "from": c["sender"] if c["host"] else None}


def send_email(to: str | list[str], subject: str, html: str, *, text: str | None = None) -> dict:
    """Send an email via SMTP when configured. Returns {sent, ...}; never raises."""
    recipients = [to] if isinstance(to, str) else list(to)
    recipients = [r.strip() for r in recipients if r and r.strip()]
    if not recipients:
        return {"sent": False, "reason": "no recipient"}
    c = _cfg()
    if not c["host"]:
        return {"sent": False, "reason": "SMTP not configured (set SMTP_HOST)"}
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = c["sender"]
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(text or "See the HTML version of this report.", "plain"))
    msg.attach(MIMEText(html, "html"))
    try:
        server = smtplib.SMTP(c["host"], c["port"], timeout=10)
        try:
            if c["tls"]:
                server.starttls()
            if c["user"]:
                server.login(c["user"], c["password"])
            server.sendmail(c["sender"], recipients, msg.as_string())
        finally:
            server.quit()
        return {"sent": True, "recipients": recipients}
    except Exception as e:  # SMTP/network failure - recorded, never crashes
        return {"sent": False, "reason": f"SMTP send failed: {str(e)[:160]}"}
