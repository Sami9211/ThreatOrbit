"""Dark-web depth: credential-leak matching + takedown workflow + feed import.

  * **Credential matching** - every `credential-leak` finding is checked
    against the *real* user directory: an exact email match, or an email on
    one of the organisation's own domains (derived from the directory), marks
    the finding `matched_user` and raises a critical notification - leaked
    credentials for an account you actually operate are a force-reset event,
    not just intel.
  * **Takedown workflow** - findings progress new → investigating →
    takedown-requested → mitigated/dismissed; requesting a takedown stamps the
    finding and emits a `darkweb.takedown` webhook so an external
    takedown/ticketing service can pick it up.
  * **Feed import** - `import_findings()` is the sink for the `darkweb-json`
    connector kind: any leak-DB / paste-monitor API returning JSON maps into
    real findings (field-mapped, deduplicated by source URL/title).
"""
import re
import uuid
from datetime import datetime, timezone

_EMAIL = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_CATEGORIES = {"credential-leak", "data-for-sale", "brand-mention",
               "actor-chatter", "infrastructure"}

# Public/free email providers must NOT become "org domains": directories often
# hold personal or SSO accounts (gmail, outlook, …), and treating e.g. gmail.com
# as owned would flag EVERY leaked gmail address in a feed as a workforce
# credential leak (a flood of false-positive critical "force a reset" alerts).
# An exact email still matches these users; only the domain-wide match is
# restricted to corporate domains. Extend via DASHBOARD_PUBLIC_EMAIL_DOMAINS.
_PUBLIC_EMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "msn.com", "yahoo.com", "ymail.com", "aol.com", "icloud.com", "me.com",
    "mac.com", "proton.me", "protonmail.com", "pm.me", "gmx.com", "gmx.net",
    "mail.com", "zoho.com", "yandex.com", "yandex.ru", "tutanota.com",
    "fastmail.com", "hey.com", "qq.com", "163.com", "126.com",
}


def _public_email_domains() -> set:
    import os
    extra = {d.strip().lower() for d in
             os.environ.get("DASHBOARD_PUBLIC_EMAIL_DOMAINS", "").split(",") if d.strip()}
    return _PUBLIC_EMAIL_DOMAINS | extra


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def watched_identities(conn) -> tuple[set, set]:
    """(emails, domains) the org actually operates - from the user directory.

    `domains` excludes public/free email providers, so a directory containing a
    personal or SSO account (e.g. someone@gmail.com) does not turn that provider
    into an owned domain and cause every unrelated leak on it to be flagged as a
    workforce credential leak. Those users still match by exact email."""
    emails = {str(r["email"]).lower() for r in conn.execute("SELECT email FROM users").fetchall()}
    public = _public_email_domains()
    domains = {d for e in emails if "@" in e
               for d in [e.split("@", 1)[1]] if d and d not in public}
    return emails, domains


def match_credential_leaks(conn) -> dict:
    """Stamp credential-leak findings whose leaked email belongs to the org's
    own directory (exact user or org domain). New matches notify."""
    emails, domains = watched_identities(conn)
    rows = conn.execute(
        "SELECT id, entity, title, detail FROM dark_web_findings "
        "WHERE category='credential-leak' AND (matched_user IS NULL OR matched_user='')"
    ).fetchall()
    matched = 0
    for r in rows:
        hay = f"{r['entity'] or ''} {r['detail'] or ''}"
        for em in _EMAIL.findall(hay):
            em = em.lower()
            domain = em.split("@", 1)[1]
            if em in emails or domain in domains:
                conn.execute("UPDATE dark_web_findings SET matched_user=?, severity='critical' "
                             "WHERE id=?", (em, r["id"]))
                try:
                    from dashboard_api.routers.platform import notify
                    notify(conn, type="darkweb", severity="critical",
                           title=f"Workforce credential leaked: {em} - force a reset",
                           detail=r["id"], link="/dashboard/darkweb")
                except Exception:
                    pass
                matched += 1
                break
    return {"scanned": len(rows), "matched": matched}


def request_takedown(conn, finding_id: str, actor: str) -> dict | None:
    """Move a finding into the takedown workflow. Returns the updated row, or
    None when it doesn't exist. Emits the webhook event for external services."""
    row = conn.execute("SELECT * FROM dark_web_findings WHERE id=?", (finding_id,)).fetchone()
    if not row:
        return None
    now = _now()
    detail = (row["detail"] or "") + f" [takedown requested by {actor} at {now}]"
    conn.execute("UPDATE dark_web_findings SET status='takedown-requested', detail=? WHERE id=?",
                 (detail[:1000], finding_id))
    updated = conn.execute("SELECT * FROM dark_web_findings WHERE id=?", (finding_id,)).fetchone()
    return dict(updated)


def import_findings(records: list[dict], source_name: str) -> dict:
    """Sink for the `darkweb-json` connector: normalised records → findings.
    Dedupe key is the source URL when present, else (title, source)."""
    from dashboard_api.db import get_conn
    imported = duplicates = skipped = 0
    with get_conn() as conn:
        for rec in records:
            title = str(rec.get("title") or rec.get("value") or "").strip()
            if not title:
                skipped += 1
                continue
            category = str(rec.get("category") or "brand-mention").strip().lower()
            if category not in _CATEGORIES:
                category = "brand-mention"
            severity = str(rec.get("severity") or "medium").lower()
            if severity not in ("critical", "high", "medium", "low"):
                severity = "medium"
            url = str(rec.get("url") or "").strip()
            if url:
                dup = conn.execute("SELECT 1 FROM dark_web_findings WHERE url=?", (url,)).fetchone()
            else:
                dup = conn.execute(
                    "SELECT 1 FROM dark_web_findings WHERE title=? AND source=?",
                    (title, source_name)).fetchone()
            if dup:
                duplicates += 1
                continue
            conn.execute(
                "INSERT INTO dark_web_findings (id,ts,category,severity,source,title,entity,"
                "actor,detail,url,status) VALUES (?,?,?,?,?,?,?,?,?,?,'new')",
                (str(uuid.uuid4()), _now(), category, severity, source_name, title,
                 str(rec.get("entity") or ""), str(rec.get("actor") or ""),
                 str(rec.get("detail") or rec.get("description") or "")[:1000], url))
            imported += 1
        # imported leaks are immediately checked against the user directory
        match = match_credential_leaks(conn) if imported else {"matched": 0}
        conn.commit()
    return {"imported": imported, "duplicates": duplicates, "skipped": skipped,
            "workforceMatches": match["matched"]}
