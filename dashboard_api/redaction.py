"""Opt-in PII / secret redaction for stored raw log text.

Raw log lines routinely carry personal data (emails) and credential material
(passwords, tokens, API keys) that a SIEM has no need to persist verbatim.
When `DASHBOARD_LOG_REDACT` names one or more categories, `redact()` masks
them in the raw text at the ingest seam - BEFORE persistence - so the stored
copy never contains them. Off by default: redaction is lossy and irreversible,
so turning it on is a deliberate policy decision (docs/PII_HANDLING.md).

Categories (comma-separated in the env var):
  * ``email``  - the local part of email addresses is masked; the domain is
    kept because it carries the analytic value (phishing/typosquat pivots).
  * ``secret`` - values following credential-ish keys (password/token/api_key/
    authorization …) and AWS access-key ids are replaced outright. Secrets in
    logs are a liability regardless of privacy law.
  * ``cc``     - 13-19 digit sequences that pass the Luhn check (card numbers);
    Luhn keeps ordinary long numbers (timestamps, ids) intact.
  * ``ssn``    - US SSNs in their canonical dashed form.

Deliberately scoped to the RAW text only: structured pivot fields
(src_ip / username / hostname) are what detection correlates on and are
retained. Operators who must not store those either should minimise at the
log forwarder - see the policy doc.
"""
import re

CATEGORIES = ("email", "secret", "cc", "ssn")

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
# key [:=] (Bearer|Basic )? value  - the value is replaced, the key kept so the
# line stays diagnosable ("password=[REDACTED]" still tells the analyst what
# happened). Value charset stops at common log delimiters.
_SECRET = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|"
    r"access[_-]?key|authorization|auth)(\s*[:=]\s*)((?:Bearer|Basic)\s+)?"
    r"([^\s&,;\"']+)")
_AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_CC = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


def _enabled_categories() -> list[str]:
    from dashboard_api import config
    return [c for c in getattr(config, "LOG_REDACT", []) if c in CATEGORIES]


def enabled() -> bool:
    return bool(_enabled_categories())


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, d in enumerate(reversed(digits)):
        n = int(d)
        if i % 2 == 1:
            n = n * 2 - 9 if n * 2 > 9 else n * 2
        total += n
    return total % 10 == 0


def _redact_cc(m: re.Match) -> str:
    digits = re.sub(r"[ -]", "", m.group(0))
    if 13 <= len(digits) <= 19 and _luhn_ok(digits):
        return "[CC-REDACTED]"
    return m.group(0)   # long number, not a card - leave it alone


def redact(text: str | None, categories: list[str] | None = None) -> str | None:
    """Mask the configured categories in `text`. Returns the input unchanged
    when redaction is off (or `text` is empty) - safe to call unconditionally
    on the ingest path."""
    if not text:
        return text
    cats = categories if categories is not None else _enabled_categories()
    if not cats:
        return text
    if "secret" in cats:
        text = _SECRET.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", text)
        text = _AWS_KEY.sub("[AWS-KEY-REDACTED]", text)
    if "email" in cats:
        text = _EMAIL.sub(lambda m: f"[redacted]@{m.group(1)}", text)
    if "cc" in cats:
        text = _CC.sub(_redact_cc, text)
    if "ssn" in cats:
        text = _SSN.sub("[SSN-REDACTED]", text)
    return text
