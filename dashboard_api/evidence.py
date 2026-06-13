"""Signed evidence bundles (audit & compliance pack).

Exports a case's full investigation record - the case itself, its evidence
items (each already carrying a per-item SHA-256 + chain-of-custody), the war
room, tasks, and the case's audit-log slice - as one canonical JSON document
signed with HMAC-SHA256. The signature makes the bundle *tamper-evident*:
any later change to a single byte of the content fails verification, which is
what "immutable" means for an export that has left the platform.

The signing key defaults to the platform secret and can be pinned with
`DASHBOARD_EVIDENCE_SECRET` so bundle verification can outlive JWT-secret
rotation. Verification is pure (canonical-JSON + HMAC) so an auditor with the
key can independently re-verify a bundle.
"""
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone

from dashboard_api.config import JWT_SECRET

EVIDENCE_SECRET = os.environ.get("DASHBOARD_EVIDENCE_SECRET", JWT_SECRET)


def canonical(doc: dict) -> bytes:
    """Deterministic byte serialisation: sorted keys, no whitespace."""
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sign_bundle(doc: dict) -> dict:
    """Wrap `doc` with its HMAC-SHA256 signature + content digest."""
    payload = canonical(doc)
    return {
        "bundle": doc,
        "signature": {
            "alg": "HMAC-SHA256",
            "value": hmac.new(EVIDENCE_SECRET.encode(), payload, hashlib.sha256).hexdigest(),
            "contentSha256": hashlib.sha256(payload).hexdigest(),
        },
    }


def verify_bundle(doc: dict, signature: str) -> bool:
    """True iff `signature` is the HMAC of the canonical form of `doc`."""
    expected = hmac.new(EVIDENCE_SECRET.encode(), canonical(doc), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def build_case_bundle(conn, case_row: dict, *, exported_by: str) -> dict:
    """Assemble the export document for a case (caller signs it)."""
    case_id = case_row["id"]
    audit_rows = conn.execute(
        "SELECT ts, actor, action, target, detail FROM audit_log WHERE target=? ORDER BY ts",
        (case_id,),
    ).fetchall()
    return {
        "kind": "threatorbit.case-evidence-bundle",
        "version": 1,
        "exportedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "exportedBy": exported_by,
        "case": case_row,
        "auditTrail": [dict(r) for r in audit_rows],
    }
