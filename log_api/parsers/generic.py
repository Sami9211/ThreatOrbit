import json
import re
import logging
from datetime import datetime, timezone
from typing import List, Tuple, Dict, Any
from log_api.models import ParsedLogEntry

logger = logging.getLogger(__name__)

KV_RE = re.compile(r'(\w+)=(?:"([^"]*?)"|(\S+))')
IP_RE = re.compile(r'\b((?:\d{1,3}\.){3}\d{1,3})\b')
LEVEL_RE = re.compile(r'\b(DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|CRITICAL|FATAL|ALERT|EMERG)\b', re.I)
HTTP_RE = re.compile(r'\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(/\S*)', re.I)
STATUS_RE = re.compile(r'\bstatus[\s=:]+(\d{3})\b', re.I)


def parse_generic(lines: List[str]) -> Tuple[List[ParsedLogEntry], int]:
    entries: List[ParsedLogEntry] = []
    errors = 0

    for raw in lines:
        raw = raw.rstrip()
        if not raw:
            continue

        if raw.lstrip().startswith("{"):
            try:
                obj = json.loads(raw)
                entries.append(_from_json(obj, raw))
                continue
            except json.JSONDecodeError as e:
                logger.debug("Failed to parse line as JSON, falling back to KV/plaintext: %s", e)

        kv = _extract_kv(raw)
        if len(kv) >= 2:
            entries.append(_from_kv(kv, raw))
            continue

        entries.append(_from_plaintext(raw))

    return entries, errors


def _from_json(obj: Dict[str, Any], raw: str) -> ParsedLogEntry:
    ts = _parse_ts(obj.get("timestamp") or obj.get("@timestamp") or obj.get("time"))
    source_ip = obj.get("source_ip") or obj.get("src") or obj.get("ip")
    username = obj.get("username") or obj.get("user")
    message = obj.get("message") or obj.get("msg") or raw[:200]

    return ParsedLogEntry(
        raw=raw,
        log_format="generic",
        timestamp=ts,
        source_ip=str(source_ip) if source_ip else None,
        username=str(username) if username else None,
        http_method=obj.get("http_method") or obj.get("method"),
        http_path=obj.get("http_path") or obj.get("path"),
        http_status=_to_int(obj.get("status") or obj.get("http_status")),
        bytes_sent=_to_int(obj.get("bytes") or obj.get("bytes_sent")),
        user_agent=obj.get("user_agent") or obj.get("ua"),
        message=str(message),
        log_level=str(obj.get("level", "INFO")).upper(),
        extra={k: v for k, v in obj.items() if k not in {"timestamp", "@timestamp", "time"}},
    )


def _from_kv(kv: Dict[str, str], raw: str) -> ParsedLogEntry:
    lower = {k.lower(): v for k, v in kv.items()}
    return ParsedLogEntry(
        raw=raw,
        log_format="generic",
        timestamp=_parse_ts(lower.get("timestamp") or lower.get("time")),
        source_ip=lower.get("src") or lower.get("source_ip") or lower.get("ip"),
        username=lower.get("user") or lower.get("username"),
        http_method=lower.get("method"),
        http_path=lower.get("path") or lower.get("uri"),
        http_status=_to_int(lower.get("status")),
        bytes_sent=_to_int(lower.get("bytes")),
        user_agent=lower.get("user_agent") or lower.get("ua"),
        message=lower.get("msg") or lower.get("message") or raw[:200],
        log_level=str(lower.get("level", "INFO")).upper(),
        extra=lower,
    )


def _from_plaintext(raw: str) -> ParsedLogEntry:
    ip = None
    m = IP_RE.search(raw)
    if m:
        ip = m.group(1)

    level = "INFO"
    lm = LEVEL_RE.search(raw)
    if lm:
        level = lm.group(1).upper()

    hm = HTTP_RE.search(raw)
    method = hm.group(1) if hm else None
    path = hm.group(2) if hm else None

    sm = STATUS_RE.search(raw)
    status = int(sm.group(1)) if sm else None

    return ParsedLogEntry(
        raw=raw,
        log_format="generic",
        source_ip=ip,
        log_level=level,
        http_method=method,
        http_path=path,
        http_status=status,
        message=raw[:500],
    )


def _extract_kv(text: str) -> Dict[str, str]:
    return {m.group(1): (m.group(2) if m.group(2) is not None else m.group(3)) for m in KV_RE.finditer(text)}


def _parse_ts(val: Any) -> datetime | None:
    if not val:
        return None
    s = str(val).strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(s[:26], fmt)
            return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def _to_int(val: Any) -> int | None:
    try:
        return int(val)
    except Exception:
        return None
