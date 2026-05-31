import json
import logging
from datetime import datetime, timezone
from typing import List, Tuple, Dict, Any
from log_api.models import ParsedLogEntry

logger = logging.getLogger(__name__)

EVENT_ID_MAP: Dict[str, str] = {
    "4624": "Successful Logon",
    "4625": "Failed Logon",
    "4648": "Logon with Explicit Credentials",
    "4672": "Special Privileges Assigned to New Logon",
    "4688": "Process Created",
    "4698": "Scheduled Task Created",
    "4719": "System Audit Policy Changed",
    "4720": "User Account Created",
    "4726": "User Account Deleted",
    "4732": "Member Added to Security-Enabled Local Group",
    "4740": "User Account Locked Out",
    "7045": "New Service Installed",
    "1102": "Audit Log Cleared",
}


def parse_windows_event(lines: List[str]) -> Tuple[List[ParsedLogEntry], int]:
    entries: List[ParsedLogEntry] = []
    errors = 0

    joined = "\n".join(lines).strip()
    if joined.startswith("["):
        try:
            records = json.loads(joined)
            for record in records:
                e = _parse_record(record)
                if e:
                    entries.append(e)
                else:
                    errors += 1
            return entries, errors
        except json.JSONDecodeError as e:
            logger.debug("Windows Event log is not a JSON array, falling back to line-by-line: %s", e)

    for raw in lines:
        raw = raw.rstrip()
        if not raw:
            continue
        try:
            record = json.loads(raw)
            e = _parse_record(record, raw_line=raw)
            if e:
                entries.append(e)
            else:
                errors += 1
        except json.JSONDecodeError:
            errors += 1
            entries.append(ParsedLogEntry(raw=raw, log_format="windows_event", message=raw))

    return entries, errors


def _parse_record(record: Dict[str, Any], raw_line: str = "") -> ParsedLogEntry | None:
    if not isinstance(record, dict):
        return None

    raw = raw_line or json.dumps(record)
    event_data = record.get("EventData") or record.get("event_data") or {}
    system = record.get("System") or {}
    event_id = str(record.get("EventID") or record.get("event_id") or system.get("EventID") or "")

    ts = _parse_ts(
        record.get("TimeCreated")
        or record.get("timestamp")
        or record.get("@timestamp")
        or system.get("TimeCreated", {}).get("#attributes", {}).get("SystemTime", "")
    )

    username = (
        event_data.get("SubjectUserName")
        or event_data.get("TargetUserName")
        or record.get("username")
        or system.get("Security", {}).get("UserID")
    )

    source_ip = event_data.get("IpAddress") or event_data.get("WorkstationName") or record.get("source_ip")
    if source_ip in ("-", "::1", "127.0.0.1"):
        source_ip = None

    hostname = system.get("Computer") or record.get("Computer") or record.get("hostname")
    process_name = event_data.get("NewProcessName") or event_data.get("ProcessName")

    level_map = {"0": "INFO", "1": "CRITICAL", "2": "ERROR", "3": "WARNING", "4": "INFO", "5": "DEBUG"}
    level = level_map.get(str(system.get("Level", "4")), "INFO")

    description = EVENT_ID_MAP.get(event_id, f"Event {event_id}")

    return ParsedLogEntry(
        raw=raw,
        log_format="windows_event",
        timestamp=ts,
        source_ip=source_ip,
        username=_clean(username),
        hostname=hostname,
        event_id=event_id,
        log_level=level,
        message=description,
        process=process_name,
        extra={
            "command_line": event_data.get("CommandLine"),
            "target_user": event_data.get("TargetUserName"),
            "subject_user": event_data.get("SubjectUserName"),
        },
    )


def _parse_ts(ts_val: Any) -> datetime | None:
    if not ts_val:
        return None
    ts_str = str(ts_val)
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(ts_str[:26], fmt)
            return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
        except ValueError:
            continue
    return None


def _clean(val: Any) -> str | None:
    if val is None:
        return None
    s = str(val).strip()
    return None if s in ("-", "", "N/A", "SYSTEM", "LOCAL SERVICE") else s
