"""Sigma rule import/export - vendor-neutral detection content.

Import maps a Sigma YAML rule onto ThreatOrbit's evaluable definition
(conditions + AND/OR logic over the raw event stream):

  * `detection.<selection>` blocks become field conditions. Sigma field
    modifiers map to operators: |contains, |re, |gt/|gte/|lt/|lte,
    |startswith/|endswith (→ regex), lists → `in`.
  * Field names resolve through a Sigma→native map plus the ECS alias layer,
    so `source.ip`, `SourceIp`, `c-ip` … all land on `src_ip`. Fields with no
    mapping degrade to a `raw contains <value>` condition (noted in the
    description) instead of silently dropping detection logic.
  * `condition: selection`, `sel1 and sel2`, `sel1 or sel2` are supported;
    aggregation (`… | count() by X > N`) becomes threshold-over-window.
    `not` / `1 of` / `all of` patterns are rejected with a clear error.
  * `level` → severity, `tags` (attack.tXXXX / attack.<tactic>) → MITRE.

The original YAML is preserved on the rule (kql column) so export returns
the source document; rules authored natively export as generated Sigma.
"""
import re

from dashboard_api.rule_engine import ECS_ALIASES, FIELDS, canonical_field

_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium",
             "low": "low", "informational": "info", "info": "info"}

# Sigma/community field spellings → native event fields (beyond ECS aliases).
SIGMA_FIELD_MAP = {
    "sourceip": "src_ip", "source_ip": "src_ip", "src-ip": "src_ip", "c-ip": "src_ip",
    "clientip": "src_ip", "ipaddress": "src_ip", "remote_ip": "src_ip",
    "destinationip": "dest_ip", "dst_ip": "dest_ip", "dst-ip": "dest_ip",
    "destinationport": "dest_port", "dst_port": "dest_port", "destport": "dest_port",
    "targetusername": "username", "user": "username", "username": "username",
    "subjectusername": "username", "accountname": "username",
    "computername": "hostname", "computer": "hostname", "host": "hostname",
    "workstationname": "hostname",
    "image": "process_name", "processname": "process_name",
    "originalfilename": "process_name", "parentimage": "process_name",
    "commandline": "raw", "message": "raw", "payload": "raw", "url": "raw",
    "cs-uri-query": "raw", "uri": "raw", "useragent": "raw",
    "eventtype": "event_type", "event_type": "event_type",
    "action": "action", "category": "category", "country": "country",
    "bytes": "bytes_out", "bytes_out": "bytes_out", "sentbytes": "bytes_out",
}

_TACTIC_TAGS = {
    "initial_access": ("Initial Access", "TA0001"), "execution": ("Execution", "TA0002"),
    "persistence": ("Persistence", "TA0003"), "privilege_escalation": ("Privilege Escalation", "TA0004"),
    "defense_evasion": ("Defense Evasion", "TA0005"), "credential_access": ("Credential Access", "TA0006"),
    "discovery": ("Discovery", "TA0007"), "lateral_movement": ("Lateral Movement", "TA0008"),
    "collection": ("Collection", "TA0009"), "exfiltration": ("Exfiltration", "TA0010"),
    "command_and_control": ("Command and Control", "TA0011"), "impact": ("Impact", "TA0040"),
}

_MOD_OPS = {"contains": "contains", "re": "regex", "gt": "gt", "gte": "gte",
            "lt": "lt", "lte": "lte", "cidr": "cidr"}


def _resolve_field(name: str) -> str | None:
    """Sigma field name → native event field (None when unmappable)."""
    if name in FIELDS:
        return name
    ecs = canonical_field(name)
    if ecs in FIELDS:
        return ecs
    return SIGMA_FIELD_MAP.get(name.lower().replace(" ", ""))


def _conditions_from_selection(sel: dict, notes: list[str]) -> list[dict]:
    conds: list[dict] = []
    for raw_key, value in sel.items():
        parts = str(raw_key).split("|")
        field_name, mods = parts[0], [m.lower() for m in parts[1:]]
        native = _resolve_field(field_name)
        op = "equals"
        for m in mods:
            if m in _MOD_OPS:
                op = _MOD_OPS[m]
            elif m == "startswith":
                op, value = "regex", f"^{re.escape(str(value))}"
            elif m == "endswith":
                op, value = "regex", f"{re.escape(str(value))}$"
            elif m == "all":
                pass  # list handled below; AND-of-contains approximated per item
        if isinstance(value, list):
            if op in ("equals", "contains") and "all" not in mods:
                conds.append({"field": native or "raw", "op": "in",
                              "value": ",".join(str(v) for v in value)})
                if not native:
                    notes.append(f"field '{field_name}' mapped to raw")
                continue
            for v in value:  # |all or operator lists → one condition each (AND)
                conds.append({"field": native or "raw", "op": op if native else "contains", "value": str(v)})
            if not native:
                notes.append(f"field '{field_name}' mapped to raw contains")
            continue
        if native:
            conds.append({"field": native, "op": op, "value": value})
        else:
            # Unknown field: keep the detection value as a raw-content match.
            conds.append({"field": "raw", "op": "contains", "value": str(value)})
            notes.append(f"field '{field_name}' mapped to raw contains")
    return conds


_AGG_RE = re.compile(r"\|\s*count\(\s*\)\s*(?:by\s+([\w.]+))?\s*([><]=?)\s*(\d+)")


def split_sigma_documents(text: str) -> list[str]:
    """Split a pasted multi-rule YAML stream into individual rule documents.

    Downloaded Sigma rule collections (e.g. a cloned SigmaHQ directory
    concatenated into one paste) are standard YAML multi-document streams:
    each rule separated by a line that's just `---`. Splitting on the raw
    text (not re-parsing/re-serializing through a YAML loader) means a
    malformed document can't affect its neighbours - each chunk is handed to
    `sigma_to_rule` independently, which does its own parsing and error
    reporting per-document."""
    parts = re.split(r"(?m)^---\s*$", text)
    return [p.strip() for p in parts if p.strip()]


def sigma_to_rule(text: str) -> dict:
    """Parse Sigma YAML → ThreatOrbit rule fields. Raises ValueError."""
    import yaml
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ValueError(f"invalid YAML: {e}")
    if not isinstance(doc, dict):
        raise ValueError("Sigma rule must be a YAML mapping")
    title = str(doc.get("title") or "").strip()
    if not title:
        raise ValueError("Sigma rule needs a title")
    detection = doc.get("detection")
    if not isinstance(detection, dict):
        raise ValueError("Sigma rule needs a detection block")

    condition = str(detection.get("condition") or "selection").strip()
    agg = None
    m = _AGG_RE.search(condition)
    if m:
        group_by = _resolve_field(m.group(1)) if m.group(1) else "src_ip"
        agg = {"groupBy": group_by or "src_ip", "threshold": int(m.group(3)), "windowMinutes": 5}
        condition = condition[:m.start()].strip()
    low = condition.lower()
    if re.search(r"\bnot\b|\b1 of\b|\ball of\b|\(", low):
        raise ValueError(f"unsupported Sigma condition: '{condition}' "
                         "(not / 1-of / all-of / grouping are not supported yet)")
    logic = "or" if " or " in low else "and"
    sel_names = [s.strip() for s in re.split(r"\s+(?:and|or)\s+", condition) if s.strip()]

    notes: list[str] = []
    conditions: list[dict] = []
    for name in sel_names:
        sel = detection.get(name)
        if sel is None:
            raise ValueError(f"condition references unknown selection '{name}'")
        if isinstance(sel, list):  # list of maps → OR within; approximate by merging
            for entry in sel:
                if isinstance(entry, dict):
                    conditions.extend(_conditions_from_selection(entry, notes))
            if logic == "and" and len(sel) > 1:
                logic = "or"
                notes.append(f"selection '{name}' is a list - evaluated as OR")
        elif isinstance(sel, dict):
            conditions.extend(_conditions_from_selection(sel, notes))
        else:
            raise ValueError(f"selection '{name}' must be a mapping")
    if not conditions:
        raise ValueError("no usable conditions in the detection block")

    tech_id = tactic = tactic_id = None
    tags = [str(t) for t in (doc.get("tags") or [])]
    for t in tags:
        tm = re.fullmatch(r"attack\.([ts]\d{4}(?:\.\d{3})?)", t.lower())
        if tm and tm.group(1).startswith("t") and not tech_id:
            tech_id = tm.group(1).upper()
        name = t.lower().removeprefix("attack.")
        if name in _TACTIC_TAGS and not tactic:
            tactic, tactic_id = _TACTIC_TAGS[name]

    definition = {"conditions": conditions, "logic": logic}
    if agg:
        definition["aggregation"] = agg
    description = str(doc.get("description") or f"Imported Sigma rule: {title}.")
    if notes:
        description += " [import notes: " + "; ".join(sorted(set(notes))) + "]"
    return {
        "name": title,
        "severity": _SEVERITY.get(str(doc.get("level") or "medium").lower(), "medium"),
        "description": description,
        "definition": definition,
        "mitre_tech_id": tech_id, "mitre_tactic": tactic, "mitre_tactic_id": tactic_id,
        "category": str((doc.get("logsource") or {}).get("category")
                        or (doc.get("logsource") or {}).get("product") or "Imported").title(),
        "tags": ["sigma"] + tags,
        "notes": sorted(set(notes)),
    }


_OP_TO_MOD = {"contains": "|contains", "regex": "|re", "gt": "|gt", "gte": "|gte",
              "lt": "|lt", "lte": "|lte", "cidr": "|cidr"}
_NATIVE_TO_ECS = {v: k for k, v in reversed(list(ECS_ALIASES.items()))}


def rule_to_sigma(rule: dict) -> str:
    """Generate Sigma YAML from a native rule definition (export)."""
    import yaml
    definition = rule.get("definition") or {}
    sel: dict = {}
    for c in definition.get("conditions") or []:
        field = _NATIVE_TO_ECS.get(c.get("field"), c.get("field"))
        op = c.get("op", "equals")
        value = c.get("value")
        if op == "in":
            sel[field] = [s.strip() for s in str(value).split(",")]
        elif op == "not_equals":
            sel[f"{field}|re"] = f"^(?!{re.escape(str(value))}$).*"
        else:
            sel[f"{field}{_OP_TO_MOD.get(op, '')}"] = value
    condition = "selection"
    agg = definition.get("aggregation")
    if agg and agg.get("threshold"):
        by = _NATIVE_TO_ECS.get(agg.get("groupBy"), agg.get("groupBy") or "src_ip")
        condition += f" | count() by {by} > {int(agg['threshold']) - 1}"
    level = {"info": "informational"}.get(rule.get("severity"), rule.get("severity") or "medium")
    tags = []
    if rule.get("mitre_tactic"):
        key = next((k for k, v in _TACTIC_TAGS.items() if v[0] == rule["mitre_tactic"]), None)
        if key:
            tags.append(f"attack.{key}")
    if rule.get("mitre_tech_id"):
        tags.append(f"attack.{rule['mitre_tech_id'].lower()}")
    doc = {
        "title": rule.get("name") or "ThreatOrbit rule",
        "status": "stable",
        "description": rule.get("description") or "",
        "author": "ThreatOrbit export",
        "tags": tags,
        "logsource": {"category": (rule.get("category") or "generic").lower()},
        "detection": {"selection": sel, "condition": condition},
        "level": level,
    }
    return yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
