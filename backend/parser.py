from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

HEADER_SPLIT_RE = re.compile(r"(?=^TimeCreated\s*:)", re.MULTILINE)
TOP_FIELD_RE = re.compile(r"^(TimeCreated|Id|ProviderName|MachineName)\s*:\s*(.*)$")
SECTION_RE = re.compile(r"^\s{0,20}([A-Za-z][A-Za-z0-9 \-]+):\s*$")
KV_RE = re.compile(r"^\s{0,40}([A-Za-z][A-Za-z0-9 \-\(\)\/]+):\s*(.*)$")


def split_records(text: str) -> List[str]:
    chunks = [c.strip() for c in HEADER_SPLIT_RE.split(text) if c.strip()]
    return chunks


def _ensure_section(container: Dict[str, Any], section: str) -> Dict[str, Any]:
    if section not in container or not isinstance(container[section], dict):
        container[section] = {}
    return container[section]


def parse_record(record_text: str) -> Dict[str, Any]:
    lines = [line.rstrip("\n") for line in record_text.splitlines() if line.strip() != ""]
    event: Dict[str, Any] = {"raw_record": record_text}
    current_section: Optional[str] = None
    last_key: Optional[str] = None

    for line in lines:
        line = line.expandtabs(4)

        # top level fields
        m_top = TOP_FIELD_RE.match(line.strip())
        if m_top and current_section is None:
            key, value = m_top.groups()
            if key == "Id":
                event["event_id"] = int(value.strip())
            elif key == "TimeCreated":
                event["timestamp"] = value.strip()
            elif key == "ProviderName":
                event["provider_name"] = value.strip()
            elif key == "MachineName":
                event["machine_name"] = value.strip()
            last_key = None
            continue

        # Message line
        if line.strip().startswith("Message"):
            event["message"] = line.split(":", 1)[1].strip()
            current_section = None
            last_key = None
            continue

        # section heading
        m_section = SECTION_RE.match(line)
        if m_section:
            sec = m_section.group(1).strip()
            # Prevent top-level "Privileges: value" from being mistaken for heading
            if sec == "Privileges" and line.strip().count(":") == 1 and line.strip().endswith(":") is False:
                pass
            current_section = sec
            _ensure_section(event, current_section)
            last_key = None
            continue

        # key/value within section or top-level message area
        m_kv = KV_RE.match(line)
        if m_kv:
            key = m_kv.group(1).strip()
            value = m_kv.group(2).strip()

            # handle privileges as multi-line list
            if key == "Privileges" and current_section is None:
                event["privileges"] = [value] if value else []
                last_key = "privileges"
                continue

            if current_section:
                sec = _ensure_section(event, current_section)
                if key == "Privileges":
                    sec["Privileges"] = [value] if value else []
                    last_key = f"{current_section}.Privileges"
                else:
                    sec[key] = value
                    last_key = f"{current_section}.{key}"
            else:
                event[key] = value
                last_key = key
            continue

        # continuation line for privileges
        stripped = line.strip()
        if stripped and last_key:
            if last_key == "privileges":
                event.setdefault("privileges", []).append(stripped)
                continue
            if last_key.endswith(".Privileges"):
                sec_name = last_key.split(".", 1)[0]
                event.setdefault(sec_name, {}).setdefault("Privileges", []).append(stripped)
                continue

    return event


def normalize_event(event: Dict[str, Any]) -> Dict[str, Any]:
    subject = event.get("Subject", {})
    new_logon = event.get("New Logon", {})
    failed = event.get("Account For Which Logon Failed", {})
    failure_info = event.get("Failure Information", {})
    network = event.get("Network Information", {})
    logon_info = event.get("Logon Information", {})
    process_info = event.get("Process Information", {})
    details = event.get("Detailed Authentication Information", {})
    privileges = event.get("Privileges") or event.get("privileges") or event.get("Subject", {}).get("Privileges") or []

    if isinstance(privileges, str):
        privileges = [privileges]

    return {
        "event_id": event.get("event_id"),
        "timestamp": event.get("timestamp"),
        "provider_name": event.get("provider_name"),
        "machine_name": event.get("machine_name"),
        "message": event.get("message"),
        "subject_account": subject.get("Account Name"),
        "subject_domain": subject.get("Account Domain"),
        "subject_security_id": subject.get("Security ID"),
        "subject_logon_id": subject.get("Logon ID"),
        "new_logon_account": new_logon.get("Account Name"),
        "new_logon_domain": new_logon.get("Account Domain"),
        "new_logon_security_id": new_logon.get("Security ID"),
        "new_logon_logon_id": new_logon.get("Logon ID"),
        "target_account": failed.get("Account Name"),
        "target_domain": failed.get("Account Domain"),
        "target_security_id": failed.get("Security ID"),
        "logon_type": logon_info.get("Logon Type") or event.get("Logon Type"),
        "elevated_token": logon_info.get("Elevated Token"),
        "virtual_account": logon_info.get("Virtual Account"),
        "restricted_admin_mode": logon_info.get("Restricted Admin Mode"),
        "workstation_name": network.get("Workstation Name"),
        "source_network_address": network.get("Source Network Address"),
        "source_port": network.get("Source Port"),
        "process_name": process_info.get("Process Name") or process_info.get("Caller Process Name"),
        "failure_reason": failure_info.get("Failure Reason"),
        "status": failure_info.get("Status"),
        "substatus": failure_info.get("Sub Status"),
        "logon_process": details.get("Logon Process"),
        "authentication_package": details.get("Authentication Package"),
        "privileges": privileges,
        "raw_record": event.get("raw_record"),
    }

def normalize_events(events: list[dict]) -> list[dict]:
    return [normalize_event(event) for event in events]

def parse_text(text: str) -> List[Dict[str, Any]]:
    records = split_records(text)
    parsed = [parse_record(r) for r in records]
    return [normalize_event(p) for p in parsed]


def parse_file(input_path: str | Path, output_path: str | Path | None = None) -> List[Dict[str, Any]]:
    input_path = Path(input_path)
    text = input_path.read_text(encoding="utf-8")
    parsed = parse_text(text)

    if output_path:
        output_path = Path(output_path)
        output_path.write_text(json.dumps(parsed, indent=2), encoding="utf-8")

    return parsed


if __name__ == "__main__":
    sample_path = Path(__file__).parent / "data" / "sample_windows_logs.txt"
    output_path = Path(__file__).parent / "data" / "parsed_sample_events.json"
    results = parse_file(sample_path, output_path)
    print(json.dumps(results, indent=2))
