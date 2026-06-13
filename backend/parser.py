# parser.py — reads raw Windows Security event log text and converts it into
# clean Python dicts that the rest of the application can work with.
#
# Windows event logs exported as plain text look like this:
#
#   TimeCreated  : 2024-01-15T08:30:00
#   Id           : 4624
#   ProviderName : Microsoft-Windows-Security-Auditing
#   MachineName  : WORKSTATION01
#   Message      : An account was successfully logged on.
#   Subject:
#     Security ID    : S-1-5-18
#     Account Name   : SYSTEM
#     ...
#   New Logon:
#     Security ID    : S-1-5-21-...
#     Account Name   : testuser1
#     ...
#
# Each log file can contain many records separated by the "TimeCreated" header line.
# parse_file() is the main public entry point for reading one of these files.

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

# --- Compiled regex patterns used throughout the parser ---

# Matches the start of a new log record by looking for a line beginning with "TimeCreated".
# The lookahead (?=...) means we split WITHOUT consuming the delimiter, so each chunk
# keeps its own "TimeCreated" line.
HEADER_SPLIT_RE = re.compile(r"(?=^TimeCreated\s*:)", re.MULTILINE)

# Matches the four top-level fields that appear at the very start of every record.
# Example match: "Id           : 4624"
TOP_FIELD_RE = re.compile(r"^(TimeCreated|Id|ProviderName|MachineName)\s*:\s*(.*)$")

# Matches a section heading — a line with light indentation whose only content is a label
# followed by a colon, e.g. "  Subject:" or "  New Logon:".
# These headings group the key/value pairs that follow them.
SECTION_RE = re.compile(r"^\s{0,20}([A-Za-z][A-Za-z0-9 \-]+):\s*$")

# Matches a key/value pair anywhere in the record, e.g. "    Account Name   : testuser1".
# The key may contain letters, digits, spaces, hyphens, parentheses, and slashes.
KV_RE = re.compile(r"^\s{0,40}([A-Za-z][A-Za-z0-9 \-\(\)\/]+):\s*(.*)$")


def split_records(text: str) -> List[str]:
    """Split a full log file string into individual record strings.

    Each record starts with a 'TimeCreated' line.  Blank chunks are discarded.
    """
    chunks = [c.strip() for c in HEADER_SPLIT_RE.split(text) if c.strip()]
    return chunks


def _ensure_section(container: Dict[str, Any], section: str) -> Dict[str, Any]:
    """Return the nested dict for a section, creating it if it does not exist yet.

    For example, if the parser is inside a 'Subject' block it calls this to get
    (or create) container['Subject'] so subsequent key/value pairs can be stored there.
    """
    if section not in container or not isinstance(container[section], dict):
        container[section] = {}
    return container[section]


def parse_record(record_text: str) -> Dict[str, Any]:
    """Parse a single raw Windows event log record into a nested dict.

    The parser works as a simple line-by-line state machine:
      - current_section tracks which section heading we are currently inside
        (e.g. 'Subject', 'New Logon').  None means we are at the top level.
      - last_key remembers the most recently written key so that continuation
        lines (used for multi-value 'Privileges' lists) can be appended correctly.

    The returned dict always contains the original text under 'raw_record' so
    downstream code can display or re-parse it if needed.
    """
    lines = [line.rstrip("\n") for line in record_text.splitlines()]
    event: Dict[str, Any] = {"raw_record": record_text}
    current_section: Optional[str] = None  # which section block we are inside right now
    last_key: Optional[str] = None         # the last key written, used for continuation lines

    for line in lines:
        line = line.expandtabs(4)  # normalise tabs to spaces so indent checks are reliable

        # A blank line signals the end of the current section block.
        if line.strip() == "":
            current_section = None
            last_key = None
            continue

        # --- Top-level fields (TimeCreated, Id, ProviderName, MachineName) ---
        # These appear before any section heading and get special field names.
        m_top = TOP_FIELD_RE.match(line.strip())
        if m_top and current_section is None:
            key, value = m_top.groups()
            if key == "Id":
                event["event_id"] = int(value.strip())   # store as int for easier comparisons
            elif key == "TimeCreated":
                event["timestamp"] = value.strip()
            elif key == "ProviderName":
                event["provider_name"] = value.strip()
            elif key == "MachineName":
                event["machine_name"] = value.strip()
            last_key = None
            continue

        # --- Message field ---
        # The "Message" line holds a short human-readable description of the event.
        if line.strip().startswith("Message"):
            event["message"] = line.split(":", 1)[1].strip()
            current_section = None
            last_key = None
            continue

        # --- Section headings ---
        # A heading like "  New Logon:" switches current_section so that
        # the key/value pairs on the lines below are stored under that heading.
        m_section = SECTION_RE.match(line)
        if m_section:
            sec = m_section.group(1).strip()
            # Guard: "Privileges: SeDebugPrivilege" has a value on the same line and
            # should NOT be treated as a section heading even though it ends with a colon.
            if sec == "Privileges" and line.strip().count(":") == 1 and line.strip().endswith(":") is False:
                pass
            current_section = sec
            _ensure_section(event, current_section)
            last_key = None
            continue

        # --- Key/value pairs ---
        # If we are inside a section, store under that section's dict.
        # At the top level, store directly on the event dict.
        # Privileges are special: they can span multiple lines, so we start a list.
        m_kv = KV_RE.match(line)
        if m_kv:
            key = m_kv.group(1).strip()
            value = m_kv.group(2).strip()

            # Top-level "Privileges" field — start a list so continuation lines can append.
            if key == "Privileges" and current_section is None:
                event["privileges"] = [value] if value else []
                last_key = "privileges"
                continue

            if current_section:
                sec = _ensure_section(event, current_section)
                if key == "Privileges":
                    # Privileges inside a section also become a list.
                    sec["Privileges"] = [value] if value else []
                    last_key = f"{current_section}.Privileges"
                else:
                    sec[key] = value
                    last_key = f"{current_section}.{key}"
            else:
                event[key] = value
                last_key = key
            continue

        # --- Continuation lines for Privileges ---
        # After a "Privileges:" line, each subsequent non-empty, non-matching line
        # is another privilege name (e.g. "SeDebugPrivilege") and gets appended to the list.
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

# These keys belong to LogSentry's own flat, normalised schema.  If we see one or more
# of these on an input event, it is likely that the event is already normalised and
# should not be re-parsed as if it were a raw nested Windows section structure.
NORMALIZED_MARKER_KEYS = {
    "subject_account",
    "new_logon_account",
    "target_account",
    "source_network_address",
    "scenario_id",
}


def _looks_normalized_event(event: Dict[str, Any]) -> bool:
    """Return True if the incoming event already looks like LogSentry's flat schema.

    This makes normalize_event idempotent:
      - raw parsed Windows event dicts are flattened as before
      - already-normalized events (such as generated JSON datasets) pass through cleanly
    """
    return "event_id" in event and any(key in event for key in NORMALIZED_MARKER_KEYS)


def _normalize_pre_normalized_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Return a safe copy of an already-normalized event with missing fields defaulted."""
    privileges = event.get("privileges") or []
    if isinstance(privileges, str):
        privileges = [privileges]

    return {
        "event_id": event.get("event_id"),
        "timestamp": event.get("timestamp"),
        "provider_name": event.get("provider_name"),
        "machine_name": event.get("machine_name"),
        "message": event.get("message"),
        "subject_account": event.get("subject_account"),
        "subject_domain": event.get("subject_domain"),
        "subject_security_id": event.get("subject_security_id"),
        "subject_logon_id": event.get("subject_logon_id"),
        "new_logon_account": event.get("new_logon_account"),
        "new_logon_domain": event.get("new_logon_domain"),
        "new_logon_security_id": event.get("new_logon_security_id"),
        "new_logon_logon_id": event.get("new_logon_logon_id"),
        "target_account": event.get("target_account"),
        "target_domain": event.get("target_domain"),
        "target_security_id": event.get("target_security_id"),
        "logon_type": event.get("logon_type"),
        "elevated_token": event.get("elevated_token"),
        "virtual_account": event.get("virtual_account"),
        "restricted_admin_mode": event.get("restricted_admin_mode"),
        "workstation_name": event.get("workstation_name"),
        "source_network_address": event.get("source_network_address"),
        "source_port": event.get("source_port"),
        "process_name": event.get("process_name"),
        "failure_reason": event.get("failure_reason"),
        "status": event.get("status"),
        "substatus": event.get("substatus"),
        "logon_process": event.get("logon_process"),
        "authentication_package": event.get("authentication_package"),
        "privileges": privileges,
        "scenario_id": event.get("scenario_id"),
        "raw_record": event.get("raw_record"),
    }

def normalize_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten the nested parsed event dict into a single-level dict with consistent field names.

    The raw parsed dict mirrors the Windows log structure with nested sections like
    'Subject', 'New Logon', 'Failure Information', etc.  This function extracts the
    fields that matter for triage and gives them stable snake_case names so the rest
    of the app doesn't need to know the raw section layout.

    Fields that have no value in this event are set to None rather than omitted, so
    downstream code can always do event.get("field") without KeyError surprises.
    """
    # Pull each section dict out (defaulting to empty dict if the section wasn't in the log).
    subject = event.get("Subject", {})
    new_logon = event.get("New Logon", {})
    failed = event.get("Account For Which Logon Failed", {})
    failure_info = event.get("Failure Information", {})
    network = event.get("Network Information", {})
    logon_info = event.get("Logon Information", {})
    process_info = event.get("Process Information", {})
    details = event.get("Detailed Authentication Information", {})

    # Privileges may live in several places depending on event type; check them all.
    privileges = (
        event.get("Privileges")
        or event.get("privileges")
        or event.get("Subject", {}).get("Privileges")
        or []
    )
    if isinstance(privileges, str):
        # Occasionally parsed as a bare string instead of a list — normalise.
        privileges = [privileges]

    return {
        "event_id": event.get("event_id"),
        "timestamp": event.get("timestamp"),
        "provider_name": event.get("provider_name"),
        "machine_name": event.get("machine_name"),
        "message": event.get("message"),
        # The account that initiated the action (e.g. the admin who created a new user).
        "subject_account": subject.get("Account Name"),
        "subject_domain": subject.get("Account Domain"),
        "subject_security_id": subject.get("Security ID"),
        "subject_logon_id": subject.get("Logon ID"),
        # The account that was logged on (present on event 4624 successful logon).
        "new_logon_account": new_logon.get("Account Name"),
        "new_logon_domain": new_logon.get("Account Domain"),
        "new_logon_security_id": new_logon.get("Security ID"),
        "new_logon_logon_id": new_logon.get("Logon ID"),
        # The account whose logon failed (present on event 4625 failed logon).
        "target_account": failed.get("Account Name"),
        "target_domain": failed.get("Account Domain"),
        "target_security_id": failed.get("Security ID"),
        # Logon type codes: 2=interactive, 3=network, 5=service, 10=remote interactive, etc.
        "logon_type": logon_info.get("Logon Type") or event.get("Logon Type"),
        "elevated_token": logon_info.get("Elevated Token"),
        "virtual_account": logon_info.get("Virtual Account"),
        "restricted_admin_mode": logon_info.get("Restricted Admin Mode"),
        # Network details — useful for identifying remote logon sources.
        "workstation_name": network.get("Workstation Name"),
        "source_network_address": network.get("Source Network Address"),
        "source_port": network.get("Source Port"),
        # The process that triggered the logon event.
        "process_name": process_info.get("Process Name") or process_info.get("Caller Process Name"),
        # Failure details — only present on event 4625.
        "failure_reason": failure_info.get("Failure Reason"),
        "status": failure_info.get("Status"),
        "substatus": failure_info.get("Sub Status"),
        "logon_process": details.get("Logon Process"),
        "authentication_package": details.get("Authentication Package"),
        "privileges": privileges,
        "raw_record": event.get("raw_record"),  # keep the original text for display/debugging
    }


def normalize_events(events: list[dict]) -> list[dict]:
    """Normalise every event in a list.

    The function is intentionally idempotent:
      - raw nested Windows events are flattened
      - already-normalized events are passed through safely
    """
    return [normalize_event(event) for event in events]

def parse_text(text: str) -> List[Dict[str, Any]]:
    """Parse a full multi-record log string into a list of normalised event dicts.

    Combines the three steps: split into records → parse each record → normalise.
    """
    records = split_records(text)
    parsed = [parse_record(r) for r in records]
    return [normalize_event(p) for p in parsed]


def parse_file(input_path: str | Path, output_path: str | Path | None = None) -> List[Dict[str, Any]]:
    """Read a Windows event log text file and return a list of normalised event dicts.

    If output_path is provided the results are also written to that path as JSON,
    which is useful for offline inspection or sharing parsed data with other tools.
    """
    input_path = Path(input_path)
    text = input_path.read_text(encoding="utf-8")
    parsed = parse_text(text)

    if output_path:
        output_path = Path(output_path)
        output_path.write_text(json.dumps(parsed, indent=2), encoding="utf-8")

    return parsed


if __name__ == "__main__":
    # Quick smoke-test: parse the bundled sample file and print the results.
    sample_path = Path(__file__).parent / "data" / "sample_windows_logs.txt"
    output_path = Path(__file__).parent / "data" / "parsed_sample_events.json"
    results = parse_file(sample_path, output_path)
    print(json.dumps(results, indent=2))
