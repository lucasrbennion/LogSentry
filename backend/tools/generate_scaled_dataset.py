# generate_scaled_dataset.py — create a reproducible, varied 2,000-event dataset for
# LogSentry scale testing.
#
# The generator intentionally uses a hybrid strategy:
#   1. Real manually captured events are used as canonical seed templates where available
#      (4624 successful logon, 4625 failed logon, 4672 privileged logon).
#   2. Additional event families are generated synthetically but in a Windows-log shape
#      that the parser can read and the current rules can triage.
#
# Outputs:
#   backend/data/generated/generated_events_2000.json
#   backend/data/generated/generated_windows_logs_2000.txt
#   backend/data/generated/generated_labels_2000.csv
#
# The JSON file is the clean "master" dataset for logic-scale testing.
# The raw-text file is for parser-scale and end-to-end /triage-file testing.

from __future__ import annotations

import csv
import json
import random
import sys
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List

# Make the backend package importable when this script is run from backend/tools/.
BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from parser import parse_file
from rules import evaluate_event
from scoring import score_event

RNG = random.Random(20260613)

DATA_DIR = BACKEND_DIR / "data"
GENERATED_DIR = DATA_DIR / "generated"
SAMPLE_RAW_PATH = DATA_DIR / "sample_windows_logs.txt"

GENERATED_JSON_PATH = GENERATED_DIR / "generated_events_2000.json"
GENERATED_TEXT_PATH = GENERATED_DIR / "generated_windows_logs_2000.txt"
GENERATED_LABELS_PATH = GENERATED_DIR / "generated_labels_2000.csv"

PROVIDER_NAME = "Microsoft-Windows-Security-Auditing"

MACHINE_NAMES = ["WIN-H96JM6F374S", "WS2022-LAB01", "WS2022-LAB02"]
STANDARD_USERS = [f"testuser{i}" for i in range(1, 21)]
ADMIN_USERS = ["labadmin", "opsadmin1", "opsadmin2", "opsadmin3"]
SERVICE_USERS = ["SYSTEM", "DWM-1", "DWM-2", "UMFD-1", "UMFD-2"]
NEW_LOCAL_USERS = [f"tempuser{i:03d}" for i in range(1, 401)]
GROUP_NAMES = ["Administrators", "Remote Desktop Users", "Backup Operators"]

START_TIME = datetime(2026, 6, 13, 9, 0, 0)

# Target distribution.  Total = 2,000 events.
TARGET_COUNTS = {
    "baseline_success": 400,
    "system_noise": 320,
    "failed_single": 350,
    "failed_burst_events": 240,   # 60 burst sequences x 4 events (3 failures + 1 success)
    "privileged_logon": 180,
    "account_created": 160,
    "account_deleted": 120,
    "group_added": 120,
    "group_removed": 70,
    "log_cleared": 40,
}


class Timeline:
    """Simple helper to generate ascending timestamps with small random jitter."""

    def __init__(self, start: datetime):
        self.current = start

    def next(self, min_seconds: int = 5, max_seconds: int = 45) -> str:
        timestamp = self.current.strftime("%d/%m/%Y %H:%M:%S")
        self.current += timedelta(seconds=RNG.randint(min_seconds, max_seconds))
        return timestamp


def random_sid() -> str:
    """Return a plausible-looking local Windows SID."""
    return f"S-1-5-21-1843355061-959072039-615746888-{RNG.randint(1000, 9999)}"


def random_logon_id() -> str:
    """Return a plausible-looking Windows logon ID in hex format."""
    return f"0x{RNG.randint(65536, 999999):X}"


def pick_machine() -> str:
    return RNG.choice(MACHINE_NAMES)


def pick_standard_user() -> str:
    return RNG.choice(STANDARD_USERS)


def pick_admin_user() -> str:
    return RNG.choice(ADMIN_USERS)


def pick_source_ip(local_bias: bool = False) -> str:
    """Return a plausible source IP.

    local_bias=True pushes more events toward 127.0.0.1 to resemble local lab activity,
    while False gives a broader spread across internal lab subnets.
    """
    if local_bias and RNG.random() < 0.75:
        return "127.0.0.1"

    subnet = RNG.choice(["10.0.0", "192.168.56", "172.16.10"])
    return f"{subnet}.{RNG.randint(2, 254)}"


def load_seed_templates() -> Dict[int, Dict]:
    """Load the canonical real sample events and index them by event ID."""
    seeds = parse_file(SAMPLE_RAW_PATH)
    return {event["event_id"]: event for event in seeds}


def base_event(event_id: int, timestamp: str, machine_name: str, message: str, scenario_id: str) -> Dict:
    """Create a normalized-event skeleton with common fields pre-populated."""
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "provider_name": PROVIDER_NAME,
        "machine_name": machine_name,
        "message": message,
        "subject_account": None,
        "subject_domain": None,
        "subject_security_id": None,
        "subject_logon_id": None,
        "new_logon_account": None,
        "new_logon_domain": None,
        "new_logon_security_id": None,
        "new_logon_logon_id": None,
        "target_account": None,
        "target_domain": None,
        "target_security_id": None,
        "logon_type": None,
        "elevated_token": None,
        "virtual_account": None,
        "restricted_admin_mode": None,
        "workstation_name": None,
        "source_network_address": None,
        "source_port": None,
        "process_name": None,
        "failure_reason": None,
        "status": None,
        "substatus": None,
        "logon_process": None,
        "authentication_package": None,
        "privileges": [],
        "scenario_id": scenario_id,
        "raw_record": None,
    }


def build_success_logon(seed_4624: Dict, timestamp: str, scenario_id: str, account: str | None = None) -> Dict:
    """Build a normal successful interactive logon based on the real 4624 seed."""
    event = deepcopy(seed_4624)
    machine = pick_machine()
    account = account or pick_standard_user()

    event.update({
        "timestamp": timestamp,
        "machine_name": machine,
        "subject_account": f"{machine}$",
        "subject_domain": "WORKGROUP",
        "subject_security_id": "S-1-5-18",
        "subject_logon_id": random_logon_id(),
        "new_logon_account": account,
        "new_logon_domain": machine,
        "new_logon_security_id": random_sid(),
        "new_logon_logon_id": random_logon_id(),
        "logon_type": "2",
        "elevated_token": "No",
        "virtual_account": "No",
        "restricted_admin_mode": "-",
        "workstation_name": machine,
        "source_network_address": pick_source_ip(local_bias=True),
        "source_port": "0",
        "process_name": r"C:\Windows\System32\svchost.exe",
        "scenario_id": scenario_id,
        "raw_record": None,
    })
    return event


def build_failed_logon(seed_4625: Dict, timestamp: str, scenario_id: str, account: str | None = None) -> Dict:
    """Build a failed interactive logon based on the real 4625 seed."""
    event = deepcopy(seed_4625)
    machine = pick_machine()
    account = account or pick_standard_user()

    failure_variants = [
        ("Unknown user name or bad password.", "0xC000006D", "0xC000006A"),
        ("Unknown user name or bad password.", "0xC000006D", "0xC0000064"),
        ("User not allowed to log on at this computer.", "0xC000006E", "0x0"),
    ]
    failure_reason, status, substatus = RNG.choice(failure_variants)

    event.update({
        "timestamp": timestamp,
        "machine_name": machine,
        "subject_account": f"{machine}$",
        "subject_domain": "WORKGROUP",
        "subject_security_id": "S-1-5-18",
        "subject_logon_id": "0x3E7",
        "target_account": account,
        "target_domain": machine,
        "target_security_id": random_sid(),
        "logon_type": "2",
        "failure_reason": failure_reason,
        "status": status,
        "substatus": substatus,
        "workstation_name": machine,
        "source_network_address": pick_source_ip(local_bias=False),
        "source_port": str(RNG.randint(0, 65000)),
        "process_name": r"C:\Windows\System32\svchost.exe",
        "scenario_id": scenario_id,
        "raw_record": None,
    })
    return event


def build_privileged_logon(seed_4672: Dict, timestamp: str, scenario_id: str) -> Dict:
    """Build a privileged logon based on the real 4672 seed."""
    event = deepcopy(seed_4672)
    machine = pick_machine()

    event.update({
        "timestamp": timestamp,
        "machine_name": machine,
        "subject_account": pick_admin_user(),
        "subject_domain": machine,
        "subject_security_id": random_sid(),
        "subject_logon_id": random_logon_id(),
        "privileges": [
            "SeSecurityPrivilege",
            "SeTakeOwnershipPrivilege",
            "SeBackupPrivilege",
            "SeRestorePrivilege",
        ],
        "scenario_id": scenario_id,
        "raw_record": None,
    })
    return event


def build_system_noise(timestamp: str, scenario_id: str) -> Dict:
    """Build a routine Windows noise event that should be deprioritised by the rules."""
    machine = pick_machine()
    noise_account = RNG.choice(SERVICE_USERS)

    event = base_event(
        event_id=4624,
        timestamp=timestamp,
        machine_name=machine,
        message="An account was successfully logged on.",
        scenario_id=scenario_id,
    )
    event.update({
        "subject_account": "SYSTEM",
        "subject_domain": "NT AUTHORITY",
        "subject_security_id": "S-1-5-18",
        "subject_logon_id": "0x3E7",
        "new_logon_account": noise_account,
        "new_logon_domain": "Window Manager",
        "new_logon_security_id": "S-1-5-90-0-1",
        "new_logon_logon_id": random_logon_id(),
        "logon_type": "5",
        "elevated_token": "Yes",
        "virtual_account": "No",
        "restricted_admin_mode": "-",
        "workstation_name": machine,
        "source_network_address": "-",
        "source_port": "0",
        "process_name": r"C:\Windows\System32\services.exe",
    })
    return event


def build_account_created(timestamp: str, scenario_id: str) -> Dict:
    """Build event 4720 — local account created."""
    machine = pick_machine()
    created_user = NEW_LOCAL_USERS.pop(0)

    event = base_event(
        event_id=4720,
        timestamp=timestamp,
        machine_name=machine,
        message="A user account was created.",
        scenario_id=scenario_id,
    )
    event.update({
        "subject_account": pick_admin_user(),
        "subject_domain": machine,
        "subject_security_id": random_sid(),
        "subject_logon_id": random_logon_id(),
        "process_name": r"C:\Windows\System32\mmc.exe",
        "extra_new_account": created_user,
        "extra_new_account_domain": machine,
        "extra_new_account_sid": random_sid(),
    })
    return event


def build_account_deleted(timestamp: str, scenario_id: str) -> Dict:
    """Build event 4726 — local account deleted."""
    machine = pick_machine()
    deleted_user = RNG.choice(NEW_LOCAL_USERS + STANDARD_USERS)

    event = base_event(
        event_id=4726,
        timestamp=timestamp,
        machine_name=machine,
        message="A user account was deleted.",
        scenario_id=scenario_id,
    )
    event.update({
        "subject_account": pick_admin_user(),
        "subject_domain": machine,
        "subject_security_id": random_sid(),
        "subject_logon_id": random_logon_id(),
        "process_name": r"C:\Windows\System32\mmc.exe",
        "extra_deleted_account": deleted_user,
        "extra_deleted_account_domain": machine,
        "extra_deleted_account_sid": random_sid(),
    })
    return event


def build_group_added(timestamp: str, scenario_id: str) -> Dict:
    """Build event 4732 — user added to a security-enabled local group."""
    machine = pick_machine()
    member_account = RNG.choice(STANDARD_USERS + ADMIN_USERS)
    group_name = RNG.choice(GROUP_NAMES)

    event = base_event(
        event_id=4732,
        timestamp=timestamp,
        machine_name=machine,
        message="A member was added to a security-enabled local group.",
        scenario_id=scenario_id,
    )
    event.update({
        "subject_account": pick_admin_user(),
        "subject_domain": machine,
        "subject_security_id": random_sid(),
        "subject_logon_id": random_logon_id(),
        "process_name": r"C:\Windows\System32\net.exe",
        "extra_member_account": member_account,
        "extra_member_sid": random_sid(),
        "extra_group_name": group_name,
        "extra_group_domain": machine,
    })
    return event


def build_group_removed(timestamp: str, scenario_id: str) -> Dict:
    """Build event 4733 — user removed from a security-enabled local group."""
    machine = pick_machine()
    member_account = RNG.choice(STANDARD_USERS + ADMIN_USERS)
    group_name = RNG.choice(GROUP_NAMES)

    event = base_event(
        event_id=4733,
        timestamp=timestamp,
        machine_name=machine,
        message="A member was removed from a security-enabled local group.",
        scenario_id=scenario_id,
    )
    event.update({
        "subject_account": pick_admin_user(),
        "subject_domain": machine,
        "subject_security_id": random_sid(),
        "subject_logon_id": random_logon_id(),
        "process_name": r"C:\Windows\System32\net.exe",
        "extra_member_account": member_account,
        "extra_member_sid": random_sid(),
        "extra_group_name": group_name,
        "extra_group_domain": machine,
    })
    return event


def build_log_cleared(timestamp: str, scenario_id: str) -> Dict:
    """Build event 1102 — Security log cleared."""
    machine = pick_machine()

    event = base_event(
        event_id=1102,
        timestamp=timestamp,
        machine_name=machine,
        message="The audit log was cleared.",
        scenario_id=scenario_id,
    )
    event.update({
        "subject_account": pick_admin_user(),
        "subject_domain": machine,
        "subject_security_id": random_sid(),
        "subject_logon_id": random_logon_id(),
        "process_name": r"C:\Windows\System32\wevtutil.exe",
    })
    return event


def add_section(lines: List[str], title: str, pairs: List[tuple[str, str | None]]) -> None:
    """Render a Windows-style section heading and its key/value lines."""
    lines.append("")
    lines.append(f"               {title}:")
    for key, value in pairs:
        if value in (None, ""):
            continue
        lines.append(f"               \t{key}:\t\t{value}")


def render_windows_record(event: Dict) -> str:
    """Render one normalized/generated event into the text shape that parser.py expects."""
    lines = [
        f"TimeCreated  : {event.get('timestamp')}",
        f"Id           : {event.get('event_id')}",
        f"ProviderName : {event.get('provider_name') or PROVIDER_NAME}",
        f"MachineName  : {event.get('machine_name')}",
        f"Message      : {event.get('message') or '-'}",
    ]

    event_id = event.get("event_id")

    if event_id == 4624:
        add_section(lines, "Subject", [
            ("Security ID", event.get("subject_security_id")),
            ("Account Name", event.get("subject_account")),
            ("Account Domain", event.get("subject_domain")),
            ("Logon ID", event.get("subject_logon_id")),
        ])
        add_section(lines, "Logon Information", [
            ("Logon Type", event.get("logon_type") or "2"),
            ("Restricted Admin Mode", event.get("restricted_admin_mode") or "-"),
            ("Virtual Account", event.get("virtual_account") or "No"),
            ("Elevated Token", event.get("elevated_token") or "No"),
        ])
        add_section(lines, "New Logon", [
            ("Security ID", event.get("new_logon_security_id")),
            ("Account Name", event.get("new_logon_account")),
            ("Account Domain", event.get("new_logon_domain")),
            ("Logon ID", event.get("new_logon_logon_id")),
        ])
        add_section(lines, "Process Information", [
            ("Process Name", event.get("process_name")),
        ])
        add_section(lines, "Network Information", [
            ("Workstation Name", event.get("workstation_name")),
            ("Source Network Address", event.get("source_network_address")),
            ("Source Port", event.get("source_port")),
        ])

    elif event_id == 4625:
        add_section(lines, "Subject", [
            ("Security ID", event.get("subject_security_id")),
            ("Account Name", event.get("subject_account")),
            ("Account Domain", event.get("subject_domain")),
            ("Logon ID", event.get("subject_logon_id")),
        ])
        lines.append("")
        lines.append(f"               Logon Type:\t\t\t{event.get('logon_type') or '2'}")
        add_section(lines, "Account For Which Logon Failed", [
            ("Security ID", event.get("target_security_id")),
            ("Account Name", event.get("target_account")),
            ("Account Domain", event.get("target_domain")),
        ])
        add_section(lines, "Failure Information", [
            ("Failure Reason", event.get("failure_reason")),
            ("Status", event.get("status")),
            ("Sub Status", event.get("substatus")),
        ])
        add_section(lines, "Process Information", [
            ("Caller Process Name", event.get("process_name")),
        ])
        add_section(lines, "Network Information", [
            ("Workstation Name", event.get("workstation_name")),
            ("Source Network Address", event.get("source_network_address")),
            ("Source Port", event.get("source_port")),
        ])

    elif event_id == 4672:
        add_section(lines, "Subject", [
            ("Security ID", event.get("subject_security_id")),
            ("Account Name", event.get("subject_account")),
            ("Account Domain", event.get("subject_domain")),
            ("Logon ID", event.get("subject_logon_id")),
        ])
        privileges = event.get("privileges") or []
        if privileges:
            lines.append("")
            lines.append(f"               Privileges:\t\t{privileges[0]}")
            for privilege in privileges[1:]:
                lines.append(f"               \t\t\t{privilege}")

    elif event_id == 4720:
        add_section(lines, "Subject", [
            ("Security ID", event.get("subject_security_id")),
            ("Account Name", event.get("subject_account")),
            ("Account Domain", event.get("subject_domain")),
            ("Logon ID", event.get("subject_logon_id")),
        ])
        add_section(lines, "New Account", [
            ("Security ID", event.get("extra_new_account_sid")),
            ("Account Name", event.get("extra_new_account")),
            ("Account Domain", event.get("extra_new_account_domain")),
        ])

    elif event_id == 4726:
        add_section(lines, "Subject", [
            ("Security ID", event.get("subject_security_id")),
            ("Account Name", event.get("subject_account")),
            ("Account Domain", event.get("subject_domain")),
            ("Logon ID", event.get("subject_logon_id")),
        ])
        add_section(lines, "Deleted Account", [
            ("Security ID", event.get("extra_deleted_account_sid")),
            ("Account Name", event.get("extra_deleted_account")),
            ("Account Domain", event.get("extra_deleted_account_domain")),
        ])

    elif event_id in (4732, 4733):
        add_section(lines, "Subject", [
            ("Security ID", event.get("subject_security_id")),
            ("Account Name", event.get("subject_account")),
            ("Account Domain", event.get("subject_domain")),
            ("Logon ID", event.get("subject_logon_id")),
        ])
        add_section(lines, "Member", [
            ("Security ID", event.get("extra_member_sid")),
            ("Account Name", event.get("extra_member_account")),
        ])
        add_section(lines, "Group", [
            ("Group Name", event.get("extra_group_name")),
            ("Group Domain", event.get("extra_group_domain")),
        ])

    elif event_id == 1102:
        add_section(lines, "Subject", [
            ("Security ID", event.get("subject_security_id")),
            ("Account Name", event.get("subject_account")),
            ("Account Domain", event.get("subject_domain")),
            ("Logon ID", event.get("subject_logon_id")),
        ])

    return "\n".join(lines)


def trim_for_json_output(event: Dict) -> Dict:
    """Drop generation-only helper fields before writing the master JSON dataset."""
    trimmed = dict(event)
    trimmed.pop("raw_record", None)
    return trimmed


def label_event(event: Dict) -> Dict:
    """Use the live rules/scoring pipeline to derive the expected label row for one event."""
    triaged = score_event(event, evaluate_event(event))
    attack_ids = [m.get("attack_technique_id") for m in triaged.get("attack_mappings", []) if m.get("attack_technique_id")]

    return {
        "scenario_id": event.get("scenario_id"),
        "event_id": event.get("event_id"),
        "timestamp": event.get("timestamp"),
        "account": triaged.get("account"),
        "priority": triaged.get("priority"),
        "recommended_owner": triaged.get("recommended_owner"),
        "attack_technique_ids": ", ".join(attack_ids),
        "message": triaged.get("message"),
    }


def build_dataset() -> List[Dict]:
    """Generate the full 2,000-event dataset."""
    seeds = load_seed_templates()
    timeline = Timeline(START_TIME)
    events: List[Dict] = []

    # 400 baseline successful interactive logons.
    for index in range(TARGET_COUNTS["baseline_success"]):
        scenario_id = f"BASELINE-SUCCESS-{index:04d}"
        events.append(build_success_logon(seeds[4624], timeline.next(), scenario_id))

    # 320 routine Windows noise events.
    for index in range(TARGET_COUNTS["system_noise"]):
        scenario_id = f"SYSTEM-NOISE-{index:04d}"
        events.append(build_system_noise(timeline.next(), scenario_id))

    # 350 single failed logons.
    for index in range(TARGET_COUNTS["failed_single"]):
        scenario_id = f"FAILED-SINGLE-{index:04d}"
        events.append(build_failed_logon(seeds[4625], timeline.next(), scenario_id))

    # 60 burst sequences x 4 events each = 240 events.
    burst_sequences = TARGET_COUNTS["failed_burst_events"] // 4
    for index in range(burst_sequences):
        scenario_id = f"FAILED-BURST-{index:04d}"
        shared_account = pick_standard_user()

        # Three failures in quick succession...
        events.append(build_failed_logon(seeds[4625], timeline.next(1, 5), scenario_id, account=shared_account))
        events.append(build_failed_logon(seeds[4625], timeline.next(1, 5), scenario_id, account=shared_account))
        events.append(build_failed_logon(seeds[4625], timeline.next(1, 5), scenario_id, account=shared_account))
        # ...followed by one success, representing a plausible attack/guess/typo sequence.
        events.append(build_success_logon(seeds[4624], timeline.next(1, 5), scenario_id, account=shared_account))

    # 180 privileged logons.
    for index in range(TARGET_COUNTS["privileged_logon"]):
        scenario_id = f"PRIV-LOGON-{index:04d}"
        events.append(build_privileged_logon(seeds[4672], timeline.next(), scenario_id))

    # 160 local account creations.
    for index in range(TARGET_COUNTS["account_created"]):
        scenario_id = f"ACCOUNT-CREATED-{index:04d}"
        events.append(build_account_created(timeline.next(), scenario_id))

    # 120 local account deletions.
    for index in range(TARGET_COUNTS["account_deleted"]):
        scenario_id = f"ACCOUNT-DELETED-{index:04d}"
        events.append(build_account_deleted(timeline.next(), scenario_id))

    # 120 local group additions.
    for index in range(TARGET_COUNTS["group_added"]):
        scenario_id = f"GROUP-ADDED-{index:04d}"
        events.append(build_group_added(timeline.next(), scenario_id))

    # 70 local group removals.
    for index in range(TARGET_COUNTS["group_removed"]):
        scenario_id = f"GROUP-REMOVED-{index:04d}"
        events.append(build_group_removed(timeline.next(), scenario_id))

    # 40 security-log-cleared events.
    for index in range(TARGET_COUNTS["log_cleared"]):
        scenario_id = f"LOG-CLEARED-{index:04d}"
        events.append(build_log_cleared(timeline.next(), scenario_id))

    assert len(events) == 2000, f"Expected 2000 events, got {len(events)}"
    return events


def write_outputs(events: List[Dict]) -> None:
    """Write the generated JSON dataset, raw text log, and labels CSV to disk."""
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)

    # Render raw records first so the text file and parser-scale tests are available.
    raw_records = []
    for event in events:
        event["raw_record"] = render_windows_record(event)
        raw_records.append(event["raw_record"])

    GENERATED_TEXT_PATH.write_text("\n\n".join(raw_records), encoding="utf-8")

    json_payload = {"events": [trim_for_json_output(event) for event in events]}
    GENERATED_JSON_PATH.write_text(json.dumps(json_payload, indent=2), encoding="utf-8")

    labels = [label_event(event) for event in events]
    with GENERATED_LABELS_PATH.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "scenario_id",
                "event_id",
                "timestamp",
                "account",
                "priority",
                "recommended_owner",
                "attack_technique_ids",
                "message",
            ],
        )
        writer.writeheader()
        writer.writerows(labels)


def smoke_test_generated_text() -> None:
    """Sanity-check that the generated raw-text file can be parsed end-to-end."""
    parsed = parse_file(GENERATED_TEXT_PATH)
    if len(parsed) != 2000:
        raise RuntimeError(f"Parser smoke test failed: expected 2000 events, got {len(parsed)}")


def main() -> None:
    events = build_dataset()
    write_outputs(events)
    smoke_test_generated_text()

    print("Generated scaled dataset successfully.")
    print(f"JSON dataset : {GENERATED_JSON_PATH}")
    print(f"Raw text log : {GENERATED_TEXT_PATH}")
    print(f"Labels CSV   : {GENERATED_LABELS_PATH}")


if __name__ == "__main__":
    main()