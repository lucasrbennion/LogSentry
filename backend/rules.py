# rules.py — maps Windows Security event IDs to triage decisions.
#
# Each rule looks at a normalised event dict and, if the event matches a known
# security pattern, appends a "hit" dict to the results list.  Multiple rules
# can fire on the same event.
#
# A hit dict contains:
#   rule_id  — a stable identifier (never reused) so hits can be tracked over time
#   name     — short human-readable label
#   effect   — priority signal consumed by scoring.py
#               ("critical" > "high_priority" > "medium_priority" > "review" >
#                "baseline" > "deprioritise")
#   reason   — plain-English explanation shown to the analyst

from typing import Dict, List, Optional


SYSTEM_LIKE_PREFIXES = ("SYSTEM", "DWM-", "UMFD-")


def attack(
    tactic: str,
    technique_id: str,
    technique: str,
    confidence: str = "high",
) -> Dict:
    """
    Build a consistent MITRE ATT&CK mapping object for a rule hit.

    confidence is intended to distinguish high-confidence direct mappings
    from lower-confidence signal/candidate mappings if you add those later.
    """
    return {
        "attack_tactic": tactic,
        "attack_technique_id": technique_id,
        "attack_technique": technique,
        "attack_confidence": confidence,
    }


def _is_system_noise(event: Dict) -> bool:
    """
    Identify common Windows background/session-management activity that
    should be deprioritised rather than treated as analyst-worthy triage.
    """
    account = (event.get("new_logon_account") or event.get("subject_account") or "").upper()
    logon_type = event.get("logon_type")
    return (
        account.startswith(SYSTEM_LIKE_PREFIXES)
        or account == "SYSTEM"
        or (logon_type == "5" and account == "SYSTEM")
    )


def evaluate_event(event: Dict) -> List[Dict]:
    """
    Evaluate one normalized event against the current rule set.

    Each rule hit may include:
    - triage effect
    - explanation
    - optional MITRE ATT&CK mapping
    """
    hits: List[Dict] = []
    event_id = event.get("event_id")
    account = event.get("new_logon_account") or event.get("target_account") or event.get("subject_account")
    logon_type = event.get("logon_type")

    if _is_system_noise(event):
        hits.append({
            "rule_id": "R001",
            "name": "System noise / service logon",
            "effect": "deprioritise",
            "reason": "System, DWM, UMFD, or service-driven logon identified.",
            "attack": None,
        })

    if event_id == 4624 and logon_type == "2" and account and str(account).lower().startswith("testuser"):
        hits.append({
            "rule_id": "R010",
            "name": "Interactive standard-user logon",
            "effect": "baseline",
            "reason": "Successful interactive logon by a non-admin test account.",
            "attack": None,
        })

    # Keep this conservative for now.
    # A single failed logon is not strong enough by itself to claim ATT&CK Brute Force.
    if event_id == 4625:
        hits.append({
            "rule_id": "R020",
            "name": "Failed interactive logon",
            "effect": "review",
            "reason": "Failed logon detected; requires authentication review.",
            "attack": None,
        })

    # Keep this conservative too.
    # 4672 is a strong signal of privileged activity, but not a clean one-to-one ATT&CK technique mapping.
    if event_id == 4672 and (event.get("subject_account") or "").lower() == "labadmin":
        hits.append({
            "rule_id": "R030",
            "name": "Privileged logon",
            "effect": "high_priority",
            "reason": "Special privileges assigned to labadmin.",
            "attack": None,
        })

    if event_id == 4720:
        hits.append({
            "rule_id": "R040",
            "name": "User account created",
            "effect": "high_priority",
            "reason": "Creation of a local account is security-relevant.",
            "attack": attack(
                tactic="Persistence",
                technique_id="T1136.001",
                technique="Create Account: Local Account",
                confidence="high",
            ),
        })

    # Keep deletion conservative for now. Depending on context, this may align to impact or admin cleanup.
    if event_id == 4726:
        hits.append({
            "rule_id": "R050",
            "name": "User account deleted",
            "effect": "high_priority",
            "reason": "Deletion of a local account is security-relevant.",
            "attack": None,
        })

    if event_id == 4732:
        hits.append({
            "rule_id": "R060",
            "name": "Added to security-enabled local group",
            "effect": "high_priority",
            "reason": "Group-membership expansion can indicate privilege escalation.",
            "attack": attack(
                tactic="Persistence; Privilege Escalation",
                technique_id="T1098.007",
                technique="Account Manipulation: Additional Local or Domain Groups",
                confidence="high",
            ),
        })

    if event_id == 4733:
        hits.append({
            "rule_id": "R070",
            "name": "Removed from security-enabled local group",
            "effect": "medium_priority",
            "reason": "Group-membership removal may still warrant review.",
            "attack": None,
        })

    if event_id == 1102:
        hits.append({
            "rule_id": "R080",
            "name": "Security log cleared",
            "effect": "critical",
            "reason": "Clearing the audit log is a high-risk event.",
            "attack": attack(
                tactic="Defense Evasion",
                technique_id="T1070.001",
                technique="Indicator Removal on Host: Clear Windows Event Logs",
                confidence="high",
            ),
        })

    if not hits:
        hits.append({
            "rule_id": "R999",
            "name": "No specific rule matched",
            "effect": "review",
            "reason": "Event retained for manual review pending rule expansion.",
            "attack": None,
        })

    return hits


# Optional future extension:
# If you want ATT&CK candidate mappings for currently unmapped events, do it explicitly
# and mark them low-confidence rather than pretending they are definitive.
#
# Example ideas for later:
# - repeated 4625 failures over a threshold -> T1110 Brute Force (low/medium confidence)
# - privileged valid local-account use in suspicious context -> T1078.003 Valid Accounts: Local Accounts