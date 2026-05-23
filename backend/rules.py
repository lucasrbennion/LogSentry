from typing import Dict, List

SYSTEM_LIKE_PREFIXES = ("SYSTEM", "DWM-", "UMFD-")

def _is_system_noise(event: Dict) -> bool:
    account = (event.get("new_logon_account") or event.get("subject_account") or "").upper()
    logon_type = event.get("logon_type")
    return (
        account.startswith(SYSTEM_LIKE_PREFIXES)
        or (account == "SYSTEM")
        or (logon_type == "5" and account == "SYSTEM")
    )

def evaluate_event(event: Dict) -> List[Dict]:
    hits: List[Dict] = []
    event_id = event.get("event_id")
    account = event.get("new_logon_account") or event.get("target_account") or event.get("subject_account")

    if _is_system_noise(event):
        hits.append({
            "rule_id": "R001",
            "name": "System noise / service logon",
            "effect": "deprioritise",
            "reason": "System, DWM, UMFD, or service-driven logon identified."
        })

    if event_id == 4624 and event.get("logon_type") == "2" and account and str(account).lower().startswith("testuser"):
        hits.append({
            "rule_id": "R010",
            "name": "Interactive standard-user logon",
            "effect": "baseline",
            "reason": "Successful interactive logon by a non-admin test account."
        })

    if event_id == 4625:
        hits.append({
            "rule_id": "R020",
            "name": "Failed interactive logon",
            "effect": "review",
            "reason": "Failed logon detected; requires authentication review."
        })

    if event_id == 4672 and (event.get("subject_account") or "").lower() == "labadmin":
        hits.append({
            "rule_id": "R030",
            "name": "Privileged logon",
            "effect": "high_priority",
            "reason": "Special privileges assigned to labadmin."
        })

    if event_id == 4720:
        hits.append({
            "rule_id": "R040",
            "name": "User account created",
            "effect": "high_priority",
            "reason": "Creation of a local account is security-relevant."
        })

    if event_id == 4726:
        hits.append({
            "rule_id": "R050",
            "name": "User account deleted",
            "effect": "high_priority",
            "reason": "Deletion of a local account is security-relevant."
        })

    if event_id == 4732:
        hits.append({
            "rule_id": "R060",
            "name": "Added to security-enabled local group",
            "effect": "high_priority",
            "reason": "Group-membership expansion can indicate privilege escalation."
        })

    if event_id == 4733:
        hits.append({
            "rule_id": "R070",
            "name": "Removed from security-enabled local group",
            "effect": "medium_priority",
            "reason": "Group-membership removal may still warrant review."
        })

    if event_id == 1102:
        hits.append({
            "rule_id": "R080",
            "name": "Security log cleared",
            "effect": "critical",
            "reason": "Clearing the audit log is a high-risk event."
        })

    if not hits:
        hits.append({
            "rule_id": "R999",
            "name": "No specific rule matched",
            "effect": "review",
            "reason": "Event retained for manual review pending rule expansion."
        })

    return hits
