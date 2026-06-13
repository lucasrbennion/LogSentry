# scoring.py — converts rule hits into analyst-friendly priority levels and ownership assignments.
#
# After rules.py decides WHAT happened, this module decides HOW URGENT it is and
# WHO should investigate.  It also produces a summary of the full triage run so
# the caller can see high-level counts without scanning every individual result.

from typing import Dict, List
from collections import Counter


PRIORITY_MAP = {
    "critical": ("P1", "SOC / Incident Response"),
    "high_priority": ("P2", "SOC / Security Operations"),
    "medium_priority": ("P3", "IAM / Infrastructure"),
    "review": ("P3", "SOC / Security Operations"),
    "baseline": ("P4", "Infrastructure / Operations"),
    "deprioritise": ("P4", "Infrastructure / Operations"),
}


def extract_attack_mappings(rule_hits: List[Dict]) -> List[Dict]:
    """
    Pull out unique ATT&CK mappings from the matched rules.

    Deduplication is based on technique ID + tactic + confidence so the frontend
    receives a clean list even if multiple rules later point to the same technique.
    """
    seen = set()
    mappings = []

    for hit in rule_hits:
        attack = hit.get("attack")
        if not attack:
            continue

        key = (
            attack.get("attack_technique_id"),
            attack.get("attack_tactic"),
            attack.get("attack_confidence"),
        )
        if key in seen:
            continue

        seen.add(key)
        mappings.append(attack)

    return mappings


def score_event(event: Dict, rule_hits: List[Dict]) -> Dict:
    """
    Turn matched rule hits into a scored triage result suitable for the API/UI.
    """
    effects = [rule["effect"] for rule in rule_hits]
    priority = "P4"
    owner = "Infrastructure / Operations"

    for effect in ("critical", "high_priority", "medium_priority", "review", "baseline", "deprioritise"):
        if effect in effects:
            priority, owner = PRIORITY_MAP[effect]
            break

    explanation = " | ".join(f"{r['rule_id']}: {r['reason']}" for r in rule_hits)
    attack_mappings = extract_attack_mappings(rule_hits)

    return {
        "event_id": event.get("event_id"),
        "timestamp": event.get("timestamp"),
        "account": event.get("new_logon_account") or event.get("target_account") or event.get("subject_account"),
        "machine_name": event.get("machine_name"),
        "provider_name": event.get("provider_name"),
        "message": event.get("message"),
        "logon_type": event.get("logon_type"),
        "priority": priority,
        "recommended_owner": owner,
        "rule_hits": rule_hits,
        "attack_mappings": attack_mappings,
        "explanation": explanation,
        "normalized_event": event,
    }


def summarise_results(results: List[Dict]) -> Dict:
    """
    Build the summary block returned by the API and displayed by the frontend.
    """
    priorities = Counter(r["priority"] for r in results)
    event_ids = Counter(r["event_id"] for r in results)

    attack_counter = Counter()
    for result in results:
        for attack in result.get("attack_mappings", []):
            technique_id = attack.get("attack_technique_id")
            if technique_id:
                attack_counter[technique_id] += 1

    return {
        "total_events": len(results),
        "priority_breakdown": dict(priorities),
        "event_id_breakdown": dict(event_ids),
        "attack_technique_breakdown": dict(attack_counter),
    }
