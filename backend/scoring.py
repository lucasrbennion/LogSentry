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

def score_event(event: Dict, rule_hits: List[Dict]) -> Dict:
    effects = [rule["effect"] for rule in rule_hits]
    priority = "P4"
    owner = "Infrastructure / Operations"

    for effect in ("critical", "high_priority", "medium_priority", "review", "baseline", "deprioritise"):
        if effect in effects:
            priority, owner = PRIORITY_MAP[effect]
            break

    explanation = " | ".join(f"{r['rule_id']}: {r['reason']}" for r in rule_hits)

    return {
        "event_id": event.get("event_id"),
        "timestamp": event.get("timestamp"),
        "account": event.get("new_logon_account") or event.get("target_account") or event.get("subject_account"),
        "machine_name": event.get("machine_name"),
        "logon_type": event.get("logon_type"),
        "priority": priority,
        "recommended_owner": owner,
        "rule_hits": rule_hits,
        "explanation": explanation,
        "normalized_event": event,
    }

def summarise_results(results: List[Dict]) -> Dict:
    priorities = Counter(r["priority"] for r in results)
    event_ids = Counter(r["event_id"] for r in results)
    return {
        "total_events": len(results),
        "priority_breakdown": dict(priorities),
        "event_id_breakdown": dict(event_ids),
    }
