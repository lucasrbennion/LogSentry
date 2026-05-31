# scoring.py — converts rule hits into analyst-friendly priority levels and ownership assignments.
#
# After rules.py decides WHAT happened, this module decides HOW URGENT it is and
# WHO should investigate.  It also produces a summary of the full triage run so
# the caller can see high-level counts without scanning every individual result.

from typing import Dict, List
from collections import Counter

# Maps each rule effect to a (priority_label, recommended_owner) pair.
# The priority labels follow a P1–P4 scale:
#   P1 = drop everything, respond now   (critical events like audit log cleared)
#   P2 = investigate today              (high-risk events like new admin account)
#   P3 = investigate this week          (moderate or manual-review events)
#   P4 = informational / low noise      (baseline activity, system service logons)
PRIORITY_MAP = {
    "critical":        ("P1", "SOC / Incident Response"),
    "high_priority":   ("P2", "SOC / Security Operations"),
    "medium_priority": ("P3", "IAM / Infrastructure"),
    "review":          ("P3", "SOC / Security Operations"),
    "baseline":        ("P4", "Infrastructure / Operations"),
    "deprioritise":    ("P4", "Infrastructure / Operations"),
}


def score_event(event: Dict, rule_hits: List[Dict]) -> Dict:
    """Assign a priority and recommended owner to a single event based on its rule hits.

    When multiple rules fired, the most severe effect wins.  The order defined in
    the loop below matches the PRIORITY_MAP ordering (critical first, deprioritise last),
    so the first effect found in that order becomes the event's priority.

    The returned dict is the complete triage record that gets stored in the results list
    and eventually returned to the API caller.
    """
    effects = [rule["effect"] for rule in rule_hits]

    # Default to the lowest priority in case none of the effects below match.
    priority = "P4"
    owner = "Infrastructure / Operations"

    # Walk effects from most severe to least severe and stop at the first match.
    for effect in ("critical", "high_priority", "medium_priority", "review", "baseline", "deprioritise"):
        if effect in effects:
            priority, owner = PRIORITY_MAP[effect]
            break

    # Build a single readable string that lists all fired rules and their reasons.
    # Example: "R020: Failed logon detected | R999: Event retained for manual review"
    explanation = " | ".join(f"{r['rule_id']}: {r['reason']}" for r in rule_hits)

    return {
        "event_id": event.get("event_id"),
        "timestamp": event.get("timestamp"),
        # Best available account name for quick identification in the results table.
        "account": (
            event.get("new_logon_account")
            or event.get("target_account")
            or event.get("subject_account")
        ),
        "machine_name": event.get("machine_name"),
        "logon_type": event.get("logon_type"),
        "priority": priority,
        "recommended_owner": owner,
        "rule_hits": rule_hits,       # full list of rules that fired, for drill-down
        "explanation": explanation,   # human-readable summary of why this priority was assigned
        "normalized_event": event,    # the full normalised event for further inspection
    }


def summarise_results(results: List[Dict]) -> Dict:
    """Produce aggregate counts across all triaged events.

    Returns:
        total_events       — total number of events processed
        priority_breakdown — count of events at each priority level (P1, P2, P3, P4)
        event_id_breakdown — count of events for each Windows event ID
    """
    priorities = Counter(r["priority"] for r in results)
    event_ids = Counter(r["event_id"] for r in results)
    return {
        "total_events": len(results),
        "priority_breakdown": dict(priorities),
        "event_id_breakdown": dict(event_ids),
    }
