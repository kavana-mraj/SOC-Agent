import json
import os
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)
print("[case_manager] module imported")

CASES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cases")

# SLA targets (minutes) per tier
SLA_MINUTES = {"L1": 240, "L2": 120, "L3": 30}

VALID_STATUSES = ("open", "in_progress", "resolved", "closed")


def _assign_tier(severity: str, confidence: float) -> str:
    sev_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(severity, 1)
    if sev_rank >= 4 or confidence >= 0.90:
        return "L3"
    if sev_rank >= 3 or confidence >= 0.70:
        return "L2"
    return "L1"


def _priority_score(severity: str, confidence: float, threat_score: float = 0.0) -> float:
    sev_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(severity, 1)
    return round(sev_rank * 25 + confidence * 40 + threat_score * 0.35, 2)


def save_case(incident, verdict, investigation, response, source_name, decision=None,
              threat_intel=None, asset_context=None):
    os.makedirs(CASES_DIR, exist_ok=True)

    timestamp = datetime.utcnow()
    filename = os.path.join(CASES_DIR, f"case_{source_name}_{timestamp.strftime('%Y%m%d_%H%M%S')}.json")

    severity = incident.get("severity", "low")
    triage_confidence = verdict.get("confidence", 0.5)
    inv_confidence = investigation.get("confidence", 0.5)
    avg_confidence = (triage_confidence + inv_confidence) / 2

    threat_score = 0.0
    if threat_intel:
        threat_score = threat_intel.get("max_threat_score", 0.0)

    tier = _assign_tier(severity, avg_confidence)
    sla_deadline = (timestamp + timedelta(minutes=SLA_MINUTES[tier])).isoformat()
    priority = _priority_score(severity, avg_confidence, threat_score)

    case_data = {
        "case_id": os.path.basename(filename).replace(".json", ""),
        "timestamp": timestamp.isoformat(),
        "source_name": source_name,
        "status": "open",
        "analyst_tier": tier,
        "assigned_analyst": None,
        "priority_score": priority,
        "sla_deadline": sla_deadline,
        "sla_minutes": SLA_MINUTES[tier],
        "incident": incident,
        "triage_verdict": verdict,
        "investigation_result": investigation,
        "decision_result": decision,
        "response_action": response,
        "threat_intel": threat_intel,
        "asset_context": asset_context,
        "analyst_notes": [],
        "evidence": [],
        "escalation_history": [],
        "status_history": [
            {"status": "open", "timestamp": timestamp.isoformat(), "actor": "system"}
        ],
        "decision_summary": (
            f"{incident.get('incident_type')} reviewed by {verdict.get('agent_name')}. "
            f"Final action: {response.get('action')}. Tier: {tier}."
        )
    }

    with open(filename, "w") as f:
        json.dump(case_data, f, indent=4)

    logger.info("Case saved: %s tier=%s priority=%.2f", filename, tier, priority)
    return filename


def update_status(case_path: str, new_status: str, actor: str = "analyst") -> dict:
    if new_status not in VALID_STATUSES:
        raise ValueError(f"Invalid status: {new_status}. Must be one of {VALID_STATUSES}")

    with open(case_path) as f:
        case = json.load(f)

    case["status"] = new_status
    case["status_history"].append({
        "status": new_status,
        "timestamp": datetime.utcnow().isoformat(),
        "actor": actor
    })

    if new_status == "resolved":
        opened_at = datetime.fromisoformat(case["timestamp"])
        resolved_at = datetime.utcnow()
        case["time_to_resolve_minutes"] = round((resolved_at - opened_at).total_seconds() / 60, 1)

    with open(case_path, "w") as f:
        json.dump(case, f, indent=4)

    return case


def add_note(case_path: str, note: str, analyst: str = "analyst") -> dict:
    with open(case_path) as f:
        case = json.load(f)

    case["analyst_notes"].append({
        "timestamp": datetime.utcnow().isoformat(),
        "analyst": analyst,
        "note": note
    })

    with open(case_path, "w") as f:
        json.dump(case, f, indent=4)

    return case


def attach_evidence(case_path: str, description: str, data: dict, analyst: str = "analyst") -> dict:
    with open(case_path) as f:
        case = json.load(f)

    case["evidence"].append({
        "timestamp": datetime.utcnow().isoformat(),
        "analyst": analyst,
        "description": description,
        "data": data
    })

    with open(case_path, "w") as f:
        json.dump(case, f, indent=4)

    return case


def escalate_case(case_path: str, from_tier: str, reason: str, actor: str = "analyst") -> dict:
    tier_order = ["L1", "L2", "L3"]
    if from_tier not in tier_order or from_tier == "L3":
        raise ValueError(f"Cannot escalate from {from_tier}")

    with open(case_path) as f:
        case = json.load(f)

    new_tier = tier_order[tier_order.index(from_tier) + 1]
    new_sla_deadline = (datetime.utcnow() + timedelta(minutes=SLA_MINUTES[new_tier])).isoformat()

    case["analyst_tier"] = new_tier
    case["sla_deadline"] = new_sla_deadline
    case["sla_minutes"] = SLA_MINUTES[new_tier]
    case["escalation_history"].append({
        "from_tier": from_tier,
        "to_tier": new_tier,
        "timestamp": datetime.utcnow().isoformat(),
        "actor": actor,
        "reason": reason
    })

    with open(case_path, "w") as f:
        json.dump(case, f, indent=4)

    logger.info("Case %s escalated %s → %s", case_path, from_tier, new_tier)
    return case


def get_sla_status(case: dict) -> dict:
    if not case.get("sla_deadline"):
        return {"status": "unknown", "remaining_minutes": None}
    try:
        deadline = datetime.fromisoformat(case["sla_deadline"])
    except (ValueError, TypeError):
        return {"status": "unknown", "remaining_minutes": None}
    now = datetime.utcnow()
    remaining = (deadline - now).total_seconds() / 60

    if case.get("status") in ("resolved", "closed"):
        return {"status": "met", "remaining_minutes": None}
    if remaining < 0:
        return {"status": "breached", "remaining_minutes": round(remaining, 1)}
    if remaining < 30:
        return {"status": "at_risk", "remaining_minutes": round(remaining, 1)}
    return {"status": "on_track", "remaining_minutes": round(remaining, 1)}


def list_cases(status_filter=None, tier_filter=None) -> list:
    from glob import glob
    cases = []
    for path in sorted(glob(os.path.join(CASES_DIR, "case_*.json")), reverse=True):
        try:
            with open(path) as f:
                case = json.load(f)
        except Exception as e:
            logger.warning("Failed to parse case file %s: %s", path, e)
            continue
        try:
            if status_filter and case.get("status") != status_filter:
                continue
            if tier_filter and case.get("analyst_tier") != tier_filter:
                continue
            case.setdefault("case_id", os.path.basename(path).replace(".json", ""))
            case.setdefault("status", "open")
            case.setdefault("analyst_tier", "L1")
            case.setdefault("priority_score", 0)
            case["sla_status"] = get_sla_status(case)
            cases.append(case)
        except Exception as e:
            logger.warning("Failed to load case %s: %s", path, e)
    return cases
