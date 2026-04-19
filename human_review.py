import json
import os
from datetime import datetime

_HERE = os.path.dirname(os.path.abspath(__file__))
REVIEW_QUEUE_FILE = os.path.join(_HERE, "cases", "review_queue.json")


def _load_queue():
    if not os.path.exists(REVIEW_QUEUE_FILE):
        return []
    with open(REVIEW_QUEUE_FILE) as f:
        return json.load(f)


def _save_queue(queue):
    os.makedirs(os.path.dirname(REVIEW_QUEUE_FILE), exist_ok=True)
    with open(REVIEW_QUEUE_FILE, "w") as f:
        json.dump(queue, f, indent=2)


def queue_for_review(case_id, incident, triage_result, investigation_result, decision_result):
    queue = _load_queue()
    entry = {
        "case_id": case_id,
        "queued_at": datetime.utcnow().isoformat(),
        "status": "pending",
        "analyst_tier": triage_result.get("analyst_tier", "L1"),
        "incident": incident,
        "triage": triage_result,
        "investigation": investigation_result,
        "decision": decision_result,
        "analyst_decision": None,
        "analyst_notes": None,
        "evidence": [],
        "escalation_history": [],
        "reviewed_at": None,
        "reviewed_by": None
    }
    queue.append(entry)
    _save_queue(queue)
    return entry


def approve(case_id, analyst_notes="", analyst="analyst"):
    return _update_review(case_id, "approved", analyst_notes, analyst)


def reject(case_id, analyst_notes="", analyst="analyst"):
    return _update_review(case_id, "rejected", analyst_notes, analyst)


def _update_review(case_id, decision, analyst_notes, analyst="analyst"):
    queue = _load_queue()
    for entry in queue:
        if entry["case_id"] == case_id:
            entry["status"] = decision
            entry["analyst_decision"] = decision
            entry["analyst_notes"] = analyst_notes
            entry["reviewed_at"] = datetime.utcnow().isoformat()
            entry["reviewed_by"] = analyst
            _save_queue(queue)
            return entry
    return None


def add_evidence(case_id, description, data, analyst="analyst"):
    queue = _load_queue()
    for entry in queue:
        if entry["case_id"] == case_id:
            entry.setdefault("evidence", []).append({
                "timestamp": datetime.utcnow().isoformat(),
                "analyst": analyst,
                "description": description,
                "data": data
            })
            _save_queue(queue)
            return entry
    return None


def escalate(case_id, from_tier, reason, actor="analyst"):
    tier_order = ["L1", "L2", "L3"]
    if from_tier not in tier_order or from_tier == "L3":
        raise ValueError(f"Cannot escalate from {from_tier}")

    new_tier = tier_order[tier_order.index(from_tier) + 1]
    queue = _load_queue()
    for entry in queue:
        if entry["case_id"] == case_id:
            entry["analyst_tier"] = new_tier
            entry.setdefault("escalation_history", []).append({
                "from_tier": from_tier,
                "to_tier": new_tier,
                "timestamp": datetime.utcnow().isoformat(),
                "actor": actor,
                "reason": reason
            })
            _save_queue(queue)
            return entry
    return None


def list_pending():
    return [e for e in _load_queue() if e["status"] == "pending"]


def list_by_tier(tier):
    return [e for e in _load_queue() if e.get("analyst_tier") == tier and e["status"] == "pending"]


def get_entry(case_id):
    for e in _load_queue():
        if e["case_id"] == case_id:
            return e
    return None
