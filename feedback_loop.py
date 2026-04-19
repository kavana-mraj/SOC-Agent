"""Feedback loop — closed cases feed rule performance stats for tuning."""

import json
import os
from glob import glob
from collections import Counter, defaultdict
from datetime import datetime

FEEDBACK_DB = "cases/feedback_stats.json"


def _load_stats() -> dict:
    if os.path.exists(FEEDBACK_DB):
        with open(FEEDBACK_DB) as f:
            return json.load(f)
    return {"rules": {}, "last_updated": None}


def _save_stats(stats: dict):
    os.makedirs("cases", exist_ok=True)
    with open(FEEDBACK_DB, "w") as f:
        json.dump(stats, f, indent=2)


def ingest_closed_cases():
    """Scan closed/resolved cases and accumulate outcome stats per rule."""
    stats = _load_stats()
    rules = stats.setdefault("rules", {})

    for path in glob("cases/case_*.json"):
        try:
            with open(path) as f:
                case = json.load(f)
        except Exception:
            continue

        if case.get("status") not in ("resolved", "closed"):
            continue

        case_id = case.get("case_id", os.path.basename(path))
        if case_id in stats.get("processed_cases", []):
            continue

        itype = case.get("incident", {}).get("incident_type", "unknown")
        decision = case.get("decision_result", {})
        response = case.get("response_action", {})
        analyst_decision = None

        review_path = "cases/review_queue.json"
        if os.path.exists(review_path):
            with open(review_path) as f:
                queue = json.load(f)
            for entry in queue:
                if entry.get("case_id") == case_id:
                    analyst_decision = entry.get("analyst_decision")
                    break

        rec = rules.setdefault(itype, {
            "total": 0, "auto_resolved": 0, "human_approved": 0,
            "human_rejected": 0, "escalated": 0, "avg_confidence": 0.0
        })

        rec["total"] += 1
        conf = decision.get("confidence", 0.5)
        rec["avg_confidence"] = round(
            (rec["avg_confidence"] * (rec["total"] - 1) + conf) / rec["total"], 3
        )

        if response.get("automated"):
            rec["auto_resolved"] += 1
        if analyst_decision == "approved":
            rec["human_approved"] += 1
        elif analyst_decision == "rejected":
            rec["human_rejected"] += 1

        if case.get("escalation_history"):
            rec["escalated"] += 1

        stats.setdefault("processed_cases", []).append(case_id)

    stats["last_updated"] = datetime.utcnow().isoformat()
    _save_stats(stats)
    return stats


def get_rule_performance() -> list:
    stats = ingest_closed_cases()
    rows = []
    for rule, rec in stats["rules"].items():
        total = rec["total"]
        if total == 0:
            continue
        false_positive_rate = round(rec["human_rejected"] / total, 3) if total else 0.0
        rows.append({
            "rule": rule,
            "total_cases": total,
            "auto_resolved": rec["auto_resolved"],
            "human_approved": rec["human_approved"],
            "human_rejected": rec["human_rejected"],
            "escalated": rec["escalated"],
            "avg_confidence": rec["avg_confidence"],
            "false_positive_rate": false_positive_rate,
            "suggested_threshold_adjustment": (
                "lower_confidence_threshold" if false_positive_rate > 0.2 else
                "raise_confidence_threshold" if false_positive_rate < 0.05 and total > 5 else
                "no_change"
            )
        })
    rows.sort(key=lambda r: r["false_positive_rate"], reverse=True)
    return rows
