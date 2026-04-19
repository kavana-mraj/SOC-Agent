import json
from llm_connector import ask_llm_json

print("[decision_agent] module imported")

_SYSTEM_PROMPT = """You are a SOC decision agent. Given triage and investigation results, determine autonomous response action and confidence.

Return JSON with:
- action: one of "block_ip", "disable_user", "create_ticket", "notify_analyst", "monitor_only"
- confidence: float 0.0-1.0 (how confident you are in this action)
- reasoning: why this action at this confidence (2-3 sentences)
- auto_respond: boolean — true only if confidence >= 0.85 and action is safe to automate
"""

CONFIDENCE_THRESHOLD = 0.85

def decide(incident, triage_result, investigation_result):
    payload = {
        "incident": incident,
        "triage": triage_result,
        "investigation": investigation_result
    }

    result = ask_llm_json(
        _SYSTEM_PROMPT,
        f"Decision context:\n{json.dumps(payload, indent=2)}"
    )

    if result and "action" in result and "confidence" in result:
        confidence = float(result.get("confidence", 0.0))
        auto_respond = confidence >= CONFIDENCE_THRESHOLD and result.get("auto_respond", False)
        return {
            "agent_name": "Decision Agent",
            "action": result["action"],
            "confidence": confidence,
            "reasoning": result.get("reasoning", ""),
            "auto_respond": auto_respond,
            "requires_human_review": not auto_respond
        }

    # fallback: conservative default
    return {
        "agent_name": "Decision Agent",
        "action": "notify_analyst",
        "confidence": 0.5,
        "reasoning": "LLM unavailable; defaulting to human review",
        "auto_respond": False,
        "requires_human_review": True
    }
