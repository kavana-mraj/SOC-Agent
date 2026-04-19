import json
from llm_connector import ask_llm_json

print("[triage_agent] module imported")

_SYSTEM_PROMPT = """You are a SOC triage analyst. Analyze the incident and return JSON with these exact keys:
- decision: one of "escalate", "investigate", "monitor"
- reason: brief explanation (1-2 sentences)
- recommended_action: concrete next step
- severity: one of "critical", "high", "medium", "low"
- confidence: float 0.0-1.0 reflecting certainty in this triage decision
"""

_SEVERITY_CONFIDENCE = {
    "critical": 0.95,
    "high": 0.85,
    "medium": 0.65,
    "low": 0.50,
}


def triage_incident(incident):
    result = ask_llm_json(
        _SYSTEM_PROMPT,
        f"Incident to triage:\n{json.dumps(incident, indent=2)}"
    )

    if result and all(k in result for k in ("decision", "reason", "recommended_action", "severity")):
        confidence = float(result.get("confidence", _SEVERITY_CONFIDENCE.get(result["severity"], 0.6)))
        confidence = max(0.0, min(1.0, confidence))
        return {
            "agent_name": "Triage Agent",
            "decision": result["decision"],
            "reason": result["reason"],
            "recommended_action": result["recommended_action"],
            "severity": result["severity"],
            "confidence": confidence
        }

    return _rule_based_triage(incident)


def _rule_based_triage(incident):
    itype = incident.get("incident_type", "")

    rules = {
        "ddos_syn_flood": ("escalate", "critical", "SYN flood detected — immediate containment required", "Rate-limit or null-route source IPs", 0.95),
        "brute_force_ssh": ("escalate", "high", "SSH brute force from single source", "Block source IP and audit SSH keys", 0.88),
        "brute_force_http": ("escalate", "high", "HTTP credential stuffing detected", "Block source IP and enforce MFA", 0.85),
        "port_scan": ("investigate", "medium", "Port scan indicates reconnaissance activity", "Identify scanner and check for follow-on connections", 0.80),
        "dns_tunneling": ("escalate", "high", "High-volume DNS may indicate tunneling/exfil", "Block external DNS and inspect payload", 0.82),
        "lateral_movement": ("escalate", "high", "Internal lateral movement on admin protocols", "Isolate source host immediately", 0.90),
        "repeated_suspicious_destination": ("escalate", "high", "Multiple connections to suspicious destination", "Investigate source host and block destination if confirmed", 0.80),
        "suspicious_port_access": ("investigate", "medium", "Connection to SSH port 22", "Validate whether SSH access is authorized", 0.65),
        "malware_c2": ("escalate", "critical", "Suspected C2 beacon pattern", "Isolate host and image for forensics", 0.93),
        "data_exfiltration": ("escalate", "critical", "Suspected data exfiltration", "Block egress and preserve logs", 0.92),
        "phishing": ("escalate", "high", "Phishing activity detected", "Block sender and alert affected users", 0.85),
        "privilege_escalation": ("escalate", "critical", "Privilege escalation attempt", "Lock account and audit privilege grants", 0.92),
    }

    if itype in rules:
        dec, sev, reason, action, conf = rules[itype]
        return {
            "agent_name": "Triage Agent",
            "decision": dec,
            "reason": reason,
            "recommended_action": action,
            "severity": sev,
            "confidence": conf
        }

    return {
        "agent_name": "Triage Agent",
        "decision": "monitor",
        "reason": "No high-confidence malicious pattern identified",
        "recommended_action": "Continue monitoring",
        "severity": "low",
        "confidence": 0.40
    }
