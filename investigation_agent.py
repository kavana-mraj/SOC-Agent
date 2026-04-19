import json
import logging
from llm_connector import ask_llm_json


def _json_safe(obj):
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_json_safe(i) for i in obj]
    try:
        json.dumps(obj)
        return obj
    except TypeError:
        return str(obj)

logger = logging.getLogger(__name__)
logger.info("[Investigation Agent] module imported")

_SYSTEM_PROMPT = """You are a SOC investigation analyst. Given an incident and related network events, return JSON with:
- summary: what is happening (2-3 sentences)
- threat_indicators: list of suspicious observations
- attacker_hypothesis: likely attack type or intent
- recommended_containment: immediate containment steps (list)
- confidence: float 0.0-1.0 reflecting confidence in this investigation
"""


def investigate_incident(incident, events):
    logger.info("investigate_incident called: incident_type=%s src=%s dst=%s",
                incident.get("incident_type"), incident.get("src_ip"), incident.get("dst_ip"))

    related_events = [
        e for e in events
        if e.get("src_ip") == incident.get("src_ip") and e.get("dst_ip") == incident.get("dst_ip")
    ]

    payload = {
        "incident": incident,
        "related_events_count": len(related_events),
        "sample_events": related_events[:5]
    }

    result = ask_llm_json(
        _SYSTEM_PROMPT,
        f"Investigation context:\n{json.dumps(_json_safe(payload), indent=2)}"
    )

    if result and "summary" in result:
        confidence = float(result.get("confidence", 0.70))
        confidence = max(0.0, min(1.0, confidence))
        logger.info("LLM investigation result: summary_len=%d indicators=%d confidence=%.2f",
                    len(result.get("summary", "")), len(result.get("threat_indicators", [])), confidence)
        return {
            "agent_name": "Investigation Agent",
            "summary": result.get("summary", ""),
            "threat_indicators": result.get("threat_indicators", []),
            "attacker_hypothesis": result.get("attacker_hypothesis", "Unknown"),
            "recommended_containment": result.get("recommended_containment", []),
            "related_events_count": len(related_events),
            "source_ip": incident.get("src_ip"),
            "destination_ip": incident.get("dst_ip"),
            "confidence": confidence
        }

    logger.warning("LLM unavailable; using fallback investigation")
    return _rule_based_investigation(incident, related_events)


def _rule_based_investigation(incident, related_events):
    itype = incident.get("incident_type", "")
    src = incident.get("src_ip", "unknown")
    dst = incident.get("dst_ip", "unknown")
    count = len(related_events)

    hypotheses = {
        "brute_force_ssh": ("Automated credential attack against SSH service",
                            ["Multiple failed auth attempts", "High-frequency connections"],
                            ["Block source IP", "Enable fail2ban", "Rotate SSH keys"], 0.80),
        "brute_force_http": ("Credential stuffing or web application attack",
                             ["High request rate to login endpoint", "Single source IP"],
                             ["Block source IP", "Enable rate limiting", "Force password reset for affected users"], 0.78),
        "ddos_syn_flood": ("Distributed Denial of Service via SYN flood",
                           ["Massive SYN packet volume", "Incomplete TCP handshakes"],
                           ["Activate SYN cookies", "Rate-limit at border", "Contact upstream ISP"], 0.90),
        "port_scan": ("Reconnaissance / network mapping prior to attack",
                      ["Sequential port probing", "Multiple dst ports from single src"],
                      ["Block scanning IP", "Review exposed services", "Enable IDS signatures"], 0.75),
        "lateral_movement": ("Attacker pivoting through internal network",
                             ["Admin protocol use (SMB/RDP/WinRM)", "Internal src→dst"],
                             ["Isolate source host", "Audit AD/service accounts", "Inspect logs on target"], 0.85),
        "dns_tunneling": ("Data exfiltration or C2 via DNS",
                          ["Abnormal DNS query volume", "Long subdomain labels"],
                          ["Block external DNS", "Capture DNS traffic for analysis", "Check for data exfil"], 0.82),
        "repeated_suspicious_destination": ("Possible C2 beacon or exfiltration",
                                            ["Repeated connections to external IP", "Consistent interval"],
                                            ["Block destination IP", "Forensic capture of src host"], 0.75),
    }

    hyp, indicators, containment, confidence = hypotheses.get(
        itype,
        ("Unknown threat pattern",
         [f"Found {count} related events between {src} and {dst}"],
         ["Escalate to L2 for manual review"],
         0.45)
    )

    return {
        "agent_name": "Investigation Agent",
        "summary": f"{itype.replace('_', ' ').title()} detected from {src} to {dst}. {count} related events captured.",
        "threat_indicators": indicators,
        "attacker_hypothesis": hyp,
        "recommended_containment": containment,
        "related_events_count": count,
        "source_ip": src,
        "destination_ip": dst,
        "confidence": confidence
    }
