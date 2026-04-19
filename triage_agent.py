def triage_incident(incident):
    if incident["incident_type"] == "repeated_suspicious_destination":
        return {
            "agent_name": "Triage Agent",
            "decision": "escalate",
            "reason": "Multiple connections to suspicious destination detected",
            "recommended_action": "Investigate source host and block destination if confirmed malicious"
        }

    if incident["incident_type"] == "suspicious_port_access":
        return {
            "agent_name": "Triage Agent",
            "decision": "investigate",
            "reason": "Connection observed to SSH port 22",
            "recommended_action": "Validate whether SSH access is authorized"
        }

    return {
        "agent_name": "Triage Agent",
        "decision": "monitor",
        "reason": "No high-confidence malicious pattern identified",
        "recommended_action": "Continue monitoring"
    }