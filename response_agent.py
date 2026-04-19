def respond_to_incident(incident, verdict):
    if verdict["decision"] == "escalate":
        return {
            "agent_name": "Response Agent",
            "action": "create_case",
            "status": "ready",
            "message": f"Security case created for {incident['src_ip']} communicating with {incident['dst_ip']}"
        }

    if verdict["decision"] == "investigate":
        return {
            "agent_name": "Response Agent",
            "action": "assign_for_review",
            "status": "pending_analysis",
            "message": f"Incident queued for analyst review: {incident['incident_type']}"
        }

    return {
        "agent_name": "Response Agent",
        "action": "monitor_only",
        "status": "no_action",
        "message": "No response action taken"
    }