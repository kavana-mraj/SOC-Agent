def respond_to_incident(incident, triage_result, decision_result):
    print("[response_agent] respond_to_incident called: action_hint=", decision_result.get("action"))
    action = decision_result.get("action", "notify_analyst")
    auto = decision_result.get("auto_respond", False)

    action_messages = {
        "block_ip": f"AUTO: Blocking IP {incident['dst_ip']} — confirmed malicious",
        "disable_user": f"AUTO: Disabling user account associated with {incident['src_ip']}",
        "create_ticket": f"Ticket created for incident: {incident['incident_type']} from {incident['src_ip']}",
        "notify_analyst": f"Analyst notified: {incident['incident_type']} from {incident['src_ip']} → {incident['dst_ip']}",
        "monitor_only": f"Monitoring only — no action for {incident['incident_type']}"
    }

    return {
        "agent_name": "Response Agent",
        "action": action,
        "automated": auto,
        "status": "executed" if auto else "pending_human_approval",
        "message": action_messages.get(action, f"Action: {action}")
    }
