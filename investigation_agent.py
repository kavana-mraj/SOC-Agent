def investigate_incident(incident, events):
    related_events = []

    for event in events:
        if event["src_ip"] == incident["src_ip"] and event["dst_ip"] == incident["dst_ip"]:
            related_events.append(event)

    return {
        "agent_name": "Investigation Agent",
        "summary": f"Found {len(related_events)} related events between {incident['src_ip']} and {incident['dst_ip']}",
        "related_events_count": len(related_events),
        "source_ip": incident["src_ip"],
        "destination_ip": incident["dst_ip"]
    }