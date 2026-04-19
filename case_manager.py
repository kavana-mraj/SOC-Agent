import json
from datetime import datetime
import os

def save_case(incident, verdict, investigation, response, source_name):
    severity_map = {
        "low": 1,
        "medium": 2,
        "high": 3
    }

    os.makedirs("cases", exist_ok=True)

    timestamp = datetime.now()
    filename = f"cases/case_{source_name}_{timestamp.strftime('%Y%m%d_%H%M%S')}.json"

    case_data = {
        "timestamp": timestamp.isoformat(),
        "source_name": source_name,
        "incident": incident,
        "triage_verdict": verdict,
        "investigation_result": investigation,
        "response_action": response,
        "priority_score": severity_map.get(incident.get("severity", "low"), 1),
        "decision_summary": f"{incident['incident_type']} was reviewed by {verdict['agent_name']} and the final action is {response['action']}"
    }

    with open(filename, "w") as f:
        json.dump(case_data, f, indent=4)

    return filename