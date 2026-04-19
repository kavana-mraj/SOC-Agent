PROJECT_SCOPE = {
    "goal": "Build an AI-based autonomous SOC with LLM-connected agents, optional human-in-the-loop, vendor API integration, and demo UI",
    "core_modules": [
        "Detection Engine",
        "Triage Agent",
        "Investigation Agent",
        "Decision Agent",
        "Response Agent",
        "LLM Connector",
        "Confidence Evaluator",
        "Human Review Gate",
        "Vendor Integration Layer",
        "UI Dashboard"
    ],
    "execution_flow": [
        "PCAP or log input",
        "Detection Engine generates incident",
        "Triage Agent analyzes incident with LLM",
        "Investigation Agent enriches context",
        "Decision Agent assigns action and confidence score",
        "If confidence >= threshold: autonomous response",
        "If confidence < threshold: send to human review",
        "Save case",
        "Show result in UI"
    ],
    "future_inputs": [
        "PCAP files",
        "SIEM alerts",
        "EDR alerts",
        "Firewall logs",
        "Email security alerts",
        "Cloud security alerts"
    ],
    "future_outputs": [
        "Case creation",
        "Analyst review queue",
        "Block IP",
        "Disable user",
        "Create ticket",
        "Send notification"
    ]
}

print(PROJECT_SCOPE)