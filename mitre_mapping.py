"""Static MITRE ATT&CK technique mapping per incident type."""

TECHNIQUE_MAP = {
    "repeated_suspicious_destination": [
        {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
        {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    ],
    "suspicious_port_access": [
        {"id": "T1021.004", "name": "Remote Services: SSH", "tactic": "Lateral Movement"},
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    ],
    "brute_force_ssh": [
        {"id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access"},
        {"id": "T1021.004", "name": "Remote Services: SSH", "tactic": "Lateral Movement"},
    ],
    "brute_force_http": [
        {"id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access"},
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"},
    ],
    "port_scan": [
        {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
        {"id": "T1595.001", "name": "Active Scanning: Scanning IP Blocks", "tactic": "Reconnaissance"},
    ],
    "ddos_syn_flood": [
        {"id": "T1498.001", "name": "Network DoS: Direct Network Flood", "tactic": "Impact"},
    ],
    "lateral_movement": [
        {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
        {"id": "T1570", "name": "Lateral Tool Transfer", "tactic": "Lateral Movement"},
    ],
    "dns_tunneling": [
        {"id": "T1071.004", "name": "Application Layer Protocol: DNS", "tactic": "Command and Control"},
        {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    ],
    "malware_c2": [
        {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
        {"id": "T1573", "name": "Encrypted Channel", "tactic": "Command and Control"},
    ],
    "privilege_escalation": [
        {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
        {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"},
    ],
    "phishing": [
        {"id": "T1566", "name": "Phishing", "tactic": "Initial Access"},
        {"id": "T1204", "name": "User Execution", "tactic": "Execution"},
    ],
    "data_exfiltration": [
        {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
        {"id": "T1030", "name": "Data Transfer Size Limits", "tactic": "Exfiltration"},
    ],
}


def get_techniques(incident_type: str) -> list:
    return TECHNIQUE_MAP.get(incident_type, [
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}
    ])
