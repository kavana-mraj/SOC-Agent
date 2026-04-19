from scapy.all import IP, TCP

def generate_events(packets):
    events = []

    for pkt in packets:
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            event = {
                "type": "network_connection",
                "src_ip": src_ip,
                "dst_ip": dst_ip
            }

            if pkt.haslayer(TCP):
                event["protocol"] = "TCP"
                event["dst_port"] = pkt[TCP].dport

            events.append(event)

    return events


def detect_incident(events):
    # Rule 1: repeated connections to suspicious destination
    incident_count = 0
    for e in events:
        if e["dst_ip"] == "8.8.8.8":
            incident_count += 1

    if incident_count > 0:
        return {
            "incident_type": "repeated_suspicious_destination",
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "total_hits": incident_count,
            "severity": "high" if incident_count >= 5 else "medium"
        }

    # Rule 2: suspicious port access (example: port 22 - SSH)
    for e in events:
        if e.get("dst_port") == 22:
            return {
                "incident_type": "suspicious_port_access",
                "src_ip": e["src_ip"],
                "dst_ip": e["dst_ip"],
                "dst_port": 22,
                "severity": "medium"
            }

    return None