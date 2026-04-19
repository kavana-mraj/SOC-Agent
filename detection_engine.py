from scapy.all import IP, TCP, UDP, ICMP
from collections import Counter, defaultdict
from mitre_mapping import get_techniques

print("[detection_engine] module imported")

# Thresholds
BRUTE_FORCE_SSH_THRESHOLD = 5      # distinct packets to port 22 from same src
BRUTE_FORCE_HTTP_THRESHOLD = 20    # same src → port 80/443 in same capture
PORT_SCAN_UNIQUE_PORTS = 15        # unique dst ports from one src → scan
DDOS_SYN_THRESHOLD = 100           # SYN packets to single dst
REPEATED_DEST_THRESHOLD = 3        # hits to same unusual dst


def generate_events(packets):
    events = []
    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        event = {
            "type": "network_connection",
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
        }
        if pkt.haslayer(TCP):
            event["protocol"] = "TCP"
            event["dst_port"] = pkt[TCP].dport
            event["src_port"] = pkt[TCP].sport
            event["flags"] = pkt[TCP].flags
        elif pkt.haslayer(UDP):
            event["protocol"] = "UDP"
            event["dst_port"] = pkt[UDP].dport
        elif pkt.haslayer(ICMP):
            event["protocol"] = "ICMP"
            event["icmp_type"] = pkt[ICMP].type
        events.append(event)
    return events


def _make_incident(incident_type, src_ip, dst_ip, severity, extra=None):
    inc = {
        "incident_type": incident_type,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "severity": severity,
        "mitre_techniques": get_techniques(incident_type),
    }
    if extra:
        inc.update(extra)
    return inc


def detect_incident(events):
    if not events:
        return None

    # aggregate per source
    src_dst_counts = Counter()
    src_port_sets = defaultdict(set)
    syn_dst_counts = Counter()
    ssh_per_src = Counter()
    http_per_src = Counter()
    dns_queries = Counter()

    for e in events:
        src = e.get("src_ip", "")
        dst = e.get("dst_ip", "")
        port = e.get("dst_port")
        proto = e.get("protocol")
        flags = e.get("flags", 0)

        src_dst_counts[(src, dst)] += 1

        if port:
            src_port_sets[src].add(port)

        if proto == "TCP" and port == 22:
            ssh_per_src[src] += 1

        if proto == "TCP" and port in (80, 443, 8080, 8443):
            http_per_src[src] += 1

        if proto == "TCP" and (flags & 0x02) and not (flags & 0x10):  # SYN only
            syn_dst_counts[dst] += 1

        if proto == "UDP" and port == 53:
            dns_queries[src] += 1

    # Rule 1: DDoS SYN flood
    for dst, count in syn_dst_counts.items():
        if count >= DDOS_SYN_THRESHOLD:
            top_src = max(
                (s for s, d in src_dst_counts if d == dst),
                key=lambda s: src_dst_counts[(s, dst)],
                default="unknown"
            )
            return _make_incident(
                "ddos_syn_flood", top_src, dst, "critical",
                {"syn_count": count, "target_ip": dst}
            )

    # Rule 2: SSH brute force
    for src, count in ssh_per_src.items():
        if count >= BRUTE_FORCE_SSH_THRESHOLD:
            dst_ips = [d for (s, d) in src_dst_counts if s == src]
            dst = dst_ips[0] if dst_ips else "unknown"
            return _make_incident(
                "brute_force_ssh", src, dst, "high",
                {"attempt_count": count, "dst_port": 22}
            )

    # Rule 3: HTTP brute force
    for src, count in http_per_src.items():
        if count >= BRUTE_FORCE_HTTP_THRESHOLD:
            dst_ips = [d for (s, d) in src_dst_counts if s == src]
            dst = dst_ips[0] if dst_ips else "unknown"
            return _make_incident(
                "brute_force_http", src, dst, "high",
                {"attempt_count": count}
            )

    # Rule 4: Port scan
    for src, ports in src_port_sets.items():
        if len(ports) >= PORT_SCAN_UNIQUE_PORTS:
            dst_ips = list({d for (s, d) in src_dst_counts if s == src})
            dst = dst_ips[0] if dst_ips else "unknown"
            return _make_incident(
                "port_scan", src, dst, "medium",
                {"unique_ports_scanned": len(ports), "sample_ports": sorted(ports)[:20]}
            )

    # Rule 5: DNS tunneling (high volume DNS from single src)
    for src, count in dns_queries.items():
        if count >= 50:
            return _make_incident(
                "dns_tunneling", src, "dns_server", "high",
                {"dns_query_count": count}
            )

    # Rule 6: Repeated suspicious destination
    for (src, dst), count in src_dst_counts.items():
        if dst == "8.8.8.8" and count >= REPEATED_DEST_THRESHOLD:
            return _make_incident(
                "repeated_suspicious_destination", src, dst,
                "high" if count >= 5 else "medium",
                {"total_hits": count}
            )

    # Rule 7: Lateral movement (internal → internal on admin ports)
    ADMIN_PORTS = {445, 135, 139, 3389, 5985, 5986}
    INTERNAL = ("10.", "172.", "192.168.")
    for e in events:
        src = e.get("src_ip", "")
        dst = e.get("dst_ip", "")
        port = e.get("dst_port")
        if (any(src.startswith(p) for p in INTERNAL) and
                any(dst.startswith(p) for p in INTERNAL) and
                port in ADMIN_PORTS):
            return _make_incident(
                "lateral_movement", src, dst, "high",
                {"dst_port": port}
            )

    # Rule 8: Suspicious SSH access (any port-22 hit — lowest priority)
    for e in events:
        if e.get("dst_port") == 22:
            return _make_incident(
                "suspicious_port_access", e["src_ip"], e["dst_ip"], "medium",
                {"dst_port": 22}
            )

    return None


def correlate_events(events_list: list) -> list:
    """Group a list of incidents into correlated clusters by shared src_ip."""
    clusters = defaultdict(list)
    for inc in events_list:
        clusters[inc.get("src_ip", "unknown")].append(inc)
    return [
        {"src_ip": src, "incident_count": len(incs), "incidents": incs}
        for src, incs in clusters.items()
        if len(incs) > 1
    ]
