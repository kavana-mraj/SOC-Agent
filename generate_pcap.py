"""Generate diverse demo PCAPs that trigger ALL detection rules."""

from scapy.all import IP, TCP, UDP, Ether, wrpcap, RandShort, conf
import os

# Suppress Scapy warnings on Windows
conf.verb = 0

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
os.makedirs(DATA_DIR, exist_ok=True)


def gen_ssh_brute_force():
    """Rule 2: SSH brute force - 10 SSH attempts from single src."""
    packets = []
    for i in range(10):
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="10.20.30.40", dst="192.168.1.20") / TCP(sport=RandShort(), dport=22, flags="S")
        packets.append(pkt)
    path = os.path.join(DATA_DIR, "ssh_brute_force.pcap")
    wrpcap(path, packets)
    print("  [OK] %s -- %d packets (SSH brute force)" % (path, len(packets)))


def gen_ddos_syn_flood():
    """Rule 1: DDoS SYN flood - 120 SYN packets to same dst."""
    packets = []
    for i in range(120):
        src = "10.%d.%d.%d" % (i % 256, (i // 256) % 256, (i * 7) % 254 + 1)
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src=src, dst="192.168.1.20") / TCP(sport=RandShort(), dport=80, flags="S")
        packets.append(pkt)
    path = os.path.join(DATA_DIR, "ddos_syn_flood.pcap")
    wrpcap(path, packets)
    print("  [OK] %s -- %d packets (DDoS SYN flood)" % (path, len(packets)))


def gen_port_scan():
    """Rule 4: Port scan - 20 unique dst ports from one src."""
    packets = []
    ports = list(range(20, 45))  # 25 unique ports
    for port in ports:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="172.16.5.100", dst="192.168.1.30") / TCP(sport=RandShort(), dport=port, flags="S")
        packets.append(pkt)
    path = os.path.join(DATA_DIR, "port_scan.pcap")
    wrpcap(path, packets)
    print("  [OK] %s -- %d packets (port scan, %d unique ports)" % (path, len(packets), len(ports)))


def gen_dns_tunneling():
    """Rule 5: DNS tunneling - 60 DNS queries from single src."""
    packets = []
    for i in range(60):
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=RandShort(), dport=53)
        packets.append(pkt)
    path = os.path.join(DATA_DIR, "dns_tunneling.pcap")
    wrpcap(path, packets)
    print("  [OK] %s -- %d packets (DNS tunneling)" % (path, len(packets)))


def gen_lateral_movement():
    """Rule 7: Lateral movement - internal to internal on admin ports."""
    packets = []
    admin_ports = [445, 3389, 5985, 135]
    for port in admin_ports:
        for _ in range(3):
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="192.168.1.10", dst="10.0.0.5") / TCP(sport=RandShort(), dport=port, flags="S")
            packets.append(pkt)
    path = os.path.join(DATA_DIR, "lateral_movement.pcap")
    wrpcap(path, packets)
    print("  [OK] %s -- %d packets (lateral movement)" % (path, len(packets)))


def gen_suspicious_dest():
    """Rule 6: Repeated suspicious destination - 5+ hits to 8.8.8.8."""
    packets = []
    for i in range(7):
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="192.168.1.10", dst="8.8.8.8") / TCP(sport=RandShort(), dport=443, flags="S")
        packets.append(pkt)
    path = os.path.join(DATA_DIR, "suspicious_dest.pcap")
    wrpcap(path, packets)
    print("  [OK] %s -- %d packets (suspicious destination)" % (path, len(packets)))


if __name__ == "__main__":
    print("Generating demo PCAPs...")
    gen_ssh_brute_force()
    gen_ddos_syn_flood()
    gen_port_scan()
    gen_dns_tunneling()
    gen_lateral_movement()
    gen_suspicious_dest()
    print("\nDone -- 6 PCAPs generated in %s" % DATA_DIR)