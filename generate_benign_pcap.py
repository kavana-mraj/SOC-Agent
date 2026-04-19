from scapy.all import Ether, IP, TCP, wrpcap

packets = []

for i in range(3):
    pkt = (
        Ether()
        / IP(src="192.168.1.50", dst="192.168.1.60")
        / TCP(sport=3000 + i, dport=443)
    )
    packets.append(pkt)

wrpcap("data/benign_test.pcap", packets)

print("PCAP file generated: data/benign_test.pcap")