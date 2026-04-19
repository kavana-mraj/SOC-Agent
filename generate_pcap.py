from scapy.all import Ether, IP, TCP, wrpcap

packets = []

for i in range(5):
    pkt = (
        Ether()
        / IP(src="192.168.1.10", dst="8.8.8.8")
        / TCP(sport=1000 + i, dport=80)
    )
    packets.append(pkt)

wrpcap("data/generated_ether.pcap", packets)

print("PCAP file generated: data/generated_ether.pcap")