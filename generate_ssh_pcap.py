from scapy.all import Ether, IP, TCP, wrpcap

packets = []

for i in range(3):
    pkt = (
        Ether()
        / IP(src="10.10.10.5", dst="192.168.1.20")
        / TCP(sport=2000 + i, dport=22)
    )
    packets.append(pkt)

wrpcap("data/ssh_test.pcap", packets)

print("PCAP file generated: data/ssh_test.pcap")