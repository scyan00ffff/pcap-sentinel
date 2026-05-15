from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP

packets = rdpcap("C:/Users/reube/Documents/Uni/custB.pcap")  # adjust path if needed

syn_counts = {}

for pkt in packets:
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        tcp = pkt[TCP]
        ip = pkt[IP]
        if str(tcp.flags) == "S":
            src = ip.src
            if src not in syn_counts:
                syn_counts[src] = set()
            syn_counts[src].add(tcp.dport)

print(f"\nTotal IPs sending SYN packets: {len(syn_counts)}")
print("\nTop 10 by distinct ports probed:")
sorted_ips = sorted(syn_counts.items(), key=lambda x: len(x[1]), reverse=True)
for ip, ports in sorted_ips[:10]:
    print(f"  {ip} -> {len(ports)} ports")