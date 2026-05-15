from scapy.layers.inet import IP, TCP 
from .base import BaseDetector
import json

HIGH_RISK_PORTS = {}

try:
    with open("config.json", "r") as f:
        config = json.load(f)
    HIGH_RISK_PORTS =  {int(k): v for k, v in config["high_risk_ports"].items()}
except FileNotFoundError:
    HIGH_RISK_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        80: "HTTP",
        443: "HTTPS"
    }

#print(f"[DEBUG] Loaded {len(HIGH_RISK_PORTS)} high risk ports")


class SynScanDetector(BaseDetector):

    #threshold value = number of ports probed to be flagged, lower is more sensitive
    def __init__(self, threshold=50):
        self.threshold = threshold

    def analyze(self, packets) -> list[dict]:

        findings = []
        syn_counts = {} # [src_ip: set of destination ports: times port scanned]

        for pkt in packets:
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                tcp = pkt[TCP]
                ip = pkt[IP]

                if str(tcp.flags) == "S":
                    src = ip.src
                    dst_port = tcp.dport 

                    if src not in syn_counts:
                        syn_counts[src] = dict()
                    if dst_port in syn_counts[src]:
                        syn_counts[src][dst_port] += 1
                    else:
                        syn_counts[src][dst_port] = 1
                        
        aggregated_ports = {}

        for src in syn_counts:
            for dst_port, count in syn_counts[src].items():
                if dst_port in aggregated_ports:
                    aggregated_ports[dst_port] += count
                else:
                    aggregated_ports[dst_port] = count

        top_ports = sorted(aggregated_ports.items(), key=lambda x: x[1], reverse=True)[:10] 
        top_ports_formatted = [f"{dst_port}/{HIGH_RISK_PORTS.get(dst_port, 'Unknown')}: {count} hits" for dst_port, count in top_ports]
        top_ports_str = "\n".join(top_ports_formatted)
        risky_hits = {port: count for port, count in aggregated_ports.items() if port in HIGH_RISK_PORTS}
        risky_hits_formatted = [f"{dst_port}/{HIGH_RISK_PORTS.get(dst_port, 'Unknown')}: {count} hits" for dst_port, count in risky_hits.items()]
        risky_hits_str = "\n".join(risky_hits_formatted)

        findings.append({
            "Severity": "INFO",
            "Description": "SYN Scan Summary",
            "Detail": f"\n[!]Top ports scanned: \n\n{top_ports_str}, \n\n[!]High risk ports: \n\n{risky_hits_str}, \n\n[!]Top Malicious IP's: \n\n ",
            "src": src
        })
        
        for src_ip, port_counts in syn_counts.items():
            if len(port_counts) >= self.threshold:
                findings.append({
                    "Severity": "HIGH",
                    "Description": f"SYN scan detected from {src_ip}",
                    "Detail": f"Probed {len(port_counts)} distinct ports\n", 
                    "src": src_ip
                })

        return(findings)