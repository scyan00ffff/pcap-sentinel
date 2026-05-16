from scapy.layers.inet import IP, TCP 
from .base import BaseDetector
import json

HIGH_RISK_PORTS = {}
MEDIUM_RISK_PORTS = {}

try:
    with open("config.json", "r") as f:
        config = json.load(f)
    HIGH_RISK_PORTS =  {int(k): v for k, v in config["high_risk_ports"].items()}
    MEDIUM_RISK_PORTS = {int(k): v for k, v in config["medium_risk_ports"].items()}
except FileNotFoundError:
    HIGH_RISK_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        80: "HTTP",
        443: "HTTPS"
    }
    MEDIUM_RISK_PORTS = {
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
        2376: "Docker-TLS",
        8888: "HTTP-Dev",
        9090: "HTTP-Alt",
        3000: "Dev-Server",
        5000: "Dev-Server",
        9200: "Elasticsearch",
        6380: "Redis-Alt"
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
        top_ports_labels = [f"{port}/{HIGH_RISK_PORTS.get(port, MEDIUM_RISK_PORTS.get(port, 'Unknown'))}" for port, count in top_ports]
        top_ports_str = "\n".join(top_ports_formatted)

        risky_hits = {port: count for port, count in aggregated_ports.items() if port in HIGH_RISK_PORTS}
        risky_hits_sorted = sorted(risky_hits.items(), key=lambda x: x[1], reverse=True)
        risky_hits_formatted = [f"{dst_port}/{HIGH_RISK_PORTS.get(dst_port, 'Unknown')}: {count} hits" for dst_port, count in risky_hits_sorted]
        risky_hits_str = "\n".join(risky_hits_formatted)

        sorted_ips_formatted = []
        sorted_ips = sorted(syn_counts.items(), key=lambda x: len(x[1]), reverse=True)
        for ip, ports in sorted_ips[:10]:
            sorted_ips_formatted.append(f"\n {ip} -> {len(ports)} ports")
            sorted_ips_str = "".join(sorted_ips_formatted)
        
        findings.append({
            "Severity": "INFO",
            "Description": "SYN Scan Summary:",
            "unique_ips": len(syn_counts),
            "top_ips": sorted_ips_formatted,
            "top_ports": top_ports_formatted,
            "top_ports_raw": top_ports,
            "top_ports_labels": top_ports_labels,
            "risky_ports": risky_hits_formatted,
            "high_risk_port_nums": list(HIGH_RISK_PORTS.keys()),
            "medium_risk_port_nums": list(MEDIUM_RISK_PORTS.keys()),
            "top_ips_raw": sorted_ips[:10],
            "top_ips_labels": [ip for ip, _ in sorted_ips[:10]],
            "top_ips_counts": [len(ports) for _, ports in sorted_ips[:10]],
            "src": None
        })
        

        for src_ip, port_counts in syn_counts.items():
            if len(port_counts) >= self.threshold:
                risky_ports = {port: count for port, count in port_counts.items() if port in HIGH_RISK_PORTS}
                risky_ports_sorted = sorted(risky_ports.items(), key= lambda x: x[1], reverse=True)
                risky_ports_formatted = [f"{dst_port}/{HIGH_RISK_PORTS.get(dst_port, 'Unknown')}: {count} hits" for dst_port, count in risky_ports_sorted]
                medium_ports = {port: count for port, count in port_counts.items() if port in MEDIUM_RISK_PORTS}
                medium_ports_sorted = sorted(medium_ports.items(), key=lambda x: x[1], reverse=True)
                medium_ports_formatted = [f"{dst_port}/{MEDIUM_RISK_PORTS.get(dst_port, 'Unkown')}: {count} hits" for dst_port, count in medium_ports_sorted]
                if risky_ports_formatted:
                    severity = "HIGH"
                elif medium_ports_formatted:
                    severity = "MEDIUM"
                    risky_ports_str = "None Detected"
                else:
                    severity = "LOW"
                    risky_ports_str = "None Detected"
                findings.append({
                    "Severity": severity,
                    "Description": f"SYN scan detected from {src_ip}",
                    "ports_probed": len(port_counts),
                    "risky_ports_count": len(risky_ports_formatted),
                    "risky_ports_list": risky_ports_formatted,
                    "medium_ports_list": medium_ports_formatted,
                    "src": src_ip
                })

        return(findings)