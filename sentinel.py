import argparse 
from scapy.all import rdpcap 
from detectors.syn_scan import SynScanDetector

def run(pcap_path: str):
    print(f"\n[*] Loading packets from {pcap_path}...")

    packets = rdpcap(pcap_path) #reads pcap files from the pcap path 
    print(f"[*] {len(packets)} packets loaded.") #prints number of packets in pcap file 

    
    # initalises the detectors to be run, add future detectors here
    detectors = [
        SynScanDetector(threshold=50)
    ]
 
    all_findings = []

    for detector in detectors:
        name = detector.__class__.__name__ #gets name of the detector currently running 
        print(f"\n[*] Running {name}...")
        findings = detector.analyze(packets) #calls the analyze function to run

        if findings:
            print(f"[!] {len(findings)} finding(s) from {name}:")
            
            for f in findings:
                print(f"[{f['Severity']}]")
                print(f"[{f['Description']}")
                print(f"{f['Detail']}")

        else:
            print(f"[+] No findings from {name}.")

        all_findings.extend(findings) #adds all findings to the list

    print(f"\n[*] Scan complete. {len(all_findings)} total finding(s).")
    return all_findings

if __name__ == "__main__": #only true when file ran directly not imported

    parser = argparse.ArgumentParser(
        description="pcap-sentinel - network threat detector"
    )

    parser.add_argument("pcap", help="Path to the .pcap file to analyse")

    parser.add_argument(
        "--threshold-ports",
        type=int,
        default=50,
        help="Number of distinct ports to trigger SYN scan alert (default: 50)"
    )

    args = parser.parse_args()

    run(args.pcap)