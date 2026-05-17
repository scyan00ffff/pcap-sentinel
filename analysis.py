from scapy.all import rdpcap
from detectors.syn_scan import SynScanDetector
from progress import update_progress, set_complete, reset


def run(pcap_path: str):
    reset()
    print(f"\n[*] Loading packets from {pcap_path}...")
    

    packets = rdpcap(pcap_path) #reads pcap files from the pcap path 
    print(f"[*] {len(packets)} packets loaded.") #prints number of packets in pcap file 

    
    # initalises the detectors to be run, add future detectors here
    detectors = [
        SynScanDetector(threshold=50)
    ]
 
    all_findings = []
    total = len(detectors)

    for i, detector in enumerate(detectors):
        name = detector.__class__.__name__ #gets name of the detector currently running 
        print(f"\n[*] Running {name}...")
        findings = detector.analyze(packets) #calls the analyze function to run
        update_progress(name, i + 1, total)

        if findings:
            print(f"[!] {len(findings)} finding(s) from {name}:")
            
            for f in findings:
                print(f"\n[{f['Severity']}]")
                print(f"{f['Description']}")
                if 'Detail' in f:
                    print(f"{f['Detail']}")
                elif 'ports_probed' in f:
                    print(f"Probed {f['ports_probed']} distinct ports")
                    print(f"Risky ports hit: {f['risky_ports_count']}")
                else:
                    print("See dashboard for summary")

        else:
            print(f"[+] No findings from {name}.")

        all_findings.extend(findings) #adds all findings to the list

    print(f"\n[*] Scan complete. {len(all_findings)} total finding(s).")
    set_complete()
    return all_findings