from flask import Flask, render_template 
from collections import Counter 
from collections import defaultdict

app = Flask(__name__)

findings_data = []

@app.route("/")
def overview():
    total = len(findings_data)
    #getting summary findings for port classification 

    high = len([f for f in findings_data if f.get('Severity') == 'HIGH'])
    medium = len([f for f in findings_data if f.get('Severity') == 'MEDIUM'])
    low = len([f for f in findings_data if f.get('Severity') == 'LOW'])

    #getting summary findings for top ports data

    summary = next((f for f in findings_data if f.get('Severity') == 'INFO'), None)

    high_risk_ports = list(summary.get('high_risk_port_nums', [])) if summary else []
    medium_risk_ports = list(summary.get('medium_risk_port_nums', [])) if summary else []

    #counts the results per scanner 

    scanner_counts = Counter(f.get('scanner') for f in findings_data if f.get('scanner') and f.get('Severity') != 'INFO')

    #ip severity score calculator 

    severity_points = {"HIGH": 10, "MEDIUM": 5, "LOW":1}
    threat_scores = defaultdict(int)
    threat_highest_severity = {}

    for f in findings_data:
        src = f.get('src')
        severity = f.get('Severity')
        if src and severity in severity_points:
            threat_scores[src] += severity_points[severity]
            current = threat_highest_severity.get(src, 'LOW')
            if severity == 'HIGH' or (severity == 'MEDIUM' and current == 'LOW'):
                threat_highest_severity[src] = severity

    top_threats = sorted(threat_scores.items(), key=lambda x: x[1], reverse=True)[:10]
    threat_labels = [ip for ip, _ in top_threats]
    threat_scores_data = [score for _, score in top_threats]
    threat_colours = [
        '#a00817' if threat_highest_severity.get(ip) == 'HIGH'
        else 'rgb(201, 111, 9)' if threat_highest_severity.get(ip) == 'MEDIUM'
        else 'rgb(1, 94, 1)'
        for ip in threat_labels
    ]

    return render_template("overview.html",
                           current_page="overview",
                           total = total,
                           high = high,
                           medium = medium,
                           low = low,
                           summary = summary,
                           high_risk_ports = high_risk_ports,
                           medium_risk_ports = medium_risk_ports,
                           scanner_counts = scanner_counts,
                           threat_labels = threat_labels,
                           threat_scores_data = threat_scores_data,
                           threat_colours = threat_colours
                           )

@app.route("/syn")
def syn():
    info_findings = [f for f in findings_data if f['Severity'] == 'INFO']
    high_low_findings = [f for f in findings_data if f['Severity'] != 'INFO']
    summary = info_findings[0] if info_findings else None
    return render_template("syn.html",
                            findings = high_low_findings,
                            summary=summary,
                            current_page = "syn",
                            high_risk_ports =list(summary['high_risk_port_nums']) if summary else [],
                            medium_risk_ports = list(summary['medium_risk_port_nums']) if summary else [])

@app.route("/credential-detection")
def credential_detection():
    return render_template("placeholder.html", current_page="credential")

@app.route("/data-exfiltration")
def data_exfiltration():
    return render_template("placeholder.html", current_page="data")

@app.route("/dns-tunnelling")
def dns_tunnelling():
    return render_template("placeholder.html", current_page="dns")

@app.route("/brute-force")
def brute_force():
    return render_template("placeholder.html", current_page="bruteforce")

@app.route("/anomolous-traffic")
def anomolous_traffic():
    return render_template("placeholder.html", current_page="anomolous")

@app.route("/threat-intel")
def threat_intel():
    return render_template("placeholder.html", current_page="threat")

@app.route("/live")
def live():
    return render_template("placeholder.html", current_page="live")

def start_server(findings):
    global findings_data
    findings_data = findings
    app.run(debug=False, port=5000)

