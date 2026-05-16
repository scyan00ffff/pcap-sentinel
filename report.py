from flask import Flask, render_template 

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

    return render_template("overview.html",
                           current_page="overview",
                           total = total,
                           high = high,
                           medium = medium,
                           low = low,
                           summary = summary,
                           high_risk_ports = high_risk_ports,
                           medium_risk_ports = medium_risk_ports
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

