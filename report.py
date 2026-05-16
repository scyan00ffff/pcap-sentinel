from flask import Flask, render_template 

app = Flask(__name__)

findings_data = []

@app.route("/")
def dashboard():
    info_findings = [f for f in findings_data if f['Severity'] == 'INFO']
    high_findings = [f for f in findings_data if f['Severity'] != 'INFO']
    summary = info_findings[0] if info_findings else None
    return render_template("dashboard.html",
                            findings = high_findings,
                            summary=summary)

def start_server(findings):
    global findings_data
    findings_data = findings
    app.run(debug=False, port=5000)

