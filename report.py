from flask import Flask, render_template 

app = Flask(__name__)

findings_data = []

@app.route("/")
def dashboard():
    info_findings = [f for f in findings_data if f['Severity'] == 'INFO']
    high_findings = [f for f in findings_data if f['Severity'] != 'INFO']
    return render_template("dashboard.html",
                            findings = high_findings,
                            info_findings=info_findings)

def start_server(findings):
    global findings_data
    findings_data = findings
    app.run(debug=False, port=5000)

