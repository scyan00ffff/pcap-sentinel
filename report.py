from flask import Flask, render_template 

app = Flask(__name__)

findings_data = []

@app.route("/")
def dashboard():
    return render_template("dashboard.html", findings = findings_data)

def start_server(findings):
    global findings_data
    findings_data = findings
    app.run(debug=False, port=5000)

