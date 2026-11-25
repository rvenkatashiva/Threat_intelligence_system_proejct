"""
AI-Based Endpoint Threat Intelligence Correlation System for Zero-Day Attack Identification

Pipeline (matches project abstract):
  1. module1_collect — continuous endpoint metrics (CPU, memory, processes, network, disk).
  2. module2_detect — Isolation Forest anomaly detection vs learned normal patterns.
  3. module3_correlate — threat-intelligence correlation: MITRE ATT&CK techniques + risk.
  4. module4_alert — prioritized alerts for the monitoring dashboard.

Auth: FLASK_SECRET_KEY for sessions; optional DASHBOARD_USER/PASSWORD fallback; registered users in users.db (see auth_users).
"""
import os
from functools import wraps

from flask import Flask, jsonify, redirect, render_template, request, session, url_for

import auth_users
import module1_collect
import module2_detect
import module3_correlate
import module4_alert

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-only-change-with-FLASK_SECRET_KEY")

DASHBOARD_USER = os.environ.get("DASHBOARD_USER", "admin")
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "admin")

auth_users.init_db()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("logged_in"):
            return view(*args, **kwargs)
        if request.path.startswith("/api/"):
            return jsonify({"error": "Unauthorized", "login": url_for("login")}), 401
        p = request.path
        if p and p != "/" and p.startswith("/"):
            return redirect(url_for("login", next=p))
        return redirect(url_for("login"))

    return wrapped


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))

    err = None
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        p2 = request.form.get("password2", "")
        ok, msg = auth_users.register_user(u, p, p2)
        if ok:
            session["logged_in"] = True
            return redirect(url_for("dashboard"))
        err = msg

    return render_template("signup.html", error=err)


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))

    err = None
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        if auth_users.verify_login(u, p) or (u == DASHBOARD_USER and p == DASHBOARD_PASSWORD):
            session["logged_in"] = True
            nxt = request.form.get("next") or request.args.get("next") or url_for("dashboard")
            if isinstance(nxt, str) and nxt.startswith("/") and not nxt.startswith("//"):
                return redirect(nxt)
            return redirect(url_for("dashboard"))
        err = "Invalid operator ID or access key."

    return render_template("login.html", error=err)


@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/metrics")
@login_required
def api_metrics():
    metrics = module1_collect.collect_metrics()
    anomaly = module2_detect.detect_anomalies(metrics)
    correlations = module3_correlate.correlate(metrics)

    alert = module4_alert.generate_alert(anomaly, correlations, metrics)
    module4_alert.log_alert(alert)

    return jsonify({
        "metrics": metrics,
        "anomaly": anomaly,
        "correlations": correlations,
        "alert": alert,
        "summary": module4_alert.get_alert_summary()
    })

if __name__ == "__main__":
    app.run(debug=True)