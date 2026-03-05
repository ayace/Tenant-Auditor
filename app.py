import os
import json
import threading
from glob import glob
from datetime import datetime, timezone
from flask import Flask, render_template, jsonify
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

_audit_state = {"running": False, "error": None}


def _load_runs():
    files = sorted(glob("runs/*.json"), reverse=True)
    runs = []
    for f in files:
        try:
            with open(f, encoding="utf-8") as fh:
                runs.append(json.load(fh))
        except Exception:
            continue
    return runs


def _run_audit_background():
    from main import run_audit, save_run
    _audit_state["running"] = True
    _audit_state["error"] = None
    try:
        tenant_id = os.getenv("TENANT_ID")
        results, score = run_audit()
        save_run(tenant_id, results, score)
    except Exception as e:
        _audit_state["error"] = str(e)
    finally:
        _audit_state["running"] = False


@app.route("/")
def index():
    runs = _load_runs()
    latest = runs[0] if runs else None
    history = [
        {"timestamp": r["timestamp"], "score": r["score"]["overall"]}
        for r in reversed(runs)
    ]
    return render_template("index.html", latest=latest, history=history, state=_audit_state)


@app.route("/api/run", methods=["POST"])
def trigger_run():
    if _audit_state["running"]:
        return jsonify({"status": "already_running"}), 409
    thread = threading.Thread(target=_run_audit_background, daemon=True)
    thread.start()
    return jsonify({"status": "started"})


@app.route("/api/status")
def audit_status():
    return jsonify(_audit_state)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
