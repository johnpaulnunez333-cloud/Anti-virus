"""NovaScan - educational antivirus demo (Flask backend)."""
import random
import threading
import time
import uuid
from datetime import datetime

from flask import Flask, jsonify, request, send_from_directory

import config
import storage
from demo_scan import DEMO_FILES, build_result
from scanner import analyze_file

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_BYTES

scan_sessions = {}
sessions_lock = threading.Lock()


# ---------- pages ----------

@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


# ---------- simulated system scan ----------

def _run_demo_scan(scan_id):
    total = len(DEMO_FILES)
    with sessions_lock:
        scan_sessions[scan_id]["total_files"] = total

    for i, (path, size, status, threat) in enumerate(DEMO_FILES, start=1):
        time.sleep(random.uniform(0.15, 0.35))
        result = build_result(path, size, status, threat)
        counter = {"threat": "threats", "warning": "warnings"}.get(status, "clean")
        with sessions_lock:
            s = scan_sessions[scan_id]
            s["results"].append(result)
            s["scanned"] = i
            s["progress"] = int(i / total * 100)
            s[counter] += 1

    with sessions_lock:
        s = scan_sessions[scan_id]
        s["status"] = "completed"
        s["completed_at"] = datetime.now().isoformat()
        entry = {
            "id": scan_id,
            "date": s["started_at"],
            "total": total,
            "threats": s["threats"],
            "warnings": s["warnings"],
            "clean": s["clean"],
        }
    storage.add_history_entry(entry)


def _trim_sessions():
    """Keep memory bounded: drop the oldest finished sessions."""
    if len(scan_sessions) <= config.MAX_SESSIONS_IN_MEMORY:
        return
    finished = sorted(
        (s for s in scan_sessions.values() if s["status"] == "completed"),
        key=lambda s: s["started_at"],
    )
    for s in finished[: len(scan_sessions) - config.MAX_SESSIONS_IN_MEMORY]:
        scan_sessions.pop(s["id"], None)


@app.route("/api/scan/start", methods=["POST"])
def start_scan():
    scan_id = uuid.uuid4().hex[:12]
    with sessions_lock:
        _trim_sessions()
        scan_sessions[scan_id] = {
            "id": scan_id,
            "status": "running",
            "simulated": True,
            "progress": 0,
            "total_files": 0,
            "scanned": 0,
            "threats": 0,
            "warnings": 0,
            "clean": 0,
            "results": [],
            "started_at": datetime.now().isoformat(),
            "completed_at": None,
        }
    threading.Thread(target=_run_demo_scan, args=(scan_id,), daemon=True).start()
    return jsonify({"scan_id": scan_id, "status": "started"})


@app.route("/api/scan/status/<scan_id>")
def scan_status(scan_id):
    with sessions_lock:
        session = scan_sessions.get(scan_id)
        if session is None:
            return jsonify({"error": "Scan not found"}), 404
        data = {**session, "results": list(session["results"])}
    return jsonify(data)


# ---------- real file scan ----------

@app.route("/api/scan/upload", methods=["POST"])
def scan_upload():
    file = request.files.get("file")
    if file is None:
        return jsonify({"error": "No file provided"}), 400
    result = analyze_file(file.filename, file.read())
    result["simulated"] = False
    return jsonify(result)


# ---------- history / stats / threat log ----------

@app.route("/api/history")
def get_history():
    return jsonify(storage.load_history())


@app.route("/api/stats")
def get_stats():
    history = storage.load_history()
    return jsonify({
        "total_scans": len(history),
        "total_threats_found": sum(h.get("threats", 0) for h in history),
        "total_files_scanned": sum(h.get("total", 0) for h in history),
        "last_scan": history[0]["date"] if history else None,
        "mode": "demo",
    })


@app.route("/api/threatlog")
def get_threat_log():
    """Past scans that found threats (a log, not a real quarantine)."""
    return jsonify([
        {"scan_id": h["id"], "date": h["date"], "count": h["threats"]}
        for h in storage.load_history()
        if h.get("threats", 0) > 0
    ])


# ---------- errors ----------

@app.errorhandler(413)
def too_large(_e):
    mb = config.MAX_UPLOAD_BYTES // (1024 * 1024)
    return jsonify({"error": f"File too large (max {mb} MB)"}), 413


if __name__ == "__main__":
    print(f"NovaScan running at http://localhost:{config.PORT}")
    app.run(debug=config.DEBUG, port=config.PORT)
