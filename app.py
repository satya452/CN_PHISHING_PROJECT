import os
import time
from datetime import datetime, timezone
from flask import Flask, render_template, request, jsonify
from detector.url_features import analyze_url
from detector.dns_checker import check_dns
from detector.rule_engine import score_rules
from detector.reputation import check_google_safe_browsing
from detector.fusion import combine_signals
from detector.history import add_scan, get_recent_scans

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # refuse oversized requests

@app.get("/")
def index():
    return render_template("index.html")

@app.post("/api/scan")
def scan():
    started = time.perf_counter()
    payload = request.get_json(silent=True) or request.form
    raw_url = (payload.get("url") or "").strip()

    parsed, error = analyze_url(raw_url)
    if error:
        return jsonify({"error": error}), 400

    dns_started = time.perf_counter()
    dns_result = check_dns(parsed["hostname"])
    dns_ms = round((time.perf_counter() - dns_started) * 1000, 2)

    rules = score_rules(parsed)
    # Optional provider: if API key is absent, report "not_configured".
    rep_started = time.perf_counter()
    reputation = check_google_safe_browsing(raw_url)
    rep_ms = round((time.perf_counter() - rep_started) * 1000, 2)

    result = combine_signals(parsed, dns_result, rules, reputation)
    result["url"] = raw_url
    result["hostname"] = parsed["hostname"]
    result["dns"] = dns_result
    result["timings_ms"] = {
        "dns": dns_ms,
        "reputation": rep_ms,
        "total": round((time.perf_counter() - started) * 1000, 2)
    }
    result["timestamp"] = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    result["disclaimer"] = (
        "This is a risk estimate, not a safety guarantee. A low score does not prove a URL is safe. "
        "The submitted URL is not opened by this application."
    )
    add_scan(result)
    return jsonify(result)

@app.get("/api/history")
def history():
    return jsonify(get_recent_scans())

@app.get("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "reputation_configured": bool(os.getenv("GOOGLE_SAFE_BROWSING_API_KEY"))
    })

@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": "Request is too large."}), 413

if __name__ == "__main__":
    # Debug mode is intentionally off by default.
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), debug=False)
