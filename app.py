"""
SENTIO — 4-Phase Security Platform
Phase 1: Known Vulnerability Scanner (NVD, EPSS, KEV)
Phase 2: Behavioral Baselining & Anomaly Detection (Mos)
Phase 3: Proactive Fuzzing Engine (Fragilis)
Phase 4: Correlation Engine & Threat Intelligence (Nexus)
"""
import os
import sys
import json
import threading
import time
import sqlite3

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify, render_template
from config import Config
from utils.validators import validate_target, ValidationError
from utils.logger import get_logger
from services.vuln_enricher import VulnEnricher
from services.behavior_monitor import BehaviorMonitor
from services.baseline_engine import BaselineEngine
from services.deviation_detector import DeviationDetector
from models.behavior_models import BehaviorMetric
from services.fuzzer_engine import FuzzerEngine
from models.fuzz_models import FuzzCampaign
from services.correlation_engine import CorrelationEngine
from models.correlation_models import ThreatIntelReport

logger = get_logger("app")
app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = Config.SECRET_KEY

# ── Phase 1: Vulnerability Scanner ──
_enricher = VulnEnricher()

# ── Phase 2: Behavioral Monitor ──
_monitor = BehaviorMonitor(db_path=Config.MONITOR_DB_PATH)
_baseline = BaselineEngine(db_path=Config.MONITOR_DB_PATH)
_detector = DeviationDetector()

# ── Phase 3: Fuzzing Engine ──
_fuzzer = FuzzerEngine("http://127.0.0.1:5001")

# ── Phase 4: Correlation Engine / Nexus ──
_nexus = CorrelationEngine(nexus_db=getattr(Config, 'NEXUS_DB_PATH', 'sentio_nexus.db'))

# ═══════════════════════════════════════════════════════════════
# PHASE 1 ROUTES
# ═══════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/scan", methods=["POST"])
def api_scan():
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    body = request.get_json(silent=True) or {}
    raw_target = body.get("target", "").strip()
    if not raw_target:
        return jsonify({"error": "Missing 'target' field"}), 400
    try:
        target = validate_target(raw_target)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400
    try:
        result = _enricher.scan_target(target)
        return jsonify(result.to_dict()), 200
    except Exception as e:
        logger.exception(f"Scan failed for {target}")
        return jsonify({"error": f"Scan engine failure: {str(e)}"}), 500

# ═══════════════════════════════════════════════════════════════
# PHASE 2 ROUTES: Behavioral Monitoring
# ═══════════════════════════════════════════════════════════════

@app.route("/api/monitor/start", methods=["POST"])
def monitor_start():
    """Start polling a target application."""
    body = request.get_json(silent=True) or {}
    target_url = body.get("target_url", "").strip()
    if not target_url:
        return jsonify({"error": "Missing 'target_url'"}), 400

    endpoints = body.get("endpoints", [
        {"path": "/api/health", "method": "GET"},
        {"path": "/api/auth/login", "method": "POST", "payload": {"username": "admin", "password": "admin123"}},
        {"path": "/api/auth/register", "method": "POST", "payload": {"username": "testuser", "password": "testpass"}},
        {"path": "/api/search", "method": "POST", "payload": {"q": "test", "scope": "files"}},
        {"path": "/api/metrics", "method": "GET"},
    ])
    interval = body.get("interval", getattr(Config, 'MONITOR_POLL_INTERVAL', 5.0))

    _monitor.start_polling(target_url, endpoints, interval)
    return jsonify({
        "status": "monitoring_started",
        "target": target_url,
        "endpoints": len(endpoints),
        "interval_seconds": interval,
    })

@app.route("/api/monitor/stop", methods=["POST"])
def monitor_stop():
    _monitor.stop_polling()
    return jsonify({"status": "monitoring_stopped"})

@app.route("/api/monitor/status")
def monitor_status():
    stats = _monitor.get_stats()
    return jsonify({
        "status": "running" if _monitor._running else "idle",
        "target": _monitor._target_url,
        **stats,
    })

@app.route("/api/monitor/metrics")
def monitor_metrics():
    """Get recent metrics for visualization."""
    minutes = request.args.get("minutes", 60, type=int)
    metrics = _monitor.get_recent_metrics(minutes)
    return jsonify({
        "count": len(metrics),
        "metrics": [m.to_dict() for m in metrics],
    })

@app.route("/api/monitor/webhook", methods=["POST"])
def monitor_webhook():
    """Receive pushed metrics from target app."""
    data = request.get_json(silent=True) or {}
    success = _monitor.ingest_webhook(data)
    return jsonify({"accepted": success}), 200 if success else 400

@app.route("/api/baseline/compute", methods=["POST"])
def baseline_compute():
    """Compute baseline from collected metrics."""
    body = request.get_json(silent=True) or {}
    minutes = body.get("minutes", getattr(Config, 'BASELINE_WINDOW_MINUTES', 60))
    target_host = body.get("target_host", _monitor._target_url)

    report = _baseline.compute_baseline(minutes=minutes, target_host=target_host)
    return jsonify(report.to_dict())

@app.route("/api/baseline/latest")
def baseline_latest():
    target_host = request.args.get("target_host", _monitor._target_url)
    report = _baseline.get_latest_baseline(target_host)
    if not report:
        return jsonify({"error": "No baseline found. Run /api/baseline/compute first."}), 404
    return jsonify(report.to_dict())

@app.route("/api/anomaly/detect", methods=["POST"])
def anomaly_detect():
    """Run anomaly detection against recent metrics."""
    body = request.get_json(silent=True) or {}
    minutes = body.get("minutes", 5)
    target_host = body.get("target_host", _monitor._target_url)

    baseline_report = _baseline.get_latest_baseline(target_host)
    if not baseline_report:
        return jsonify({"error": "No baseline found. Run /api/baseline/compute first."}), 400

    recent_metrics = _monitor.get_recent_metrics(minutes)
    recent_metrics = [m for m in recent_metrics if not target_host or m.target_host == target_host]

    alerts = _detector.detect_batch(recent_metrics, baseline_report)
    
    # NEXUS: Persist alerts for correlation analysis
    _nexus.store_anomaly_alerts(alerts, baseline_id=baseline_report.report_id)

    return jsonify({
        "baseline_id": baseline_report.report_id,
        "metrics_analyzed": len(recent_metrics),
        "anomalies_detected": len(alerts),
        "alerts": [a.to_dict() for a in alerts],
    })

# ═══════════════════════════════════════════════════════════════
# PHASE 3 ROUTES: Fuzzing Engine
# ═══════════════════════════════════════════════════════════════

@app.route("/api/fuzz/start", methods=["POST"])
def fuzz_start():
    """Run a fuzzing campaign against the target."""
    body = request.get_json(silent=True) or {}
    target_url = body.get("target_url", "http://127.0.0.1:5001")
    max_payloads = body.get("max_payloads", 50)

    fuzzer = FuzzerEngine(target_url)
    campaign = fuzzer.run_campaign(max_payloads=max_payloads)
    
    # NEXUS: Persist campaign for correlation analysis
    _nexus.store_fuzz_campaign(campaign)
    
    return jsonify(campaign.to_dict())

@app.route("/api/fuzz/status")
def fuzz_status():
    """Return fuzzing engine status."""
    return jsonify({"status": "ready", "target": _fuzzer.target_url})

# ═══════════════════════════════════════════════════════════════
# PHASE 4 ROUTES: Nexus / Correlation Engine
# ═══════════════════════════════════════════════════════════════

@app.route("/api/nexus/correlate", methods=["POST"])
def nexus_correlate():
    """Run correlation analysis between fuzz findings and anomalies."""
    body = request.get_json(silent=True) or {}
    hours = body.get("time_window_hours", 48)
    findings = _nexus.correlate(time_window_hours=hours)
    return jsonify({
        "status": "correlation_complete",
        "findings_count": len(findings),
        "findings": [f.to_dict() for f in findings],
    })

@app.route("/api/nexus/findings")
def nexus_findings():
    """Get all open correlation findings."""
    findings = _nexus.get_open_findings()
    return jsonify({
        "count": len(findings),
        "findings": [f.to_dict() for f in findings],
    })

@app.route("/api/nexus/report", methods=["POST", "GET"])
def nexus_report():
    """Generate or retrieve latest threat intel report."""
    if request.method == "POST":
        body = request.get_json(silent=True) or {}
        target_host = body.get("target_host", _monitor._target_url)
        report = _nexus.generate_threat_intel_report(target_host=target_host)
        return jsonify(report.to_dict())
    else:
        report = _nexus.get_latest_report()
        if not report:
            return jsonify({"error": "No threat intel report found. Generate one first."}), 404
        return jsonify(report.to_dict())

# ═══════════════════════════════════════════════════════════════
# NEW: ONE-BUTTON FULL ANALYSIS PIPELINE
# ═══════════════════════════════════════════════════════════════

@app.route("/api/nexus/full-analysis", methods=["POST"])
def nexus_full_analysis():
    """
    ONE-BUTTON PIPELINE:
    1. Detect anomalies (Phase 2)
    2. Correlate with fuzz findings (Phase 4)
    3. Generate threat intelligence report
    """
    body = request.get_json(silent=True) or {}
    target_host = body.get("target_host", _monitor._target_url)
    minutes = body.get("minutes", 5)

    # Step 1: Detect anomalies
    baseline_report = _baseline.get_latest_baseline(target_host)
    if not baseline_report:
        return jsonify({"error": "No baseline found. Run Phase 2 first."}), 400

    recent_metrics = _monitor.get_recent_metrics(minutes)
    recent_metrics = [m for m in recent_metrics if not target_host or m.target_host == target_host]
    alerts = _detector.detect_batch(recent_metrics, baseline_report)
    _nexus.store_anomaly_alerts(alerts, baseline_id=baseline_report.report_id)

    # Step 2: Correlate
    findings = _nexus.correlate(time_window_hours=48)

    # Step 3: Generate report
    report = _nexus.generate_threat_intel_report(target_host=target_host)

    return jsonify({
        "status": "analysis_complete",
        "anomalies_detected": len(alerts),
        "correlations_found": len(findings),
        "report": report.to_dict()
    })

@app.route("/api/nexus/status")
def nexus_status():
    """Return Nexus engine status and stats."""
    return jsonify({
        "status": "active",
        "engine": "Nexus v1.0",
        "rules_loaded": len(_nexus._rules),
        "stats": _nexus.get_stats(),
    })

@app.route("/api/nexus/finding/<finding_id>/status", methods=["PUT"])
def nexus_update_finding(finding_id):
    """Update correlation finding status."""
    body = request.get_json(silent=True) or {}
    new_status = body.get("status", "open")
    try:
        with sqlite3.connect(_nexus.nexus_db) as conn:
            conn.execute("UPDATE correlations SET status = ? WHERE finding_id = ?", (new_status, finding_id))
            conn.commit()
        return jsonify({"finding_id": finding_id, "status": new_status})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ═══════════════════════════════════════════════════════════════
# SHARED
# ═══════════════════════════════════════════════════════════════

@app.route("/api/health")
def api_health():
    return jsonify({
        "status": "ok",
        "phase1_cache": _enricher.cache.stats(),
        "phase2_monitor": _monitor.get_stats(),
        "phase4_nexus": _nexus.get_stats(),
    })

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    app.run(
        host=getattr(Config, 'HOST', '0.0.0.0'),
        port=getattr(Config, 'PORT', 5000),
        debug=getattr(Config, 'DEBUG', False)
    )
