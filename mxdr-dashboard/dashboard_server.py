#!/usr/bin/env python3
"""
MXDR Monitoring Dashboard Server
Serves the dashboard UI and exposes a JSON API for live data
"""

from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
import json
import os
import threading
import sys

# Import collector
sys.path.insert(0, os.path.dirname(__file__))
from collector import run_collector, events, ip_stats, event_lock, EVENTS_FILE

app = Flask(__name__, static_folder='.')
CORS(app)

# ─── API ROUTES ────────────────────────────────────────────────────────────────
@app.route('/api/events')
def api_events():
    with event_lock:
        recent = list(reversed(events[-100:]))
    return jsonify({"events": recent, "total": len(events)})


@app.route('/api/stats')
def api_stats():
    with event_lock:
        total_alerts = len(events)
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        type_counts = {}
        for e in events:
            sev = e.get("severity", "LOW")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            t = e.get("attack_type", "Unknown")
            type_counts[t] = type_counts.get(t, 0) + 1

        top_ips = sorted(ip_stats.items(),
                         key=lambda x: x[1].get("alerts", 0), reverse=True)[:10]

    return jsonify({
        "total_alerts": total_alerts,
        "severity_counts": sev_counts,
        "attack_type_counts": type_counts,
        "top_attacker_ips": [{"ip": k, **v} for k, v in top_ips],
        "total_ips": len(ip_stats),
    })


@app.route('/api/timeline')
def api_timeline():
    """Events grouped by minute for chart"""
    from collections import defaultdict
    buckets = defaultdict(int)
    with event_lock:
        for e in events:
            ts = e.get("timestamp", "")[:16]   # YYYY-MM-DDTHH:MM
            buckets[ts] += 1
    timeline = [{"time": k, "count": v} for k, v in sorted(buckets.items())][-60:]
    return jsonify({"timeline": timeline})


@app.route('/')
def dashboard():
    return send_from_directory('.', 'dashboard.html')


if __name__ == '__main__':
    print("=" * 60)
    print("  MXDR Dashboard — Starting")
    print("  URL → http://0.0.0.0:8080")
    print("=" * 60)
    run_collector()
    app.run(host='0.0.0.0', port=8080, debug=False)
