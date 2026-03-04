#!/usr/bin/env python3
"""
MXDR Log Collector + Analyzer
Reads logs from the target website, classifies threats, stores in mxdr_events.json
Run on MXDR machine (or same machine on a different port)
"""

import json
import os
import re
import time
import threading
from datetime import datetime
from collections import defaultdict

# ─── CONFIG ────────────────────────────────────────────────────────────────────
LOG_FILE = os.getenv('TARGET_LOG', '/home/hani/mxdr-project/dummy-website/logs/access.log')
ALERT_FILE = os.getenv('ALERT_LOG', '/home/hani/mxdr-project/dummy-website/logs/alerts.log')
EVENTS_FILE    = 'mxdr_events.json'
POLL_INTERVAL  = 2   # seconds between log checks

# Brute force thresholds
BF_WINDOW = 60
BF_LIMIT  = 8

# ─── IN-MEMORY EVENT STORE ─────────────────────────────────────────────────────
events = []           # list of classified events
ip_stats = defaultdict(lambda: {"requests": 0, "alerts": 0, "first_seen": None, "last_seen": None})
event_lock = threading.Lock()


# ─── ATTACK CLASSIFIERS ────────────────────────────────────────────────────────
CLASSIFIERS = [
    {
        "name": "SQL Injection",
        "severity": "HIGH",
        "color": "#e74c3c",
        "patterns": [
            r"('|--|;|/\*|\*/)",
            r"\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|EXEC)\b",
            r"(OR\s+1=1|AND\s+1=1)",
            r"(SLEEP\(|BENCHMARK\(|WAITFOR)",
        ]
    },
    {
        "name": "XSS Attack",
        "severity": "HIGH",
        "color": "#e67e22",
        "patterns": [
            r"<script",
            r"javascript:",
            r"(onerror|onload|onclick|onmouseover)\s*=",
            r"alert\s*\(",
        ]
    },
    {
        "name": "Path Traversal",
        "severity": "MEDIUM",
        "color": "#f39c12",
        "patterns": [
            r"\.\./",
            r"etc/passwd",
            r"etc/shadow",
            r"%2e%2e",
        ]
    },
    {
        "name": "Scanner / Recon",
        "severity": "MEDIUM",
        "color": "#8e44ad",
        "patterns": [
            r"(sqlmap|nikto|nmap|nessus|acunetix|burp|dirbuster|wfuzz|gobuster|nuclei|zap)",
        ],
        "field": "user_agent"
    },
    {
        "name": "Brute Force",
        "severity": "CRITICAL",
        "color": "#c0392b",
        "patterns": [],   # handled by rate logic below
    },
    {
        "name": "Suspicious Request",
        "severity": "LOW",
        "color": "#7f8c8d",
        "patterns": [
            r"(\bphpMyAdmin\b|\bwp-login\b|\b\.env\b|\b\.git\b|\.bak|\.sql)",
            r"(cmd=|exec=|system=|passthru=|shell_exec=)",
        ]
    },
]

# Track login attempts per IP for brute-force detection
login_tracker = defaultdict(list)


def classify_entry(entry: dict) -> dict | None:
    """Return a classified event dict or None if benign"""
    ip  = entry.get("ip", "")
    path = entry.get("path", "")
    qs   = entry.get("query_string", "")
    body = entry.get("body_snippet", "")
    ua   = entry.get("user_agent", "")
    method = entry.get("method", "")
    ts   = entry.get("timestamp", datetime.utcnow().isoformat() + "Z")

    full_text = f"{path} {qs} {body}".lower()

    # ── Brute Force ──────────────────────────────────────────────
    if path in ['/login', '/api/login'] and method == 'POST':
        now = time.time()
        login_tracker[ip] = [t for t in login_tracker[ip] if now - t < BF_WINDOW]
        login_tracker[ip].append(now)
        if len(login_tracker[ip]) >= BF_LIMIT:
            return _make_event(ip, ts, "Brute Force", "CRITICAL", "#c0392b",
                               f"{len(login_tracker[ip])} POSTs to /login in {BF_WINDOW}s",
                               path, ua)

    # ── Pattern classifiers ──────────────────────────────────────
    for clf in CLASSIFIERS:
        if clf["name"] == "Brute Force":
            continue
        check_field = ua.lower() if clf.get("field") == "user_agent" else full_text
        for pattern in clf["patterns"]:
            if re.search(pattern, check_field, re.IGNORECASE):
                return _make_event(ip, ts, clf["name"], clf["severity"], clf["color"],
                                   f"Pattern: {pattern[:50]}", path, ua)

    # ── Pre-classified alerts already in entry ───────────────────
    if "attacks" in entry:
        a = entry["attacks"][0]
        return _make_event(ip, ts, a["type"].replace("_", " ").title(),
                           a["severity"], "#e74c3c", a.get("detail", ""), path, ua)

    return None


def _make_event(ip, ts, attack_type, severity, color, detail, path, ua):
    return {
        "id": int(time.time() * 1000),
        "timestamp": ts,
        "ip": ip,
        "attack_type": attack_type,
        "severity": severity,
        "color": color,
        "detail": detail,
        "path": path,
        "user_agent": ua[:80],
    }


def save_events():
    with event_lock:
        data = {
            "events": events[-500:],   # keep last 500
            "ip_stats": dict(ip_stats),
            "updated": datetime.utcnow().isoformat() + "Z"
        }
    with open(EVENTS_FILE, 'w') as f:
        json.dump(data, f, indent=2)


# ─── TAIL LOG FILE ─────────────────────────────────────────────────────────────
def tail_log(filepath, callback):
    """Continuously tail a log file and pass new lines to callback"""
    print(f"[Collector] Watching: {filepath}")
    # Seek to end initially
    try:
        fh = open(filepath, 'r')
        fh.seek(0, 2)
    except FileNotFoundError:
        fh = None

    while True:
        if fh is None:
            try:
                fh = open(filepath, 'r')
                fh.seek(0, 2)
                print(f"[Collector] Opened: {filepath}")
            except FileNotFoundError:
                time.sleep(2)
                continue

        try:
            line = fh.readline()
            if line:
                callback(line.strip())
            else:
                time.sleep(POLL_INTERVAL)
        except Exception as e:
            print(f"[Collector] Error: {e}")
            fh = None
            time.sleep(2)


def process_line(line: str):
    if not line:
        return
    try:
        entry = json.loads(line)
    except json.JSONDecodeError:
        return

    ip = entry.get("ip", "unknown")
    ts = entry.get("timestamp", "")

    # Update IP stats
    with event_lock:
        stats = ip_stats[ip]
        stats["requests"] += 1
        stats["last_seen"] = ts
        if not stats["first_seen"]:
            stats["first_seen"] = ts

    # Classify
    event = classify_entry(entry)
    if event:
        with event_lock:
            events.append(event)
            ip_stats[ip]["alerts"] += 1
        print(f"[ALERT] {event['severity']:8s} | {event['attack_type']:20s} | IP: {ip} | {event['detail']}")
        save_events()


def run_collector():
    """Run log tailing in background thread"""
    t = threading.Thread(target=tail_log, args=(LOG_FILE, process_line), daemon=True)
    t.start()


if __name__ == '__main__':
    print("=" * 60)
    print("  MXDR Log Collector — Started")
    print(f"  Watching: {LOG_FILE}")
    print(f"  Events → {EVENTS_FILE}")
    print("=" * 60)
    run_collector()
    try:
        while True:
            time.sleep(10)
            save_events()
    except KeyboardInterrupt:
        print("\n[Collector] Stopped.")
