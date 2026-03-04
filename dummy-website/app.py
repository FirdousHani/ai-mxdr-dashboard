#!/usr/bin/env python3
"""
IndiaRail Express - Dummy Target Website Server
Logs all requests for MXDR monitoring
"""

from flask import Flask, request, jsonify, send_from_directory, render_template_string
import logging
import json
import os
import re
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler

app = Flask(__name__, static_folder='.')

# ─── LOG SETUP ─────────────────────────────────────────────────────────────────
os.makedirs('logs', exist_ok=True)

# Access log (all requests)
access_logger = logging.getLogger('access')
access_logger.setLevel(logging.INFO)
access_handler = RotatingFileHandler('logs/access.log', maxBytes=10*1024*1024, backupCount=5)
access_logger.addHandler(access_handler)

# Attack/alert log (suspicious requests)
alert_logger = logging.getLogger('alert')
alert_logger.setLevel(logging.WARNING)
alert_handler = RotatingFileHandler('logs/alerts.log', maxBytes=10*1024*1024, backupCount=5)
alert_logger.addHandler(alert_handler)

# ─── ATTACK SIGNATURES ──────────────────────────────────────────────────────────
SQLI_PATTERNS = [
    r"('|--|;|/\*|\*/|xp_|UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)",
    r"(OR\s+1=1|AND\s+1=1|OR\s+'1'='1'|AND\s+'1'='1')",
    r"(SLEEP\(|BENCHMARK\(|WAITFOR\s+DELAY|pg_sleep)",
    r"(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)",
]

XSS_PATTERNS = [
    r"(<script|</script|javascript:|onerror=|onload=|onclick=|onmouseover=)",
    r"(alert\(|confirm\(|prompt\(|document\.cookie|window\.location)",
    r"(<iframe|<img\s|<svg|<body\s|<input\s.*on)",
    r"(eval\(|setTimeout\(|setInterval\(|innerHTML)",
]

TRAVERSAL_PATTERNS = [
    r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f)",
    r"(/etc/passwd|/etc/shadow|/proc/self|/var/www|boot\.ini|win\.ini)",
]

SCANNER_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "nessus", "openvas",
    "acunetix", "burpsuite", "dirbuster", "wfuzz", "gobuster",
    "hydra", "medusa", "metasploit", "nuclei", "zap"
]

BRUTE_FORCE_WINDOW = 60   # seconds
BRUTE_FORCE_LIMIT  = 10   # requests
login_attempts = {}  # ip -> [timestamps]

def get_client_ip():
    """Get real IP, always return IPv4"""
    ip = (request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
          or request.headers.get('X-Real-IP', '')
          or request.remote_addr)
    # Convert IPv6 mapped IPv4 (::ffff:x.x.x.x) to plain IPv4
    if ip.startswith('::ffff:'):
        ip = ip[7:]
    return ip


def detect_attack(ip, path, method, user_agent, body, query_string):
    """Analyse request and return list of detected attack types"""
    alerts = []
    full_input = f"{path} {query_string} {body}".lower()
    ua_lower = user_agent.lower()

    # SQL Injection
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, full_input, re.IGNORECASE):
            alerts.append({"type": "SQL_INJECTION", "severity": "HIGH",
                           "detail": f"Pattern matched: {pattern[:40]}"})
            break

    # XSS
    for pattern in XSS_PATTERNS:
        if re.search(pattern, full_input, re.IGNORECASE):
            alerts.append({"type": "XSS", "severity": "HIGH",
                           "detail": f"Pattern matched: {pattern[:40]}"})
            break

    # Path Traversal
    for pattern in TRAVERSAL_PATTERNS:
        if re.search(pattern, full_input, re.IGNORECASE):
            alerts.append({"type": "PATH_TRAVERSAL", "severity": "MEDIUM",
                           "detail": "Directory traversal attempt"})
            break

    # Scanner Detection
    for scanner in SCANNER_AGENTS:
        if scanner in ua_lower:
            alerts.append({"type": "SCANNER_DETECTED", "severity": "MEDIUM",
                           "detail": f"Known scanner UA: {scanner}"})
            break

    # Brute Force Detection (login endpoint)
    if path in ['/login', '/api/login'] and method == 'POST':
        now = time.time()
        login_attempts.setdefault(ip, [])
        login_attempts[ip] = [t for t in login_attempts[ip] if now - t < BRUTE_FORCE_WINDOW]
        login_attempts[ip].append(now)
        if len(login_attempts[ip]) >= BRUTE_FORCE_LIMIT:
            alerts.append({"type": "BRUTE_FORCE", "severity": "CRITICAL",
                           "detail": f"{len(login_attempts[ip])} login attempts in {BRUTE_FORCE_WINDOW}s"})

    return alerts


def log_request(status_code):
    """Log every request in structured JSON"""
    ip        = get_client_ip()
    from datetime import timezone, timedelta
    IST = timezone(timedelta(hours=5, minutes=30))
    timestamp = datetime.now(IST).strftime('%Y-%m-%dT%H:%M:%S')
    method    = request.method
    path      = request.path
    qs        = request.query_string.decode('utf-8', errors='replace')
    ua        = request.headers.get('User-Agent', '-')
    referer   = request.headers.get('Referer', '-')
    body      = ''
    try:
        body = request.get_data(as_text=True)[:500]
    except Exception:
        pass

    entry = {
        "timestamp": timestamp,
        "ip": ip,
        "method": method,
        "path": path,
        "query_string": qs,
        "status": status_code,
        "user_agent": ua,
        "referer": referer,
        "body_snippet": body[:200] if body else ""
    }

    # Detect attacks
    attacks = detect_attack(ip, path, method, ua, body, qs)
    if attacks:
        entry["attacks"] = attacks
        for attack in attacks:
            alert_entry = {**entry, "alert": attack}
            alert_logger.warning(json.dumps(alert_entry))
            print(f"[ALERT] {attack['type']} from {ip} — {attack['detail']}")

    access_logger.info(json.dumps(entry))


# ─── MIDDLEWARE: LOG EVERY RESPONSE ────────────────────────────────────────────
@app.after_request
def after_request(response):
    response.headers['ngrok-skip-browser-warning'] = '1' 
    log_request(response.status_code)
    return response

# ─── ROUTES ────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:filename>')
def static_files(filename):
    return send_from_directory('.', filename)

@app.route('/search')
def search():
    """Train search endpoint"""
    from_st = request.args.get('from', '')
    to_st   = request.args.get('to', '')
    return jsonify({"status": "ok", "from": from_st, "to": to_st,
                    "results": ["Rajdhani Express", "Shatabdi Express"]})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', request.json.get('username', '') if request.is_json else '')
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401
    return send_from_directory('.', 'index.html')

@app.route('/pnr')
def pnr():
    pnr_num = request.args.get('pnr', '')
    return jsonify({"pnr": pnr_num, "status": "No booking found"})

@app.route('/api/log', methods=['POST'])
def api_log():
    """Client-side event logging endpoint"""
    data = request.get_json(silent=True) or {}
    access_logger.info(json.dumps({"source": "client", **data,
                                    "ip": get_client_ip(),
                                    "timestamp": datetime.utcnow().isoformat() + "Z"}))
    return jsonify({"ok": True})

@app.route('/api/status')
def status():
    return jsonify({"status": "running", "server": "IndiaRail Express",
                    "timestamp": datetime.utcnow().isoformat() + "Z"})

# Health probe used by MXDR log collector
@app.route('/health')
def health():
    return jsonify({"healthy": True})


if __name__ == '__main__':
    print("=" * 60)
    print("  IndiaRail Express — Target Website Running")
    print("  Logs → logs/access.log  |  logs/alerts.log")
    print("  URL  → http://0.0.0.0:5000")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=False)
