# Web Attack Lab & Log Intelligence Dashboard

A controlled local environment for simulating web-based attacks against a 
dummy Flask application, capturing structured logs, and visualizing threat 
events through a real-time dashboard.

Built as a hands-on lab to understand attacker behavior, log pipeline design, 
and SOC-style monitoring — without requiring live malicious traffic.

## What This Does

- **dummy-website/** — Target Flask app that receives simulated attack traffic
- **simulate_attacks.py** — Attack simulator generating SQLi, XSS, and 
  brute-force requests against the dummy site
- **logs/** — Structured log output from captured attack traffic
- **mxdr-dashboard/** — Real-time dashboard for viewing attack events, 
  request logs, and detection summaries

## Why I Built It

Most threat detection projects either use pre-baked datasets or require 
live internet exposure. This lab generates its own attack traffic locally, 
giving full control over attack types, frequency, and volume — useful for 
testing detection logic without ethical or legal constraints.

## Tech Stack

- Python, Flask
- Custom log collection pipeline
- HTML/CSS dashboard (`dashboard.html`, `dashboard_server.py`)

## How to Run

```bash
# 1. Start the dummy target website
cd dummy-website
python app.py

# 2. In a second terminal, run the attack simulator
python simulate_attacks.py

# 3. In a third terminal, start the dashboard
cd mxdr-dashboard
python dashboard_server.py
```

Then open `http://localhost:<port>/dashboard` to view live events.

## Limitations

This is a local lab environment. Logs are generated synthetically — 
no real external traffic is captured. Designed for learning and 
demonstration purposes.
