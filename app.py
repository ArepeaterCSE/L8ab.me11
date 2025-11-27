from flask import Flask, request, jsonify, render_template, session, redirect, url_for, render_template_string
import requests
import socket
import ipaddress
from ping3 import ping
import logging
import datetime
import os
import json

logging.basicConfig(level=logging.INFO)

app = Flask(__name__)

# --- CONFIG ---
app.secret_key = 'L8AB_SECURE_KEY_X99'
ADMIN_PASSCODE = "Asim1001@"
BLACKLIST = ["L8AB.ME", "L8AB.COM", "127.0.0.1", "0.0.0.0", "LOCALHOST"]
NEWS_FILE = "news.txt"
ACTIVITY_FILE = "activity_log.txt" 
PUBLIC_LOGS_FILE = "chat_logs.json"

# --- HELPERS ---
def get_real_ip():
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    return request.remote_addr

def get_geo_location(ip_address):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=2)
        if response.status_code == 200:
            return response.json().get('country', 'Unknown')
    except:
        return 'Unknown'

# --- LOGGING SYSTEM ---
def load_public_logs():
    if not os.path.exists(PUBLIC_LOGS_FILE): return []
    try:
        with open(PUBLIC_LOGS_FILE, 'r', encoding='utf-8') as f:
            logs = json.load(f)
    except: return []

    # Clean old logs (24h)
    cleaned_logs = []
    cutoff = datetime.datetime.now() - datetime.timedelta(hours=24)
    changed = False
    for log in logs:
        if datetime.datetime.fromisoformat(log['timestamp']) > cutoff:
            cleaned_logs.append(log)
        else:
            changed = True
    
    if changed: save_public_logs_to_file(cleaned_logs)
    return cleaned_logs

def save_public_logs_to_file(logs):
    with open(PUBLIC_LOGS_FILE, 'w', encoding='utf-8') as f:
        json.dump(logs, f, ensure_ascii=False, indent=4)

def add_public_log(text, log_type='info'):
    logs = load_public_logs()
    logs.append({
        "timestamp": datetime.datetime.now().isoformat(),
        "text": text,
        "type": log_type
    })
    save_public_logs_to_file(logs)

# --- SCANNERS ---
def is_safe_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local)
    except: return False

def smart_host_check(ip):
    try:
        if ping(ip, unit='ms', timeout=1) is not None: return 'UP'
    except: pass 
    try: socket.create_connection((ip, 80), timeout=1).close(); return 'UP'
    except: pass
    try: socket.create_connection((ip, 443), timeout=1).close(); return 'UP'
    except: return 'DOWN'

def scan_ports(ip):
    open_ports = []
    for port in [21, 22, 53, 80, 443, 3306, 8080]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.4) 
            if s.connect_ex((ip, port)) == 0: open_ports.append(port)
            s.close()
        except: continue
    return open_ports

def get_http_headers(target):
    url = target if target.startswith('http') else f"http://{target}"
    try:
        r = requests.head(url, timeout=3, allow_redirects=True)
        return {"Server": r.headers.get("Server", "Hidden"), "Status": r.status_code}
    except: return None

# --- ROUTES ---
@app.route('/')
def index():
    ip = get_real_ip()
    return render_template('index.html', my_ip=ip, my_country=get_geo_location(ip))

@app.route('/api/news')
def api_news():
    if os.path.exists(NEWS_FILE):
        with open(NEWS_FILE, "r", encoding="utf-8") as f:
            return jsonify([line.strip() for line in f.readlines() if line.strip()][::-1])
    return jsonify([])

@app.route('/api/public-logs')
def get_public_logs():
    return jsonify(load_public_logs())

@app.route('/api/scan', methods=['POST'])
def scan_target():
    data = request.get_json()
    target = data.get('target', '').strip()
    
    if not target: return jsonify({"status": "ERROR"}), 400

    # 1. Checking Msg
    add_public_log(f"Checking {target}...", "info")

    try:
        hostname = target.replace("http://", "").replace("https://", "").split('/')[0]
        ip = socket.gethostbyname(hostname)
    except:
        add_public_log(f"Could not resolve {target}", "error")
        return jsonify({"status": "ERROR"}), 200

    if any(b in target.upper() for b in BLACKLIST) or not is_safe_ip(ip):
        add_public_log(f"Blocked access to {target}", "error")
        return jsonify({"status": "BLOCKED"}), 200

    status = smart_host_check(ip)
    geo = get_geo_location(ip)
    
    # 2. Results formatted cleanly
    add_public_log(f"Host: {status}", "success" if status == 'UP' else "warning")
    add_public_log(f"Country: {geo}", "warning")

    if status == 'UP':
        ports = scan_ports(ip)
        if ports:
            add_public_log(f"Ports: {', '.join(map(str, ports))}", "success")
        else:
            add_public_log("Ports: None found", "info")

    return jsonify({"status": "SUCCESS"})

# --- ADMIN ---
@app.route('/admin-panel-x99', methods=['GET', 'POST'])
def admin_panel():
    if request.method == 'POST':
        if request.form.get('passcode') == ADMIN_PASSCODE:
            session['is_admin'] = True
            return redirect(url_for('admin_panel'))
        if session.get('is_admin') and request.form.get('news_text'):
             with open(NEWS_FILE, "a", encoding="utf-8") as f:
                 f.write(f"[{datetime.datetime.now().strftime('%H:%M')}] {request.form.get('news_text')}\n")
    
    if not session.get('is_admin'): return render_template_string(LOGIN_HTML)
    return """<body style="background:#000;color:#0f8;text-align:center;font-family:monospace;padding:50px;">
    <h1 style="border-bottom:1px solid #0f8;">COMMAND CENTER</h1>
    <form method="POST"><input name="news_text" style="padding:10px;width:300px;" placeholder="Update news..."><button style="padding:10px;background:#0f8;border:none;">POST</button></form>
    <br><a href="/" style="color:#555;">[Back]</a></body>"""

LOGIN_HTML = """<!DOCTYPE html><html><body style="background:#050505;color:#0f8;display:flex;justify-content:center;align-items:center;height:100vh;font-family:monospace;">
<div style="border:1px solid #0f8;padding:40px;text-align:center;background:rgba(0,0,0,0.8);">
<h2>// RESTRICTED ACCESS</h2><form method="POST"><input type="password" name="passcode" style="background:transparent;border:none;border-bottom:1px solid #0f8;color:#fff;text-align:center;font-size:1.2rem;outline:none;"><br><br><button type="submit" style="background:#0f8;border:none;padding:10px 20px;font-weight:bold;cursor:pointer;">AUTHENTICATE</button></form></div></body></html>"""

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
