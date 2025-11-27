from flask import Flask, request, jsonify, render_template, session, redirect, url_for, render_template_string
import requests
import socket
import ipaddress
from ping3 import ping
import logging
import datetime
import os

# إعداد السجل
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)

# --- إعدادات الأمان ---
app.secret_key = 'L8AB_SECURE_KEY_X99'
ADMIN_PASSCODE = "Asim1001@"

# --- الملفات ---
BLACKLIST = ["L8AB.ME", "L8AB.COM", "127.0.0.1", "0.0.0.0", "LOCALHOST"]
NEWS_FILE = "news.txt"
ACTIVITY_FILE = "activity_log.txt" # ملف السجل الشامل الجديد

# --- دوال المساعدة ---

def get_real_ip():
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    return request.remote_addr

def get_geo_location(ip_address):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=2)
        if response.status_code == 200:
            data = response.json()
            return data.get('country', 'Unknown')
    except:
        pass
    return 'Unknown'

# دالة التسجيل الجديدة (تسجل IP والهدف الذي جربه)
def log_activity(ip, country, target, status):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # تنسيق السجل: الوقت | الايبي (الدولة) | بحث عن: الهدف | النتيجة
    log_entry = f"[{timestamp}] IP: {ip} ({country}) | TRIED SCANNING: {target} | RESULT: {status}\n"
    try:
        with open(ACTIVITY_FILE, "a", encoding="utf-8") as f:
            f.write(log_entry)
    except Exception as e:
        logging.error(f"Failed to log activity: {e}")

def get_news():
    try:
        if not os.path.exists(NEWS_FILE):
            return []
        with open(NEWS_FILE, "r", encoding="utf-8") as f:
            return [line.strip() for line in f.readlines() if line.strip()][::-1]
    except:
        return []

def is_safe_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return False
        return True
    except ValueError:
        return False

def smart_host_check(ip):
    try:
        latency = ping(ip, unit='ms', timeout=1)
        if latency is not None: return 'UP', round(latency, 2)
    except: pass 
    try:
        sock = socket.create_connection((ip, 80), timeout=1)
        sock.close(); return 'UP', 10 
    except: pass
    try:
        sock = socket.create_connection((ip, 443), timeout=1)
        sock.close(); return 'UP', 10
    except: return 'DOWN', 0

def scan_ports(ip):
    target_ports = [21, 22, 53, 80, 443, 3306, 8080]
    open_ports = []
    for port in target_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.4) 
            result = s.connect_ex((ip, port))
            if result == 0: open_ports.append(port)
            s.close()
        except: continue
    return open_ports

def get_http_headers(target):
    if not target.startswith('http'): url = f"http://{target}"
    else: url = target
    try:
        response = requests.head(url, timeout=3, allow_redirects=True)
        return {
            "Server": response.headers.get("Server", "Hidden"),
            "Status": response.status_code,
            "X-Powered-By": response.headers.get("X-Powered-By", "Hidden")
        }
    except: return None

# --- HTML شاشة القفل ---
LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>SECURE ACCESS // ADMIN</title>
    <style>
        body { background-color: #000; color: #0f8; font-family: monospace; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-box { border: 2px solid #0f8; padding: 40px; text-align: center; background: rgba(0, 0, 0, 0.9); }
        input { background: transparent; border: none; border-bottom: 2px solid #0f8; color: #fff; font-size: 1.5rem; text-align: center; outline: none; margin-top: 20px; }
        button { margin-top: 20px; background: #0f8; color: #000; border: none; padding: 10px 20px; font-weight: bold; cursor: pointer; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>// AUTHENTICATION REQUIRED</h2>
        <form method="POST"><input type="password" name="passcode" autofocus><br><button type="submit">UNLOCK</button></form>
        {% if error %}<p style="color:red">>> ACCESS DENIED</p>{% endif %}
    </div>
</body>
</html>
"""

# --- المسارات ---

@app.route('/')
def index():
    ip = get_real_ip()
    country = get_geo_location(ip)
    # نسجل الدخول فقط (بدون هدف)
    log_activity(ip, country, "HOMEPAGE_VISIT", "N/A")
    return render_template('index.html', my_ip=ip, my_country=country)

@app.route('/api/news')
def api_news():
    return jsonify(get_news())

@app.route('/api/scan', methods=['POST'])
def scan_target():
    data = request.get_json()
    target = data.get('target', '').strip()
    visitor_ip = get_real_ip()
    visitor_country = get_geo_location(visitor_ip)

    if not target: 
        return jsonify({"status": "ERROR", "message": "No target provided"}), 400

    try:
        clean_hostname = target.replace("http://", "").replace("https://", "").split('/')[0]
        ip_address = socket.gethostbyname(clean_hostname)
    except socket.gaierror:
        log_activity(visitor_ip, visitor_country, target, "DNS_ERROR")
        return jsonify({"status": "ERROR", "message": "Could not resolve hostname."}), 200

    if any(blk in target.upper() for blk in BLACKLIST) or not is_safe_ip(ip_address):
        log_activity(visitor_ip, visitor_country, target, "BLOCKED_TARGET")
        return jsonify({"status": "BLOCKED", "message": "Restricted Target", "ip": ip_address}), 200

    host_status, latency = smart_host_check(ip_address)
    geo_info = get_geo_location(ip_address)
    
    # تسجيل العملية الناجحة
    log_activity(visitor_ip, visitor_country, target, f"SCANNED_SUCCESS ({host_status})")

    open_ports = []
    headers = None
    if host_status == 'UP':
        open_ports = scan_ports(ip_address)
        headers = get_http_headers(clean_hostname)

    return jsonify({
        "status": "SUCCESS", "target": target, "ip_address": ip_address,
        "host_status": host_status, "latency": latency, "country": geo_info,
        "open_ports": open_ports, "headers": headers
    })

@app.route('/admin-panel-x99', methods=['GET', 'POST'])
def admin_panel():
    if request.method == 'POST' and 'passcode' in request.form:
        if request.form['passcode'] == ADMIN_PASSCODE:
            session['is_admin'] = True
            return redirect(url_for('admin_panel'))
        else: return render_template_string(LOGIN_HTML, error=True)

    if not session.get('is_admin'): return render_template_string(LOGIN_HTML, error=False)

    msg = ""
    if request.method == 'POST' and 'news_text' in request.form:
        new_text = request.form.get('news_text')
        if new_text:
            timestamp = datetime.datetime.now().strftime("%H:%M")
            entry = f"[{timestamp}] {new_text}\n"
            with open(NEWS_FILE, "a", encoding="utf-8") as f: f.write(entry)
            msg = ">> POSTED."
            
    logs_content = "No activity yet."
    if os.path.exists(ACTIVITY_FILE):
        with open(ACTIVITY_FILE, "r", encoding="utf-8") as f:
            # نقرأ آخر 100 سطر مثلاً
            lines = f.readlines()
            logs_content = "".join(lines[::-1]) # الأحدث في الأعلى

    return f"""
    <body style="background:#050505; color:#0f8; font-family:monospace; padding:20px; text-align:center;">
        <h1 style="border-bottom:1px solid #0f8; padding-bottom:10px;">>> ADMIN COMMAND CENTER</h1>
        
        <div style="background:#111; padding:20px; border:1px solid #333; margin-bottom:20px;">
            <h3>[ BROADCAST SYSTEM ]</h3>
            <form method="POST">
                <input type="text" name="news_text" placeholder="Type update..." style="width:60%; padding:10px; background:#000; border:1px solid #0f8; color:#fff;">
                <button type="submit" style="padding:10px 20px; background:#0f8; border:none; cursor:pointer;">PUBLISH</button>
            </form>
            <p style="color:#ffbd2e;">{msg}</p>
        </div>

        <div style="background:#111; padding:20px; border:1px solid #333; text-align:left;">
            <h3>[ FULL ACTIVITY LOGS (Who scanned What) ]</h3>
            <pre style="height:400px; overflow-y:scroll; background:#000; padding:10px; border:1px dashed #555; font-size:0.8rem; color:#ccc;">{logs_content}</pre>
        </div>
        <br><a href="/" style="color:#555;">[ Back to Home ]</a>
    </body>
    """

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
