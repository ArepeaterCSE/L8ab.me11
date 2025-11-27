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
app.secret_key = 'super_secret_key_change_me'  # مفتاح لتشفير الجلسة

# ===> تم وضع الباسورد الخاص بك هنا <===
ADMIN_PASSCODE = "Asim1001@"  

# --- الملفات والقوائم ---
BLACKLIST = ["L8AB.ME", "L8AB.COM", "127.0.0.1", "0.0.0.0", "LOCALHOST"]
VISITORS_FILE = "visitors.txt"
NEWS_FILE = "news.txt"

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
            return data.get('country', 'Unknown Location')
    except:
        pass
    return 'Unknown Location'

def log_visitor(ip, country):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] IP: {ip} | Location: {country}\n"
    try:
        with open(VISITORS_FILE, "a", encoding="utf-8") as f:
            f.write(log_entry)
    except Exception as e:
        logging.error(f"Failed to log visitor: {e}")

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
        if latency is not None:
            return 'UP', round(latency, 2)
    except:
        pass 
    try:
        sock = socket.create_connection((ip, 80), timeout=1)
        sock.close()
        return 'UP', 10 
    except:
        pass
    try:
        sock = socket.create_connection((ip, 443), timeout=1)
        sock.close()
        return 'UP', 10
    except:
        return 'DOWN', 0

def scan_ports(ip):
    target_ports = [21, 22, 53, 80, 443, 3306, 8080]
    open_ports = []
    for port in target_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.4) 
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            s.close()
        except:
            continue
    return open_ports

def get_http_headers(target):
    if not target.startswith('http'):
        url = f"http://{target}"
    else:
        url = target
    try:
        response = requests.head(url, timeout=3, allow_redirects=True)
        return {
            "Server": response.headers.get("Server", "Hidden"),
            "Status": response.status_code,
            "X-Powered-By": response.headers.get("X-Powered-By", "Hidden")
        }
    except:
        return None

# --- HTML لقفل الشاشة (Login Screen) ---
LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>SECURE ACCESS // ADMIN</title>
    <style>
        body { background-color: #000; color: #0f8; font-family: 'Courier New', monospace; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-box { border: 2px solid #0f8; padding: 40px; text-align: center; box-shadow: 0 0 20px #0f8; background: rgba(0, 20, 0, 0.9); }
        input { background: transparent; border: none; border-bottom: 2px solid #0f8; color: #fff; font-size: 1.5rem; text-align: center; outline: none; margin-top: 20px; width: 250px; font-family: monospace; }
        button { margin-top: 20px; background: #0f8; color: #000; border: none; padding: 10px 20px; font-weight: bold; cursor: pointer; font-family: monospace; }
        button:hover { background: #fff; }
        .error { color: red; margin-top: 15px; }
        h2 { margin: 0 0 20px 0; text-shadow: 0 0 5px #0f8; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>// AUTHENTICATION REQUIRED</h2>
        <p>ENTER SECURITY PASSCODE:</p>
        <form method="POST">
            <input type="password" name="passcode" autofocus autocomplete="off">
            <br>
            <button type="submit">UNLOCK SYSTEM</button>
        </form>
        {% if error %}
        <p class="error">>> ACCESS DENIED: INVALID CODE</p>
        {% endif %}
    </div>
</body>
</html>
"""

# --- المسارات العامة ---

@app.route('/')
def index():
    ip = get_real_ip()
    country = get_geo_location(ip)
    log_visitor(ip, country)
    return render_template('index.html', my_ip=ip, my_country=country)

@app.route('/api/news')
def api_news():
    return jsonify(get_news())

@app.route('/api/scan', methods=['POST'])
def scan_target():
    data = request.get_json()
    target = data.get('target', '').strip()
    if not target: return jsonify({"status": "ERROR", "message": "No target provided"}), 400

    try:
        clean_hostname = target.replace("http://", "").replace("https://", "").split('/')[0]
        ip_address = socket.gethostbyname(clean_hostname)
    except socket.gaierror:
        return jsonify({"status": "ERROR", "message": "Could not resolve hostname."}), 200

    if any(blk in target.upper() for blk in BLACKLIST) or not is_safe_ip(ip_address):
        return jsonify({"status": "BLOCKED", "message": "Restricted Target", "ip": ip_address}), 200

    host_status, latency = smart_host_check(ip_address)
    geo_info = get_geo_location(ip_address)
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

# --- المسارات المحمية (Admin Panel) ---

@app.route('/admin-panel-x99', methods=['GET', 'POST'])
def admin_panel():
    # 1. معالجة تسجيل الدخول
    if request.method == 'POST' and 'passcode' in request.form:
        if request.form['passcode'] == ADMIN_PASSCODE:
            session['is_admin'] = True # حفظ الجلسة
            return redirect(url_for('admin_panel'))
        else:
            return render_template_string(LOGIN_HTML, error=True)

    # 2. التحقق من الجلسة (إذا لم يكن مسجلاً، اظهر شاشة القفل)
    if not session.get('is_admin'):
        return render_template_string(LOGIN_HTML, error=False)

    # 3. لوحة التحكم (للمدير فقط)
    msg = ""
    # معالجة نشر الأخبار
    if request.method == 'POST' and 'news_text' in request.form:
        new_text = request.form.get('news_text')
        if new_text:
            timestamp = datetime.datetime.now().strftime("%H:%M")
            entry = f"[{timestamp}] {new_text}\n"
            with open(NEWS_FILE, "a", encoding="utf-8") as f:
                f.write(entry)
            msg = ">> POSTED SUCCESSFULLY."
            
    # قراءة سجل الزوار
    logs_content = "No logs yet."
    if os.path.exists(VISITORS_FILE):
        with open(VISITORS_FILE, "r", encoding="utf-8") as f:
            logs_content = f.read()

    # واجهة المدير
    return f"""
    <body style="background:#050505; color:#0f8; font-family:'Courier New', monospace; padding:20px; text-align:center;">
        <h1 style="border-bottom:1px solid #0f8; padding-bottom:10px;">>> ADMIN COMMAND CENTER</h1>
        
        <div style="background:#111; padding:20px; border:1px solid #333; margin-bottom:20px;">
            <h3>[ BROADCAST SYSTEM ]</h3>
            <form method="POST">
                <input type="text" name="news_text" placeholder="Type update here..." style="width:60%; padding:10px; background:#000; border:1px solid #0f8; color:#fff; font-family:monospace;">
                <button type="submit" style="padding:10px 20px; background:#0f8; border:none; cursor:pointer; font-weight:bold;">PUBLISH</button>
            </form>
            <p style="color:#ffbd2e;">{msg}</p>
        </div>

        <div style="background:#111; padding:20px; border:1px solid #333; text-align:left;">
            <h3>[ VISITOR LOGS DATABASE ]</h3>
            <pre style="height:300px; overflow-y:scroll; background:#000; padding:10px; border:1px dashed #555; font-size:0.8rem;">{logs_content}</pre>
        </div>
        
        <br>
        <a href="/" style="color:#555; text-decoration:none;">[ Back to Home ]</a>
    </body>
    """

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
