from flask import Flask, request, jsonify, render_template
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

# --- إعدادات ---
BLACKLIST = ["L8AB.ME", "L8AB.COM", "127.0.0.1", "0.0.0.0", "LOCALHOST"]
VISITORS_FILE = "visitors.txt"
NEWS_FILE = "news.txt"

# --- دوال المساعدة ---

def get_real_ip():
    """جلب IP الحقيقي وتجاوز البروكسي"""
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    return request.remote_addr

def get_geo_location(ip_address):
    """جلب الدولة"""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=2)
        if response.status_code == 200:
            data = response.json()
            return data.get('country', 'Unknown Location')
    except:
        pass
    return 'Unknown Location'

def log_visitor(ip, country):
    """تسجيل الزائر"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] IP: {ip} | Location: {country}\n"
    try:
        with open(VISITORS_FILE, "a", encoding="utf-8") as f:
            f.write(log_entry)
    except Exception as e:
        logging.error(f"Failed to log visitor: {e}")

def get_news():
    """قراءة الأخبار"""
    try:
        if not os.path.exists(NEWS_FILE):
            return []
        with open(NEWS_FILE, "r", encoding="utf-8") as f:
            return [line.strip() for line in f.readlines() if line.strip()][::-1]
    except:
        return []

def is_safe_ip(ip):
    """Anti-SSRF Check"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return False
        return True
    except ValueError:
        return False

def smart_host_check(ip):
    """فحص ذكي (Ping -> TCP 80 -> TCP 443)"""
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
    """فحص سريع للمنافذ"""
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

# --- المسارات (Routes) ---

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

    if not target:
        return jsonify({"status": "ERROR", "message": "No target provided"}), 400

    try:
        clean_hostname = target.replace("http://", "").replace("https://", "").split('/')[0]
        ip_address = socket.gethostbyname(clean_hostname)
    except socket.gaierror:
        return jsonify({"status": "ERROR", "message": "Could not resolve hostname."}), 200

    if any(blk in target.upper() for blk in BLACKLIST):
        return jsonify({"status": "BLOCKED", "message": "Blacklisted Domain", "ip": ip_address}), 200
    
    if not is_safe_ip(ip_address):
        return jsonify({"status": "BLOCKED", "message": "Private Network Restricted", "ip": ip_address}), 200

    host_status, latency = smart_host_check(ip_address)
    geo_info = get_geo_location(ip_address)
    
    open_ports = []
    headers = None
    
    if host_status == 'UP':
        open_ports = scan_ports(ip_address)
        headers = get_http_headers(clean_hostname)

    return jsonify({
        "status": "SUCCESS",
        "target": target,
        "ip_address": ip_address,
        "host_status": host_status,
        "latency": latency,
        "country": geo_info,
        "open_ports": open_ports,
        "headers": headers
    })

# --- صفحات الإدارة السرية ---

@app.route('/secret-logs-x99')
def view_logs():
    try:
        with open(VISITORS_FILE, "r", encoding="utf-8") as f:
            content = f.read()
        return f"""<body style="background:#000;color:#0f8;font-family:monospace;padding:20px;">
        <h1>>> VISITOR LOGS</h1><pre style="border:1px solid #333;padding:15px;">{content}</pre></body>"""
    except:
        return "No logs yet."

@app.route('/admin-panel-x99', methods=['GET', 'POST'])
def admin_panel():
    msg = ""
    if request.method == 'POST':
        new_text = request.form.get('news_text')
        if new_text:
            timestamp = datetime.datetime.now().strftime("%H:%M")
            entry = f"[{timestamp}] {new_text}\n"
            with open(NEWS_FILE, "a", encoding="utf-8") as f:
                f.write(entry)
            msg = "PUBLISHED!"
    
    return f"""
    <body style="background:#000;color:#0f8;font-family:monospace;padding:20px;text-align:center;">
        <h1>>> ADMIN NEWS PANEL</h1>
        <form method="POST">
            <input type="text" name="news_text" placeholder="Update text..." style="width:300px;padding:10px;background:#111;border:1px solid #0f8;color:#fff;">
            <button type="submit" style="padding:10px;background:#0f8;cursor:pointer;">POST</button>
        </form>
        <p>{msg}</p>
        <hr><pre>{'<br>'.join(get_news())}</pre>
    </body>
    """

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
