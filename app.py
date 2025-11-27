from flask import Flask, request, jsonify, render_template, session, redirect, url_for, render_template_string
import requests
import socket
import ipaddress
from ping3 import ping
import logging
import datetime
import os
import json  # <--- مكتبة جديدة ضرورية

# إعداد السجل
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)

# --- إعدادات الأمان ---
app.secret_key = 'L8AB_SECURE_KEY_X99'
ADMIN_PASSCODE = "Asim1001@"

# --- الملفات ---
BLACKLIST = ["L8AB.ME", "L8AB.COM", "127.0.0.1", "0.0.0.0", "LOCALHOST"]
NEWS_FILE = "news.txt"
ACTIVITY_FILE = "activity_log.txt" 
PUBLIC_LOGS_FILE = "chat_logs.json" # <--- ملف السجل العام الجديد

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

# --- إدارة السجل العام (Chat Logs) ---
def load_public_logs():
    """قراءة السجلات وحذف القديم (أكثر من 24 ساعة)"""
    if not os.path.exists(PUBLIC_LOGS_FILE):
        return []
    
    try:
        with open(PUBLIC_LOGS_FILE, 'r', encoding='utf-8') as f:
            logs = json.load(f)
    except:
        return []

    # فلترة السجلات: إبقاء ما هو أحدث من 24 ساعة فقط
    cleaned_logs = []
    now = datetime.datetime.now()
    cutoff = now - datetime.timedelta(hours=24)
    
    changed = False
    for log in logs:
        log_time = datetime.datetime.fromisoformat(log['timestamp'])
        if log_time > cutoff:
            cleaned_logs.append(log)
        else:
            changed = True
    
    # حفظ التنظيف إذا تم حذف شيء
    if changed:
        save_public_logs_to_file(cleaned_logs)
        
    return cleaned_logs

def save_public_logs_to_file(logs):
    with open(PUBLIC_LOGS_FILE, 'w', encoding='utf-8') as f:
        json.dump(logs, f, ensure_ascii=False, indent=4)

def add_public_log(text, log_type='info'):
    """إضافة سجل جديد"""
    logs = load_public_logs()
    new_entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "text": text,
        "type": log_type # info, success, error, warning
    }
    logs.append(new_entry)
    save_public_logs_to_file(logs)

# --- دوال الفحص القديمة (كما هي) ---
def is_safe_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local: return False
        return True
    except: return False

def smart_host_check(ip):
    try:
        if ping(ip, unit='ms', timeout=1) is not None: return 'UP'
    except: pass 
    try:
        socket.create_connection((ip, 80), timeout=1).close(); return 'UP'
    except: pass
    try:
        socket.create_connection((ip, 443), timeout=1).close(); return 'UP'
    except: return 'DOWN'

def scan_ports(ip):
    target_ports = [21, 22, 53, 80, 443, 3306, 8080]
    open_ports = []
    for port in target_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.4) 
            if s.connect_ex((ip, port)) == 0: open_ports.append(port)
            s.close()
        except: continue
    return open_ports

def get_http_headers(target):
    if not target.startswith('http'): url = f"http://{target}"
    else: url = target
    try:
        response = requests.head(url, timeout=3, allow_redirects=True)
        return {"Server": response.headers.get("Server", "Hidden"), "Status": response.status_code}
    except: return None

# --- HTML Login ---
LOGIN_HTML = """<!DOCTYPE html><html><body style="background:#000;color:#0f8;text-align:center;padding:50px;font-family:monospace;"><h2>// AUTH REQUIRED</h2><form method="POST"><input type="password" name="passcode" style="padding:10px;"><br><br><button type="submit">UNLOCK</button></form></body></html>"""

# --- Routes ---

@app.route('/')
def index():
    ip = get_real_ip()
    country = get_geo_location(ip)
    return render_template('index.html', my_ip=ip, my_country=country)

@app.route('/api/news')
def api_news():
    # جلب الأخبار + إضافة IP الزائر كخبر وهمي للمتعة (اختياري)
    news = []
    if os.path.exists(NEWS_FILE):
        with open(NEWS_FILE, "r", encoding="utf-8") as f:
            news = [line.strip() for line in f.readlines() if line.strip()][::-1]
    return jsonify(news)

# API جديد لجلب السجلات العامة للواجهة
@app.route('/api/public-logs')
def get_public_logs():
    return jsonify(load_public_logs())

@app.route('/api/scan', methods=['POST'])
def scan_target():
    data = request.get_json()
    target = data.get('target', '').strip()
    visitor_ip = get_real_ip()
    
    if not target: return jsonify({"status": "ERROR"}), 400

    # تسجيل المحاولة في السجل العام
    add_public_log(f"User [{visitor_ip}] initiated scan on: {target}", "info")

    try:
        clean_hostname = target.replace("http://", "").replace("https://", "").split('/')[0]
        ip_address = socket.gethostbyname(clean_hostname)
    except:
        add_public_log(f"DNS Resolution Failed for: {target}", "error")
        return jsonify({"status": "ERROR"}), 200

    if any(blk in target.upper() for blk in BLACKLIST) or not is_safe_ip(ip_address):
        add_public_log(f"Security Alert: Blocked scan attempt on {target}", "error")
        return jsonify({"status": "BLOCKED"}), 200

    host_status = smart_host_check(ip_address)
    geo = get_geo_location(ip_address)
    
    # تسجيل النتيجة في السجل العام ليراها الجميع
    result_msg = f"TARGET: {target} ({ip_address}) | STATUS: {host_status} | LOC: {geo}"
    add_public_log(result_msg, "success" if host_status == 'UP' else "warning")

    # تفاصيل إضافية
    open_ports = []
    headers = None
    if host_status == 'UP':
        open_ports = scan_ports(ip_address)
        if open_ports:
            add_public_log(f"Open Ports on {target}: {open_ports}", "success")
        headers = get_http_headers(clean_hostname)
        if headers:
             add_public_log(f"Server Info ({target}): {headers.get('Server')} [Code: {headers.get('Status')}]", "info")

    return jsonify({"status": "SUCCESS"}) # الرد لم يعد مهماً لأن البيانات تُقرأ من السجل العام

# --- Admin ---
@app.route('/admin-panel-x99', methods=['GET', 'POST'])
def admin_panel():
    if request.method == 'POST':
        if request.form.get('passcode') == ADMIN_PASSCODE:
            session['is_admin'] = True
            return redirect(url_for('admin_panel'))
        # معالجة نشر الأخبار
        if session.get('is_admin') and request.form.get('news_text'):
             with open(NEWS_FILE, "a", encoding="utf-8") as f:
                 f.write(f"[{datetime.datetime.now().strftime('%H:%M')}] {request.form.get('news_text')}\n")
    
    if not session.get('is_admin'): return render_template_string(LOGIN_HTML)
    
    return """<body style="background:#000;color:#0f8;text-align:center;font-family:monospace;"><h1>ADMIN PANEL</h1><form method="POST"><input name="news_text"><button>POST NEWS</button></form></body>"""

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
