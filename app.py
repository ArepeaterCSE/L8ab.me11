from flask import Flask, request, jsonify, render_template
import requests
import socket
import ipaddress
from ping3 import ping
import logging

# إعداد السجل
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)

# --- القائمة السوداء (كما هي دون تعديل) ---
BLACKLIST = ["L8AB.ME", "L8AB.COM", "127.0.0.1", "0.0.0.0", "LOCALHOST"]

def is_safe_ip(ip):
    """التحقق من أن العنوان ليس شبكة داخلية (Anti-SSRF)"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return False
        return True
    except ValueError:
        return False

def get_geo_location(ip_address):
    """جلب الموقع الجغرافي"""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=3)
        if response.status_code == 200:
            data = response.json()
            return f"{data.get('country', 'Unknown')} - {data.get('isp', '')}"
    except:
        pass
    return 'N/A'

def smart_host_check(ip):
    """
    فحص ذكي: يحاول Ping أولاً، وإذا تم حظره من قبل السيرفر،
    يجرب الاتصال عبر TCP (بورت 80 أو 443) للتأكد.
    """
    latency = 0
    status = 'DOWN'

    # 1. محاولة Ping التقليدية
    try:
        latency = ping(ip, unit='ms', timeout=1)
        if latency is not None:
            return 'UP', round(latency, 2)
    except:
        pass # تجاهل أخطاء الـ Ping (مثل الصلاحيات)

    # 2. خطة بديلة: فحص TCP (يعمل دائماً في الاستضافات السحابية)
    try:
        # تجربة الاتصال بمنفذ 80 (HTTP)
        sock = socket.create_connection((ip, 80), timeout=1)
        sock.close()
        return 'UP', 10 # قيمة افتراضية للسرعة
    except:
        try:
            # تجربة الاتصال بمنفذ 443 (HTTPS)
            sock = socket.create_connection((ip, 443), timeout=1)
            sock.close()
            return 'UP', 10
        except:
            return 'DOWN', 0

def scan_ports(ip):
    """فحص سريع لأهم المنافذ"""
    target_ports = [21, 22, 53, 80, 443, 3306, 8080]
    open_ports = []
    
    for port in target_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5) 
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            s.close()
        except:
            continue
    return open_ports

def get_http_headers(target):
    """جلب الترويسات"""
    # التأكد من وجود البروتوكول
    if not target.startswith('http'):
        url = f"http://{target}"
    else:
        url = target
        
    try:
        response = requests.head(url, timeout=3, allow_redirects=True)
        return {
            "Server": response.headers.get("Server", "Hidden"),
            "X-Powered-By": response.headers.get("X-Powered-By", "Hidden"),
            "Status": response.status_code
        }
    except:
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def scan_target():
    data = request.get_json()
    target = data.get('target', '').strip()

    if not target:
        return jsonify({"status": "ERROR", "message": "No target provided"}), 400

    # 1. تحليل العنوان (DNS Resolution)
    try:
        # إزالة http/https إذا كتبت للحصول على اسم النطاق الصافي للـ IP
        clean_hostname = target.replace("http://", "").replace("https://", "").split('/')[0]
        ip_address = socket.gethostbyname(clean_hostname)
    except socket.gaierror:
        return jsonify({"status": "ERROR", "message": "Could not resolve hostname."}), 200

    # 2. التحقق من القائمة السوداء والأمان
    # التحقق من الاسم
    if any(blk in target.upper() for blk in BLACKLIST):
        return jsonify({"status": "BLOCKED", "message": "Blacklisted Domain", "ip": ip_address}), 200
    
    # التحقق من الـ IP (SSRF Protection)
    if not is_safe_ip(ip_address):
        return jsonify({"status": "BLOCKED", "message": "Private/Local Network Restricted", "ip": ip_address}), 200

    # 3. الفحص الذكي (Smart Check)
    host_status, latency = smart_host_check(ip_address)

    # 4. باقي الفحوصات (تنفذ فقط إذا كان الهدف متاحاً أو للتأكد)
    geo_info = get_geo_location(ip_address)
    open_ports = scan_ports(ip_address) if host_status == 'UP' else []
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

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
