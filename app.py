from flask import Flask, request, jsonify, render_template
import requests
import socket
import ipaddress
from ping3 import ping
import logging
import datetime

# إعداد السجل
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)

# --- إعدادات القائمة السوداء ---
BLACKLIST = ["L8AB.ME", "L8AB.COM", "127.0.0.1", "0.0.0.0", "LOCALHOST"]

# --- دوال المساعدة (Helper Functions) ---

def get_real_ip():
    """جلب IP الحقيقي للزائر وتجاوز البروكسي"""
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    return request.remote_addr

def get_geo_location(ip_address):
    """جلب اسم الدولة بناءً على الـ IP"""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=2)
        if response.status_code == 200:
            data = response.json()
            return data.get('country', 'Unknown Location')
    except:
        pass
    return 'Unknown Location'

def log_visitor(ip, country):
    """تسجيل بيانات الزائر في ملف نصي"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] IP: {ip} | Location: {country}\n"
    try:
        with open("visitors.txt", "a", encoding="utf-8") as f:
            f.write(log_entry)
    except Exception as e:
        logging.error(f"Failed to log visitor: {e}")

def is_safe_ip(ip):
    """الحماية من SSRF: التأكد من أن العنوان ليس محلياً"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return False
        return True
    except ValueError:
        return False

def smart_host_check(ip):
    """
    فحص ذكي: يحاول Ping أولاً، وإذا فشل يجرب الاتصال المباشر (TCP)
    للتغلب على جدران الحماية التي تحظر ICMP.
    """
    # 1. محاولة Ping
    try:
        latency = ping(ip, unit='ms', timeout=1)
        if latency is not None:
            return 'UP', round(latency, 2)
    except:
        pass 

    # 2. محاولة TCP (HTTP/80)
    try:
        sock = socket.create_connection((ip, 80), timeout=1)
        sock.close()
        return 'UP', 10 # قيمة افتراضية للسرعة
    except:
        pass

    # 3. محاولة TCP (HTTPS/443)
    try:
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
            s.settimeout(0.4) 
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            s.close()
        except:
            continue
    return open_ports

def get_http_headers(target):
    """جلب ترويسات السيرفر"""
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
    # تسجيل الزائر وعرض الصفحة
    visitor_ip = get_real_ip()
    visitor_country = get_geo_location(visitor_ip)
    
    log_visitor(visitor_ip, visitor_country)
    
    return render_template('index.html', my_ip=visitor_ip, my_country=visitor_country)

@app.route('/api/scan', methods=['POST'])
def scan_target():
    data = request.get_json()
    target = data.get('target', '').strip()

    if not target:
        return jsonify({"status": "ERROR", "message": "No target provided"}), 400

    # 1. Resolve Hostname
    try:
        clean_hostname = target.replace("http://", "").replace("https://", "").split('/')[0]
        ip_address = socket.gethostbyname(clean_hostname)
    except socket.gaierror:
        return jsonify({"status": "ERROR", "message": "Could not resolve hostname."}), 200

    # 2. Security Checks
    if any(blk in target.upper() for blk in BLACKLIST):
        return jsonify({"status": "BLOCKED", "message": "Blacklisted Domain", "ip": ip_address}), 200
    
    if not is_safe_ip(ip_address):
        return jsonify({"status": "BLOCKED", "message": "Private/Local Network Restricted", "ip": ip_address}), 200

    # 3. Execution
    host_status, latency = smart_host_check(ip_address)
    geo_info = get_geo_location(ip_address)
    
    open_ports = []
    headers = None
    
    # إجراء الفحص العميق فقط إذا كان الهدف يعمل
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

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
