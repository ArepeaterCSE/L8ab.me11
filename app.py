from flask import Flask, request, jsonify, render_template
import requests
import socket
import ipaddress
from ping3 import ping
import logging

# إعداد السجل
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)

# تحسين قائمة الحظر لتشمل النطاقات المحلية بشكل أوسع
BLACKLIST_DOMAINS = ["l8ab.me", "localhost", "0.0.0.0"]

def is_safe_ip(ip):
    """
    التحقق مما إذا كان العنوان IP آمناً (ليس خاصاً أو محلياً)
    لمنع ثغرات SSRF.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        # التحقق هل هو خاص (Private) أو Loopback أو Link-local
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return False
        return True
    except ValueError:
        return False

def get_geo_location(ip_address):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=3)
        if response.status_code == 200:
            data = response.json()
            return f"{data.get('country', 'Unknown')} - {data.get('isp', '')}"
        return 'N/A'
    except:
        return 'N/A'

def scan_ports(ip, ports=[21, 22, 80, 443, 8080]):
    """فحص سريع لأهم المنافذ"""
    open_ports = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5) # مهلة قصيرة جداً للسرعة
        result = s.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        s.close()
    return open_ports

def get_http_headers(target):
    """جلب ترويسات HTTP للكشف عن نوع السيرفر"""
    url = f"http://{target}"
    try:
        response = requests.head(url, timeout=2, allow_redirects=True)
        # نرجع أهم الترويسات فقط
        headers = {
            "Server": response.headers.get("Server", "Hidden"),
            "X-Powered-By": response.headers.get("X-Powered-By", "Hidden"),
            "Status": response.status_code
        }
        return headers
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
        return jsonify({"error": "No target provided"}), 400

    # 1. Resolve IP
    try:
        ip_address = socket.gethostbyname(target)
    except socket.gaierror:
        return jsonify({"status": "ERROR", "message": "Could not resolve hostname."}), 200

    # 2. Security Check (Anti-SSRF)
    if not is_safe_ip(ip_address) or target.lower() in BLACKLIST_DOMAINS:
        return jsonify({
            "status": "BLOCKED",
            "message": "Target is restricted (Private/Local Network).",
            "ip": ip_address
        }), 200

    # 3. Ping Test
    try:
        latency = ping(ip_address, unit='ms', timeout=1)
        host_status = 'UP' if latency is not None else 'DOWN'
    except:
        host_status = 'DOWN'
        latency = 0

    # 4. Advanced Scans (Only if UP or requested)
    geo_info = get_geo_location(ip_address)
    open_ports = scan_ports(ip_address)
    headers = get_http_headers(target)

    return jsonify({
        "status": "SUCCESS",
        "target": target,
        "ip_address": ip_address,
        "host_status": host_status,
        "latency": round(latency, 2) if latency else 0,
        "country": geo_info,
        "open_ports": open_ports,
        "headers": headers
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
