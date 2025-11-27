from flask import Flask, request, jsonify, render_template
import requests
import socket
from ping3 import ping, PingError # مكتبة فحص Ping
import logging

# إعداد السجل (Log) لـ Flask
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)

# قائمة النطاقات/الـ IPs المحظورة على مستوى الخادم كإجراء أمني إضافي
BLACKLIST = ["L8AB.ME", "L8AB.COM", "127.0.0.1", "0.0.0.0"] 
GEO_IP_API = "http://ip-api.com/json/" # واجهة GeoIP مجانية

def get_geo_location(ip_address):
    """جلب الموقع الجغرافي (الدولة المستضيفة)."""
    try:
        response = requests.get(f"{GEO_IP_API}{ip_address}", timeout=5)
        response.raise_for_status()
        data = response.json()
        # نستخدم 'country' للحصول على اسم الدولة
        return data.get('country', 'N/A (GeoIP Failed)')
    except requests.exceptions.RequestException as e:
        logging.error(f"GeoIP API Error: {e}")
        return 'N/A (API Error)'

def check_host_status(target):
    """فحص حالة الاستضافة (UP/DOWN) وحل الاسم إلى IP."""
    ip_address = None
    
    try:
        # محاولة حل الاسم إلى IP أولاً
        ip_address = socket.gethostbyname(target)
    except socket.gaierror:
        # فشل حل الاسم
        return 'DOWN', None
    
    # 💥 التحقق من القائمة السوداء باستخدام IP المحلول 💥
    if ip_address in BLACKLIST:
        return 'BLOCKED', ip_address 

    # إرسال Ping
    try:
        # إرسال 3 محاولات Ping مع مهلة 1 ثانية
        delay = ping(ip_address, unit='ms', timeout=1) 
    except PingError as e:
        logging.error(f"Ping execution error: {e}")
        return 'DOWN', ip_address # فشل في عملية Ping نفسها

    # تحديد حالة الاستضافة
    if delay is not None and delay is not False:
        # إذا كانت القيمة رقمية (نجاح Ping)
        status = 'UP'
    else:
        # فشل Ping
        status = 'DOWN'

    return status, ip_address

# المسار الرئيسي لعرض الصفحة
@app.route('/')
def index():
    # يعرض ملف index.html
    return render_template('index.html')

# مسار API لمعالجة طلب الفحص من JavaScript
@app.route('/api/scan', methods=['POST'])
def scan_target():
    data = request.get_json()
    target = data.get('target', '').strip()

    if not target:
        return jsonify({"error": "No target provided"}), 400

    # 1. فحص حالة الاستضافة والـ IP
    host_status, ip_address = check_host_status(target)

    # 2. التحقق من حالة الحظر
    if host_status == 'BLOCKED' or target.upper() in [n.upper() for n in BLACKLIST]:
        return jsonify({
            "status": "BLOCKED",
            "message": "Target is on the backend blacklist.",
            "ip_address": ip_address if ip_address else 'N/A',
            "host_status": "BLOCKED",
            "country": "BLOCKED"
        }), 200

    # 3. جلب الموقع الجغرافي فقط إذا كان لدينا IP صالح
    country = 'N/A'
    if ip_address:
        country = get_geo_location(ip_address)

    # 4. إرجاع النتائج
    return jsonify({
        "target": target,
        "ip_address": ip_address if ip_address else 'N/A',
        "host_status": host_status,
        "country": country,
        "message": "Scan complete."
    })

if __name__ == '__main__':
    # هذا للتطوير المحلي فقط
    app.run(debug=True, host='0.0.0.0')
