// --- L8AB's Tools - Frontend Scanning Logic (main.js) ---

// 1. تعريف قائمة النطاقات المحظورة (Blacklist)
const BLACKLIST = [
    "L8AB.ME", 
    "L8AB.COM", 
    "127.0.0.1", 
    "LOCALHOST", 
    "0.0.0.0" 
];

// مسار API الذي سيقوم بالعمليات الفعلية على الخادم (Flask)
const API_ENDPOINT = '/api/scan'; 

// 2. الدالة الرئيسية للتحكم بعملية الفحص
function handleScanRequest() {
    const targetInput = document.getElementById('target');
    const resultsDiv = document.getElementById('results');
    const target = targetInput.value.trim();
    const normalizedTarget = target.toUpperCase(); // للتحقق من القائمة السوداء

    // إظهار قسم النتائج وتنظيف المحتوى القديم
    resultsDiv.style.display = 'block';
    resultsDiv.innerHTML = '<h2 class="results-header">// SCAN REPORT & DIAGNOSTICS</h2>';

    // التحقق من أن حقل الإدخال ليس فارغاً
    if (!target) {
        appendLog(`[<span class="status-error">ERROR</span>] يرجى إدخال هدف (IP أو Domain) صالح.`, true);
        return;
    }

    // 3. التحقق من القائمة السوداء (الهدف الأول: منع المواقع الشخصية/المحظورة)
    if (BLACKLIST.includes(normalizedTarget)) {
        displayForbiddenMessage(target, resultsDiv);
        return; 
    }

    // 4. بدء عملية الاتصال وعرض سجل البداية
    appendLog(`[<span class="status-ok">OK</span>] Initiating scan sequence for: **${target}**`, true);
    appendLog(`[<span class="status-ok">OK</span>] Establishing secure API connection...`, true);

    // 5. إرسال الطلب الفعلي إلى الخادم (Backend)
    // نستخدم دالة fetch لإرسال البيانات بأسلوب POST
    setTimeout(() => {
        fetchScanResults(target, resultsDiv);
    }, 1000); 
}

// 6. دالة لعرض رسالة "غير مسموح" بشكل واضح
function displayForbiddenMessage(target, resultsDiv) {
    const forbiddenMessage = `
        <div class="blacklisted">
            <p>🔥 ACCESS DENIED: ${target} 🔥</p>
            <p>🚫 هذا الهدف محظور من الفحص لأسباب أمنية أو سياسات الاستخدام.</p>
        </div>
    `;
    resultsDiv.innerHTML += forbiddenMessage;
    // التأكد من أن العنوان يبقى مرئياً
    document.querySelector('.results-header').scrollIntoView(); 
}

// 7. دالة إرسال الطلب وجلب النتائج من الخادم
async function fetchScanResults(target, resultsDiv) {
    try {
        const response = await fetch(API_ENDPOINT, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ target: target })
        });

        // إذا فشل الاتصال بالخادم نفسه (مثل خطأ 500)
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        
        // معالجة البيانات المستلمة وعرضها
        processBackendResponse(data, target);

    } catch (error) {
        // عرض رسالة خطأ عامة في حال فشل الاتصال بالكامل
        appendLog(`[<span class="status-error">CRITICAL</span>] ERROR: Could not connect to the scanning engine. Check console for details.`, true);
        console.error('Scanning API Fetch Error:', error);
    }
}

// 8. دالة لمعالجة نتائج الخادم وعرضها في السجل
function processBackendResponse(data, target) {
    if (data.status === 'BLOCKED') {
        // إذا قام الخادم بحظر الهدف (تحقق إضافي)
        appendLog(`[<span class="status-error">BLOCKED</span>] System Block: Target IP or Hostname is blacklisted by the server.`, true);
        displayForbiddenMessage(target, document.getElementById('results'));
        return;
    }

    // عرض IP المحلول
    appendLog(`[<span class="status-ok">OK</span>] Resolved IP Address: **${data.ip_address}**`, true);

    // عرض حالة الاستضافة (UP/DOWN)
    if (data.host_status === 'UP') {
        appendLog(`[<span class="status-ok">ONLINE</span>] Host Status: Target is **ONLINE** (Ping Success).`, true);
    } else {
        appendLog(`[<span class="status-error">OFFLINE</span>] Host Status: Target is **DOWN** (Ping Failure).`, true);
    }

    // عرض الموقع الجغرافي
    appendLog(`[<span class="status-warn">GEO-IP</span>] Host Country: **${data.country}**`, true);
    
    // رسالة نهاية الفحص
    appendLog(`[<span class="status-ok">COMPLETE</span>] Scan finished. All results displayed.`, true);
}


// 9. دالة مساعدة لإضافة سجل للنتائج
function appendLog(text, autoScroll = true) {
    const resultsDiv = document.getElementById('results');
    const log = document.createElement('div');
    log.className = 'log';
    log.innerHTML = `<p>${text}</p>`;
    resultsDiv.appendChild(log);
    
    // تمرير تلقائي للأسفل لرؤية أحدث السجلات
    if (autoScroll) {
        resultsDiv.scrollTop = resultsDiv.scrollHeight;
    }
}

// --- نهاية الكود ---
