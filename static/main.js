const API_SCAN = '/api/scan';
const API_LOGS = '/api/public-logs';
const API_NEWS = '/api/news';

// 1. تشغيل التحديث التلقائي عند التحميل
document.addEventListener('DOMContentLoaded', () => {
    loadNews();
    // تحديث السجلات فوراً
    refreshLogs();
    // تكرار التحديث كل 2 ثانية لتظهر كدردشة حية
    setInterval(refreshLogs, 2000); 
});

// 2. دالة جلب السجلات وعرضها
async function refreshLogs() {
    try {
        const response = await fetch(API_LOGS);
        const logs = await response.json();
        const logOutput = document.getElementById('log-output');
        
        // نحفظ مكان التمرير (Scroll) الحالي
        const shouldScroll = logOutput.scrollTop + logOutput.clientHeight === logOutput.scrollHeight;

        logOutput.innerHTML = ''; // مسح القديم وإعادة الكتابة (لضمان الترتيب)
        
        if (logs.length === 0) {
            logOutput.innerHTML = '<div class="log-entry">> System Ready. Waiting for traffic...</div>';
            return;
        }

        logs.forEach(log => {
            // تحديد اللون بناءً على نوع السجل
            let colorClass = 'text-blue';
            if (log.type === 'success') colorClass = 'text-green';
            if (log.type === 'error') colorClass = 'text-red';
            if (log.type === 'warning') colorClass = 'text-yellow';
            
            // تحويل الوقت
            const timeObj = new Date(log.timestamp);
            const timeStr = timeObj.toLocaleTimeString('en-US', {hour12: false});

            const html = `
                <div class="log-entry">
                    <span style="color:#555;">[${timeStr}]</span> 
                    <span class="${colorClass}">${log.text}</span>
                </div>
            `;
            logOutput.innerHTML += html;
        });

        // النزول للأسفل تلقائياً إذا كان المستخدم في الأسفل
        logOutput.scrollTop = logOutput.scrollHeight;

    } catch (e) {
        console.error("Connection Error", e);
    }
}

// 3. دالة بدء الفحص
function startScan() {
    const input = document.getElementById('target');
    const target = input.value.trim();
    const btn = document.getElementById('scanBtn');

    if (!target) { alert("Enter a target!"); return; }

    btn.disabled = true;
    btn.innerText = "QUEUED...";
    input.value = ''; // إفراغ الحقل

    // إرسال طلب الفحص (لن ننتظر النتيجة هنا، لأنها ستظهر في السجل العام)
    fetch(API_SCAN, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target })
    }).then(() => {
        // إعادة تفعيل الزر بعد فترة قصيرة
        setTimeout(() => {
            btn.disabled = false;
            btn.innerText = "EXECUTE";
        }, 3000);
    });
}

// 4. دالة الأخبار (كما هي)
function loadNews() {
    fetch(API_NEWS).then(r => r.json()).then(data => {
        const feed = document.getElementById('news-feed');
        if(!data.length) return;
        feed.innerHTML = '';
        data.forEach(t => feed.innerHTML += `<div class="news-item">${t}</div>`);
    });
}

// زر Enter
document.getElementById('target').addEventListener('keypress', function (e) {
    if (e.key === 'Enter') startScan();
});
