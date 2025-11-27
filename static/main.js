const API_ENDPOINT = '/api/scan';

function startScan() {
    const input = document.getElementById('target');
    let target = input.value.trim();
    const btn = document.getElementById('scanBtn');
    const resultsDiv = document.getElementById('results');
    const logOutput = document.getElementById('log-output');
    const loader = document.getElementById('loader');

    if (!target) {
        alert("Please enter a target!");
        return;
    }

    // تنظيف الواجهة
    logOutput.innerHTML = '';
    resultsDiv.style.display = 'block';
    loader.style.display = 'block';
    btn.disabled = true;
    btn.innerText = "SCANNING...";
    
    // سجل البداية
    addLog(`> Initializing scan for: <span class="text-blue">${target}</span>`);
    
    fetch(API_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target })
    })
    .then(response => {
        if (!response.ok) throw new Error("Server Error");
        return response.json();
    })
    .then(data => {
        loader.style.display = 'none';
        btn.disabled = false;
        btn.innerText = "EXECUTE";
        processResults(data);
    })
    .catch(error => {
        loader.style.display = 'none';
        btn.disabled = false;
        btn.innerText = "EXECUTE";
        addLog(`> <span class="text-red">CRITICAL ERROR: Connection Failed.</span>`);
        addLog(`> details: ${error.message}`);
        console.error(error);
    });
}

function processResults(data) {
    // 1. معالجة الحظر
    if (data.status === 'BLOCKED') {
        addLog(`> <span class="text-red">[!] ACCESS DENIED: Target is restricted.</span>`);
        addLog(`> Reason: ${data.message}`);
        if(data.ip) addLog(`> Resolved IP: ${data.ip}`);
        return;
    }

    // 2. معالجة أخطاء DNS
    if (data.status === 'ERROR') {
        addLog(`> <span class="text-red">[!] DNS ERROR: ${data.message}</span>`);
        return;
    }

    // 3. عرض النتائج الناجحة
    addLog(`> <span class="text-green">[+] IP Resolved:</span> ${data.ip_address}`);
    addLog(`> <span class="text-yellow">[i] Geo Location:</span> ${data.country}`);

    // حالة المضيف
    if (data.host_status === 'UP') {
        let latMsg = data.latency > 0 ? `(Latency: ~${data.latency}ms)` : "(TCP Handshake: OK)";
        addLog(`> <span class="text-green">[+] Host Status: ONLINE ${latMsg}</span>`);
    } else {
        addLog(`> <span class="text-red">[-] Host Status: OFFLINE (or blocking probes)</span>`);
    }

    // المنافذ
    if (data.open_ports && data.open_ports.length > 0) {
        addLog(`> <span class="text-green">[+] Open Ports:</span> [ ${data.open_ports.join(', ')} ]`);
    } else {
        addLog(`> <span class="text-yellow">[-] No open ports found in quick scan.</span>`);
    }

    // الترويسات
    if (data.headers) {
        addLog(`> --- HTTP HEADERS ---`);
        addLog(`> Server: <span class="text-blue">${data.headers.Server}</span>`);
        addLog(`> Code: ${data.headers.Status}`);
    }

    addLog(`> <span class="text-green">SCAN COMPLETE.</span>`);
}

function addLog(html) {
    const logOutput = document.getElementById('log-output');
    const div = document.createElement('div');
    div.className = 'log-entry';
    div.innerHTML = html;
    logOutput.appendChild(div);
    logOutput.scrollTop = logOutput.scrollHeight;
}

// تشغيل عند ضغط Enter
document.getElementById('target').addEventListener('keypress', function (e) {
    if (e.key === 'Enter') {
        startScan();
    }
});
