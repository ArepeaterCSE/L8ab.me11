const API_ENDPOINT = '/api/scan';

function startScan() {
    const input = document.getElementById('target');
    const target = input.value.trim();
    const btn = document.getElementById('scanBtn');
    const resultsDiv = document.getElementById('results');
    const logOutput = document.getElementById('log-output');
    const loader = document.getElementById('loader');

    if (!target) {
        alert("Please enter a target!");
        return;
    }

    // Reset UI
    logOutput.innerHTML = '';
    resultsDiv.style.display = 'block';
    loader.style.display = 'block';
    btn.disabled = true;
    btn.innerText = "SCANNING...";
    
    // Initial Log
    addLog(`> Initiating scan sequence for: <span class="text-blue">${target}</span>`);
    addLog(`> Resolving Hostname & Verifying Integrity...`);

    fetch(API_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target })
    })
    .then(response => response.json())
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
        console.error(error);
    });
}

function processResults(data) {
    // 1. BLOCKED
    if (data.status === 'BLOCKED') {
        addLog(`> <span class="text-red">[!] ACCESS DENIED: Target is restricted.</span>`);
        addLog(`> Reason: ${data.message}`);
        if(data.ip) addLog(`> Resolved IP: ${data.ip}`);
        return;
    }

    // 2. ERROR
    if (data.status === 'ERROR') {
        addLog(`> <span class="text-red">[!] DNS ERROR: Could not resolve host.</span>`);
        return;
    }

    // 3. SUCCESS DISPLAY
    addLog(`> <span class="text-green">[+] IP Resolved:</span> ${data.ip_address}`);
    addLog(`> <span class="text-yellow">[i] Geo Location:</span> ${data.country}`);

    // Host Status
    if (data.host_status === 'UP') {
        let latMsg = data.latency > 0 ? `(Latency: ~${data.latency}ms)` : "(TCP Handshake: OK)";
        addLog(`> <span class="text-green">[+] Host Status: ONLINE ${latMsg}</span>`);
    } else {
        addLog(`> <span class="text-red">[-] Host Status: OFFLINE (or blocking probes)</span>`);
    }

    // Ports
    if (data.open_ports && data.open_ports.length > 0) {
        addLog(`> <span class="text-green">[+] Open Ports Found:</span> [ ${data.open_ports.join(', ')} ]`);
    } else {
        if(data.host_status === 'UP') {
            addLog(`> <span class="text-yellow">[-] No standard open ports detected.</span>`);
        }
    }

    // Headers
    if (data.headers) {
        addLog(`> --- SERVER FINGERPRINT ---`);
        addLog(`> Server: <span class="text-blue">${data.headers.Server}</span>`);
        addLog(`> Status Code: ${data.headers.Status}`);
        if(data.headers['X-Powered-By'] !== 'Hidden') {
            addLog(`> X-Powered-By: ${data.headers['X-Powered-By']}`);
        }
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

// Enter Key Listener
document.getElementById('target').addEventListener('keypress', function (e) {
    if (e.key === 'Enter') {
        startScan();
    }
});
