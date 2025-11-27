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
    
    // Add initial log
    addLog(`> Initializing scan for: <span class="text-blue">${target}</span>`);
    addLog(`> Checking DNS records...`);

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
    if (data.status === 'BLOCKED') {
        addLog(`> <span class="text-red">[!] ACCESS DENIED: Target is restricted.</span>`);
        addLog(`> Reason: ${data.message}`);
        return;
    }

    if (data.status === 'ERROR') {
        addLog(`> <span class="text-red">[!] DNS ERROR: Could not resolve host.</span>`);
        return;
    }

    // IP Info
    addLog(`> <span class="text-green">[+] IP Resolved:</span> ${data.ip_address}`);
    addLog(`> <span class="text-yellow">[i] Geo Location:</span> ${data.country}`);

    // Host Status
    if (data.host_status === 'UP') {
        addLog(`> <span class="text-green">[+] Host Status: ONLINE (Latency: ${data.latency}ms)</span>`);
    } else {
        addLog(`> <span class="text-red">[-] Host Status: OFFLINE (or ICMP Blocked)</span>`);
    }

    // Ports
    if (data.open_ports && data.open_ports.length > 0) {
        addLog(`> <span class="text-green">[+] Open Ports Found:</span> [ ${data.open_ports.join(', ')} ]`);
    } else {
        addLog(`> <span class="text-yellow">[-] No standard open ports detected (or Firewall active).</span>`);
    }

    // Headers
    if (data.headers) {
        addLog(`> --- SERVER HEADERS ---`);
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

// Enter key support
document.getElementById('target').addEventListener('keypress', function (e) {
    if (e.key === 'Enter') {
        startScan();
    }
});
