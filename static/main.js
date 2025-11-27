const API_ENDPOINT = '/api/scan';

function loadNews() {
    fetch('/api/news')
        .then(res => res.json())
        .then(data => {
            const feed = document.getElementById('news-feed');
            feed.innerHTML = '';
            if (!data || data.length === 0) {
                feed.innerHTML = '<p style="color:#555;">// No updates.</p>';
                return;
            }
            data.forEach(text => {
                let timePart = text.match(/^\[.*?\]/);
                let contentPart = text.replace(/^\[.*?\]/, '');
                feed.innerHTML += `<div class="news-item"><span>${timePart ? timePart[0] : ''}</span>${contentPart}</div>`;
            });
        })
        .catch(err => console.error(err));
}

function startScan() {
    const input = document.getElementById('target');
    const target = input.value.trim();
    const btn = document.getElementById('scanBtn');
    const resultsDiv = document.getElementById('results');
    const logOutput = document.getElementById('log-output');
    const loader = document.getElementById('loader');

    if (!target) { alert("Please enter a target!"); return; }

    logOutput.innerHTML = '';
    resultsDiv.style.display = 'block';
    loader.style.display = 'block';
    btn.disabled = true;
    btn.innerText = "SCANNING...";
    
    addLog(`> Initiating scan sequence for: <span class="text-blue">${target}</span>`);
    
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
    });
}

function processResults(data) {
    if (data.status === 'BLOCKED') {
        addLog(`> <span class="text-red">[!] ACCESS DENIED: Restricted Target.</span>`);
        if(data.ip) addLog(`> IP: ${data.ip}`);
        return;
    }
    if (data.status === 'ERROR') {
        addLog(`> <span class="text-red">[!] DNS ERROR: Could not resolve.</span>`);
        return;
    }

    addLog(`> <span class="text-green">[+] IP Resolved:</span> ${data.ip_address}`);
    addLog(`> <span class="text-yellow">[i] Geo Location:</span> ${data.country}`);

    if (data.host_status === 'UP') {
        let latMsg = data.latency > 0 ? `(Latency: ~${data.latency}ms)` : "(TCP Handshake: OK)";
        addLog(`> <span class="text-green">[+] Host Status: ONLINE ${latMsg}</span>`);
        
        if (data.open_ports && data.open_ports.length > 0) {
            addLog(`> <span class="text-green">[+] Open Ports:</span> [ ${data.open_ports.join(', ')} ]`);
        } else {
            addLog(`> <span class="text-yellow">[-] No standard ports open (Firewall?).</span>`);
        }

        if (data.headers) {
            addLog(`> --- SERVER FINGERPRINT ---`);
            addLog(`> Server: <span class="text-blue">${data.headers.Server}</span>`);
            addLog(`> Code: ${data.headers.Status}`);
        }
    } else {
        addLog(`> <span class="text-red">[-] Host Status: OFFLINE.</span>`);
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

document.addEventListener('DOMContentLoaded', loadNews);
document.getElementById('target').addEventListener('keypress', function (e) {
    if (e.key === 'Enter') startScan();
});
