const API_SCAN = '/api/scan';
const API_LOGS = '/api/public-logs';
const API_NEWS = '/api/news';

document.addEventListener('DOMContentLoaded', () => {
    loadNews();
    setInterval(loadNews, 60000); // Update news every minute
    setInterval(refreshLogs, 2000);
    refreshLogs();
});

async function refreshLogs() {
    try {
        const response = await fetch(API_LOGS);
        const logs = await response.json();
        const logOutput = document.getElementById('log-output');
        
        const isScrolledToBottom = logOutput.scrollHeight - logOutput.clientHeight <= logOutput.scrollTop + 1;

        if (logs.length === 0) {
            logOutput.innerHTML = '<p style="color:#444;">> System Ready. Waiting for traffic...</p>';
            return;
        }

        let html = '';
        logs.forEach(log => {
            let color = 'text-blue';
            let prefix = '[*]';
            
            if (log.type === 'success') { color = 'text-green'; prefix = '[+]'; }
            if (log.type === 'error') { color = 'text-red'; prefix = '[!]'; }
            if (log.type === 'warning') { color = 'text-yellow'; prefix = '[?]'; }

            const time = new Date(log.timestamp).toLocaleTimeString('en-US', {hour12: false});

            html += `
                <div class="log-entry">
                    <span class="dim">${time}</span>
                    <span class="${color}">${prefix} ${log.text}</span>
                </div>
            `;
        });

        // Only update if content changed to prevent flickering
        if (logOutput.innerHTML !== html) {
            logOutput.innerHTML = html;
            if (isScrolledToBottom) logOutput.scrollTop = logOutput.scrollHeight;
        }

    } catch (e) { console.error(e); }
}

function startScan() {
    const input = document.getElementById('target');
    const target = input.value.trim();
    const btn = document.getElementById('scanBtn');

    if (!target) return;

    btn.disabled = true;
    btn.innerText = "Processing...";
    btn.style.opacity = "0.5";
    input.value = '';

    fetch(API_SCAN, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target })
    }).then(() => {
        setTimeout(() => {
            btn.disabled = false;
            btn.innerText = "EXECUTE";
            btn.style.opacity = "1";
            document.getElementById('target').focus();
        }, 2000);
    });
}

function loadNews() {
    fetch(API_NEWS).then(r => r.json()).then(data => {
        const feed = document.getElementById('news-feed');
        if(!data.length) {
            feed.innerHTML = '<p style="color:#555">No active alerts.</p>';
            return;
        }
        let html = '';
        data.forEach(t => html += `<div class="news-item">> ${t}</div>`);
        feed.innerHTML = html;
    });
}

document.getElementById('target').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') startScan();
});
