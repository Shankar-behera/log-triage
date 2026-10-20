let progressInterval = null;

async function checkConnection() {
    try {
        const r = await fetch('/health');
        const data = await r.json();
        const icon = document.getElementById('healthIcon');
        const status = document.getElementById('healthStatus');
        const modelStatus = document.getElementById('modelStatus');
        if (data.status === 'healthy') {
            icon.style.color = '#4CAF50';
            status.textContent = `✅ Connected | ${data.model}`;
            modelStatus.innerHTML = `<i class="fas fa-microchip"></i> ${data.model}`;
        } else {
            icon.style.color = '#f44336';
            status.textContent = '⚠️ Degraded (Groq unreachable)';
        }
    } catch {
        document.getElementById('healthStatus').textContent = '❌ Cannot connect';
    }
}

async function analyzeText() {
    const text = document.getElementById('logText').value.trim();
    if (!text) return alert('Paste some logs first');
    const quick = document.getElementById('quickMode').checked;
    document.getElementById('analysisSection').classList.remove('hidden');
    document.getElementById('statusText').textContent = 'Analyzing...';
    try {
        const r = await fetch('/analyze/text', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ log_text: text, analysis_type: quick ? 'quick' : 'full' }),
        });
        const result = await r.json();
        if (!r.ok) throw new Error(result.detail || 'Failed');
        displayResults(result.data);
    } catch (e) {
        document.getElementById('statusText').textContent = 'Failed';
        document.getElementById('summaryContent').textContent = 'Error: ' + e.message;
    }
}

async function analyzeFile(file) {
    if (!file) return;
    const quick = document.getElementById('quickMode').checked;
    document.getElementById('analysisSection').classList.remove('hidden');
    document.getElementById('statusText').textContent = 'Uploading...';
    const fd = new FormData();
    fd.append('file', file);
    fd.append('quick', quick ? 'true' : 'false');
    try {
        const r = await fetch('/analyze', { method: 'POST', body: fd });
        const result = await r.json();
        if (!r.ok) throw new Error(result.detail || 'Failed');
        displayResults(result.data);
    } catch (e) {
        document.getElementById('statusText').textContent = 'Failed';
        document.getElementById('summaryContent').textContent = 'Error: ' + e.message;
    }
}

function displayResults(data) {
    document.getElementById('statusText').textContent = '✅ Complete';
    document.getElementById('lineCount').textContent = data.total_lines || 0;
    const errors = data.errors_found || {};
    document.getElementById('errorCount').textContent =
        Object.values(errors).reduce((a, b) => a + b, 0);
    document.getElementById('timeText').textContent =
        data.processing_time_seconds ? `${data.processing_time_seconds}s` : '-';
    let summary = data.summary || '-';
    if (data.priority) summary = `Priority: ${data.priority.toUpperCase()}\n\n${summary}`;
    document.getElementById('summaryContent').textContent = summary;
    document.getElementById('detailsContent').textContent = data.detailed_analysis || '-';
    const errLines = Object.entries(errors).filter(([_, c]) => c > 0);
    document.getElementById('errorsContent').textContent = errLines.length
        ? errLines.map(([k, v]) => `${k}: ${v}`).join('\n')
        : 'No errors.';
}

function switchTab(name) {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
    event.target.classList.add('active');
    document.getElementById(name + 'Tab').classList.add('active');
}

function loadSample() {
    document.getElementById('logText').value =
        "2024-01-15 10:25:30 ERROR PaymentService: Failed transaction\n" +
        "2024-01-15 10:25:36 FATAL PaymentService: Unrecoverable\n" +
        "2024-01-15 10:25:42 SECURITY AuthService: Multiple failed logins";
}

document.addEventListener('DOMContentLoaded', () => {
    checkConnection();
    setInterval(checkConnection, 30000);
    const dropArea = document.getElementById('dropArea');
    const fileInput = document.getElementById('fileInput');
    dropArea.onclick = () => fileInput.click();
    dropArea.ondragover = (e) => { e.preventDefault(); };
    dropArea.ondrop = (e) => {
        e.preventDefault();
        if (e.dataTransfer.files[0]) analyzeFile(e.dataTransfer.files[0]);
    };
    fileInput.onchange = (e) => {
        if (e.target.files[0]) analyzeFile(e.target.files[0]);
    };
});