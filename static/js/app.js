async function request(url, options) {
    const res = await fetch(url, options);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
    return data;
}

const API = {
    get: url => request(url),
    post: (url, body) => request(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }),
    upload: (url, formData) => request(url, { method: "POST", body: formData })
};

// Prevent XSS: filenames come from the user's files, never insert them as raw HTML.
function escapeHtml(str) {
    return String(str ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

let activeScanId = null;
let scanInterval = null;
let scanResults = [];

function showToast(msg, type = "") {
    const toast = document.getElementById("toast");
    toast.textContent = msg;
    toast.className = "toast " + type + " show";
    clearTimeout(toast._t);
    toast._t = setTimeout(() => toast.classList.remove("show"), 3000);
}

function switchTab(tab) {
    document.querySelectorAll(".nav-btn").forEach(b => b.classList.toggle("active", b.dataset.tab === tab));
    document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
    const panel = document.getElementById("tab-" + tab);
    if (panel) panel.classList.add("active");
}

function formatBytes(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
    if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + " MB";
    return (bytes / 1073741824).toFixed(2) + " GB";
}

function formatDate(iso) {
    if (!iso) return "N/A";
    const d = new Date(iso);
    return d.toLocaleDateString() + " " + d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function spawnParticles(cx, cy) {
    const container = document.getElementById("particles");
    for (let i = 0; i < 24; i++) {
        const p = document.createElement("div");
        p.className = "particle";
        const angle = (Math.PI * 2 * i) / 24 + Math.random() * 0.5;
        const dist = 80 + Math.random() * 120;
        const tx = Math.cos(angle) * dist;
        const ty = Math.sin(angle) * dist;
        const dur = 0.6 + Math.random() * 0.8;
        p.style.cssText = `left:${cx}px;top:${cy}px;--tx:${tx}px;--ty:${ty}px;--dur:${dur}s;background:${Math.random() > 0.5 ? "#60ecff" : "#1dd3f8"};`;
        container.appendChild(p);
        setTimeout(() => p.remove(), dur * 1000 + 100);
    }
}

function spawnSideBursts(btn) {
    const rect = btn.getBoundingClientRect();
    const cx = rect.left + rect.width / 2;
    const cy = rect.top + rect.height / 2;

    for (let burst = 0; burst < 3; burst++) {
        setTimeout(() => {
            for (let i = 0; i < 16; i++) {
                const el = document.createElement("div");
                el.className = "burst-particle";
                const side = Math.random() > 0.5 ? 1 : -1;
                const tx = side * (120 + Math.random() * 100);
                const ty = -60 + Math.random() * 120;
                const dur = 0.5 + Math.random() * 0.7;
                el.style.cssText = `
          left:${cx + (Math.random() - 0.5) * rect.width}px;
          top:${cy + (Math.random() - 0.5) * rect.height}px;
          --tx:${tx}px;--ty:${ty}px;--dur:${dur}s;
          background:${Math.random() > 0.6 ? "#60ecff" : Math.random() > 0.5 ? "#1dd3f8" : "#ffffff"};
          width:${2 + Math.random() * 4}px;height:${2 + Math.random() * 4}px;
        `;
                document.body.appendChild(el);
                setTimeout(() => el.remove(), dur * 1000 + 100);
            }
        }, burst * 180);
    }
}

function spawnRocketTrail(btn) {
    const rect = btn.getBoundingClientRect();
    const cx = rect.left + rect.width / 2;
    const by = rect.bottom;

    let count = 0;
    const interval = setInterval(() => {
        if (count++ > 40) {
            clearInterval(interval);
            return;
        }
        const el = document.createElement("div");
        el.className = "burst-particle";
        const tx = (Math.random() - 0.5) * 30;
        const ty = 40 + Math.random() * 60;
        const dur = 0.4 + Math.random() * 0.4;
        el.style.cssText = `
      left:${cx + (Math.random() - 0.5) * 20}px;
      top:${by - 10}px;
      --tx:${tx}px;--ty:${ty}px;--dur:${dur}s;
      background:${Math.random() > 0.5 ? "#ff6b1a" : "#ffcc00"};
      width:${2 + Math.random() * 3}px;height:${2 + Math.random() * 3}px;
    `;
        document.body.appendChild(el);
        setTimeout(() => el.remove(), dur * 1000 + 100);
    }, 80);

    return interval;
}

function renderResultItem(r) {
    const statusClass = r.status === "threat" ? "status-threat" : r.status === "warning" ? "status-warning" : "status-clean";
    const badgeText = r.status === "threat" ? "THREAT" : r.status === "warning" ? "WARNING" : "CLEAN";
    const detail = r.threat ? r.threat : r.details[0] || "";
    const item = document.createElement("div");
    item.className = `result-item ${statusClass}`;
    item.innerHTML = `
    <div class="result-dot"></div>
    <div class="result-info">
      <div class="result-name">${escapeHtml(r.filename)}</div>
      <div class="result-detail">${escapeHtml(detail)} · ${formatBytes(r.size)}</div>
    </div>
    <span class="result-badge">${badgeText}</span>
  `;
    return item;
}

function updateResults(results) {
    const list = document.getElementById("results-list");
    list.innerHTML = "";
    if (!results || results.length === 0) {
        list.innerHTML = '<div class="empty-state"><div class="empty-icon">🛡️</div><p>No results yet</p></div>';
        return;
    }
    results.forEach(r => list.appendChild(renderResultItem(r)));

    const clean = results.filter(r => r.status === "clean").length;
    const warn = results.filter(r => r.status === "warning").length;
    const threat = results.filter(r => r.status === "threat").length;

    document.getElementById("badge-clean").textContent = `${clean} Clean`;
    document.getElementById("badge-warn").textContent = `${warn} Warnings`;
    document.getElementById("badge-threat").textContent = `${threat} Threats`;
    document.getElementById("results-summary").style.display = "flex";
}

function updateProgress(data) {
    const pct = data.progress || 0;
    document.getElementById("progress-fill").style.width = pct + "%";
    document.getElementById("prog-pct").textContent = pct + "%";
    document.getElementById("prog-files").textContent = `${data.scanned} / ${data.total_files} files`;

    const scanningTexts = ["Scanning system files...", "Checking executable signatures...", "Analyzing file behavior...", "Scanning registry entries...", "Checking network connections...", "Verifying file integrity...", "Deep scan in progress..."];
    if (data.status === "running") {
        const idx = Math.floor((pct / 100) * scanningTexts.length);
        document.getElementById("scan-status-text").textContent = scanningTexts[Math.min(idx, scanningTexts.length - 1)];
    }

    if (data.results) {
        updateResults(data.results);
    }
}

function completeScan(data, trailInterval, btn) {
    clearInterval(trailInterval);
    clearInterval(scanInterval);
    scanInterval = null;

    btn.classList.remove("scanning");
    document.getElementById("scan-progress-wrap").style.display = "none";
    document.querySelector(".ring-1").classList.remove("ring-scanning");
    document.querySelector(".ring-2").classList.remove("ring-scanning");

    updateResults(data.results);

    const threats = data.threats || 0;
    const warnings = data.warnings || 0;

    if (threats > 0) {
        showToast(`⚠️ Scan complete — ${threats} threat(s) found!`, "danger");
    } else if (warnings > 0) {
        showToast(`Scan complete — ${warnings} warning(s) found`, "");
    } else {
        showToast("✔ Scan complete — Demo system is clean!", "success");
    }

    switchTab("results");
    loadStats();
    loadHistory();
}

async function startScan() {
    const btn = document.getElementById("scan-btn");
    if (btn.classList.contains("scanning")) return;

    btn.classList.add("scanning");
    document.getElementById("scan-progress-wrap").style.display = "flex";
    document.getElementById("progress-fill").style.width = "0%";
    document.getElementById("prog-pct").textContent = "0%";
    document.getElementById("prog-files").textContent = "0 / 0 files";

    document.querySelector(".ring-1").classList.add("ring-scanning");
    document.querySelector(".ring-2").classList.add("ring-scanning");

    const cx = btn.offsetLeft + btn.offsetWidth / 2;
    const cy = btn.offsetTop + btn.offsetHeight / 2;
    spawnParticles(cx, cy);
    spawnSideBursts(btn);
    const trailInterval = spawnRocketTrail(btn);

    try {
        const data = await API.post("/api/scan/start", {});
        activeScanId = data.scan_id;

        scanInterval = setInterval(async () => {
            try {
                const status = await API.get(`/api/scan/status/${activeScanId}`);
                updateProgress(status);

                if (status.status === "completed") {
                    completeScan(status, trailInterval, btn);
                }
            } catch (e) {
                clearInterval(scanInterval);
                clearInterval(trailInterval);
                scanInterval = null;
                btn.classList.remove("scanning");
                document.getElementById("scan-progress-wrap").style.display = "none";
                showToast("Lost connection to the server", "danger");
            }
        }, 500);
    } catch (e) {
        btn.classList.remove("scanning");
        document.getElementById("scan-progress-wrap").style.display = "none";
        clearInterval(trailInterval);
        showToast("Failed to start scan — " + e.message, "danger");
    }
}

async function scanUploadedFile(file) {
    const formData = new FormData();
    formData.append("file", file);
    showToast(`Scanning: ${file.name}...`, "");
    try {
        const result = await API.upload("/api/scan/upload", formData);
        scanResults.unshift(result);
        updateResults(scanResults);
        switchTab("results");
        const msg = result.status === "threat" ? `⚠️ Threat detected: ${result.threat}` : result.status === "warning" ? `Warning: ${result.details[0]}` : `✔ File is clean`;
        showToast(msg, result.status === "threat" ? "danger" : result.status === "clean" ? "success" : "");
    } catch (e) {
        showToast(`${file.name}: ${e.message}`, "danger");
    }
}

async function loadStats() {
    try {
        const s = await API.get("/api/stats");
        document.getElementById("stat-scans").textContent = s.total_scans || 0;
        document.getElementById("stat-threats").textContent = s.total_threats_found || 0;
        const files = s.total_files_scanned || 0;
        document.getElementById("stat-files").textContent = files >= 1000 ? (files / 1000).toFixed(1) + "K" : files;
    } catch (e) {}
}

async function loadHistory() {
    try {
        const history = await API.get("/api/history");
        const list = document.getElementById("history-list");
        list.innerHTML = "";
        if (!history || history.length === 0) {
            list.innerHTML = '<div class="empty-state"><div class="empty-icon">📋</div><p>No scan history yet</p></div>';
            return;
        }
        history.forEach(h => {
            const item = document.createElement("div");
            item.className = "history-item";
            item.innerHTML = `
        <div>
          <div style="font-size:0.8rem;font-weight:500;color:var(--text)">${formatDate(h.date)}</div>
          <div class="history-date">${h.total} files scanned</div>
        </div>
        <div class="history-stats">
          <span class="h-clean">${h.clean} Clean</span>
          <span class="h-warn">${h.warnings} Warn</span>
          <span class="h-threat">${h.threats} Threat</span>
        </div>
      `;
            list.appendChild(item);
        });
    } catch (e) {}
}

async function loadThreatLog() {
    try {
        const items = await API.get("/api/threatlog");
        const list = document.getElementById("threatlog-list");
        list.innerHTML = "";
        if (!items || items.length === 0) {
            list.innerHTML = '<div class="empty-state"><div class="empty-icon">🔒</div><p>No threats logged yet</p></div>';
            return;
        }
        items.forEach(q => {
            const item = document.createElement("div");
            item.className = "threatlog-item";
            item.innerHTML = `
        <div class="threatlog-icon">☣️</div>
        <div class="threatlog-info">
          <div class="threatlog-count">${q.count} threat(s) detected</div>
          <div class="threatlog-date">Scan ID: ${escapeHtml(q.scan_id)} · ${formatDate(q.date)}</div>
        </div>
      `;
            list.appendChild(item);
        });
    } catch (e) {}
}

document.getElementById("scan-btn").addEventListener("click", startScan);

document.querySelectorAll(".nav-btn").forEach(btn => {
    btn.addEventListener("click", () => {
        switchTab(btn.dataset.tab);
        if (btn.dataset.tab === "history") loadHistory();
        if (btn.dataset.tab === "threatlog") loadThreatLog();
    });
});

const uploadZone = document.getElementById("upload-zone");
const fileInput = document.getElementById("file-input");

document.getElementById("upload-link").addEventListener("click", e => {
    e.stopPropagation();
    fileInput.click();
});

uploadZone.addEventListener("click", () => fileInput.click());

fileInput.addEventListener("change", () => {
    Array.from(fileInput.files).forEach(f => scanUploadedFile(f));
    fileInput.value = "";
});

uploadZone.addEventListener("dragover", e => {
    e.preventDefault();
    uploadZone.classList.add("drag-over");
});

uploadZone.addEventListener("dragleave", () => uploadZone.classList.remove("drag-over"));

uploadZone.addEventListener("drop", e => {
    e.preventDefault();
    uploadZone.classList.remove("drag-over");
    Array.from(e.dataTransfer.files).forEach(f => scanUploadedFile(f));
});

loadStats();
loadHistory();
