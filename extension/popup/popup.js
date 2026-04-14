// Popup JS for Block Bord AI — Full Feature Set
const API_URL = "http://127.0.0.1:8000";

document.addEventListener('DOMContentLoaded', async () => {
    const statusBadge    = document.getElementById('status-badge');
    const resultCard     = document.getElementById('result-card');
    const resultScore    = document.getElementById('result-score');
    const resultLevel    = document.getElementById('result-level');
    const resultDomain   = document.getElementById('result-domain');
    const resultCategory = document.getElementById('result-category');
    const statTotal      = document.getElementById('stat-total');
    const statSuspicious = document.getElementById('stat-suspicious');
    const statBlocked    = document.getElementById('stat-blocked');
    const recentList     = document.getElementById('recent-list');
    const btnScan        = document.getElementById('btn-manual-scan');
    const detailsToggle  = document.getElementById('details-toggle');
    const scanDetails    = document.getElementById('scan-details');
    const detailsList    = document.getElementById('details-list');

    let currentUrl = "";

    function extractDomain(url) {
        if (!url || !url.startsWith("http")) return "—";
        try {
            return new URL(url).hostname;
        } catch {
            return "—";
        }
    }

    // Load stats from local history
    loadLocalStats();

    // Get current tab info
    const [tab] = await chrome.tabs?.query({ active: true, currentWindow: true }) || [{}];
    currentUrl = tab?.url || "";
    const domain = extractDomain(currentUrl);
    
    function normalizeUrl(url) {
        if (!url) return "";
        try {
            const u = new URL(url);
            return (u.hostname + u.pathname).replace(/\/$/, "").toLowerCase();
        } catch(e) { return url.toLowerCase().replace(/^https?:\/\//, "").replace(/\/$/, ""); }
    }

    resultDomain.textContent = domain || "—";

    // Check server connection
    try {
        const r = await fetch(`${API_URL}/`, { credentials: 'include', signal: AbortSignal.timeout(3000) });
        if (r.ok) {
            statusBadge.className = 'badge-status online';
            statusBadge.textContent = '● Online';
        } else throw new Error();
    } catch {
        statusBadge.className = 'badge-status offline';
        statusBadge.textContent = '● Offline';
        btnScan.disabled = true;
    }

    // Feature #15 / #91: Show current page result from cache or recent scan
    loadCurrentPageResult(currentUrl);

    chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
        const normCurrent = normalizeUrl(currentUrl);
        const normIncoming = msg.normalizedUrl || normalizeUrl(msg.url);

        if (msg.action === 'scanComplete' && normCurrent === normIncoming) {
            setResultFromData(msg.data, extractDomain(msg.url));
        }

        if (msg.action === 'loginNeeded') {
            setResultState("scanning", "--", "Please log in to scan", domain, "");
        }
    });

    // Toggle Scan Details
    detailsToggle.addEventListener('click', () => {
        const isVisible = scanDetails.style.display === 'block';
        scanDetails.style.display = isVisible ? 'none' : 'block';
        detailsToggle.innerHTML = isVisible 
            ? '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg> Why this score? View scan details'
            : '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="18 15 12 9 6 15"></polyline></svg> Hide scan details';
    });

    // Feature #2: Manual URL Scan Button
    btnScan.addEventListener('click', async () => {
        if (!tab?.id) return;
        btnScan.disabled = true;
        btnScan.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="margin-bottom:-2px; margin-right:4px; animation: spin 1s linear infinite;"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg> Scanning…';
        setResultState("scanning", "--", "Scanning…", domain, "");

        try {
            // Corrected endpoint to /scan and enabled session credentials
            const r = await fetch(`${API_URL}/scan`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-BlockBord-Source': 'extension'
                },
                credentials: 'include', 
                body: JSON.stringify({ 
                    url: currentUrl, 
                    content: currentUrl, 
                    source: "extension_manual" 
                })
            });
            if (!r.ok) {
                if (r.status === 401) throw new Error("Please log in to the dashboard first.");
                throw new Error("HTTP error " + r.status);
            }
            const data = await r.json();
            setResultFromData(data, domain);
            
            // NEW: Save manual scan to history so it appears in the list below
            saveToHistory(currentUrl, data);
            
        } catch (err) {
            resultLevel.textContent = err.message || "Scan failed.";
            console.error("Manual scan error:", err);
        } finally {
            btnScan.disabled = false;
            btnScan.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-bottom:-2px; margin-right:4px;"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg> Scan This Page Now';
        }
    });

    function saveToHistory(url, data) {
        chrome.storage.local.get(['scanHistory'], (result) => {
            const history = result.scanHistory || [];
            history.unshift({
                date: new Date().toISOString(),
                url: url,
                score: data.risk_score,
                level: data.risk_level,
                category: data.category || "General"
            });
            if (history.length > 50) history.splice(50);
            chrome.storage.local.set({ scanHistory: history }, () => {
                // Refresh the stats and list in the UI
                loadLocalStats();
            });
        });
    }

    function setResultFromData(data, domain) {
        if (!data) return;
        
        if (data.upgrade_required || data.error?.includes("Limit")) {
            setResultState("scanning", "--", "Daily Limit is completed", domain, "Upgrade your plan");
            return;
        }

        if (!data.risk_level) {
            setResultState("scanning", "--", "Waiting for data...", domain, "");
            return;
        }
        const lvl = (data.risk_level || "OK").toLowerCase();
        const reasons = data.reasons || [];
        setResultState(lvl, data.risk_score, data.risk_level, domain, data.category || "");
        
        // Populate reasons
        detailsList.innerHTML = '';
        if (reasons.length > 0) {
            reasons.forEach(r => {
                const li = document.createElement('li');
                li.textContent = r;
                detailsList.appendChild(li);
            });
            detailsToggle.style.display = 'flex';
        } else {
            detailsToggle.style.display = 'none';
            scanDetails.style.display = 'none';
        }

        // Show reasons in tooltip/title as well
        resultCard.title = reasons.slice(0,5).join('\n') || "No specific reasons detected.";
    }

    function setResultState(lvl, score, label, domain, category) {
        const classes = { safe: "safe", ok: "safe", suspicious: "suspicious", high: "high", scanning: "scanning" };
        const cls = (lvl || "scanning").toLowerCase();
        const validCls = classes[cls] || "scanning";
        
        resultCard.className = `scan-result-card ${validCls}`;
        resultScore.className = `result-score ${validCls}`;
        resultScore.textContent = (score === undefined || score === "--") ? "--" : `${score}`;
        resultLevel.textContent = label || "Unknown";
        resultCategory.textContent = category || "";
        resultCategory.style.display = category ? "inline-block" : "none";
        
        // Make "Upgrade your plan" act like a button
        if (category && category.includes("Upgrade")) {
            resultCategory.style.cursor = "pointer";
            resultCategory.style.transition = "all 0.2s";
            resultCategory.onmouseover = () => { resultCategory.style.backgroundColor = "var(--border)"; };
            resultCategory.onmouseout = () => { resultCategory.style.backgroundColor = "var(--bg-alt)"; };
        } else {
            resultCategory.style.cursor = "default";
            resultCategory.onmouseover = null;
            resultCategory.onmouseout = null;
        }
    }

    resultCategory.addEventListener('click', () => {
        if (resultCategory.textContent.includes("Upgrade")) {
            chrome.tabs.create({ url: `${API_URL}/pricing` });
        }
    });

    async function loadCurrentPageResult(url) {
        if (!url || !url.startsWith("http")) {
            setResultState("scanning", "--", "Not a web page", "—", "");
            return;
        }

        // 1. Try background cache first
        chrome.runtime.sendMessage({ action: 'getScanResult', url }, (cached) => {
            if (cached) {
                setResultFromData(cached, domain);
                return;
            }

            // 2. Try local history
            chrome.storage.local.get(['scanHistory'], (result) => {
                const history = result.scanHistory || [];
                const match = history.find(item => item.url === url);
                if (match) {
                    const lvl = match.level || "OK";
                    setResultState(lvl.toLowerCase(), match.score, lvl, domain, match.category || "");
                } else {
                    // 3. Trigger automatic scan if never seen before
                    chrome.runtime.sendMessage({ action: 'startScan', url });
                    setResultState("scanning", "--", "Auto-scanning...", domain, "");
                }
            });
        });
    }

    // Load stats from local scan history
    function loadLocalStats() {
        chrome.storage.local.get(['scanHistory'], (result) => {
            const history = (result.scanHistory || []).filter(s => s && s.url && s.level);
            statTotal.textContent = history.length;
            const susp = history.filter(s => s.level === 'Suspicious').length;
            const high = history.filter(s => s.level === 'High').length;
            statSuspicious.textContent = susp;
            statBlocked.textContent = high;

            // Render recent scans
            recentList.innerHTML = '';
            history.slice(0, 5).forEach(scan => {
                const item = document.createElement('div');
                item.className = 'scan-item';
                const lvl = (scan.level || "OK").toLowerCase();
                const pillClass = `scan-pill pill-${lvl}`;
                try {
                    const hostname = new URL(scan.url || "http://x").hostname;
                    item.innerHTML = `
                        <div class="scan-item-url" title="${scan.url}">${hostname}</div>
                        <div class="${pillClass}">${scan.level}</div>
                    `;
                } catch {
                    item.innerHTML = `<div class="scan-item-url" title="${scan.url}">${(scan.url || "").substring(0,40)}</div>
                        <div class="${pillClass}">${scan.level}</div>`;
                }
                recentList.appendChild(item);
            });

            if (history.length === 0) {
                recentList.innerHTML = '<div style="padding:12px;font-size:0.78rem;color:var(--muted);text-align:center;">No scan history yet</div>';
            }
        });
    }
});
