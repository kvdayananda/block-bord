// Popup JS for Block Bord AI — Manifest V3 Dynamic Integration
// ═════════════════════════════════════════════════════════════

let API_URL = "http://127.0.0.1:8000";
let API_KEY = "";

document.addEventListener('DOMContentLoaded', async () => {
    const statusBadge    = document.getElementById('status-badge');
    const quotaBadge     = document.getElementById('quota-badge');
    const quotaUsed      = document.getElementById('quota-used');
    const quotaLimit     = document.getElementById('quota-limit');
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
    const statusIcon     = document.getElementById('status-icon');
    const linkDashboard  = document.getElementById('link-dashboard');
    const linkOptions    = document.getElementById('link-options');

    let currentUrl = "";

    // ─── Settings Initialization ─────────────────────────────────────────────
    const settings = await new Promise(resolve => {
        chrome.storage.local.get(['apiUrl', 'apiKey'], resolve);
    });
    if (settings.apiUrl) API_URL = settings.apiUrl.replace(/\/$/, "");
    if (settings.apiKey) API_KEY = settings.apiKey;

    // Setup dynamic footer links
    if (linkDashboard) {
        linkDashboard.addEventListener('click', (e) => {
            e.preventDefault();
            chrome.tabs.create({ url: `${API_URL}/app` });
        });
    }
    if (linkOptions) {
        linkOptions.addEventListener('click', (e) => {
            e.preventDefault();
            if (chrome.runtime.openOptionsPage) {
                chrome.runtime.openOptionsPage();
            } else {
                chrome.tabs.create({ url: chrome.runtime.getURL('options/options.html') });
            }
        });
    }

    function extractDomain(url) {
        if (!url || !url.startsWith("http")) return "—";
        try {
            return new URL(url).hostname;
        } catch {
            return "—";
        }
    }

    function normalizeUrl(url) {
        if (!url) return "";
        try {
            const u = new URL(url);
            return (u.hostname + u.pathname).replace(/\/$/, "").toLowerCase();
        } catch(e) {
            return url.toLowerCase().replace(/^https?:\/\//, "").replace(/\/$/, "");
        }
    }

    function normalizeRisk(level) {
        if (!level) return { class: 'safe', label: 'Safe' };
        const upper = level.toUpperCase();
        if (upper === 'SAFE' || upper === 'LOW' || upper === 'OK') {
            return { class: 'safe', label: 'Safe' };
        }
        if (upper === 'MEDIUM' || upper === 'SUSPICIOUS') {
            return { class: 'suspicious', label: 'Suspicious' };
        }
        if (upper === 'HIGH' || upper === 'CRITICAL' || upper === 'BLOCKED') {
            return { class: 'high', label: upper === 'CRITICAL' ? 'Critical' : 'High Risk' };
        }
        return { class: 'safe', label: level };
    }

    function unwrapResponse(data) {
        if (!data) return {};
        if (data.data && typeof data.data === 'object' && ('risk_score' in data.data || 'overall_score' in data.data)) {
            return {
                risk_score: data.data.risk_score ?? data.data.overall_score ?? 0,
                risk_level: data.data.risk_level ?? data.risk_level ?? 'SAFE',
                reasons: data.data.reasons ?? data.reasons ?? [],
                category: data.data.category ?? data.category ?? 'General',
                upgrade_required: data.upgrade_required || data.data.upgrade_required,
                error: data.error || data.data.error
            };
        }
        return {
            risk_score: data.risk_score ?? data.overall_score ?? 0,
            risk_level: data.risk_level ?? 'SAFE',
            reasons: data.reasons ?? [],
            category: data.category ?? 'General',
            upgrade_required: data.upgrade_required,
            error: data.error
        };
    }

    // Load stats from local history
    loadLocalStats();

    // Get current tab info
    const [tab] = await chrome.tabs?.query({ active: true, currentWindow: true }) || [{}];
    currentUrl = tab?.url || "";
    const domain = extractDomain(currentUrl);
    resultDomain.textContent = domain || "—";

    // Check server connection
    try {
        const headers = {};
        if (API_KEY) headers['X-API-Key'] = API_KEY;
        const r = await fetch(`${API_URL}/api/v1/ext/status`, {
            headers,
            credentials: 'include',
            signal: AbortSignal.timeout(3000)
        });
        if (r.ok) {
            statusBadge.className = 'badge-status online';
            statusBadge.textContent = '● Online';
            const statusData = await r.json();
            handleStatusData(statusData);
        } else {
            // Try fallback root ping
            const fallback = await fetch(`${API_URL}/`, { credentials: 'include', signal: AbortSignal.timeout(2000) });
            if (fallback.ok) {
                statusBadge.className = 'badge-status online';
                statusBadge.textContent = '● Online';
                updateExtStatusFallback();
            } else throw new Error();
        }
    } catch (err) {
        statusBadge.className = 'badge-status offline';
        statusBadge.textContent = '● Offline';
        btnScan.disabled = true;
    }

    // Show current page result from cache or recent scan
    loadCurrentPageResult(currentUrl);

    // Listen for scan events from background
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

    // Manual URL Scan Button
    btnScan.addEventListener('click', async () => {
        if (!tab?.id) return;
        btnScan.disabled = true;
        btnScan.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="margin-bottom:-2px; margin-right:4px; animation: spin 1s linear infinite;"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg> Scanning…';
        setResultState("scanning", "--", "Scanning…", domain, "");

        try {
            const headers = {
                'Content-Type': 'application/json',
                'X-BlockBord-Source': 'extension'
            };
            if (API_KEY) headers['X-API-Key'] = API_KEY;

            let scanEndpoint = `${API_URL}/api/v1/ext/scan`;
            let r = await fetch(scanEndpoint, {
                method: 'POST',
                headers,
                credentials: 'include', 
                body: JSON.stringify({ 
                    url: currentUrl, 
                    content: currentUrl, 
                    source: "extension_manual" 
                })
            });

            // Fallback to /api/v1/scan/url or /scan if dedicated endpoint 404s
            if (r.status === 404) {
                scanEndpoint = `${API_URL}/scan`;
                r = await fetch(scanEndpoint, {
                    method: 'POST',
                    headers,
                    credentials: 'include',
                    body: JSON.stringify({
                        url: currentUrl,
                        content: currentUrl,
                        source: "extension_manual"
                    })
                });
            }

            if (!r.ok) {
                if (r.status === 401) throw new Error("Please log in or set an API key.");
                if (r.status === 429) throw new Error("Daily scan quota reached.");
                throw new Error("HTTP error " + r.status);
            }

            const rawData = await r.json();
            const data = unwrapResponse(rawData);
            setResultFromData(data, domain);
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
            const norm = normalizeRisk(data.risk_level);
            history.unshift({
                date: new Date().toISOString(),
                url: url,
                score: data.risk_score,
                level: norm.label,
                category: data.category || "General"
            });
            if (history.length > 50) history.splice(50);
            chrome.storage.local.set({ scanHistory: history }, () => {
                loadLocalStats();
            });
        });
    }

    function setResultFromData(raw, dom) {
        if (!raw) return;
        const data = unwrapResponse(raw);
        
        if (data.upgrade_required || data.error?.includes("Limit") || data.error?.includes("quota")) {
            setResultState("scanning", "--", "Daily Limit Reached", dom, "Upgrade your plan");
            return;
        }

        const norm = normalizeRisk(data.risk_level);
        const reasons = data.reasons || [];
        setResultState(norm.class, data.risk_score, norm.label, dom, data.category || "");
        
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

        resultCard.title = reasons.slice(0, 5).join('\n') || "No specific threat flags detected.";
    }

    function setResultState(cls, score, label, dom, category) {
        const classes = { safe: "safe", suspicious: "suspicious", high: "high", scanning: "scanning" };
        const validCls = classes[cls] || "scanning";
        
        resultCard.className = `scan-result-card ${validCls}`;
        resultScore.className = `result-score ${validCls}`;
        resultScore.textContent = (score === undefined || score === "--") ? "--" : `${score}`;
        resultLevel.textContent = label || "Unknown";
        resultCategory.textContent = category || "";
        resultCategory.style.display = category ? "inline-block" : "none";
        
        // Update Icon
        statusIcon.className = `status-icon ${validCls}`;
        if (validCls === 'safe') {
            statusIcon.innerHTML = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><polyline points="9 11 12 14 15 8"></polyline></svg>';
        } else if (validCls === 'suspicious') {
            statusIcon.innerHTML = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>';
        } else if (validCls === 'high') {
            statusIcon.innerHTML = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>';
        } else {
            statusIcon.innerHTML = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>';
        }
        
        if (category && category.includes("Upgrade")) {
            resultCategory.style.cursor = "pointer";
            resultCategory.onclick = () => chrome.tabs.create({ url: `${API_URL}/pricing` });
        } else {
            resultCategory.style.cursor = "default";
            resultCategory.onclick = null;
        }
    }

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
                    const norm = normalizeRisk(match.level);
                    setResultState(norm.class, match.score, norm.label, domain, match.category || "");
                } else {
                    // 3. Trigger automatic scan if never seen before
                    chrome.runtime.sendMessage({ action: 'startScan', url });
                    setResultState("scanning", "--", "Auto-scanning...", domain, "");
                }
            });
        });
    }

    function handleStatusData(data) {
        const tierBadge = document.getElementById('user-tier-badge');
        if (!tierBadge) return;

        if (data.logged_in) {
            tierBadge.style.display = 'inline-block';
            tierBadge.textContent = (data.plan || 'FREE').toUpperCase();
            if (data.is_pro) {
                tierBadge.style.background = 'linear-gradient(135deg, #f59e0b, #d97706)';
            } else {
                tierBadge.style.background = 'linear-gradient(135deg, #6366f1, #a855f7)';
            }
            const footerVer = document.querySelector('.bb-footer-ver');
            if (footerVer && data.username) {
                footerVer.textContent = `@${data.username}`;
            }
            if (quotaBadge && data.scans_today !== undefined && data.scan_limit !== undefined) {
                quotaBadge.style.display = 'block';
                quotaUsed.textContent = data.scans_today;
                quotaLimit.textContent = data.scan_limit;
            }
        } else {
            tierBadge.style.display = 'none';
            if (quotaBadge) quotaBadge.style.display = 'none';
        }
    }

    async function updateExtStatusFallback() {
        try {
            const headers = {};
            if (API_KEY) headers['X-API-Key'] = API_KEY;
            const res = await fetch(`${API_URL}/api/ext/status`, { headers, credentials: 'include' });
            if (res.ok) {
                const data = await res.json();
                handleStatusData(data);
            }
        } catch (e) {
            console.warn("Status check failed", e);
        }
    }

    // Load stats from local scan history
    function loadLocalStats() {
        chrome.storage.local.get(['scanHistory'], (result) => {
            const history = (result.scanHistory || []).filter(s => s && s.url);
            statTotal.textContent = history.length;

            let suspCount = 0;
            let blockedCount = 0;

            recentList.innerHTML = '';
            history.slice(0, 5).forEach(scan => {
                const norm = normalizeRisk(scan.level);
                if (norm.class === 'suspicious') suspCount++;
                if (norm.class === 'high') blockedCount++;

                const item = document.createElement('div');
                item.className = 'scan-item';
                const pillClass = `scan-pill pill-${norm.class}`;
                let hostname = scan.url;
                try {
                    hostname = new URL(scan.url).hostname;
                } catch {
                    hostname = (scan.url || "").substring(0, 35);
                }
                item.innerHTML = `
                    <div class="scan-item-url" title="${scan.url}">${hostname}</div>
                    <div class="${pillClass}">${norm.label}</div>
                `;
                recentList.appendChild(item);
            });

            // Count for all history items, not just top 5
            suspCount = history.filter(s => normalizeRisk(s.level).class === 'suspicious').length;
            blockedCount = history.filter(s => normalizeRisk(s.level).class === 'high').length;

            statSuspicious.textContent = suspCount;
            statBlocked.textContent = blockedCount;

            if (history.length === 0) {
                recentList.innerHTML = '<div style="padding:12px;font-size:0.78rem;color:var(--muted);text-align:center;">No scan history yet</div>';
            }
        });
    }
});
