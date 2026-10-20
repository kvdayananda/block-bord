// Background Service Worker for Block Bord AI – Manifest V3 Compliant
// ═══════════════════════════════════════════════════════════════════════

let API_URL = "http://127.0.0.1:8000";
let API_KEY = "";

// ─── Settings Initialization ─────────────────────────────────────────────────
chrome.storage.local.get(['apiUrl', 'apiKey'], (res) => {
    if (res.apiUrl) API_URL = res.apiUrl.replace(/\/$/, "");
    if (res.apiKey) API_KEY = res.apiKey;
});

chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local') {
        if (changes.apiUrl) {
            API_URL = changes.apiUrl.newValue.replace(/\/$/, "");
            console.log("Block Bord: API URL updated to:", API_URL);
        }
        if (changes.apiKey) {
            API_KEY = changes.apiKey.newValue || "";
            console.log("Block Bord: API Key updated");
        }
    }
});

// ─── Browser-side Cache ──────────────────────────────────────────────────────
const scanCache = new Map();
const CACHE_DURATION_MS = 60 * 1000; // 1 minute
const tabCooldowns = new Map();
const COOLDOWN_DURATION_MS = 60 * 1000; // 60 seconds per tab

function normalizeUrl(url) {
    if (!url) return "";
    try {
        const u = new URL(url);
        return (u.hostname + u.pathname).replace(/\/$/, "").toLowerCase();
    } catch(e) { return url.toLowerCase().replace(/^https?:\/\//, "").replace(/\/$/, ""); }
}

function getCached(key) {
    const entry = scanCache.get(key);
    if (!entry) return null;
    if (Date.now() - entry.ts > CACHE_DURATION_MS) { scanCache.delete(key); return null; }
    return entry.data;
}
function setCache(key, data) { scanCache.set(key, { data, ts: Date.now() }); }

// ─── Risk Level Normalization ────────────────────────────────────────────────
// Backend sends: SAFE, LOW, MEDIUM, HIGH, CRITICAL
// Extension displays: Safe, Suspicious, High
function normalizeRiskLevel(backendLevel) {
    if (!backendLevel) return 'Safe';
    const upper = backendLevel.toUpperCase();
    switch (upper) {
        case 'SAFE':
        case 'LOW':
            return 'Safe';
        case 'MEDIUM':
            return 'Suspicious';
        case 'HIGH':
        case 'CRITICAL':
            return 'High';
        default:
            return backendLevel; // Pass through unknown levels
    }
}

// ─── Build Request Headers ───────────────────────────────────────────────────
function buildHeaders() {
    const headers = {
        'Content-Type': 'application/json',
        'X-BlockBord-Source': 'extension'
    };
    if (API_KEY) {
        headers['Authorization'] = `Bearer ${API_KEY}`;
    }
    return headers;
}

// ─── Context Menu (Manual Scan) ──────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({ id: "scanWithBlockBord", title: "🛡️ Scan with Block Bord AI", contexts: ["selection", "link"] });

    // Set default settings on first install
    chrome.storage.local.get(['autoScanEnabled', 'showNotifications', 'showWarningOverlays'], (res) => {
        const defaults = {};
        if (res.autoScanEnabled === undefined) defaults.autoScanEnabled = true;
        if (res.showNotifications === undefined) defaults.showNotifications = true;
        if (res.showWarningOverlays === undefined) defaults.showWarningOverlays = true;
        if (Object.keys(defaults).length > 0) {
            chrome.storage.local.set(defaults);
        }
    });
});

// ─── Alarms: Periodic Session Health Check ───────────────────────────────────
chrome.alarms.create('blockbord-session-check', { periodInMinutes: 30 });

chrome.alarms.onAlarm.addListener(async (alarm) => {
    if (alarm.name === 'blockbord-session-check') {
        try {
            const response = await fetch(`${API_URL}/api/v1/ext/status`, {
                headers: buildHeaders(),
                credentials: 'include',
                signal: AbortSignal.timeout(5000)
            });
            if (response.ok) {
                const data = await response.json();
                console.log("Block Bord: Session check OK. Logged in:", data.logged_in);
            }
        } catch (err) {
            console.warn("Block Bord: Session check failed:", err.message);
        }
    }
});

// ─── Messages from Content Scripts ───────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    const tabId = sender.tab?.id;

    if (message.action === 'pageContentDetected') {
        // Check if auto-scan is enabled
        chrome.storage.local.get(['autoScanEnabled'], (res) => {
            if (res.autoScanEnabled === false) return;

            updateBadge(tabId, "...", "#3B82F6");
            processScan(tabId, message.url, message);
        });
        return true;
    }

    if (message.action === 'getScanResult') {
        const cached = getCached(message.url + '_url') || getCached(message.url + '_content');
        sendResponse(cached);
        return true;
    }

    if (message.action === 'startScan') {
        processScan(tabId, message.url);
        sendResponse({ started: true });
        return true;
    }

    if (message.action === 'expandShortenedURL') {
        console.log("Block Bord: Shortened URL detected:", message.url);
    }

    if (message.action === 'dangerousDownload') {
        chrome.storage.local.get(['showNotifications'], (res) => {
            if (res.showNotifications === false) return;
            chrome.notifications.create(`bb-download-${Date.now()}`, {
                type: 'basic', iconUrl: 'icons/icon128.png',
                title: '⚠️ Block Bord AI — Download Blocked',
                message: `Dangerous file type blocked: ${message.url.substring(0, 80)}`,
                priority: 2
            });
        });
    }
});

// ─── Automatic Real-time URL Scanning ────────────────────────────────────────
const lastScannedUrls = new Map();

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        const url = tab.url.toLowerCase();

        // Avoid redundant scans if the URL hasn't changed for this tab
        if (lastScannedUrls.get(tabId) === url) return;
        lastScannedUrls.set(tabId, url);

        // Check if auto-scan is enabled
        chrome.storage.local.get(['autoScanEnabled'], (res) => {
            if (res.autoScanEnabled === false) return;
            console.log(`Block Bord: Auto-trigger (complete):`, url);
            processScan(tabId, tab.url);
        });
    }
});

chrome.tabs.onRemoved.addListener((tabId) => {
    lastScannedUrls.delete(tabId);
    tabCooldowns.delete(tabId);
});

// ─── Core Scan Logic ─────────────────────────────────────────────────────────
async function processScan(tabId, url, scanData = null) {
    const isEnriched = !!(scanData && (scanData.content || scanData.telemetry));

    if (tabId) {
        const lastScan = tabCooldowns.get(tabId) || { ts: 0, enriched: false };
        const timeSince = Date.now() - lastScan.ts;

        // COOLDOWN LOGIC:
        // 1. If we already did an enriched scan recently, skip.
        // 2. If we did a URL-only scan but now have enriched data, PROCEED (bypass).
        // 3. If we are doing another URL-only scan too quickly, skip.
        if (timeSince < COOLDOWN_DURATION_MS) {
            if (!isEnriched || lastScan.enriched) {
                console.log("Block Bord: Scan skipped (cooldown active):", url);
                return;
            }
            console.log("Block Bord: Bypassing cooldown for enriched content scan...");
        }
        tabCooldowns.set(tabId, { ts: Date.now(), enriched: isEnriched });
    }

    const pageContent = scanData ? scanData.content : null;
    const contentHash = scanData && scanData.contentHash ? scanData.contentHash : 'nohash';
    const cacheKey = `${url}_${contentHash}`;
    const cached = getCached(cacheKey);
    
    if (cached) {
        console.log("Block Bord: Cache hit:", url);
        handleScanResult(tabId, cached, url);
        return;
    }

    try {
        const payload = { 
            url: url, 
            content: pageContent || url,
            formData: scanData?.formData || {},
            telemetry: scanData?.telemetry || {},
            hasRedirected: scanData?.hasRedirected || false
        };

        // Try the dedicated extension endpoint first, fallback to /scan
        let response;
        try {
            response = await fetch(`${API_URL}/api/v1/ext/scan`, {
                method: 'POST',
                headers: buildHeaders(),
                credentials: 'include',
                body: JSON.stringify(payload)
            });
        } catch (e) {
            // Fallback to legacy /scan endpoint
            response = await fetch(`${API_URL}/scan`, {
                method: 'POST',
                headers: buildHeaders(),
                credentials: 'include',
                body: JSON.stringify(payload)
            });
        }

        if (!response.ok) {
            if (response.status === 401) {
                console.warn("Block Bord: Unauthorized (401). User probably not logged in.");
                updateBadge(tabId, "LOCK", "#4B5563");
                return;
            }
            throw new Error(`HTTP ${response.status}`);
        }

        let data = await response.json();

        // Unwrap if response is wrapped in {success, data} format
        if (data.success !== undefined && data.data) {
            data = data.data;
        }

        // Normalize risk level from backend bands to extension display categories
        if (data.risk_level) {
            data.risk_level = normalizeRiskLevel(data.risk_level);
        }

        // Map evidence array to reasons if needed
        if (!data.reasons && data.evidence) {
            data.reasons = data.evidence;
        }

        console.log("Block Bord:", url, "→", data.risk_level, `(${data.risk_score})`);

        setCache(cacheKey, data); 
        saveToHistory(url, data);
        handleScanResult(tabId, data, url);

    } catch (err) {
        console.error("Block Bord scan failed:", err);
        updateBadge(tabId, "ERR", "#718096");
    }
}

function updateBadge(tabId, text, color) {
    if (!tabId) return;
    chrome.action.setBadgeText({ text: text, tabId: tabId });
    chrome.action.setBadgeBackgroundColor({ color: color, tabId: tabId });
    if (chrome.action.setBadgeTextColor) {
        chrome.action.setBadgeTextColor({ color: "#FFFFFF", tabId: tabId });
    }
}

// ─── Handle Scan Results ─────────────────────────────────────────────────────
function handleScanResult(tabId, data, url) {
    if (tabId) {
        const level = (data.risk_level || 'Safe').toLowerCase();

        if (level === 'high') {
            updateBadge(tabId, "!!!", "#EF4444");
            chrome.storage.local.get(['showNotifications'], (res) => {
                if (res.showNotifications === false) return;
                chrome.notifications.create(`bb-high-${Date.now()}`, {
                    type: 'basic', iconUrl: 'icons/icon128.png',
                    title: '🚨 Block Bord AI — Dangerous Site!',
                    message: `High-risk site detected! Score: ${data.risk_score}/100. Category: ${data.category || "Phishing"}.`,
                    priority: 2
                });
            });
            // Trigger full-page warning overlay via content script
            chrome.storage.local.get(['showWarningOverlays'], (res) => {
                if (res.showWarningOverlays === false) return;
                chrome.tabs.sendMessage(tabId, { action: 'showWarning', data: data }).catch(() => {});
            });
        } else if (level === 'suspicious') {
            updateBadge(tabId, "WARN", "#F59E0B");
            chrome.storage.local.get(['showNotifications'], (res) => {
                if (res.showNotifications === false) return;
                chrome.notifications.create(`bb-susp-${Date.now()}`, {
                    type: 'basic', iconUrl: 'icons/icon128.png',
                    title: '⚠️ Block Bord AI — Suspicious Site',
                    message: `This site looks suspicious. Risk: ${data.risk_score}/100`,
                    priority: 1
                });
            });
        } else {
            updateBadge(tabId, "SAFE", "#10B981");
        }
    }

    // Notify any open popups or tabs about the new result
    chrome.runtime.sendMessage({ 
        action: 'scanComplete', 
        url, 
        normalizedUrl: normalizeUrl(url), 
        data 
    }).catch(() => {});
}

// ─── Context Menu Scan ───────────────────────────────────────────────────────
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
    if (info.menuItemId === "scanWithBlockBord") {
        const textToScan = info.selectionText || info.linkUrl || "";
        chrome.storage.local.set({ lastManualScan: textToScan });
        chrome.action.openPopup?.().catch(() => {});
    }
});

// ─── Save to Local History ───────────────────────────────────────────────────
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
        chrome.storage.local.set({ scanHistory: history });
    });
}
