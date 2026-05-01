// Background Service Worker for Block Bord AI – Full Feature Set
const API_URL = "https://block-bord.onrender.com";

// ─── Browser-side Cache (Feature #11) ────────────────────────────────────────
const scanCache = new Map();
const CACHE_DURATION_MS = 60 * 1000; // 1 min (reduced from 5 min)
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

// ─── Context Menu (Feature #2: Manual Scan) ──────────────────────────────────
chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({ id: "scanWithBlockBord", title: "🛡️ Scan with Block Bord AI", contexts: ["selection", "link"] });
});

// ─── Messages from Content Scripts ───────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    const tabId = sender.tab?.id;

    if (message.action === 'pageContentDetected') {
        const url = message.url.toLowerCase();
        if ((url.includes("127.0.0.1") || url.includes("localhost")) && !url.includes("/test-")) return;

        chrome.action.setBadgeText({ text: "…", tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#4a5568", tabId });

        // Build enriched content including form signals and page title
        let enrichedContent = `[URL: ${message.url}]\n[TITLE: ${message.title || ""}]\n${message.content || ""}`;
        
        // Pass the whole message object (which contains content, formData, telemetry)
        processScan(tabId, message.url, message);
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
    // ... rest of conditions

    if (message.action === 'expandShortenedURL') {
        // Feature #10: Just log it for now; real expansion is done server-side via /api/check-link
        console.log("Block Bord: Shortened URL detected:", message.url);
    }

    if (message.action === 'dangerousDownload') {
        // Feature #14: Notify user about dangerous download
        chrome.notifications.create(`bb-download-${Date.now()}`, {
            type: 'basic', iconUrl: 'icons/icon128.png',
            title: '⚠️ Block Bord AI — Download Blocked',
            message: `Dangerous file type blocked: ${message.url.substring(0, 80)}`,
            priority: 2
        });
    }
});

// ─── Feature #1: Automatic Real-time URL Scanning ────────────────────────────
const lastScannedUrls = new Map(); // tabId -> url

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    // Trigger ONLY on complete to prevent duplicate scans during loading redirects
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        const url = tab.url.toLowerCase();
        
        // Avoid redundant scans if the URL hasn't changed for this tab
        if (lastScannedUrls.get(tabId) === url) return;
        lastScannedUrls.set(tabId, url);

        console.log(`Block Bord: Auto-trigger (complete):`, url);
        processScan(tabId, tab.url);
    }
});

chrome.tabs.onRemoved.addListener((tabId) => {
    lastScannedUrls.delete(tabId);
    tabCooldowns.delete(tabId);
});

// ─── Core Scan Logic ─────────────────────────────────────────────────────────
// ─── Core Scan Logic ─────────────────────────────────────────────────────────
async function processScan(tabId, url, scanData = null) {
    if (tabId) {
        const lastScan = tabCooldowns.get(tabId) || 0;
        if (Date.now() - lastScan < COOLDOWN_DURATION_MS) {
            console.log("Block Bord: Scan skipped (cooldown active):", url);
            return;
        }
        tabCooldowns.set(tabId, Date.now());
    }

    // scanData can be the full message object from content.js
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
        // Enforce the correct backend endpoint: /scan (not /api/check-link)
        // Ensure credentials: 'include' is set so session cookies are sent
        const payload = { 
            url: url, 
            content: pageContent || url,
            formData: scanData?.formData || {},
            telemetry: scanData?.telemetry || {},
            hasRedirected: scanData?.hasRedirected || false
        };

        const response = await fetch(`${API_URL}/scan`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-BlockBord-Source': 'extension'
            },
            credentials: 'include', 
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            if (response.status === 401) {
                console.warn("Block Bord: Unauthorized (401). User probably not logged in.");
                chrome.action.setBadgeText({ text: "LOCK", tabId });
                chrome.action.setBadgeBackgroundColor({ color: "#718096", tabId });
                return;
            }
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        console.log("Block Bord:", url, "→", data.risk_level, `(${data.risk_score})`);

        setCache(cacheKey, data); 
        saveToHistory(url, data);
        handleScanResult(tabId, data, url);

    } catch (err) {
        console.error("Block Bord scan failed:", err);
        chrome.action.setBadgeText({ text: "!", tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#718096", tabId });
    }
}

// ─── Feature #3/#4: Handle Scan Results ──────────────────────────────────────
function handleScanResult(tabId, data, url) {
    if (tabId) {
        if (data.upgrade_required) {
            chrome.action.setBadgeText({ text: "LIMIT", tabId });
            chrome.action.setBadgeBackgroundColor({ color: "#718096", tabId });
        } else if (data.risk_level === 'High') {
            chrome.action.setBadgeText({ text: "!!!", tabId });
            chrome.action.setBadgeBackgroundColor({ color: "#e53e3e", tabId });
            chrome.notifications.create(`bb-high-${Date.now()}`, {
                type: 'basic', iconUrl: 'icons/icon128.png',
                title: '🚨 Block Bord AI — Dangerous Site!',
                message: `High-risk site detected! Score: ${data.risk_score}/100. Category: ${data.category || "Phishing"}.`,
                priority: 2
            });
            // Trigger full-page warning overlay via content script
            chrome.tabs.sendMessage(tabId, { action: 'showWarning', data: data }).catch(() => {});
        } else if (data.risk_level === 'Suspicious') {
            chrome.action.setBadgeText({ text: "!", tabId });
            chrome.action.setBadgeBackgroundColor({ color: "#e8901e", tabId });
            chrome.notifications.create(`bb-susp-${Date.now()}`, {
                type: 'basic', iconUrl: 'icons/icon128.png',
                title: '⚠️ Block Bord AI — Suspicious Site',
                message: `This site looks suspicious. Risk: ${data.risk_score}/100`,
                priority: 1
            });
            // For suspicious sites, we only show badge/notification, no full overlay
        } else {
            chrome.action.setBadgeText({ text: "OK", tabId });
            chrome.action.setBadgeBackgroundColor({ color: "#38a169", tabId });
        }
    }

    // Notify any open popups or tabs about the new result (always broadcast)
    chrome.runtime.sendMessage({ 
        action: 'scanComplete', 
        url, 
        normalizedUrl: normalizeUrl(url), 
        data 
    }).catch(() => {});
}

// ─── Feature #9: Login Notification ─────────────────────────────────────────
function showLoginNotification() {
    chrome.notifications.create('bb-login-needed', {
        type: 'basic', iconUrl: 'icons/icon128.png',
        title: 'Block Bord AI',
        message: 'Please log in to the dashboard to enable scanning.',
        priority: 2
    });
}

// ─── Feature #2: Context Menu Scan ───────────────────────────────────────────
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
    if (info.menuItemId === "scanWithBlockBord") {
        const textToScan = info.selectionText || info.linkUrl || "";
        chrome.storage.local.set({ lastManualScan: textToScan });
        // Trigger popup to open
        chrome.action.openPopup?.().catch(() => {});
    }
});

// ─── Feature #11: Save to Local History ──────────────────────────────────────
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
