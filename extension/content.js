// Content Script for Block Bord AI - Advanced Edition

const BB_REPORT_URL = "https://block-bord.onrender.com";

// Use functions to get dynamic values for SPAs
const getCurrentURL = () => window.location.href;
const getCurrentDomain = () => window.location.hostname;
const getPageTitle = () => document.title || "";

// State tracking for dynamic features
let bbState = {
    clipboardHijacked: false,
    websocketCount: 0,
    wsConnections: [],
    canvasFingerprintCalls: 0,
    keyloggerListeners: 0,
    startTime: Date.now(),
    interactionClicks: 0,
    interactionKeys: 0,
    domNodesAdded: 0
};

// ─── INJECT MAIN WORLD OVERRIDES (Features 8, 9, 10, 17) ───────────────
function injectOverrides() {
    const script = document.createElement('script');
    script.textContent = `
        (function() {
            // WebSocket Detection
            const origWS = window.WebSocket;
            if (origWS) {
                window.WebSocket = function(url, protocols) {
                    window.postMessage({ type: 'BB_TELEMETRY', event: 'ws', url: url }, '*');
                    return protocols ? new origWS(url, protocols) : new origWS(url);
                };
            }
            // Canvas Fingerprinting Detection
            const origGetContext = HTMLCanvasElement.prototype.getContext;
            if (origGetContext) {
                HTMLCanvasElement.prototype.getContext = function(type, attrs) {
                    if (type === '2d' || type === 'webgl' || type === 'webgl2') {
                        window.postMessage({ type: 'BB_TELEMETRY', event: 'canvas' }, '*');
                    }
                    return origGetContext.apply(this, arguments);
                };
            }
            // Keystroke / Clipboard listener detection
            const origAddListener = EventTarget.prototype.addEventListener;
            if (origAddListener) {
                EventTarget.prototype.addEventListener = function(type, listener, options) {
                    if (['keydown', 'keyup', 'keypress'].includes(type)) {
                        window.postMessage({ type: 'BB_TELEMETRY', event: 'keylogger' }, '*');
                    }
                    if (['copy', 'paste', 'cut'].includes(type)) {
                        window.postMessage({ type: 'BB_TELEMETRY', event: 'clipboard' }, '*');
                    }
                    return origAddListener.apply(this, arguments);
                };
            }
        })();
    `;
    (document.head || document.documentElement).appendChild(script);
    script.remove();

    window.addEventListener('message', (e) => {
        if (e.source !== window || !e.data || e.data.type !== 'BB_TELEMETRY') return;
        
        switch (e.data.event) {
            case 'ws':
                bbState.websocketCount++;
                if (e.data.url) bbState.wsConnections.push(e.data.url);
                break;
            case 'canvas': bbState.canvasFingerprintCalls++; break;
            case 'keylogger': bbState.keyloggerListeners++; break;
            case 'clipboard': bbState.clipboardHijacked = true; break;
        }
    });
}

// ─── FEATURE 3: JS OBFUSCATION DETECTION ──────────────────────────────────
function detectJSObfuscation() {
    let score = 0;
    const scripts = document.querySelectorAll('script');
    let packedCount = 0;
    
    scripts.forEach(s => {
        const html = s.innerHTML || "";
        if (html.includes('eval(') && html.length > 500) score += 10;
        if (html.includes('atob(') && html.includes('fromCharCode')) score += 10;
        if (html.includes('unescape(') && html.includes('%')) score += 5;
        if (html.match(/\\x[0-9a-f]{2}\\x[0-9a-f]{2}/i)) score += 15;
        if (html.includes('p,a,c,k,e,d')) packedCount++;
    });
    
    if (packedCount > 0) score += 20;
    return score;
}

// ─── FEATURE 4 & 15: FORM ENDPOINT & HONEYPOT ─────────────────────────────
function detectEnhancedForms() {
    const result = {
        hasLoginForm: false,
        hasPasswordField: false,
        hasOTPField: false,
        hasCardField: false,
        hasCVVField: false,
        hasBankField: false,
        formCount: 0,
        externalFormAction: false,
        honeypotDetected: false,
    };

    const forms = document.querySelectorAll('form');
    result.formCount = forms.length;

    forms.forEach(f => {
        const action = (f.action || "").toLowerCase();
        if (action && action.startsWith('http')) {
            try {
                const actionHost = new URL(action).hostname;
                if (actionHost !== getCurrentDomain()) {
                    result.externalFormAction = true;
                }
            } catch (e) {}
        }
    });

    const inputs = document.querySelectorAll('input');
    inputs.forEach(input => {
        const type = (input.type || "").toLowerCase();
        const name = (input.name || "").toLowerCase();
        const id_attr = (input.id || "").toLowerCase();
        const placeholder = (input.placeholder || "").toLowerCase();
        const combined = `${type} ${name} ${id_attr} ${placeholder}`;

        if (type === "password" || combined.includes("password")) result.hasPasswordField = true;
        if (combined.includes("otp") || combined.includes("passcode")) result.hasOTPField = true;
        if (combined.includes("card") || combined.includes("cvv") || combined.includes("cvc")) result.hasCardField = true;
        if (combined.includes("account") || combined.includes("ifsc") || combined.includes("iban")) result.hasBankField = true;
        
        if (type === "hidden" && combined.match(/name|email|password|phone|address/)) {
            result.honeypotDetected = true;
        }
        const style = window.getComputedStyle(input);
        if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
            if (combined.match(/name|email|password|phone|address/)) {
                result.honeypotDetected = true;
            }
        }
    });

    result.hasLoginForm = result.hasPasswordField || forms.length > 0;
    return result;
}

function detectRedirects() {
    const referrer = document.referrer;
    if (referrer && new URL(referrer).hostname !== getCurrentDomain()) {
        return true; 
    }
    return false;
}

// ─── FEATURE 7: DOM Manipulation Analysis ────────────────────────
function setupDOMObserver() {
    const observer = new MutationObserver((mutations) => {
        mutations.forEach(m => bbState.domNodesAdded += m.addedNodes.length);
        if (bbState.domNodesAdded > 50) {
            debouncedExtractPageContent(true);
            bbState.domNodesAdded = 0;
        }
    });
    if (document.body) observer.observe(document.body, { childList: true, subtree: true });
}

// ─── FEATURE 12: User Interaction Risk Tracking ─────────────────────────────
function setupInteractionTracking() {
    document.addEventListener('click', (e) => {
        bbState.interactionClicks++;
        if (e.target.tagName === 'BUTTON' || (e.target.tagName === 'INPUT' && e.target.type === 'submit')) {
            debouncedExtractPageContent(true); 
        }
    }, true);
    
    document.addEventListener('keydown', (e) => {
        bbState.interactionKeys++;
    }, true);
}

// ─── EXTRACT & SEND ───────────────────────────
function simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    return hash.toString(36);
}

let extractTimeout = null;
let lastScannedHash = null;

function debouncedExtractPageContent(isUpdate = false) {
    if (extractTimeout) clearTimeout(extractTimeout);
    extractTimeout = setTimeout(() => {
        extractPageContent(isUpdate);
    }, 2000);
}

function extractPageContent(isUpdate = false) {
    const pageText = document.body ? (document.body.innerText || "") : "";
    const cleanText = pageText.substring(0, 5000).replace(/\s+/g, ' ').trim();
    const timeSinceLoad = Date.now() - bbState.startTime;

    const currentHash = simpleHash(cleanText + getCurrentURL());
    if (currentHash === lastScannedHash) return; // Prevent spamming identical content

    if (cleanText.length > 30 || isUpdate) {
        lastScannedHash = currentHash;
        chrome.runtime.sendMessage({
            action: 'pageContentDetected',
            url: getCurrentURL(),
            title: getPageTitle(),
            content: cleanText,
            contentHash: simpleHash(cleanText),
            formData: detectEnhancedForms(),
            hasRedirected: detectRedirects(),
            telemetry: {
                jsObfuscationScore: detectJSObfuscation(),
                keystrokeCapture: bbState.keyloggerListeners > 0,
                clipboardHijacked: bbState.clipboardHijacked,
                websocketAbuse: bbState.websocketCount > 0,
                wsConnections: bbState.wsConnections,
                canvasFingerprinting: bbState.canvasFingerprintCalls > 0,
                interactionClicks: bbState.interactionClicks,
                interactionKeys: bbState.interactionKeys,
                timeSinceLoadMs: timeSinceLoad,
                isDynamicUpdate: isUpdate
            }
        });
    }
}

function checkShortenedURLs() {
    const shorteners = ["bit.ly","tinyurl.com","t.co","goo.gl","is.gd","cutt.ly","rb.gy","s.id","ow.ly"];
    const links = Array.from(document.querySelectorAll('a[href]'));
    links.forEach(link => {
        try {
            const url = new URL(link.href);
            if (shorteners.includes(url.hostname)) {
                chrome.runtime.sendMessage({ action: 'expandShortenedURL', url: link.href });
            }
        } catch (e) {}
    });
}

function monitorDownloads() {
    const dangerousExts = ['.exe','.apk','.scr','.bat','.cmd','.vbs','.jar','.msi','.ps1','.pif'];
    document.addEventListener('click', (e) => {
        const link = e.target.closest('a[href]');
        if (link) {
            const href = link.href.toLowerCase();
            if (dangerousExts.some(ext => href.endsWith(ext))) {
                e.preventDefault();
                chrome.runtime.sendMessage({ action: 'dangerousDownload', url: link.href });
                showDownloadWarning(link.href);
            }
        }
    }, true);
}

function showDownloadWarning(url) {
    if (document.getElementById('bb-download-warn')) return;
    const banner = document.createElement('div');
    banner.id = 'bb-download-warn';
    banner.style.cssText = `
        position: fixed; top: 0; left: 0; right: 0; z-index: 999999;
        background: #e53e3e; color: white; padding: 14px 20px;
        font-family: sans-serif; font-size: 14px; font-weight: 600;
        display: flex; justify-content: space-between; align-items: center;
        box-shadow: 0 4px 20px rgba(0,0,0,0.4);
    `;
    banner.innerHTML = `
        <div>⚠️ Block Bord AI blocked a suspicious download: <code>${url.substring(0, 60)}...</code></div>
        <button onclick="this.parentElement.remove()" style="background: white; color: #e53e3e; border: none; 
        padding: 6px 12px; border-radius: 6px; cursor: pointer; font-weight: 700;">Dismiss</button>
    `;
    document.body.prepend(banner);
}

function injectReportButton() {
    if (document.getElementById('bb-report-btn')) return;
    const btn = document.createElement('div');
    btn.id = 'bb-report-btn';
    btn.title = "Report this site as suspicious to Block Bord";
    btn.style.cssText = `
        position: fixed; bottom: 20px; left: 20px; z-index: 99998;
        background: rgba(30,30,40,0.9); color: white; padding: 8px 14px;
        border-radius: 20px; font-family: sans-serif; font-size: 12px;
        cursor: pointer; display: flex; align-items: center; gap: 6px;
        border: 1px solid rgba(255,255,255,0.15); backdrop-filter: blur(8px);
        transition: all 0.2s ease;
    `;
    btn.innerHTML = `🚩 <span>Report Site</span>`;
    btn.onmouseenter = () => btn.style.background = 'rgba(229,62,62,0.9)';
    btn.onmouseleave = () => btn.style.background = 'rgba(30,30,40,0.9)';
    btn.onclick = () => reportCurrentSite();
    document.body.appendChild(btn);
}

function reportCurrentSite() {
    const description = prompt(`Report "${getCurrentDomain()}" as suspicious to Block Bord?\n\nOptionally add a description:`);
    if (description !== null) { 
        fetch(`${BB_REPORT_URL}/report`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-BlockBord-Source': 'extension'
            },
            credentials: 'include',
            body: JSON.stringify({ url: getCurrentURL(), description: description || "" })
        }).then(r => r.json()).then(data => {
            showTemporaryBanner(data.message || "Report submitted!", "success");
        }).catch(() => {
            showTemporaryBanner("Could not submit report. Is the server running?", "error");
        });
    }
}

function showTemporaryBanner(message, type = "info") {
    const banner = document.createElement('div');
    banner.style.cssText = `
        position: fixed; bottom: 70px; left: 20px; z-index: 999999;
        background: ${type === "success" ? "#276749" : "#822727"}; color: white;
        padding: 10px 16px; border-radius: 10px; font-family: sans-serif;
        font-size: 13px; box-shadow: 0 4px 20px rgba(0,0,0,0.4); max-width: 300px;
    `;
    banner.textContent = message;
    document.body.appendChild(banner);
    setTimeout(() => banner.remove(), 4000);
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'showWarning') {
        injectWarningOverlay(message.data);
    }
    if (message.action === 'showDownloadBlockedNotice') {
        showDownloadWarning(message.url);
    }
});

function injectWarningOverlay(data) {
    if (document.getElementById('blockbord-warning-root')) return;

    const root = document.createElement('div');
    root.id = 'blockbord-warning-root';
    root.style.cssText = `
        position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
        z-index: 2147483647; background: #000; display: flex;
        align-items: center; justify-content: center; font-family: 'Inter', sans-serif;
    `;

    const iframe = document.createElement('iframe');
    iframe.src = chrome.runtime.getURL('warning/warning.html');
    iframe.style.cssText = `
        width: 100%; height: 100%; border: none;
    `;
    
    // Pass data to iframe via postMessage after it loads
    iframe.onload = () => {
        iframe.contentWindow.postMessage({
            type: 'BB_WARNING_DATA',
            data: data,
            url: window.location.href
        }, '*');
    };

    // Listen for messages from the warning iframe
    window.addEventListener('message', (event) => {
        if (!event.data) return;
        if (event.data.type === 'BB_DISMISS_WARNING') {
            const root = document.getElementById('blockbord-warning-root');
            if (root) root.remove();
        } else if (event.data.type === 'BB_GO_BACK') {
            if (window.history.length > 1) {
                window.history.back();
            } else {
                window.location.href = 'about:blank';
            }
        }
    });

    root.appendChild(iframe);
    (document.body || document.documentElement).appendChild(root);
    
    // Stop any media/scripts if possible
    window.stop();
}

// ─── SPA ROUTING HOOKS ──────────────────────────────────────
function setupSPARouting() {
    let lastUrl = location.href;
    new MutationObserver(() => {
        const url = location.href;
        if (url !== lastUrl) {
            lastUrl = url;
            console.log("Block Bord: SPA route change detected:", url);
            debouncedExtractPageContent(true);
        }
    }).observe(document, {subtree: true, childList: true});

    window.addEventListener('popstate', () => {
        if (location.href !== lastUrl) {
            lastUrl = location.href;
            console.log("Block Bord: popstate detected:", lastUrl);
            debouncedExtractPageContent(true);
        }
    });
}

function init() {
    injectOverrides();
    setupInteractionTracking();
    setupSPARouting();
    
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', run);
    } else {
        run();
    }
}

function run() {
    setupDOMObserver();
    extractPageContent(false);
    checkShortenedURLs();   
    monitorDownloads();     
    
    const isLocal = window.location.hostname === '127.0.0.1' || window.location.hostname === 'localhost';
    if (!isLocal) {
        setTimeout(injectReportButton, 1500); 
    }
}

init();
