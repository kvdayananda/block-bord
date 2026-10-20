// Options JS for Block Bord AI — Enhanced Settings Controller
// ═══════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
    const apiUrlInput        = document.getElementById('api-url');
    const apiKeyInput        = document.getElementById('api-key');
    const autoScanToggle     = document.getElementById('auto-scan');
    const warningOverlaysToggle = document.getElementById('warning-overlays');
    const notificationsToggle = document.getElementById('notifications');
    const btnTestConnection  = document.getElementById('btn-test-connection');
    const btnClearHistory    = document.getElementById('btn-clear-history');
    const historyCountLabel  = document.getElementById('history-count');
    const saveBtn            = document.getElementById('save');
    const status             = document.getElementById('status');

    function showStatus(message, isError = false) {
        status.textContent = message;
        status.className = isError ? 'error' : 'success';
        setTimeout(() => {
            status.style.display = 'none';
        }, 4000);
    }

    // Refresh history item count
    function refreshHistoryCount() {
        chrome.storage.local.get(['scanHistory'], (res) => {
            const count = (res.scanHistory || []).length;
            historyCountLabel.textContent = `${count} recent scan${count === 1 ? '' : 's'} stored locally in extension memory`;
        });
    }

    // Load current values
    chrome.storage.local.get([
        'apiUrl',
        'apiKey',
        'autoScanEnabled',
        'showWarningOverlays',
        'showNotifications'
    ], (result) => {
        if (result.apiUrl) apiUrlInput.value = result.apiUrl;
        if (result.apiKey) apiKeyInput.value = result.apiKey;
        autoScanToggle.checked = result.autoScanEnabled !== false; // default true
        warningOverlaysToggle.checked = result.showWarningOverlays !== false; // default true
        notificationsToggle.checked = result.showNotifications !== false; // default true
    });

    refreshHistoryCount();

    // Test connection handler
    btnTestConnection.addEventListener('click', async () => {
        const url = apiUrlInput.value.trim().replace(/\/$/, "") || "http://127.0.0.1:8000";
        const key = apiKeyInput.value.trim();

        btnTestConnection.disabled = true;
        btnTestConnection.innerHTML = 'Testing...';

        const startTime = Date.now();
        try {
            const headers = {};
            if (key) headers['X-API-Key'] = key;

            const res = await fetch(`${url}/api/v1/ext/status`, {
                headers,
                credentials: 'include',
                signal: AbortSignal.timeout(4000)
            });

            const latency = Date.now() - startTime;
            if (res.ok) {
                const data = await res.json();
                const authState = data.logged_in
                    ? `Authenticated as @${data.username} (${data.plan || 'Free'})`
                    : 'Connected (Guest / Unauthenticated)';
                showStatus(`Connection successful! (${latency}ms) — ${authState}`, false);
            } else {
                showStatus(`Server responded with HTTP ${res.status}: ${res.statusText}`, true);
            }
        } catch (err) {
            showStatus(`Cannot connect to ${url}. Ensure server is running and accessible.`, true);
        } finally {
            btnTestConnection.disabled = false;
            btnTestConnection.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg> Test Connection';
        }
    });

    // Clear history handler
    btnClearHistory.addEventListener('click', () => {
        if (confirm("Are you sure you want to clear all stored scan history?")) {
            chrome.storage.local.set({ scanHistory: [] }, () => {
                refreshHistoryCount();
                showStatus('Scan history cleared successfully.', false);
            });
        }
    });

    // Save configuration handler
    saveBtn.addEventListener('click', () => {
        const apiUrl = apiUrlInput.value.trim().replace(/\/$/, "");
        const apiKey = apiKeyInput.value.trim();
        const autoScanEnabled = autoScanToggle.checked;
        const showWarningOverlays = warningOverlaysToggle.checked;
        const showNotifications = notificationsToggle.checked;

        chrome.storage.local.set({ 
            apiUrl: apiUrl, 
            apiKey: apiKey,
            autoScanEnabled: autoScanEnabled,
            showWarningOverlays: showWarningOverlays,
            showNotifications: showNotifications
        }, () => {
            showStatus('Preferences saved successfully!', false);
        });
    });
});
