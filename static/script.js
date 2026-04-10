// ===============================
// THEME (Light / Dark)
// ===============================
(function initTheme() {
    const savedTheme = localStorage.getItem('bb-theme');
    // Default to light (white) theme; user can switch via toggle
    document.documentElement.setAttribute('data-theme', savedTheme || 'light');
})();

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('bb-theme', newTheme);
    
    // Optional: Add a subtle feedback animation if a toggle exists
    const btn = document.querySelector('.theme-toggle-btn');
    if (btn) {
        btn.classList.add('switching');
        setTimeout(() => btn.classList.remove('switching'), 500);
    }
}

// ===============================
// STATE
// ===============================
let lastScanContent = "";
let lastScanId = null;

// ===============================
// CSRF HELPER
// ===============================
function getCsrfToken() {
    return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
}

// ===============================
// SCAN CONTENT FUNCTION
// ===============================
async function scanContent() {
    const input = document.getElementById("content");
    const resultDiv = document.getElementById("result");
    const scanBtn = document.getElementById("scanBtn");

    const text = input.value.trim();

    if (!text) {
        showResult("Please enter some content to analyze.", "high");
        return;
    }

    // Loading state
    if (scanBtn) {
        scanBtn.disabled = true;
        scanBtn.originalHTML = scanBtn.innerHTML;
        scanBtn.innerHTML = '<span>Scanning...</span>';
    }
    showResult("🔍 Analysis in progress...", "loading");

    try {
        const response = await fetch("/scan", {
            method: "POST",
            headers: { 
                "Content-Type": "application/json",
                "X-CSRF-Token": getCsrfToken()
            },
            body: JSON.stringify({ content: text })
        });

        if (response.status === 403) {
            throw new Error("Security verification failed (CSRF). Please refresh the page.");
        }

        const data = await response.json();

        lastScanContent = text;
        lastScanId = data.scan_id ?? null;

        // 🚀 Handle daily limit first
        if (data.upgrade_required) {
            resultDiv.className = "result-box risk-high";
            resultDiv.style.marginTop = "24px";
            resultDiv.innerHTML = `
                <div style="padding: 24px; border-radius: 16px; background: var(--surface); border: 1px solid var(--border); box-shadow: var(--shadow-sm);">
                    <h3 style="margin: 0 0 12px 0; font-size: 1.1rem; font-weight: 800; color: var(--danger);">🚨 Daily Limit Reached</h3>
                    <p style="margin-bottom: 20px; color: var(--text-muted);">You have completed your daily scan limit for the ${data.plan} plan.</p>
                    <a href="/pricing" class="btn btn-primary" style="width: 100%;">Upgrade Plan</a>
                </div>
            `;
            return;
        }

        // Normal result (Premium Style)
        const riskClass = data.risk_score > 70 ? 'risk-high' : data.risk_score > 30 ? 'risk-warning' : 'risk-safe';
        const riskEmoji = data.risk_score > 70 ? '🚨' : data.risk_score > 30 ? '⚠️' : '✅';
        const labelText = data.category || data.risk_level || "Analyzed successfully";
        const detailsText = data.reasons && data.reasons.length ? data.reasons.join(', ') : "Analysis complete.";

        resultDiv.className = `result-box ${riskClass}`;
        resultDiv.style.marginTop = "24px";
        resultDiv.innerHTML = `
            <div style="padding: 24px; border-radius: 16px; background: var(--surface); border: 1px solid var(--border); box-shadow: var(--shadow-sm);">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                    <h3 style="margin: 0; font-size: 1.1rem; font-weight: 800; display: flex; align-items: center; gap: 8px;">${riskEmoji} Analysis Result</h3>
                    <span class="pill ${riskClass === 'risk-safe' ? 'pill-safe' : riskClass === 'risk-warning' ? 'pill-warn' : 'pill-danger'}" style="padding: 4px 12px; border-radius: 20px; font-weight: 800; font-size: 0.85rem; letter-spacing: 0.05em; background: ${riskClass === 'risk-safe' ? 'var(--safe-bg)' : riskClass === 'risk-warning' ? 'var(--warn-bg)' : 'var(--danger-bg)'}; color: ${riskClass === 'risk-safe' ? 'var(--safe)' : riskClass === 'risk-warning' ? 'var(--warn)' : 'var(--danger)'};">
                        ${data.risk_score}% Risk
                    </span>
                </div>
                <p style="font-size: 1.1rem; font-weight: 700; margin-bottom: 8px; color: var(--text);">${labelText}</p>
                <p style="opacity: 0.8; font-size: 0.95rem; color: var(--text-muted); line-height: 1.5; margin-bottom: 20px;">${detailsText}</p>
                
                <div class="feedback-actions" style="display: flex; gap: 12px; flex-wrap: wrap; margin-top: 24px; border-top: 1px solid rgba(0,0,0,0.05); padding-top: 20px;">
                    <button class="btn btn-outline" style="padding: 10px 18px; border-radius: 12px; font-weight: 700; display: flex; align-items: center; gap: 8px; font-size: 0.9rem;" id="markSpamBtn" type="button"><span style="font-size: 1.1rem;">🚫</span> Mark Spam</button>
                    <button class="btn btn-outline" style="padding: 10px 18px; border-radius: 12px; font-weight: 700; display: flex; align-items: center; gap: 8px; font-size: 0.9rem;" id="markHamBtn" type="button"><span style="font-size: 1.1rem;">✅</span> Not Spam</button>
                    ${labelText === "Analyzed successfully" ? '' : `<button class="btn btn-primary" style="padding: 10px 18px; border-radius: 12px; font-weight: 700; display: flex; align-items: center; gap: 8px; font-size: 0.9rem;" id="retrainBtn" type="button"><span style="font-size: 1.1rem;">🧠</span> Help Train AI</button>`}
                </div>
            </div>
        `;

        bindFeedbackButtons();

    } catch (error) {
        showResult(`⚠️ ${error.message || "Something went wrong. Please try again."}`, "high");
    } finally {
        if (scanBtn) {
            scanBtn.disabled = false;
            scanBtn.innerHTML = scanBtn.originalHTML;
        }
    }
}


// ===============================
// VIEW SCAN DETAILS FUNCTION (FIXED)
// ===============================
async function viewScan(id) {
  try {
    // ✅ Use the new secure API
    const response = await fetch(`/api/scan/${id}`);

    if (!response.ok) {
      throw new Error("Failed to fetch scan data");
    }

    const data = await response.json();

    // ✅ Set correct values
    lastScanContent = data.content || "";
    lastScanId = data.id ?? id;

    const detailBox = document.getElementById("scanDetail");
    const contentBox = document.getElementById("scanDetailContent");

    // Format date safely
    const dateText = data.created_at
      ? new Date(data.created_at).toLocaleString()
      : "—";

    const reasons = data.reasons || [];
    const reasonsHtml = reasons.length 
        ? `<ul style="list-style: none; padding: 0; margin: 0;">${reasons.map(r => `<li style="margin-bottom: 8px; font-size: 0.9rem; color: #475569; display: flex; gap: 8px;"><span style="color: var(--primary); font-weight: 900;">•</span> <span>${escapeHtml(r)}</span></li>`).join('')}</ul>`
        : `<p style="font-size: 0.9rem; color: #94a3b8; font-style: italic;">No specific forensic anomalies detected.</p>`;

    contentBox.innerHTML = `
      <div class="detail-grid">
        <div class="risk-circle" style="--progress: ${Number(data.risk_score) * 3.6}deg;">
          <span>${Number(data.risk_score).toFixed(0)}%</span>
        </div>

        <div class="detail-card" style="margin-top: 24px;">
          <div style="margin-bottom: 20px;">
             <span class="pill-premium" style="background: rgba(99, 102, 241, 0.1); color: var(--primary); font-weight: 800; font-size: 0.75rem; padding: 6px 14px; border-radius: 20px; text-transform: uppercase;">🛡️ ${escapeHtml(data.category || 'General Analysis')}</span>
          </div>
          
          <h3 style="font-size: 0.9rem; font-weight: 800; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 12px;">Original Content</h3>
          <div style="background: var(--bg-alt); padding: 16px; border-radius: 12px; border: 1px solid var(--border); font-family: var(--font-mono); font-size: 0.85rem; color: var(--text); word-break: break-all; margin-bottom: 24px; max-height: 200px; overflow-y: auto;">
            ${escapeHtml(data.content || "")}
          </div>

          <h3 style="font-size: 0.9rem; font-weight: 800; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 16px;">AI Forensic Breakdown</h3>
          <div style="margin-bottom: 24px;">
            ${reasonsHtml}
          </div>

          <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 24px;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="vertical-align: middle; margin-right: 4px;"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
            <strong>Scanned on:</strong> ${dateText}
          </p>

          <div class="feedback-actions" style="display: flex; gap: 12px; flex-wrap: wrap; border-top: 1px solid var(--border); padding-top: 24px;">
            <button class="btn btn-outline" style="padding: 10px 18px; border-radius: 12px; font-weight: 700; display: flex; align-items: center; gap: 8px; font-size: 0.85rem;" id="markSpamBtn" type="button">🚫 Mark Spam</button>
            <button class="btn btn-outline" style="padding: 10px 18px; border-radius: 12px; font-weight: 700; display: flex; align-items: center; gap: 8px; font-size: 0.85rem;" id="markHamBtn" type="button">✅ Not Spam</button>
            <button class="btn btn-primary" style="padding: 10px 18px; border-radius: 12px; font-weight: 700; display: flex; align-items: center; gap: 8px; font-size: 0.85rem;" id="retrainBtn" type="button">🧠 Retrain Model</button>
          </div>
        </div>
      </div>
    `;

    // ✅ bind feedback buttons on detail view also
    bindFeedbackButtons();

    detailBox.style.display = ""; // Clear any previous override
    detailBox.classList.remove("hidden");
    detailBox.scrollIntoView({ behavior: "smooth" });

  } catch (error) {
    alert("Unable to load scan details.");
  }
}

// ===============================
// GLOBAL CLOSE DETAIL MODAL
// ===============================
function closeScanDetail() {
    const detailBox = document.getElementById("scanDetail");
    if (detailBox) {
        detailBox.classList.add("hidden");
        detailBox.style.display = "none";
    }
}
// ===============================
// HELPER FUNCTION
// ===============================
function showResult(message, type) {
    const resultDiv = document.getElementById("result");
    resultDiv.classList.remove("hidden");

    let icon = "ℹ️";
    let bg = "var(--surface)";
    let border = "var(--border)";
    let txtColor = "var(--text)";
    
    if (type === "high") {
        icon = "🚨"; bg = "rgba(239, 68, 68, 0.05)"; border = "rgba(239, 68, 68, 0.2)"; txtColor = "#ef4444";
    } else if (type === "safe" || type === "ok") {
        icon = "✅"; bg = "rgba(16, 185, 129, 0.05)"; border = "rgba(16, 185, 129, 0.2)"; txtColor = "#10b981";
    } else if (type === "loading") {
        icon = "⏳"; bg = "rgba(99, 102, 241, 0.05)"; border = "rgba(99, 102, 241, 0.2)"; txtColor = "#6366f1";
    }

    resultDiv.className = ""; // Remove previous classes
    resultDiv.style.marginTop = "16px";
    
    resultDiv.innerHTML = `
        <div style="padding: 16px 20px; border-radius: 16px; background: ${bg}; border: 1px solid ${border}; display: flex; align-items: center; gap: 14px; animation: slideDown 0.3s ease-out;">
            <span style="font-size: 1.25rem;">${icon}</span>
            <p style="margin: 0; font-weight: 700; color: ${txtColor}; flex: 1; font-size: 0.95rem; letter-spacing: -0.01em;">${message}</p>
        </div>
    `;
}

function toggleSidebar() {
    const sidebar = document.getElementById("sidebar") || document.querySelector(".sidebar");
    if (sidebar) {
        sidebar.classList.toggle("active");
    }
}

function toggleMobileMenu() {
    const nav = document.querySelector(".nav-right");
    const toggleBtn = document.querySelector(".mobile-toggle");
    const isOpening = !nav.classList.contains("active");

    if (nav) nav.classList.toggle("active");
    if (toggleBtn) toggleBtn.classList.toggle("active");
    
    // Lock scroll when menu is open
    document.body.classList.toggle("menu-open", isOpening);

    // Close menu when clicking links
    const links = nav.querySelectorAll(".nav-link, .btn");
    links.forEach(link => {
        link.onclick = () => {
            nav.classList.remove("active");
            toggleBtn.classList.remove("active");
            document.body.classList.remove("menu-open");
        };
    });
}

// ── App Sidebar Toggle Logic ── 
function openSidebar() {
  const sidebar = document.getElementById('appSidebar');
  const overlay = document.getElementById('sidebarOverlay');
  if (sidebar && overlay) {
    sidebar.classList.add('mobile-open');
    overlay.classList.add('active');
    document.body.style.overflow = 'hidden';
  }
}

function closeSidebar() {
  const sidebar = document.getElementById('appSidebar');
  const overlay = document.getElementById('sidebarOverlay');
  if (sidebar && overlay) {
    sidebar.classList.remove('mobile-open');
    overlay.classList.remove('active');
    document.body.style.overflow = '';
  }
}



// ===============================
// FEEDBACK + RETRAIN (FastText)
// ===============================
async function sendFeedback(label){
    if (!lastScanContent) return;
    const res = await fetch("/feedback", {
        method: "POST",
        headers: { 
            "Content-Type": "application/json",
            "X-CSRF-Token": getCsrfToken()
        },
        body: JSON.stringify({
            label: label,
            content: lastScanContent,
            scan_id: lastScanId
        })
    });
    let data = {};
    try { data = await res.json(); } catch(e) {}
    return res.ok;
}

async function retrainModel(){
    const btn = document.getElementById("retrainBtn");
    const originalHTML = btn ? btn.innerHTML : '';
    
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<span style="font-size:1.1rem">⏳</span> Saving & Training...`;
    }

    // Step 1: Save feedback first (mark as spam since user is flagging a threat)
    if (lastScanContent) {
        try {
            await fetch("/feedback", {
                method: "POST",
                headers: { 
                    "Content-Type": "application/json",
                    "X-CSRF-Token": getCsrfToken()
                },
                body: JSON.stringify({
                    label: "spam",
                    content: lastScanContent,
                    scan_id: lastScanId
                })
            });
        } catch(e) { /* feedback save best-effort */ }
    }
    
    // Step 2: Trigger retrain
    try {
        const res = await fetch("/ml/retrain", { 
            method: "POST",
            headers: { "X-CSRF-Token": getCsrfToken() }
        });
        const data = await res.json();
        
        if (btn) {
            if (data.ok) {
                btn.innerHTML = `<span style="font-size:1.1rem">✅</span> Model Updated!`;
                btn.style.background = 'var(--safe)';
            } else {
                btn.innerHTML = `<span style="font-size:1.1rem">💾</span> Feedback Saved!`;
                btn.title = data.message || 'Model will retrain when more samples are collected.';
                btn.style.opacity = '0.7';
            }
            // Reset button after 3 seconds
            setTimeout(() => {
                btn.innerHTML = originalHTML;
                btn.disabled = false;
                btn.style.background = '';
                btn.style.opacity = '';
                btn.title = '';
            }, 3000);
        }
    } catch (e) {
        if (btn) {
            btn.innerHTML = originalHTML;
            btn.disabled = false;
        }
        alert('Connection error. Please try again.');
    }
}

// Attach listeners after each scan render
function bindFeedbackButtons(){
    const spamBtn = document.getElementById("markSpamBtn");
    const hamBtn = document.getElementById("markHamBtn");
    const retrainBtn = document.getElementById("retrainBtn");

    if (spamBtn) spamBtn.onclick = async () => {
        spamBtn.disabled = true;
        spamBtn.innerHTML = '⏳ Saving...';
        await sendFeedback("spam");
        spamBtn.innerHTML = '✅ Marked Spam';
        setTimeout(() => { spamBtn.innerHTML = '🚫 Mark Spam'; spamBtn.disabled = false; }, 2500);
    };
    if (hamBtn) hamBtn.onclick = async () => {
        hamBtn.disabled = true;
        hamBtn.innerHTML = '⏳ Saving...';
        await sendFeedback("ham");
        hamBtn.innerHTML = '✅ Marked Safe';
        setTimeout(() => { hamBtn.innerHTML = '✅ Not Spam'; hamBtn.disabled = false; }, 2500);
    };
    if (retrainBtn) retrainBtn.onclick = () => retrainModel();
}

function escapeHtml(str) {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

// ===============================
// AI CYBER ASSISTANT WIDGET
// ===============================
(function initCyberAssistant() {
    const toggleBtn = document.getElementById('ai-widget-toggle');
    const chatWindow = document.getElementById('ai-chat-window');
    const closeBtn = document.getElementById('ai-chat-close');
    const sendBtn = document.getElementById('ai-chat-send');
    const inputArea = document.getElementById('ai-chat-input');
    const messagesDiv = document.getElementById('ai-chat-messages');

    if (!toggleBtn || !chatWindow) return; // Widget not present (logged out)

    let isOpen = false;
    chatWindow.style.display = 'none';

    toggleBtn.addEventListener('click', () => {
        if (!isOpen) {
            chatWindow.style.display = 'flex';
            chatWindow.classList.remove('closing');
            isOpen = true;
            inputArea.focus();
        } else {
            closeChat();
        }
    });

    closeBtn.addEventListener('click', closeChat);

    function closeChat() {
        chatWindow.classList.add('closing');
        setTimeout(() => {
            chatWindow.style.display = 'none';
            chatWindow.classList.remove('closing');
            isOpen = false;
        }, 200);
    }

    // Send on button click or Enter key (not Shift+Enter)
    sendBtn.addEventListener('click', sendMessage);
    inputArea.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });

    // Auto-grow textarea
    inputArea.addEventListener('input', () => {
        inputArea.style.height = 'auto';
        inputArea.style.height = Math.min(inputArea.scrollHeight, 120) + 'px';
    });


    function addMessage(text, type) {
        const msg = document.createElement('div');
        msg.className = `ai-msg ${type === 'user' ? 'user-msg' : 'bot-msg'}`;
        // Simple markdown: **bold**
        const formatted = escapeHtml(text)
            .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
            .replace(/\n/g, '<br>');
        msg.innerHTML = formatted;
        messagesDiv.appendChild(msg);
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
        return msg;
    }

    function addTypingIndicator() {
        const msg = document.createElement('div');
        msg.className = 'ai-msg bot-msg';
        msg.id = 'typing-indicator';
        msg.innerHTML = '<span style="opacity:0.6;font-style:italic;display:flex;gap:4px;align-items:center;"><span>Analyzing</span><span style="animation:typing-dots 1.2s infinite">...</span></span>';
        messagesDiv.appendChild(msg);
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
    }

    function removeTypingIndicator() {
        const el = document.getElementById('typing-indicator');
        if (el) el.remove();
    }

    async function sendMessage() {
        const text = inputArea.value.trim();
        if (!text) return;

        addMessage(text, 'user');
        inputArea.value = '';
        inputArea.style.height = 'auto';
        sendBtn.disabled = true;

        addTypingIndicator();

        try {
            const res = await fetch('/api/assistant', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]')?.content || ''
                },
                credentials: 'include',
                body: JSON.stringify({ message: text })
            });

            removeTypingIndicator();

            if (res.status === 401) {
                addMessage('Please log in to use the AI Assistant.', 'bot');
                return;
            }

            const data = await res.json();
            addMessage(data.response || 'Sorry, I could not analyze that.', 'bot');


        } catch (err) {
            removeTypingIndicator();
            addMessage('Connection error. Please try again.', 'bot');
        } finally {
            sendBtn.disabled = false;
        }
    }

    // Add typing dots animation if not already present
    if (!document.querySelector('style[data-ai-widget]')) {
        const style = document.createElement('style');
        style.setAttribute('data-ai-widget', '1');
        style.textContent = `
            @keyframes typing-dots {
                0%, 20% { content: '.'; }
                40% { content: '..'; }
                60%, 100% { content: '...'; }
            }
        `;
        document.head.appendChild(style);
    }
})();