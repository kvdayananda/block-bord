# 🛡️ Block Bord AI: Chrome Extension Installation & Setup Guide (Manifest V3)

Welcome to **Block Bord Edge Protection**. This browser extension provides real-time client-side heuristics, automated background risk scoring, telemetry-informed threat assessment, and instant phishing warnings synchronized with your Block Bord SaaS platform.

---

## 📋 Prerequisites
- **Chromium Browser**: Google Chrome, Brave, Microsoft Edge, or Opera (Manifest V3 compatible).
- **Block Bord Server**: Ensure your local Laravel SaaS server is running:
  ```powershell
  php artisan serve
  # Server runs at http://127.0.0.1:8000
  ```

---

## 🛠️ Installation Steps

1. **Open the Chrome Extensions Manager**:
   - Navigate to `chrome://extensions/` in your browser address bar.
   - Or click the **Menu (⋮)** > **Extensions** > **Manage Extensions**.

2. **Enable Developer Mode**:
   - In the top-right corner of the Extensions page, toggle **Developer mode** to **ON**.

3. **Load Unpacked Extension**:
   - Click the **Load unpacked** button in the top-left toolbar.
   - Browse to your project's extension directory:
     `d:\BlockBord_Premium_SaaS_Style\Block Bord\extension`
   - Select the `extension` folder and confirm.

4. **Pin the Extension**:
   - Click the **Puzzle piece (🧩)** icon in your browser toolbar.
   - Locate **Block Bord AI** and click the **Pin (📌)** icon for one-click access.

---

## ⚙️ Configuration & Options

Right-click the Block Bord extension icon and select **Options** (or click the Settings gear in the popup footer):

1. **Backend Server URL**: Defaults to `http://127.0.0.1:8000`. You can change this to any staging or production domain.
2. **API Key Authentication**:
   - Dashboard users logged into the web app in the same browser automatically authenticate via session cookies.
   - Alternatively, generate an API Key from your **Dashboard → API Management** (`bb_live_...`) and paste it here for persistent authentication across sessions.
3. **Connection Test**: Click **Test Connection** to measure server latency and verify authentication status.
4. **Protection Preferences**:
   - Toggle **Automatic URL & Content Scanning** on or off.
   - Toggle **Threat Warning Overlays** on or off.
   - Toggle **System Desktop Notifications** on or off.
5. **Local History**: Clear stored client-side scan logs anytime with one click.

---

## 🚀 Key Features

- **Real-Time Edge Heuristics**: Analyzes JavaScript obfuscation, hidden honeypot fields, credential-harvesting forms, and external form actions.
- **Service Worker Background Scanning**: Utilizes Chrome Manifest V3 service workers with client-side caching to minimize redundant network calls.
- **Threat Level Normalization**: Unifies 5-tier backend risk scoring (`SAFE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) with clear visual popup feedback:
  - 🟢 **Safe** (0–29): Low-risk, legitimate domain.
  - 🟡 **Suspicious** (30–69): Suspicious behaviors or unverified origins.
  - 🔴 **High Risk / Critical** (70–100): Confirmed phishing or dangerous indicators.
- **Full-Screen Warning Interception**: Blocks navigation to verified phishing destinations with an educational explanation and a "Go Back to Safety" option.
- **Suspicious Download Blocker**: Proactively warns when clicking direct executable download links (`.exe`, `.scr`, `.apk`, `.bat`).
- **One-Click Site Reporting**: Allows users to submit phishing reports directly to the Block Bord administration console.

---

*Version: v2.5.0 (Manifest V3 Compliant)*
