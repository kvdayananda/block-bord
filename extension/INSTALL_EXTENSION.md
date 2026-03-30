# 🛡️ Block Bord AI: Chrome Extension Installation Guide

Welcome to the **Edge Protection** activation. Follow these steps to install the Block Bord AI browser extension and enable real-time phishing detection.

## 📋 Prerequisites
- **Google Chrome** (or any Chromium-based browser like Edge, Brave).
- **FastAPI Backend**: Ensure your local server is running (`python -m uvicorn app:app --reload`).

## 🛠️ Installation Steps

1.  **Open Extensions Page**:
    - In your Chrome browser, navigate to: `chrome://extensions/`
    - Alternatively, click the **three dots (⋮)** > **Extensions** > **Manage Extensions**.

2.  **Enable Developer Mode**:
    - In the top-right corner, toggle the **Developer mode** switch to **ON**.

3.  **Load Unpacked Extension**:
    - Click the **Load unpacked** button in the top-left.
    - An explorer window will open. Navigate to your project folder:
      `d:\BlockBord_Premium_SaaS_Style\Block Bord\extension`
    - Select the `extension` folder and click **Select Folder**.

4.  **Pin the Extension**:
    - Click the **Puzzle Piece (🧩)** icon in your browser toolbar.
    - Find **Block Bord AI** and click the **Pin (📌)** icon for quick access.

## 🚀 How to Use

- **Real-time Scanning**: As you browse, Block Bord AI automatically analyzes the page structure and telemetry signals.
- **Badge Indicators**:
    - 🟢 **OK**: Safe.
    - 🟡 **!**: Suspicious (JS obfuscation or external forms detected).
    - 🔴 **!!!**: High Risk (Known phishing pattern or honeypots).
- **Manual Scan**: Click the extension icon to see a detailed risk breakdown and "Why this score?" insights.
- **Reporting**: Use the **Flag (🚩)** button on the page or in the popup to report a suspicious site.

---
*Status: Complete & Functional*
