# Running Block Bord AI Locally

Follow these steps to get the platform running on your local machine.

## 1. Backend Server Setup

### Install Dependencies
Open your terminal in the project root and run:
```powershell
pip install -r requirements.txt
```

### Initialize AI Model (Recommended)
To ensure the AI has the latest threat intelligence, run:
```powershell
python update_datasets.py
```

### Start the Server
Run the FastAPI backend using Uvicorn:
```powershell
python -m uvicorn app:app --reload
```
The server will be available at: [http://127.0.0.1:8000](http://127.0.0.1:8000)

---

## 2. Browser Extension Setup

1. Open **Google Chrome**.
2. Navigate to `chrome://extensions/`.
3. Enable **Developer mode** (toggle switch in the top-right corner).
4. Click the **Load unpacked** button.
5. Select the `extension` folder located inside: `D:\BlockBord_Premium_SaaS_Style\Block Bord\extension`
6. Pin the extension to your toolbar for easy access.

---

## 3. Verifying the System

1.  **Login**: Go to [http://127.0.0.1:8000/login](http://127.0.0.1:8000/login) and log in to your account.
2.  **Browse**: Open any website (e.g., [google.com](https://google.com)).
3.  **Check Extension**:
    - You should see the extension icon update with an **OK** badge.
    - Click the extension popup to see the real-time risk analysis.
    - The dashboard at `/app` will track your total scan history.

> [!TIP]
> If you see "Scan failed" in the popup, ensure your backend server is still running in the terminal.
