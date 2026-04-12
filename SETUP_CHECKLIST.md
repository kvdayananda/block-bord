# Block Bord AI — Complete Pre-Start Setup Checklist

**Document Version:** 1.0  
**Date:** April 12, 2026  
**Purpose:** Everything YOU (the developer) must set up BEFORE we start coding. Complete every item on this list so we can work uninterrupted.

---

## Table of Contents

1. [Project Summary](#1-project-summary)
2. [What We Are Building](#2-what-we-are-building)
3. [What We Will Change](#3-what-we-will-change)
4. [Current Problems](#4-current-problems)
5. [YOUR Task List (Accounts & Setup)](#5-your-task-list)
6. [API Keys Required](#6-api-keys-required)
7. [Tools Required on Your Machine](#7-tools-required-on-your-machine)
8. [Verification Checklist](#8-verification-checklist)

---

## 1. Project Summary

**Block Bord AI** is a cybersecurity SaaS platform with a Chrome extension that detects phishing, scams, and malicious websites in real-time. Your client has given you this project to make it production-ready. Currently it is broken, unorganized, and not deployable.

**Our transformation goal:**
- Detection accuracy: from ~40% → 95%+ using XGBoost ML model
- Database: from local SQLite → Cloud PostgreSQL (Neon)
- Hosting: Deploy backend on Render (free), frontend templates from same backend
- Architecture: from 1 monolithic file (2,006 lines) → clean modular structure
- Security: Fix all critical vulnerabilities
- Extension: Make it production-ready with dynamic API URL

---

## 2. What We Are Building

### Architecture After Transformation

```
┌─────────────────────┐      ┌─────────────────────┐
│   Chrome Extension   │─────▶│   Render (Backend)   │
│   (Manifest V3)      │ API  │   FastAPI + Uvicorn   │
└─────────────────────┘      │   XGBoost ML Model    │
                              │   Jinja2 Templates    │
┌─────────────────────┐      │                       │
│   User's Browser     │─────▶│   Routes:             │
│   (Web Dashboard)    │ HTTP │   /scan, /app, /admin │
└─────────────────────┘      └──────────┬────────────┘
                                        │
                    ┌───────────────────┼───────────────────┐
                    │                   │                   │
            ┌───────▼───────┐   ┌───────▼───────┐   ┌─────▼─────────┐
            │ Neon Database  │   │ Google Safe   │   │ PhishTank     │
            │ (PostgreSQL)   │   │ Browsing API  │   │ (Training     │
            │ Free: 0.5 GB   │   │ Free          │   │  Data)        │
            └───────────────┘   └───────────────┘   └───────────────┘
```

### 3-Layer Detection Engine

| Layer | What It Does | Accuracy |
|:------|:-------------|:---------|
| Layer 1: Google Safe Browsing API | Checks URL against Google's global phishing/malware database | ~99% for known threats |
| Layer 2: XGBoost ML Model | Trained on 235,000 URLs with 54 features — catches unknown threats | 97%+ |
| Layer 3: Heuristic Engine | 80+ custom rules (SSL, WHOIS, domain age, brand impersonation) | Good for zero-day |
| **Combined** | **Weighted blend of all 3 layers** | **95-97%** |

---

## 3. What We Will Change

### Files We Will CREATE (New)

| File | Purpose |
|:-----|:--------|
| `backend/app/main.py` | New FastAPI app entry point with clean middleware setup |
| `backend/app/config.py` | Type-safe environment configuration using Pydantic Settings |
| `backend/app/dependencies.py` | Database session, auth, and CSRF reusable dependencies |
| `backend/app/routers/auth.py` | Login, Register, Logout, Password Reset routes |
| `backend/app/routers/scan.py` | POST /scan, GET /scan/{id}, scan detail routes |
| `backend/app/routers/dashboard.py` | Dashboard, History, Analytics page routes |
| `backend/app/routers/admin.py` | Admin panel, User management, Blacklist/Whitelist |
| `backend/app/routers/payments.py` | Razorpay checkout, verification, webhooks |
| `backend/app/routers/tools.py` | Leak checker, AI chatbot, Scam map routes |
| `backend/app/routers/public.py` | Landing, About, Status, Contact, Legal pages |
| `backend/app/models/user.py` | User SQLAlchemy model |
| `backend/app/models/scan.py` | ScanHistory SQLAlchemy model |
| `backend/app/models/payment.py` | Payment SQLAlchemy model |
| `backend/app/models/feedback.py` | Feedback SQLAlchemy model |
| `backend/app/models/domain_lists.py` | Blacklist + Whitelist models |
| `backend/app/models/report.py` | UserReport + PasswordResetToken models |
| `backend/app/services/risk_engine.py` | Cleaned-up heuristic risk engine |
| `backend/app/services/ml_engine.py` | XGBoost model loader + prediction |
| `backend/app/services/feature_extractor.py` | URL feature extraction (54 features) |
| `backend/app/services/safe_browsing.py` | Google Safe Browsing API integration |
| `backend/app/services/email_service.py` | SMTP email alert service |
| `backend/app/services/plan_service.py` | Subscription plan logic |
| `backend/app/middleware/security.py` | Dynamic security headers (CSP) |
| `backend/app/middleware/csrf.py` | CSRF protection middleware |
| `backend/app/database/connection.py` | Database engine and session setup |
| `backend/ml/train_model.py` | XGBoost training script |
| `backend/ml/evaluate_model.py` | Model accuracy evaluation |
| `backend/ml/feature_engineering.py` | Feature extraction pipeline |
| `backend/render.yaml` | Render deployment config |
| `scripts/migrate_sqlite_to_neon.py` | One-time data migration script |
| `scripts/seed_data.py` | Test data seeding |

### Files We Will MODIFY

| File | What Changes |
|:-----|:-------------|
| `requirements.txt` | Remove dead deps (scikit-learn, pandas), add XGBoost, safe-browsing |
| `Dockerfile` | Update for new project structure |
| `docker-compose.yml` | Remove hardcoded secrets, add proper env vars |
| `.gitignore` | Add *.db, __pycache__, .env, models/*.joblib |
| `extension/manifest.json` | Dynamic API URL, updated permissions |
| `extension/background.js` | Configurable backend URL, improved error handling |
| `extension/content.js` | Enhanced DOM analysis, better telemetry |
| `extension/popup.js` | Dynamic API URL, improved UX |
| All 26 HTML templates | Update API endpoints, fix CSRF, improve UI |
| `static/style.css` | Admin panel redesign styles |
| `static/script.js` | Updated API calls, new admin features |

### Files We Will DELETE

| File | Reason |
|:-----|:-------|
| `app.py` | Replaced by modular `backend/app/` structure |
| `database.py` | Split into `models/` and `database/connection.py` |
| `risk_engine.py` | Replaced by `services/risk_engine.py` (cleaned up) |
| `ml_spam.py` | Replaced by `services/ml_engine.py` (XGBoost) |
| `ml_ensemble.py` | 11-line pass-through — eliminated |
| `security.py` | Replaced by `middleware/security.py` |
| `update_datasets.py` | Replaced by `ml/train_model.py` |
| `make_admin.py` | Moved to `scripts/make_admin.py` |
| `blockbord.db` | Moving to Neon PostgreSQL cloud |
| `__pycache__/` | Should never be in git |

---

## 4. Current Problems (What's Broken)

### CRITICAL — Will Crash or Get Hacked

| # | Problem | Impact |
|:--|:--------|:-------|
| 1 | `GET /upgrade` gives FREE Pro access to anyone | Any user can become Pro without paying |
| 2 | `hmac.new()` on line 1978 of app.py | Python has no `hmac.new()` — Razorpay webhook CRASHES |
| 3 | CORS allows ALL origins (`r".*"`) | Any website can make API calls to your backend |
| 4 | `/api/scam-stats` defined TWICE | Second definition silently overrides first |
| 5 | ML model files don't exist | FastText model referenced but never created |
| 6 | `docker-compose.yml` has `SESSION_SECRET=dev_only_change_me` | Production will crash OR use weak secret |
| 7 | No password validation | Users can register with 1-character passwords |
| 8 | `.env` with real secrets is in git | Secrets exposed in version control |
| 9 | `blockbord.db` SQLite committed to git | Database file should never be in git |
| 10 | CSP hardcoded to `localhost:8000` | Will block all requests in production |

### HIGH — Needs Fixing

| # | Problem |
|:--|:--------|
| 11 | 2,006-line monolithic `app.py` — unmaintainable |
| 12 | `norm()` function defined 3 times in same file |
| 13 | `import secrets`, `import ast`, etc. imported multiple times inline |
| 14 | Scan reasons stored as `str(list)` and parsed with `ast.literal_eval()` |
| 15 | `scikit-learn` in requirements but never used (dead dependency) |
| 16 | Only 4 tests for 3,000+ lines of code |
| 17 | No structured logging (uses `print()` everywhere) |
| 18 | `datetime.utcnow()` deprecated — should use `datetime.now(timezone.utc)` |
| 19 | No health check endpoint for deployment |
| 20 | Leak checker returns FAKE data (simulated breaches) |

---

## 5. YOUR Task List (Accounts & Setup)

> **IMPORTANT: Complete ALL items below before we start coding.**

### Task 1: Create a Neon Database Account (FREE)

| Step | Action |
|:-----|:-------|
| 1 | Go to **https://neon.tech** |
| 2 | Click "Sign Up" — use your GitHub or Google account |
| 3 | Create a new Project — name it `blockbord` |
| 4 | Select region closest to your users (e.g., `ap-south-1` for India, `us-east-1` for US) |
| 5 | Once created, go to the **Dashboard** → **Connection Details** |
| 6 | Copy the **Connection String** — it looks like: `postgresql://username:password@ep-xxxx.region.aws.neon.tech/neondb?sslmode=require` |
| 7 | **Save this connection string** — I will need it later |

**What you get FREE:**
- 0.5 GB storage
- 100 compute-hours/month
- Automatic backups
- SSL included

---

### Task 2: Create a Render Account (FREE)

| Step | Action |
|:-----|:-------|
| 1 | Go to **https://render.com** |
| 2 | Click "Get Started for Free" — use your GitHub account |
| 3 | Connect your GitHub repository (the `block-bord` repo) |
| 4 | **Do NOT create any services yet** — we will do this together after restructuring |
| 5 | Just ensure your account is active and GitHub is connected |

**What you get FREE:**
- 750 instance-hours/month (enough for 24/7)
- Auto-TLS/SSL certificates
- Custom domain support
- Automatic deployments from GitHub

---

### Task 3: Get a Google Safe Browsing API Key (FREE)

| Step | Action |
|:-----|:-------|
| 1 | Go to **https://console.cloud.google.com** |
| 2 | Sign in with your Google account |
| 3 | Create a new project — name it `BlockBord AI` |
| 4 | Go to **APIs & Services** → **Library** |
| 5 | Search for **"Safe Browsing API"** |
| 6 | Click on **"Web Risk API"** or **"Safe Browsing API (v4)"** |
| 7 | Click **"Enable"** |
| 8 | Go to **APIs & Services** → **Credentials** |
| 9 | Click **"+ CREATE CREDENTIALS"** → **"API Key"** |
| 10 | Copy the API key and **save it** — I will need it later |
| 11 | (Optional but recommended) Click "Edit API Key" → Restrict to "Safe Browsing API" only |

**What you get FREE:**
- 10,000 requests/day (more than enough)
- Real-time phishing/malware database
- No credit card required

---

### Task 4: Download the PhiUSIIL Training Dataset (FREE)

| Step | Action |
|:-----|:-------|
| 1 | Go to **https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset** |
| 2 | Click **"Download"** to get the CSV file |
| 3 | The file contains ~235,000 URLs with 54 pre-extracted features |
| 4 | Save the downloaded file to your project folder: `block-bord/ml_data/` (create this folder) |
| 5 | The file should be named something like `PhiUSIIL_Phishing_URL_Dataset.csv` |

**Why we need this:**
- This is the training data for our XGBoost model
- It has both phishing URLs and legitimate URLs already labeled
- 54 features are pre-extracted (URL length, entropy, domain age, etc.)
- Research shows 97%+ accuracy with XGBoost on this dataset

---

### Task 5: Ensure Your GitHub Repository is Ready

| Step | Action |
|:-----|:-------|
| 1 | Make sure `block-bord` is pushed to a GitHub repository |
| 2 | If not already on GitHub, create a new repo and push: |
|   | `git remote add origin https://github.com/YOUR_USERNAME/block-bord.git` |
|   | `git push -u origin main` |
| 3 | Ensure your Render account is connected to this GitHub account |

---

### Task 6: (OPTIONAL) Razorpay API Keys — If You Want Payments

> Skip this if you don't need the payment system right now.

| Step | Action |
|:-----|:-------|
| 1 | Go to **https://dashboard.razorpay.com** |
| 2 | Sign up or log in |
| 3 | Go to **Settings** → **API Keys** |
| 4 | Generate a new API Key (Test Mode is fine for now) |
| 5 | Save the **Key ID** and **Key Secret** |
| 6 | Go to **Settings** → **Webhooks** |
| 7 | Create a webhook pointing to `https://YOUR-RENDER-URL/webhooks/razorpay` |
| 8 | Save the **Webhook Secret** |

---

### Task 7: (OPTIONAL) Gemini API Key — If You Want AI Chatbot

> Skip this if you're fine with the rule-based chatbot fallback.

| Step | Action |
|:-----|:-------|
| 1 | Go to **https://aistudio.google.com/app/apikey** |
| 2 | Click "Create API Key" |
| 3 | Select the Google Cloud project you created in Task 3 |
| 4 | Copy and save the API key |

---

### Task 8: (OPTIONAL) HIBP API Key — If You Want Real Leak Checker

> Skip this if the simulated leak checker is acceptable for now.

| Step | Action |
|:-----|:-------|
| 1 | Go to **https://haveibeenpwned.com/API/Key** |
| 2 | Purchase an API key ($3.50/month) |
| 3 | Save the API key |

---

## 6. API Keys Summary — What I Need From You

After completing the tasks above, you should have these values ready. I will use them to configure the application:

```
# ═══════════════════════════════════════════════════
# REQUIRED (Must have before we start)
# ═══════════════════════════════════════════════════

NEON_DATABASE_URL=postgresql://username:password@ep-xxxx.region.aws.neon.tech/neondb?sslmode=require
GOOGLE_SAFE_BROWSING_API_KEY=AIzaSy...your-key-here
PHIUSIIL_DATASET_PATH=./ml_data/PhiUSIIL_Phishing_URL_Dataset.csv

# ═══════════════════════════════════════════════════
# OPTIONAL (Can add later)
# ═══════════════════════════════════════════════════

RAZORPAY_KEY_ID=rzp_test_xxx          (skip if no payments needed now)
RAZORPAY_KEY_SECRET=xxx               (skip if no payments needed now)
RAZORPAY_WEBHOOK_SECRET=xxx           (skip if no payments needed now)
GEMINI_API_KEY=xxx                    (skip if rule-based chatbot is fine)
HIBP_API_KEY=xxx                      (skip if simulated leak checker is fine)
```

---

## 7. Tools Required on Your Machine

Make sure these are installed on your development machine:

### Must Have

| Tool | How to Check | How to Install |
|:-----|:-------------|:---------------|
| **Python 3.9+** | `python --version` | https://python.org/downloads |
| **pip** | `pip --version` | Comes with Python |
| **Git** | `git --version` | https://git-scm.com/downloads |
| **Google Chrome** | Open Chrome | https://google.com/chrome |
| **VS Code** (or any editor) | Open it | https://code.visualstudio.com |

### Nice to Have

| Tool | Purpose | Install |
|:-----|:--------|:--------|
| **Docker Desktop** | Local testing with containers | https://docker.com/products/docker-desktop |
| **PostgreSQL client (psql)** | Direct database access | `pip install pgcli` or install PostgreSQL |
| **Postman** | API testing | https://postman.com/downloads |

---

## 8. Verification Checklist

Before you tell me "I'm ready to start," verify:

- [ ] **Neon account created** and connection string copied
- [ ] **Render account created** and GitHub connected
- [ ] **Google Safe Browsing API** key generated
- [ ] **PhiUSIIL dataset** downloaded and saved to `block-bord/ml_data/`
- [ ] **GitHub repository** is set up with block-bord code
- [ ] **Python 3.9+** is installed on your machine
- [ ] **Git** is installed and configured
- [ ] **Google Chrome** is installed (for extension testing)
- [ ] All API keys are saved somewhere safe (NOT in a git-tracked file)

### Optional Items (If Applicable)
- [ ] Razorpay API keys (if payments needed)
- [ ] Gemini API key (if AI chatbot needed)
- [ ] HIBP API key (if real leak checker needed)
- [ ] Docker Desktop (if container testing needed)

---

## What Happens After You Complete This

Once you have everything above ready, I will:

1. **Phase 1** — Restructure the entire codebase (split app.py, clean architecture)
2. **Phase 2** — Train XGBoost ML model on PhiUSIIL dataset (95%+ accuracy)
3. **Phase 3** — Integrate Google Safe Browsing API
4. **Phase 4** — Fix all security vulnerabilities
5. **Phase 5** — Upgrade Chrome extension
6. **Phase 6** — Redesign admin panel
7. **Phase 7** — Deploy to Render + Neon
8. **Phase 8** — Test everything end-to-end

**Estimated time:** This is a significant transformation. Each phase builds on the previous one.

---

*Document generated for the Block Bord AI Production Transformation Project*
*If you have questions about any step, ask before proceeding.*
