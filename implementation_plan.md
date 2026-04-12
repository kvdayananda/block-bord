# Block Bord AI — 100X Production Transformation Plan

## Goal

Transform the current broken, monolithic Block Bord AI into an **advanced, production-ready cybersecurity platform** with:
- **95%+ phishing detection accuracy** using XGBoost + open-source datasets
- **Clean modular architecture** deployed across free cloud services
- **Advanced Chrome extension** with real-time protection
- **Professional admin panel** with full platform visibility

---

## My Recommendations (Answers to Your Questions)

### 🗄️ Database: **Neon PostgreSQL** (Recommended)

| Option | Free Tier | Verdict |
|---|---|---|
| **Neon** | 0.5 GB storage, 100 compute-hours/mo, serverless PostgreSQL | ✅ **Best choice** — pure PostgreSQL, auto-scales to zero, branching for dev/prod |
| Supabase | 500 MB, pauses after 1 week idle | ❌ Pausing will break the extension's real-time scanning |
| MongoDB Atlas | 512 MB, always-on | ❌ Would require rewriting all SQLAlchemy models — wastes time |
| Firebase | NoSQL Firestore | ❌ Same problem — completely different paradigm |

> [!IMPORTANT]
> **Neon PostgreSQL is the clear winner.** Your existing code already uses SQLAlchemy + PostgreSQL support. We only need to change the connection string — **zero model rewrites**. It's serverless, so it costs nothing when idle, and the 0.5 GB free storage is plenty for a cybersecurity platform.

### 🚀 Hosting Architecture

| Component | Platform | Free Tier | Why |
|---|---|---|---|
| **Backend API** | **Render** (not Railway) | 750 hrs/mo, auto-TLS, Git deploy | Railway has NO free tier (only $5 trial credit that expires). Render gives truly free hosting with 750hrs/month. |
| **Frontend** | **Vercel** | 100 GB bandwidth, 1M requests/mo | Perfect for static HTML/Jinja2 templates or a future React/Next.js frontend |
| **Database** | **Neon** | 0.5 GB PostgreSQL | Serverless, zero-cost when idle |
| **ML Model** | Bundled with backend on Render | Included | XGBoost model (~2-5MB) ships with the backend |

> [!WARNING]
> **Railway does NOT have a free tier.** It only has a $5 trial credit. Once exhausted, your app dies. **Render** gives 750 free hours/month permanently (enough to run one service 24/7). I strongly recommend Render instead.

> [!NOTE]
> **Alternative**: We can also deploy the FastAPI backend directly on Vercel as a serverless function. This eliminates the Render cold-start problem but has a 500MB bundle size limit. Since XGBoost + our dependencies are lightweight, this is feasible. We can discuss this option.

### 🤖 ML Model: **XGBoost + PhiUSIIL Dataset** (97%+ accuracy)

Current state: FastText model that doesn't exist on disk + only basic heuristics.

**New approach — 3-layer detection engine:**

| Layer | Technology | Accuracy | Cost |
|---|---|---|---|
| **Layer 1: Google Safe Browsing API** | Real-time URL check against Google's database | ~99% for known threats | **Free** (non-commercial) |
| **Layer 2: XGBoost ML Model** | Trained on PhiUSIIL dataset (235K URLs, 54 features) | **97%+ accuracy** | **Free** (open-source) |
| **Layer 3: Heuristic Engine** | Existing 80+ rule engine (improved) | Catches zero-day patterns | **Free** |

**Training data sources (all free & open-source):**
- [PhiUSIIL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) — 235,000 labeled URLs with 54 pre-extracted features
- [PhishTank](https://phishtank.org/) — Community-verified phishing URLs (free API)
- [Kaggle Phishing Datasets](https://www.kaggle.com/search?q=phishing+url+dataset) — Multiple datasets with feature extraction

**Feature extraction (54 features per URL):**
```
Lexical: URL length, dot count, hyphen count, digit ratio, entropy, special chars
Domain: TLD type, subdomain count, domain age, WHOIS privacy, punycode
SSL: Certificate validity, issuer, expiry, domain match
Content: Login form presence, password fields, iframe count, redirect chain
Behavioral: JS obfuscation score, clipboard access, keystroke capture
```

---

## Project Restructure

### Current Structure (Messy)
```
block-bord/
├── app.py              ← 2,006 lines — EVERYTHING in one file
├── risk_engine.py      ← 994 lines  
├── database.py         ← Mixed migrations + models
├── ml_spam.py          ← Dead FastText model
├── ml_ensemble.py      ← 11-line pass-through
├── security.py         ← Hardcoded CSP
├── make_admin.py       
├── update_datasets.py  ← Doesn't actually update anything
├── blockbord.db        ← SQLite DB committed to git (BAD)
├── __pycache__/        ← Should not be in git
├── extension/          ← Chrome extension
├── static/             ← CSS + JS + images
├── templates/          ← 26 Jinja2 HTML templates
└── tests/              ← Only 4 tests
```

### New Structure (Clean, Modular, Production-Ready)
```
block-bord/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                  ← FastAPI app creation + middleware
│   │   ├── config.py                ← Environment config (Pydantic Settings)
│   │   ├── dependencies.py          ← DB session, auth, CSRF dependencies
│   │   │
│   │   ├── routers/                 ← Modular API routes
│   │   │   ├── __init__.py
│   │   │   ├── auth.py              ← Login, Register, Logout, Password Reset
│   │   │   ├── scan.py              ← POST /scan, GET /scan/{id}
│   │   │   ├── dashboard.py         ← Dashboard, History, Analytics
│   │   │   ├── admin.py             ← Admin panel, User management, Blacklist
│   │   │   ├── payments.py          ← Razorpay checkout, webhooks
│   │   │   ├── tools.py             ← Leak checker, AI chatbot, Scam map
│   │   │   └── public.py            ← Landing, About, Status, Contact, Legal
│   │   │
│   │   ├── models/                  ← SQLAlchemy ORM models
│   │   │   ├── __init__.py
│   │   │   ├── user.py
│   │   │   ├── scan.py
│   │   │   ├── payment.py
│   │   │   ├── feedback.py
│   │   │   ├── domain_lists.py      ← Blacklist + Whitelist
│   │   │   └── report.py
│   │   │
│   │   ├── services/                ← Business logic
│   │   │   ├── __init__.py
│   │   │   ├── risk_engine.py       ← Heuristic rule engine (cleaned up)
│   │   │   ├── ml_engine.py         ← XGBoost model loader + prediction
│   │   │   ├── feature_extractor.py ← URL feature extraction (54 features)
│   │   │   ├── safe_browsing.py     ← Google Safe Browsing API integration
│   │   │   ├── email_service.py     ← SMTP email alerts
│   │   │   └── plan_service.py      ← Plan/subscription logic
│   │   │
│   │   ├── middleware/
│   │   │   ├── __init__.py
│   │   │   ├── security.py          ← Security headers (dynamic CSP)
│   │   │   └── csrf.py              ← CSRF middleware
│   │   │
│   │   └── database/
│   │       ├── __init__.py
│   │       ├── connection.py        ← Engine + SessionLocal
│   │       └── migrations/          ← Alembic migrations
│   │
│   ├── ml/
│   │   ├── train_model.py           ← XGBoost training script
│   │   ├── evaluate_model.py        ← Accuracy/F1/AUC evaluation
│   │   ├── feature_engineering.py   ← Feature extraction pipeline
│   │   ├── data/                    ← Training datasets (gitignored)
│   │   │   └── .gitkeep
│   │   └── models/                  ← Trained model files
│   │       └── xgboost_phishing_v1.joblib
│   │
│   ├── tests/
│   │   ├── conftest.py              ← Test fixtures
│   │   ├── test_auth.py
│   │   ├── test_scan.py
│   │   ├── test_risk_engine.py
│   │   ├── test_ml_engine.py
│   │   ├── test_admin.py
│   │   └── test_feature_extractor.py
│   │
│   ├── alembic.ini
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── Procfile
│   ├── render.yaml                  ← Render deployment config
│   └── .env.example
│
├── frontend/                        ← Vercel deployment
│   ├── templates/                   ← Jinja2 HTML (or future Next.js)
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css
│   │   ├── js/
│   │   │   └── app.js
│   │   └── images/
│   └── vercel.json
│
├── extension/                       ← Chrome Extension (Manifest V3)
│   ├── manifest.json
│   ├── background.js                ← Service worker
│   ├── content.js                   ← Content script (DOM analysis)
│   ├── popup/
│   │   ├── popup.html
│   │   ├── popup.js
│   │   └── popup.css
│   ├── warning/
│   │   ├── warning.html             ← Full-page warning overlay
│   │   └── warning.css
│   ├── options/
│   │   ├── options.html             ← Extension settings
│   │   └── options.js
│   └── icons/
│
├── scripts/
│   ├── make_admin.py
│   ├── migrate_sqlite_to_neon.py    ← One-time migration script
│   └── seed_data.py                 ← Seed test data
│
├── .gitignore                       ← Properly configured
├── .env.example
├── README.md
├── LICENSE
└── docker-compose.yml               ← Local development
```

### Files to DELETE
| File | Reason |
|---|---|
| `blockbord.db` | SQLite DB — moving to Neon PostgreSQL |
| `__pycache__/` | Python cache — should be gitignored |
| `ml_spam.py` | Replaced by XGBoost `ml_engine.py` |
| `ml_ensemble.py` | 11-line pass-through — eliminated |
| `update_datasets.py` | Doesn't do anything — replaced with `train_model.py` |
| `.env` | Contains secrets — keep only `.env.example` |

---

## Proposed Changes (Phase-by-Phase)

### Phase 1: Foundation & Database Migration
**Goal: Clean architecture + Neon PostgreSQL**

#### Backend Restructure
- Split `app.py` (2,006 lines) into 7 routers + services + models
- Create proper `config.py` with Pydantic `BaseSettings` for type-safe env vars
- Set up Alembic for database migrations
- Remove dead code and duplicate imports

#### Database Migration (SQLite → Neon)
- Create Neon PostgreSQL account (free tier: 0.5 GB)
- Write `migrate_sqlite_to_neon.py` to transfer existing data
- Update `DATABASE_URL` to point to Neon
- Test all queries work with PostgreSQL

#### Security Fixes (Critical)
- **Remove `/upgrade` endpoint** (free Pro hack)
- **Remove `/downgrade` GET endpoint** (CSRF vulnerability)
- **Fix `hmac.new()` crash** → `hmac.HMAC()`
- **Fix duplicate `/api/scam-stats` route**
- **Add password validation** (min 8 chars, complexity)
- **Fix CORS** — restrict to actual frontend domain
- **Dynamic CSP** — remove hardcoded localhost

---

### Phase 2: ML Engine (95%+ Accuracy)
**Goal: Train XGBoost model on PhiUSIIL dataset**

#### [NEW] `ml/train_model.py`
- Download PhiUSIIL dataset (235,000 URLs, 54 features)
- Feature engineering pipeline (extracting 54 features from raw URLs)
- Train XGBoost classifier with hyperparameter tuning
- Evaluate with precision, recall, F1-score, AUC-ROC
- Export model as `.joblib` file (~2-5MB)

#### [NEW] `app/services/ml_engine.py`
- Load trained XGBoost model at startup
- `predict_phishing_probability(url) → float` (0.0 to 1.0)
- Feature extraction from URL at runtime

#### [NEW] `app/services/safe_browsing.py`
- Integrate Google Safe Browsing API (free, non-commercial)
- Check URL against Google's phishing/malware database
- Cache results to reduce API calls

#### [MODIFY] `app/services/risk_engine.py`
- 3-layer scoring:
  1. Google Safe Browsing → if flagged, instant High Risk
  2. XGBoost prediction → ML confidence score
  3. Heuristic rules → rule-based scoring
- Weighted blend: `final_score = 0.15 * safe_browsing + 0.45 * xgboost + 0.40 * heuristics`
- Target: **95-97% accuracy** on test set

---

### Phase 3: Advanced Chrome Extension
**Goal: Smarter, more responsive extension**

#### Enhanced Detection
- **DOM deep analysis** — detect hidden iframes, fake login forms, clipboard hijacking
- **Real-time telemetry** — send JS obfuscation score, keystroke capture detection
- **Visual similarity detection** — screenshot comparison against known brand login pages
- **QR code scanning** — detect and analyze QR codes on pages

#### UX Improvements
- **Full-page warning overlay** — instead of just a popup badge, block the page with a scary warning
- **Extension options page** — let users configure sensitivity, whitelist domains
- **Scan history in popup** — show last 10 scans directly in the extension
- **Right-click context menu** — "Scan this link with Block Bord AI"

#### Production Configuration
- **Dynamic API URL** — configurable backend URL (not hardcoded to localhost)
- **Extension authentication** — proper login flow within the extension

---

### Phase 4: Admin Panel Overhaul
**Goal: Professional admin dashboard with full platform visibility**

#### Admin Dashboard
- **Real-time platform stats** — total users, scans today, active threats, revenue
- **User management table** — search, filter, sort, paginate
- **Threat intelligence feed** — live stream of high-risk detections
- **Domain management** — blacklist/whitelist CRUD with bulk import
- **Report queue** — review user-submitted reports with one-click actions
- **ML model dashboard** — show model accuracy, last retrain date, feature importance chart

#### Admin Features
- **Bulk user actions** — select multiple users for plan changes, suspend, etc.
- **Audit log** — track all admin actions
- **Export reports** — CSV/PDF export of platform data
- **Notification center** — alerts for high-risk detections, new user signups

---

### Phase 5: Deployment & Production Hardening
**Goal: Deploy to Render + Vercel + Neon**

#### Render (Backend)
- `render.yaml` for one-click deploy
- Environment variables configured
- Auto-deploy from GitHub
- Health check endpoint at `/health`

#### Vercel (Frontend) — Optional for Phase 1
- Currently the app uses Jinja2 server-side rendering
- **Option A**: Keep serving templates from Render (simplest)
- **Option B**: Later migrate to Next.js on Vercel for a faster, more modern frontend

#### Production Hardening
- **Structured logging** — Python `logging` module with JSON format
- **Error monitoring** — Sentry free tier integration
- **Rate limiting** — per-user, per-IP limits
- **HTTPS enforcement** — redirect all HTTP to HTTPS
- **Proper `.gitignore`** — exclude `.env`, `__pycache__`, `*.db`, `models/*.joblib`

---

## Cost Breakdown

| Service | Monthly Cost | What You Get |
|---|---|---|
| **Neon PostgreSQL** | **$0** | 0.5 GB storage, 100 compute-hours |
| **Render** | **$0** | 750 free instance hours, auto-TLS |
| **Google Safe Browsing API** | **$0** | Free for non-commercial use |
| **PhiUSIIL Dataset** | **$0** | Open-source, free download |
| **XGBoost** | **$0** | Open-source ML library |
| **GitHub** | **$0** | Source code hosting |
| **Total** | **$0/month** | Full production deployment |

> [!CAUTION]
> **Render free tier has cold starts** — the first request after 15 minutes of inactivity will take ~30 seconds. This is acceptable for a cybersecurity dashboard, but the Chrome extension should handle this gracefully (show "Connecting..." state). If this becomes a problem, upgrading to the $7/mo Render starter tier eliminates cold starts permanently.

---

## Detection Accuracy Roadmap

| Phase | Approach | Expected Accuracy |
|---|---|---|
| **Current** | Basic keyword regex + dead FastText model | ~40-50% (estimated) |
| **Phase 2A** | XGBoost on PhiUSIIL (54 features) | **95-97%** |
| **Phase 2B** | + Google Safe Browsing API | **97-99%** (known threats) |
| **Phase 2C** | + Heuristic engine v2 (improved rules) | **97%+** (including zero-day) |
| **Future** | + DistilBERT for raw URL sequence analysis | **98%+** |

---

## Open Questions

> [!IMPORTANT]
> 1. **Render vs Railway**: Railway has NO free tier (only $5 trial). I recommend Render instead — is that acceptable to you?
> 2. **Frontend approach**: Should we keep Jinja2 templates served from the backend (simpler), or migrate to a React/Next.js frontend on Vercel (more modern but more work)?
> 3. **Vercel for backend too?** We could deploy the FastAPI backend as Vercel Serverless Functions (eliminating Render entirely). The tradeoff is a 500MB bundle limit and no persistent file storage. Is this worth exploring?
> 4. **Chrome Web Store**: Do you plan to publish the extension to the Chrome Web Store? This requires signing up as a developer ($5 one-time fee).
> 5. **Existing data**: Should we migrate the existing SQLite data to Neon, or start fresh?
> 6. **Admin panel redesign**: Do you want a completely new admin UI design, or just reorganize the existing one with better features?

## Verification Plan

### Automated Tests
- Unit tests for all routers (auth, scan, admin, payments)
- ML model evaluation: precision, recall, F1, AUC-ROC on test split
- Integration tests for the full scan pipeline
- Extension E2E test with test phishing pages

### Manual Verification
- Deploy to Render + Neon and verify all endpoints
- Install Chrome extension and test against known phishing sites
- Verify admin panel functionality
- Load test with 100 concurrent scan requests
