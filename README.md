# 🛡️ Block Bord AI

**Block Bord AI** is a premium SaaS cybersecurity platform that protects users from phishing URLs, malicious websites, scam domains, and online threats — powered by ML and AI.

---

## ✨ Features

- 🔍 **Real-time URL / Domain Scanner** — ML + Google Safe Browsing + VirusTotal
- 🤖 **AI Assistant** — Gemini-powered scam detection chatbot
- 🌐 **Domain & IP Lookup** — WHOIS, DNS, geolocation, abuse scores
- 🔐 **Password Strength Checker** — entropy & breach detection
- 🔒 **SSL Certificate Inspector** — expiry, issuer, chain validation
- 📊 **User Dashboard** — scan history, analytics, API key management
- 💳 **Subscription Payments** — Razorpay integration (Free / Pro / Enterprise)
- 🧩 **Chrome Extension** — real-time browser protection
- 👮 **Admin Console** — user management, blacklist/whitelist control

---

## 🏗️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | PHP 8.3+ + Laravel 13 (see `composer.json`) |
| **Database** | MySQL (via XAMPP) |
| **ML Microservice** | Python 3 + FastAPI + XGBoost |
| **AI** | Google Gemini API |
| **Payments** | Razorpay |
| **Email** | SMTP / Mailgun |
| **Chrome Extension** | Manifest V3 (Vanilla JS) |

---

## 🚀 Local Development Setup

### Prerequisites
- **PHP 8.3+** with the Laravel-required extensions, and **MySQL 8**
- **Composer** (`composer install`)
- **Python 3.10+** (`pip install -r requirements.txt`)
- **ClamAV daemon** and **zbarimg** for file and QR scanning outside Docker

### 1. Clone & Install

```bash
git clone https://github.com/kvdayananda/block-bord.git
cd block-bord
composer install
cp .env.example .env
php artisan key:generate
```

### 2. Configure `.env`

Edit `.env`, generate a fresh `APP_KEY` using `php artisan key:generate`, and set:
```
DB_DATABASE=blockbord
DB_USERNAME=root
DB_PASSWORD=your_password

GEMINI_API_KEY=your_key
RAZORPAY_KEY_ID=your_key
RAZORPAY_KEY_SECRET=your_secret
RAZORPAY_WEBHOOK_SECRET=your_webhook_secret
GOOGLE_SAFE_BROWSING_API_KEY=your_key
ML_API_URL=http://127.0.0.1:8001
ML_API_SECRET=generate_a_long_random_secret
CLAMAV_HOST=127.0.0.1
CLAMAV_PORT=3310
```

### 3. Database Setup

```bash
php artisan migrate
php artisan db:seed
```

### 4. Train the ML Model (Optional)

The trained model and PhiUSIIL dataset are not included in this repository. Obtain the dataset from the UCI repository referenced in `backend/ml/train_model.py`, place it at `ml_data/PhiUSIIL_Phishing_URL_Dataset.csv`, then run:
```bash
python backend/ml/train_model.py
```
Without a model artifact, the ML service reports that it is unavailable and Laravel uses its clearly-marked heuristic fallback.

### 5. Start Servers

```bash
# Laravel (Terminal 1)
php artisan serve

# ML Microservice (Terminal 2)
$env:ML_API_SECRET="same-long-random-secret-as-Laravel"
python -m uvicorn backend.ml.main:app --host 127.0.0.1 --port 8001
```

Open **http://127.0.0.1:8000** in your browser.

---

## 📁 Project Structure

```
block-bord/
├── app/                    # Laravel controllers, models, middleware
│   ├── Http/Controllers/   # All page & API controllers
│   ├── Models/             # Eloquent models
│   └── Http/Middleware/    # Auth, Security headers, Rate limiting
├── backend/
│   └── ml/                 # Python ML microservice (FastAPI + XGBoost)
│       ├── main.py         # FastAPI app
│       ├── train_model.py  # Model training script
│       └── feature_extractor.py
├── config/                 # Laravel configuration files
├── database/               # Migrations & seeders
├── extension/              # Chrome Extension (Manifest V3)
├── public/                 # Public assets (CSS, JS, images)
├── resources/views/        # Blade templates
├── routes/web.php          # All application routes
└── ml_data/                # Feedback data for model retraining
```

---

## Seeded accounts

No default passwords are embedded. `php artisan db:seed` creates an admin and demo account only when `SEED_ADMIN_PASSWORD` and/or `SEED_DEMO_PASSWORD` are provided, and never seeds accounts in production. Keep these values out of source control.

---

## 📦 Deployment

See [DEPLOYMENT.md](DEPLOYMENT.md) for production deployment instructions (Render, Railway, VPS).

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
