# Block Bord AI

## 🛡️ Welcome to Block Bord AI
Block Bord AI is a premium SaaS-style cybersecurity platform and browser extension designed to protect users from phishing, scams, and malicious websites in real-time. It leverages advanced heuristic risk engines and machine learning to analyze text, URLs, domains, and web behavior, alerting users before they fall victim to cyber threats.

## ✨ Core Features
- **Real-Time Threat Detection**: The Chrome extension automatically scans websites in the background using an NLP-powered engine and structural domain analysis.
- **Multi-Layered Risk Engine**: Combines over 80+ security heuristics (SSL, WHOIS domain age, Fast-Flux DNS, Brand Impersonation) with a FastText machine learning model (`ml_spam.py`).
- **Premium User Dashboard**: A modern, glassmorphism-inspired UI with tracking functionality for users to view scan histories, detection insights, and account status.
- **Monetization Built-In**: Integrated Razorpay checkout flow, premium subscription tiers, and API access management.
- **Robust Admin Portal**: Full visibility for platform owners into user metrics, system logs, and threat intelligence.

## 🏗️ Technology Stack
- **Backend**: Python 3.9+ with FastAPI (Uvicorn ASGI server).
- **Frontend**: HTML5, Vanilla CSS (Premium SaaS UI), Jinja2 Templates.
- **Database**: SQLite (using SQLAlchemy ORM) with production-ready PostgreSQL support enabled via `database.py`.
- **Browser Extension**: Manifest V3 Google Chrome Extension (JavaScript, HTML, CSS).
- **Machine Learning**: `fasttext` for spam probability and NLP categorization.
- **Payment Gateway**: Razorpay API integration.

## 🚀 Getting Started

If you are a developer looking to deploy or run the site locally, please refer to our dedicated setup documentation:

1. [**Local Development Guide**](./RUNNING_LOCALLY.md) - Step-by-step instructions to run the FastAPI backend on your machine and load the unpacked browser extension into Google Chrome.
2. [**Deployment Guide**](./DEPLOYMENT.md) - Instructions to push the application to production environments using Docker or PaaS providers like Render and Railway.

## 🔒 Security & Privacy
The platform was built with strict privacy controls. Our extension only communicates with the backend to perform necessary risk assessments and adheres to modern CSP (Content Security Policy) standards. Sensitive environment variables, such as API keys and Session Secrets, are strictly managed via `.env`.

---
*Built with ❤️ to keep the internet safe.*
