# Block Bord AI Deployment Guide

This guide provides steps to deploy Block Bord AI to a production environment.

## 🚀 One-Click Deploy (Recommended)

The easiest way to deploy is using **Render** or **Railway**:
1. Connect this GitHub repository.
2. Add the environment variables (see below).
3. The `Procfile` will automatically handle the startup commands.

## 🛠️ Environment Variables

Ensure the following variables are set in your production environment:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `ENV` | Set to `production` | `development` |
| `SESSION_SECRET` | A long, random string for security | `dev_only_change_me` |
| `RAZORPAY_KEY_ID` | Your Razorpay API Key ID | Required for payments |
| `RAZORPAY_KEY_SECRET` | Your Razorpay API Key Secret | Required for payments |
| `RAZORPAY_WEBHOOK_SECRET`| Your Razorpay Webhook Secret | Required for automated upgrades |

## 📦 Docker Deployment

If you want to host it yourself using Docker:

```bash
# 1. Clone the repo
git clone <your-repo-url>
cd blockbord

# 2. Start using Docker Compose
docker-compose up -d
```

## 🧠 Database & ML Initialization

After the first deployment, run these commands inside the server (or shell) to ensure your AI is updated:

```bash
# Download latest threat data and train the AI model
python update_datasets.py

# (Optional) Verify detection
python test_scan.py
```

## 🔒 Security Best Practices
- Use a production-grade database like **PostgreSQL** for high traffic.
- Ensure `https_only` is active (handled automatically when `ENV=production`).
- Regularly update the AI model by running `update_datasets.py` via a weekly Cron Job.
