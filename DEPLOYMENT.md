# Production deployment

## Supported layout

The application is Laravel 13 (`composer.json`) and requires PHP 8.3 or newer; the supplied PHP image uses PHP 8.3, Nginx, and PHP-FPM. Docker Compose runs the Laravel app, MySQL, Redis, FastAPI ML service, and ClamAV. The Render blueprint defines a Docker web service and private ML/ClamAV services; Render deployments still require an externally managed MySQL database.

Session serialization remains set to PHP for compatibility with existing sessions. Set `SESSION_SERIALIZATION=json` only when you are prepared to invalidate active sessions and have verified the application stores no PHP objects in sessions.

Before deploying, review the exact framework and PHP versions in `composer.json` and `Dockerfile`. Do not deploy using development `.env` values.

## Docker Compose

1. Create a private deployment `.env` file based on `.env.example`.
2. Generate `APP_KEY` with `php artisan key:generate`. Set strong unique values for `DB_PASSWORD` and `ML_API_SECRET`. Configure the payment and AI provider credentials only if those features are enabled.
3. Build and start the stack:

   ```sh
   docker compose up --build -d
   docker compose exec app php artisan migrate --force
   ```

4. Configure HTTPS at the public load balancer/reverse proxy. Set `APP_URL` to the public HTTPS URL, keep `APP_DEBUG=false`, and configure trusted hosts/proxies for the deployment.
5. Confirm `/api/health`, inspect the ML `/health` response from the private network, and verify ClamAV has completed its signature update before enabling file scanning.

The ML service requires a trained artifact at `backend/ml/models/xgboost_phishing_v1.joblib`. The model and its training dataset are intentionally not committed. Until you provision the artifact, the service reports that predictions are unavailable and the Laravel code marks its heuristic fallback. Do not present fallback output as an active trained model.

## Render blueprint

The included `render.yaml` deploys the Laravel Docker app plus private FastAPI and ClamAV services. Before creating the deployment:

- Configure all `sync: false` values in the Render dashboard.
- Point `DB_HOST`, `DB_DATABASE`, `DB_USERNAME`, and `DB_PASSWORD` at a reachable MySQL 8 provider; Render does not provision MySQL in this blueprint.
- Set `APP_KEY`, `APP_URL`, and `ML_API_SECRET`. Use the identical `ML_API_SECRET` value on both the Laravel web service and ML service.
- Add actual Razorpay, Safe Browsing, and AI provider keys only in the Render dashboard. Rotate any real credentials that have ever been committed to Git.
- Provision the trained model artifact into the ML service and verify `ml_available: true`; otherwise its prediction endpoint correctly returns `503`.
- Check that the private service DNS names and port assignments resolve in the deployed environment.

## Operations and security

- Never commit `.env`, private keys, provider credentials, or trained model artifacts.
- Configure Razorpay's webhook URL and a dedicated webhook secret. Events are rejected if the webhook secret is missing or the signature is invalid.
- Keep ClamAV and ML ports private; only the Laravel app should connect to them.
- Keep backups for MySQL and monitor application logs, provider failures, queue health, disk usage, and antivirus signature updates.
- The extension uses broad website access to preserve its all-site automatic scanning behavior. Tell users why access is required and offer a manual-only mode before reducing those permissions.
- Seeded accounts are disabled in production. In local/test environments, provide `SEED_ADMIN_PASSWORD` or `SEED_DEMO_PASSWORD` explicitly if you need those accounts.

See `RUNNING_LOCALLY.md` for local setup and model training instructions.
