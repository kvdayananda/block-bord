# Running Block Bord AI locally

The PHP application uses Laravel 13 and requires PHP 8.3 or newer. The optional ML service is FastAPI. The repository does not contain a trained ML model or its PhiUSIIL training dataset.

## Docker Compose (recommended)

Prerequisites: Docker Compose v2 and Composer.

1. Copy `.env.example` to `.env`.
2. Install PHP dependencies and generate an application key:

   ```powershell
   composer install
   php artisan key:generate
   ```

3. In `.env`, set a non-empty `DB_PASSWORD` and a long random `ML_API_SECRET`. Keep `.env` private; use the same ML secret for the Laravel app and Python service.
4. Build and start the services, then migrate the database:

   ```powershell
   docker compose up --build -d
   docker compose exec app php artisan migrate --force
   ```

The app is available at `http://127.0.0.1:8000` by default (`APP_PORT` changes the host port), MySQL at port `3307` (`DB_HOST_PORT` changes it), and Redis at port `6379` (`REDIS_HOST_PORT` changes it). The internal ML and ClamAV services are not published to the host. ClamAV may need time to download its initial signature database; scans return an explicit unavailable response until it is ready.

To enable XGBoost inference, install the Python dependencies locally, download the UCI PhiUSIIL dataset, place it at `ml_data/PhiUSIIL_Phishing_URL_Dataset.csv`, and run:

```powershell
pip install -r requirements.txt
python backend/ml/train_model.py
```

The trained artifact is stored in the ignored `backend/ml/models` directory and mounted into the ML container. If no artifact exists, its health endpoint reports `ml_available: false` and prediction requests return `503`; Laravel identifies its heuristic fallback in the scan evidence.

## Run services without Docker

Prerequisites: PHP 8.3+, Composer, MySQL 8, Python 3.10+, a reachable ClamAV daemon, and `zbarimg` for QR decoding.

1. Copy `.env.example` to `.env`, run `composer install`, and generate `APP_KEY` with `php artisan key:generate`.
2. Configure database credentials and set the same strong `ML_API_SECRET` for both services. Configure `CLAMAV_HOST` and `CLAMAV_PORT` to reach ClamAV.
3. Run migrations:

   ```powershell
   php artisan migrate
   ```

4. Start the ML service in one PowerShell window:

   ```powershell
   $env:ML_API_SECRET = "same-long-random-secret-as-Laravel"
   python -m uvicorn backend.ml.main:app --host 127.0.0.1 --port 8001
   ```

5. Start Laravel in another window:

   ```powershell
   php artisan serve --host 127.0.0.1 --port 8000
   ```

The ML service can start without a model, but predictions remain unavailable until a trained model artifact is installed. File scans require an available ClamAV daemon; QR scans require `zbarimg`.

## Chrome extension

1. Open `chrome://extensions/` and enable Developer mode.
2. Select **Load unpacked** and choose the repository's `extension` folder.
3. Review Chrome's site-access prompt. The extension requests broad site access because its current behavior automatically scans pages across websites.

## Health checks

```powershell
curl http://127.0.0.1:8000/api/health
curl http://127.0.0.1:8001/health
```

Laravel should return `{"status":"healthy"}`. The ML health response also states whether a trained model was loaded.
