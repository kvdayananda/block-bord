# Running Block Bord AI (PHP 8.3 / Laravel 12 + MySQL 8)

Follow these steps to run the migrated **Block Bord AI** platform on your local machine.

---

## Option A: Running with Docker (Recommended)

Docker automatically sets up the PHP 8.3 application, Nginx web server, MySQL 8 database, Redis cache, and Python XGBoost ML microservice.

### 1. Start Docker Containers
In your terminal, navigate to the project root and run:

```bash
docker-compose up --build
```

### 2. Verify Services
Once started, the following services will be active:
- **Laravel Web App & API**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **API Health Check**: [http://127.0.0.1:8000/api/health](http://127.0.0.1:8000/api/health)
- **Python ML Service**: `http://127.0.0.1:8001`
- **MySQL 8 Database**: Port `3306`

---

## Option B: Running Locally (PHP + MySQL + Python)

If running without Docker, follow these steps:

### 1. Environment Configuration
Copy the example environment configuration:
```powershell
copy .env.example .env
```

Ensure your `.env` contains your MySQL database credentials:
```env
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=blockbord
DB_USERNAME=root
DB_PASSWORD=your_mysql_password
```

### 2. Database Migrations
Run the Laravel migrations to create all 11 MySQL tables:
```powershell
php artisan migrate
```

### 3. Start the Python ML Service
In terminal window #1, start the Python XGBoost microservice:
```powershell
pip install -r requirements.txt
python backend/ml/train_model.py
python -m uvicorn backend.ml.main:app --port 8001
```

### 4. Start the Laravel Backend
In terminal window #2, start the Laravel dev server:
```powershell
php artisan serve --port=8000
```
Access the application at: [http://127.0.0.1:8000](http://127.0.0.1:8000)

---

## 3. Browser Extension Setup

1. Open **Google Chrome**.
2. Navigate to `chrome://extensions/`.
3. Enable **Developer mode** (toggle switch in top-right corner).
4. Click **Load unpacked**.
5. Select the `extension` folder in this repository.
6. Pin the extension to your toolbar.

---

## 4. Health Check Verification

Test the health check API endpoint:
```bash
curl http://127.0.0.1:8000/api/health
```
Expected response:
```json
{
  "status": "healthy"
}
```
