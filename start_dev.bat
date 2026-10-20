@echo off
echo Starting Laravel Web Server...
start "Laravel Web Server" /B "C:\xampp\php\php.exe" artisan serve --host=127.0.0.1 --port=8000

echo Starting FastAPI ML Service...
start "FastAPI ML Service" /B uvicorn backend.ml_service:app --host=127.0.0.1 --port=8001

echo Starting Laravel Queue Worker...
start "Laravel Queue Worker" /B "C:\xampp\php\php.exe" artisan queue:work --timeout=300

echo Development environment started.
