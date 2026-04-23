@echo off
:: start_backend.bat — Windows launcher for the GRC backend
:: Double-click this file from the project root on Windows.

echo === BABCOM GRC Platform ===
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Install from https://python.org
    pause
    exit /b 1
)

:: Install dependencies
echo Installing Python dependencies...
cd backend
pip install -r requirements.txt --quiet

echo.
echo Starting backend on http://localhost:8000
echo Open frontend\index.html in your browser once it starts.
echo Press Ctrl+C to stop.
echo.

:: Set local evidence path env var (edit this to match your setup)
set GRC_LOCAL_PATH=D:\GRC\evidence_store\policies

uvicorn main:app --host 0.0.0.0 --port 8000 --reload

pause
