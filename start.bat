@echo off
rem ThreatLens launcher - starts backend (API) and frontend (Vite dev server)
cd /d "%~dp0"

start "ThreatLens API" cmd /k "cd /d %~dp0backend && .venv\Scripts\python -m uvicorn app.main:app --reload"
start "ThreatLens Frontend" cmd /k "cd /d %~dp0frontend && npm run dev"

echo.
echo ThreatLens baslatildi:
echo   API      : http://localhost:8000
echo   Frontend : http://localhost:5173
echo Kapamak icin acilan iki pencereyi kapatin.
timeout /t 5 >nul