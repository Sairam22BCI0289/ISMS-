@echo off
setlocal EnableExtensions EnableDelayedExpansion

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

title ISMS Launcher (Admin)

echo ==========================================
echo   ISMS – Intelligent Security Monitoring
echo   Starting all components...
echo ==========================================

set SSLKEYLOGFILE=
set ROOT=%~dp0
set BACKEND=%ROOT%backend
set VENV=%BACKEND%\.venv
set PYTHON=%VENV%\Scripts\python.exe

if not exist "%PYTHON%" (
    echo [ERROR] Virtual environment not found.
    echo Expected: %PYTHON%
    pause
    exit /b
)

echo [1/5] Starting backend API...
start "ISMS Backend" cmd /k ^
cd /d "%BACKEND%" ^& ^
"%PYTHON%" -m uvicorn app.main:app --host 127.0.0.1 --port 8000

timeout /t 5 >nul

echo [2/5] Starting host log agent...
start "ISMS Host Agent" cmd /k ^
cd /d "%BACKEND%" ^& ^
"%PYTHON%" -m app.ingest.host_windows_eventlog

timeout /t 2 >nul

echo [3/5] Starting network log agent...
start "ISMS Network Agent" cmd /k ^
cd /d "%BACKEND%" ^& ^
"%PYTHON%" -m app.ingest.network_windows_firewall

timeout /t 2 >nul

echo [4/5] Starting cloud log agent...
start "ISMS Cloud Agent" cmd /k ^
cd /d "%BACKEND%" ^& ^
"%PYTHON%" -m app.ingest.cloud_aws_cloudtrail

timeout /t 2 >nul

echo [5/5] Opening dashboard...
start "" http://127.0.0.1:8000/dashboard

echo ==========================================
echo ISMS started successfully.
echo ==========================================
