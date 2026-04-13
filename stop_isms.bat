@echo off
setlocal EnableExtensions EnableDelayedExpansion

:: =====================================================
:: ISMS STOP SCRIPT (ADMIN REQUIRED)
:: Location: Documents\isms\stop_isms.bat
:: =====================================================

:: --- Relaunch as admin if needed ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

title ISMS Stopper (Admin)

echo ==========================================
echo   ISMS – Stopping all components
echo ==========================================

:: -----------------------------------------------------
:: Kill backend window
:: -----------------------------------------------------
echo Stopping backend API...
taskkill /FI "WINDOWTITLE eq ISMS Backend*" /T /F >nul 2>&1

:: -----------------------------------------------------
:: Kill host agent window
:: -----------------------------------------------------
echo Stopping host agent...
taskkill /FI "WINDOWTITLE eq ISMS Host Agent*" /T /F >nul 2>&1

:: -----------------------------------------------------
:: Kill network agent window
:: -----------------------------------------------------
echo Stopping network agent...
taskkill /FI "WINDOWTITLE eq ISMS Network Agent*" /T /F >nul 2>&1

echo ------------------------------------------
echo ISMS stopped successfully.
echo ------------------------------------------
timeout /t 2 >nul
