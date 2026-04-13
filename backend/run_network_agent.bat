@echo off
cd /d "%~dp0"
call .venv\Scripts\activate.bat
python app\ingest\network_windows_firewall.py
pause
