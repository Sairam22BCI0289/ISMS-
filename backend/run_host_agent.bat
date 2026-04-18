@echo off
cd /d "%~dp0"
call .venv311\Scripts\activate.bat
python app\ingest\host_windows_eventlog.py
pause
