@echo off
cd /d "%~dp0"
call .venv311\Scripts\activate.bat
python -m uvicorn app.main:app --port 8000
pause
