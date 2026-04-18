@echo off
cd /d "%~dp0"
call .venv311\Scripts\activate.bat
set SSLKEYLOGFILE=
python -m app.ingest.cloud_aws_cloudtrail
pause
