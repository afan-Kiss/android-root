@echo off
cd /d "%~dp0"
set SERVER=http://127.0.0.1:8787
python live_collect_client.py --server %SERVER% --workers 50 --duration 1800
pause
