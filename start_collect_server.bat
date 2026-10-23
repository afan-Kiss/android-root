@echo off
cd /d "%~dp0"
python live_collect_server.py --host 0.0.0.0 --port 8787
pause
