@echo off
chcp 65001 >nul
cd /d %~dp0
set ROOM=7699816673754221322
set MODE=demo
set WORKERS=5
set WATCH=180
set DURATION=600
python live_boost_client.py --room %ROOM% --mode %MODE% --workers %WORKERS% --watch %WATCH% --duration %DURATION%
pause
