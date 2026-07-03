@echo off
cd /d "%~dp0"
title InsiderShield — Agent (Monitored PC)
color 0C

echo.
echo  ============================================================
echo    INSIDERSHIELD — AGENT  (Monitored PC)
echo  ============================================================
echo.

python --version >nul 2>&1
if errorlevel 1 ( echo [ERROR] Python not found. & pause & exit /b )

echo  Installing packages...
pip install pynput psutil requests numpy --quiet
echo  Done.
echo.

set /p SERVER_IP="Enter Dashboard PC IP (shown in START_SERVER window): "
set /p MY_NAME="Enter your name/username: "

echo.
echo  Testing connection to http://%SERVER_IP%:5000 ...
python -c "import requests; r=requests.get('http://%SERVER_IP%:5000/api/ping',timeout=5); print('[OK] Server reachable!' if r.status_code==200 else '[FAIL]')" 2>nul
if errorlevel 1 (
    echo.
    echo  [!] Cannot reach server. Check:
    echo      1. START_SERVER.bat is running on Dashboard PC
    echo      2. IP is correct - look at START_SERVER window for "Agent URL"
    echo      3. Both PCs on same WiFi network
    echo.
    echo  Press any key to try anyway...
    pause >nul
)

echo.
echo  ============================================================
echo   Connecting to : http://%SERVER_IP%:5000
echo   Reporting as  : %MY_NAME%
echo   Sending data every 30 seconds
echo.
echo   Minimize this window and work normally.
echo   To trigger alerts: open cmd.exe, powershell, etc.
echo  ============================================================
echo.

python agent\agent.py --server http://%SERVER_IP%:5000 --user %MY_NAME%

pause
