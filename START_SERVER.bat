@echo off
cd /d "%~dp0"
title InsiderShield — Dashboard Server
color 0A

echo.
echo  ============================================================
echo    INSIDERSHIELD — DASHBOARD SERVER
echo  ============================================================
echo.

python --version >nul 2>&1
if errorlevel 1 ( echo [ERROR] Python not found. & pause & exit /b )

echo  [1/3] Installing Flask...
pip install flask --quiet
echo        Done.
echo.

echo  [2/3] Adding firewall rule (allows agents to connect)...
netsh advfirewall firewall delete rule name="InsiderShield" >nul 2>&1
netsh advfirewall firewall add rule name="InsiderShield" dir=in action=allow protocol=TCP localport=5000 >nul 2>&1
echo        Done.
echo.

echo  [3/3] Getting your IP address...
echo.

for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /i "IPv4" ^| findstr /v "127.0.0.1"') do (
    set MYIP=%%a
)
set MYIP=%MYIP: =%

echo  ============================================================
echo   Dashboard  : http://localhost:5000
echo   Agent URL  : http://%MYIP%:5000
echo.
echo   On the monitored PC run:
echo   python agent\agent.py --server http://%MYIP%:5000 --user NAME
echo.
echo   Or just click "LOAD DEMO USERS" on the dashboard.
echo   Press CTRL+C to stop the server.
echo  ============================================================
echo.

start http://localhost:5000
python server\server.py

pause
