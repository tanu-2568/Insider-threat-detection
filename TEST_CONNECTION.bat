@echo off
cd /d "%~dp0"
title InsiderShield — Connection Tester
color 0E

echo.
echo  ============================================================
echo    INSIDERSHIELD — CONNECTION TESTER
echo    Run this on the AGENT PC to diagnose problems
echo  ============================================================
echo.

set /p SERVER_IP="Enter Dashboard PC IP: "

echo.
echo  [1] Pinging %SERVER_IP% ...
ping -n 2 %SERVER_IP% | findstr "TTL"
if errorlevel 1 (
    echo  [FAIL] Cannot ping %SERVER_IP%
    echo         PCs may be on different networks
) else (
    echo  [OK]  Ping successful
)

echo.
echo  [2] Testing port 5000 ...
python -c "
import socket, sys
try:
    s = socket.create_connection(('%SERVER_IP%', 5000), timeout=3)
    s.close()
    print('  [OK]  Port 5000 is OPEN')
except ConnectionRefusedError:
    print('  [FAIL] Port 5000 REFUSED - server not running?')
except socket.timeout:
    print('  [FAIL] Port 5000 TIMEOUT - firewall blocking it')
except Exception as e:
    print(f'  [FAIL] {e}')
"

echo.
echo  [3] Testing HTTP API ...
python -c "
import requests
try:
    r = requests.get('http://%SERVER_IP%:5000/api/ping', timeout=5)
    if r.status_code == 200:
        print('  [OK]  API reachable! Server is running correctly.')
        print(f'        Response: {r.json()}')
    else:
        print(f'  [FAIL] Status {r.status_code}')
except Exception as e:
    print(f'  [FAIL] {e}')
" 2>nul

echo.
echo  ============================================================
echo   If all 3 tests pass, re-run START_AGENT.bat
echo   If [2] fails, run this on Dashboard PC as Admin:
echo   netsh advfirewall firewall add rule name="InsiderShield"
echo   dir=in action=allow protocol=TCP localport=5000
echo  ============================================================
echo.
pause
