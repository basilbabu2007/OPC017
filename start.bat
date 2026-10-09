@echo off
REM OPC017 one-click launcher: starts the backend (which serves the UI) and opens it.
cd /d "%~dp0backend"
if not exist data\forensics.test.db (
  echo Seeding demo databases first...
  cmd /c "C:\Progra~1\nodejs\node.exe src/seed.js"
)
start "OPC017 backend" "C:\Program Files\nodejs\node.exe" src/server.js
echo Waiting for server...
timeout /t 5 /nobreak >nul
start http://localhost:4000/
echo.
echo OPC017 is running at http://localhost:4000/
echo Close the "OPC017 backend" window to stop the server.
pause
