```bat
@echo off
setlocal

set "ROOT=%~dp0"
set "BACKEND=%ROOT%backend"
set "PYTHON=%ROOT%.venv\Scripts\python.exe"

echo ========================================
echo       OPC017 Forensics Platform
echo ========================================
echo.

if not exist "%PYTHON%" (
    echo ERROR: Python virtual environment not found.
    echo Expected: "%PYTHON%"
    echo.
    echo Create a Windows venv and install requirements.txt.
    pause
    exit /b 1
)

where node >nul 2>&1
if errorlevel 1 (
    echo ERROR: Node.js is not installed or not on PATH.
    pause
    exit /b 1
)

where npm >nul 2>&1
if errorlevel 1 (
    echo ERROR: npm is not installed or not on PATH.
    pause
    exit /b 1
)

if not exist "%BACKEND%\node_modules" (
    echo ERROR: Node dependencies are missing.
    echo Run: cd backend ^&^& npm install
    pause
    exit /b 1
)

echo Starting Python investigation API...
start "OPC017 Python API" /D "%ROOT%" cmd /k ""%PYTHON%" -m uvicorn app.main:app --host 127.0.0.1 --port 8000"

echo Starting Node.js backend...
start "OPC017 Node Backend" /D "%BACKEND%" cmd /k "npm run dev"

echo.
echo Waiting for services to start...
timeout /t 5 /nobreak >nul

echo Dashboard:  http://127.0.0.1:4000
echo Python API: http://127.0.0.1:8000/docs
echo.
echo If AI does not work, check both service windows.
start "" "http://127.0.0.1:4000"

endlocal
```
