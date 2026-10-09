
$ErrorActionPreference = "Stop"

$Root = $PSScriptRoot
$Python = Join-Path $Root ".venv\Scripts\python.exe"
$Backend = Join-Path $Root "backend"
$NodeModules = Join-Path $Backend "node_modules"

if (-not (Test-Path $Python)) {
    Write-Host "ERROR: Python virtual environment not found:"
    Write-Host "  $Python"
    Write-Host "Create a Windows virtual environment and install dependencies first."
    exit 1
}

if (-not (Test-Path $NodeModules)) {
    Write-Host "ERROR: Node dependencies are missing."
    Write-Host "Run: cd backend; npm install"
    exit 1
}

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Node.js is not installed or not on PATH."
    exit 1
}

$PythonCommand = "& '$Python' -m uvicorn app.main:app --reload --port 8000"
$NodeCommand = "Set-Location '$Backend'; npm run dev"

Write-Host "Starting OPC017 Python forensic engine..."
Start-Process powershell.exe `
    -WorkingDirectory $Root `
    -ArgumentList @("-NoExit", "-Command", $PythonCommand)

Write-Host "Starting OPC017 Node.js backend..."
Start-Process powershell.exe `
    -WorkingDirectory $Backend `
    -ArgumentList @("-NoExit", "-Command", $NodeCommand)

Write-Host ""
Write-Host "OPC017 services are starting."
Write-Host "Dashboard:  http://127.0.0.1:4000"
Write-Host "Health:     http://127.0.0.1:4000/api/health"
Write-Host "Python API: http://127.0.0.1:8000/docs"
Write-Host "Close the two service windows to stop the services."
