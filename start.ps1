
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

Write-Host "Starting OPC017 Python forensic engine..."
Start-Process powershell.exe `
    -WorkingDirectory $Root `
    -ArgumentList @(
        "-NoExit",
        "-Command",
        "& '$Python' -m uvicorn app.main:app --reload --port 8000"
    )

Write-Host "Starting OPC017 Node.js backend..."
Start-Process powershell.exe `
    -WorkingDirectory $Backend `
    -ArgumentList @(
        "-NoExit",
        "-Command",
        "Set-Location '$Backend'; npm run dev"
    )

Write-Host ""
Write-Host "Waiting for the Node.js backend..."

$Ready = $false

for ($Attempt = 1; $Attempt -le 30; $Attempt++) {
    try {
        $Response = Invoke-RestMethod `
            -Uri "http://127.0.0.1:4000/api/health" `
            -TimeoutSec 2

        $Ready = $true
        break
    }
    catch {
        Start-Sleep -Seconds 1
    }
}

Write-Host ""
Write-Host "Dashboard:  http://127.0.0.1:4000"
Write-Host "Health:     http://127.0.0.1:4000/api/health"
Write-Host "Python API: http://127.0.0.1:8000/docs"

if ($Ready) {
    Write-Host "Backend is ready. Opening OPC017..."
    Start-Process "http://127.0.0.1:4000"
}
else {
    Write-Warning "Backend did not respond within 30 seconds."
    Write-Host "Check the Node.js terminal for errors."
    Write-Host "Once fixed, open http://127.0.0.1:4000 manually."
}

Write-Host ""
Write-Host "Close the service windows to stop the services."
