$ErrorActionPreference = "Stop"

Write-Host "=== MetaClean Windows Installer ===" -ForegroundColor Cyan

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "Python 3 is required. Install it from https://www.python.org/downloads/windows/"
    exit 1
}

if (-not (Test-Path (Join-Path $PSScriptRoot "main.py"))) {
    Write-Error "Run this installer from the MetaClean project folder."
    exit 1
}

python --version

if (-not (Test-Path (Join-Path $PSScriptRoot "venv"))) {
    python -m venv (Join-Path $PSScriptRoot "venv")
}

$venvPython = Join-Path $PSScriptRoot "venv\Scripts\python.exe"

& $venvPython -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw "Failed to upgrade pip." }

& $venvPython -m pip install -r (Join-Path $PSScriptRoot "requirements.txt")
if ($LASTEXITCODE -ne 0) { throw "Failed to install Python dependencies." }

if (-not (Get-Command exiftool -ErrorAction SilentlyContinue)) {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Host "Installing ExifTool..." -ForegroundColor Yellow
        winget install --id OliverBetz.ExifTool --exact --accept-package-agreements --accept-source-agreements
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "ExifTool installation may have failed. Install it manually, then reopen PowerShell."
        }
    } else {
        Write-Warning "winget was not found. Install ExifTool manually: https://exiftool.org/"
    }
}

Write-Host "`nInstallation steps completed." -ForegroundColor Green
Write-Host "Close and reopen PowerShell if ExifTool was just installed."
Write-Host "Then run: .\run.ps1"
