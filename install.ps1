$ErrorActionPreference = "Stop"

Write-Host "=== MetaClean Windows Installer ===" -ForegroundColor Cyan

# Find Python
$python = Get-Command py -ErrorAction SilentlyContinue
$pythonArgs = @("-3")

if (-not $python) {
    $python = Get-Command python -ErrorAction SilentlyContinue
    $pythonArgs = @()
}

if (-not $python) {
    throw "Python 3 is required. Install it from https://www.python.org/downloads/windows/"
}

& $python.Source @pythonArgs --version
if ($LASTEXITCODE -ne 0) {
    throw "Python could not be started."
}

# Create an isolated virtual environment
if (-not (Test-Path ".venv\Scripts\python.exe")) {
    & $python.Source @pythonArgs -m venv .venv
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create virtual environment."
    }
}

$venvPython = Join-Path $PWD ".venv\Scripts\python.exe"

# Install Python dependencies
& $venvPython -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) {
    throw "Failed to upgrade pip."
}

& $venvPython -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    throw "Failed to install Python dependencies."
}

# Check ExifTool
$exiftool = Get-Command exiftool -ErrorAction SilentlyContinue

if (-not $exiftool) {
    $winget = Get-Command winget -ErrorAction SilentlyContinue

    if ($winget) {
        Write-Host "Installing ExifTool..." -ForegroundColor Yellow
        & $winget.Source install --id OliverBetz.ExifTool --exact --accept-package-agreements --accept-source-agreements
        Write-Host "If installation succeeded, reopen PowerShell."
    } else {
        Write-Warning "Install ExifTool manually: https://exiftool.org/"
    }
} else {
    Write-Host "ExifTool found: $($exiftool.Source)" -ForegroundColor Green
}

Write-Host ""
Write-Host "Installation steps completed." -ForegroundColor Green
Write-Host "Run the application using .\run.ps1 --help"
