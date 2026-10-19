$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "=== MetaClean Windows Installer ===" -ForegroundColor Cyan

# Locate Python
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

# Create virtual environment
if (-not (Test-Path ".venv\Scripts\python.exe")) {
    & $python.Source @pythonArgs -m venv .venv
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create virtual environment."
    }
}

$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"

# Install dependencies
& $venvPython -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) {
    throw "Failed to upgrade pip."
}

& $venvPython -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    throw "Failed to install Python dependencies."
}

# Locate ExifTool
$exiftool = Get-Command exiftool -ErrorAction SilentlyContinue

if (-not $exiftool) {
    $winget = Get-Command winget -ErrorAction SilentlyContinue

    if ($winget) {
        Write-Host "ExifTool not found. Attempting installation with winget..." -ForegroundColor Yellow

        & $winget.Source install --id OliverBetz.ExifTool --exact --accept-package-agreements --accept-source-agreements

        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Automatic ExifTool installation did not complete successfully."
        }

        # Refresh PATH for this process from the common machine/user locations
        $env:PATH = [Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" +
                    [Environment]::GetEnvironmentVariable("PATH", "User") + ";" +
                    $env:PATH

        $exiftool = Get-Command exiftool -ErrorAction SilentlyContinue
    }
}

if ($exiftool) {
    Write-Host "ExifTool found: $($exiftool.Source)" -ForegroundColor Green
} else {
    Write-Warning "ExifTool was not detected. Install it from https://exiftool.org/ and reopen PowerShell."
    Write-Warning "Some metadata features may be limited without ExifTool."
}

Write-Host ""
Write-Host "Python dependencies installed." -ForegroundColor Green
Write-Host "Next: .\run.ps1 --help"
