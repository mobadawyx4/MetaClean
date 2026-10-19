$ErrorActionPreference = "Stop"

$python = Join-Path $PSScriptRoot "venv\Scripts\python.exe"

if (-not (Test-Path $python)) {
    Write-Host "MetaClean is not installed. Run .\install.ps1 first."
    exit 1
}

& $python (Join-Path $PSScriptRoot "main.py") @args
exit $LASTEXITCODE
