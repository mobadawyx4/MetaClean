$ErrorActionPreference = "Stop"

$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$main = Join-Path $PSScriptRoot "main.py"

if (-not (Test-Path $python)) {
    Write-Error "MetaClean is not installed. Run .\install.ps1 first."
    exit 1
}

if (-not (Test-Path $main)) {
    Write-Error "main.py was not found."
    exit 1
}

& $python $main @args
exit $LASTEXITCODE
