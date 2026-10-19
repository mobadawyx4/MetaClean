$ErrorActionPreference = "Stop"

$projectRoot = $PSScriptRoot
$python = Join-Path $projectRoot ".venv\Scripts\python.exe"
$main = Join-Path $projectRoot "main.py"

if (-not (Test-Path $python)) {
    Write-Error "MetaClean is not installed. Run .\install.ps1 first."
    exit 1
}

if (-not (Test-Path $main)) {
    Write-Error "main.py was not found in $projectRoot"
    exit 1
}

Push-Location $projectRoot
try {
    & $python $main @args
    $code = $LASTEXITCODE
} finally {
    Pop-Location
}

exit $code
