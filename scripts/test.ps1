$ErrorActionPreference = "Stop"

$projectDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$pythonBin = Join-Path $projectDir ".venv\Scripts\python.exe"

if (-not (Test-Path $pythonBin)) {
    $pythonBin = "python"
}

Push-Location $projectDir
try {
    $env:PYTHONPATH = Join-Path $projectDir "src"
    & $pythonBin -m unittest discover -s tests -p "test_*.py" -v
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}
finally {
    Pop-Location
}
