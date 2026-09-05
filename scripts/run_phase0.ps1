$ErrorActionPreference = "Stop"

$projectDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$pythonBin = Join-Path $projectDir ".venv\Scripts\python.exe"

if (-not (Test-Path $pythonBin)) {
    $pythonBin = "python"
}

Push-Location $projectDir
try {
    $env:PYTHONPATH = Join-Path $projectDir "src"
    & $pythonBin -m cyberdetect.cli phase0 --config configs/pilot.yaml
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}
finally {
    Pop-Location
}
