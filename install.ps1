# sanitext installer (Windows PowerShell).
# Editable-installs the package and copies the .cmd launcher to ~\.local\bin
# if that directory exists on PATH.
$ErrorActionPreference = "Stop"

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

$py = "python"
Write-Host "Installing sanitext (editable) with $py ..."
& $py -m pip install -e .

$target = Join-Path $env:USERPROFILE ".local\bin"
if (Test-Path $target) {
    Copy-Item -Force (Join-Path $here "bin\sanitext.cmd") (Join-Path $target "sanitext.cmd")
    Copy-Item -Force (Join-Path $here "bin\sanitext") (Join-Path $target "sanitext")
    Write-Host "Launchers copied to $target"
}

Write-Host "Done. Try:  sanitext scan -t 'x`u{202E}y'"
