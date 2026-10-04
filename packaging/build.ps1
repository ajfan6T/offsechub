# Build the desktop app on Windows into dist\OffsecHub\.
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

Push-Location frontend
npm ci
npm run build
Pop-Location

python -m pip install -e "./backend[build]"
pyinstaller packaging/offsechub.spec --noconfirm --distpath dist --workpath build/pyinstaller
Write-Host "Built: dist\OffsecHub\offsechub.exe"
