# Build dist\offsechub-setup-<version>.exe on Windows.
#
# Needs Python 3.11+, Node 20+ and Inno Setup 6 (winget install JRSoftware.InnoSetup,
# or choco install innosetup). The WebView2 bootstrapper is downloaded and
# embedded, so the installer can add the runtime where it is missing.
#
#   packaging\build.ps1                  build everything
#   packaging\build.ps1 -SkipFrontend    reuse an existing frontend\dist (CI)
param([switch]$SkipFrontend)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

if (-not $SkipFrontend) {
    Push-Location frontend
    npm ci
    npm run build
    Pop-Location
}

python -m pip install -e "./backend[build]"
python -m PyInstaller packaging/offsechub.spec --noconfirm --distpath dist --workpath build/pyinstaller

New-Item -ItemType Directory -Force build | Out-Null
$bootstrapper = "build\MicrosoftEdgeWebview2Setup.exe"
if (-not (Test-Path $bootstrapper)) {
    Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/p/?LinkId=2124703" -OutFile $bootstrapper
}

$version = python packaging/version.py
$iscc = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup 6 not found: winget install JRSoftware.InnoSetup" }
& $iscc "/DAppVersion=$version" packaging\windows\offsechub.iss
if ($LASTEXITCODE -ne 0) { throw "ISCC failed" }
Write-Host "Built dist\offsechub-setup-$version.exe"
