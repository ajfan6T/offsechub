# Build dist\offsechub-setup-<version>.exe on Windows.
#
# Needs Python 3.11+, Node 20+ and Inno Setup 6 (winget install JRSoftware.InnoSetup,
# or choco install innosetup). The WebView2 bootstrapper is downloaded and
# embedded, so the installer can add the runtime where it is missing.
#
# Signing: set the variables described in packaging\windows\sign.ps1 and every
# binary, Setup.exe and the uninstaller are Authenticode-signed (see
# docs\CODE_SIGNING.md). Without them the build is unsigned.
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
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }

New-Item -ItemType Directory -Force build | Out-Null
. (Join-Path $PSScriptRoot "windows\sign.ps1")
$signing = Get-SigningConfig
if ($signing) {
    Invoke-Signing $signing (Get-UnsignedBinaries "dist\OffsecHub")
    Assert-Signed @("dist\OffsecHub\offsechub.exe", "dist\OffsecHub\offsechub-cli.exe")
}
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
$isccArgs = @("/DAppVersion=$version")
if ($signing) { $isccArgs += @("/DSign", "/Ssigntool=$(Get-IsccSignCommand $signing)") }
& $iscc @isccArgs packaging\windows\offsechub.iss
if ($LASTEXITCODE -ne 0) { throw "ISCC failed" }
$setup = "dist\offsechub-setup-$version.exe"
if ($signing) { Assert-Signed @($setup) }
Write-Host "Built $setup$(if ($signing) { ' (signed)' } else { ' (unsigned)' })"
