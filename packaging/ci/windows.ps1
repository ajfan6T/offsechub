# CI: build the Windows installer, install it silently, smoke-test the
# installed app, uninstall. Signs when packaging\windows\sign.ps1 finds a signer.
#
#   packaging\ci\windows.ps1                  unsigned, or signed for a release
#   packaging\ci\windows.ps1 -SigningDryRun   sign with a throwaway self-signed
#                                             certificate, trusted on this machine
#                                             only, to test the signing pipeline
#
# Needs Inno Setup 6 and a built frontend\dist.
param([switch]$SigningDryRun)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..\..")
. packaging\windows\sign.ps1

$testCert = $null
if ($SigningDryRun) {
    $testCert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=OffsecHub CI test signing" `
        -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(1)
    $root = [System.Security.Cryptography.X509Certificates.X509Store]::new("Root", "LocalMachine")
    $root.Open("ReadWrite"); $root.Add($testCert); $root.Close()
    $env:WINDOWS_SIGN_CERT_THUMBPRINT = $testCert.Thumbprint
}
try {
    $signed = Test-SigningConfigured
    if (-not $signed) { Write-Host "::warning::No signing configured: building an unsigned installer" }
    ./packaging/build.ps1 -SkipFrontend

    $version = python packaging/version.py
    $setup = (Resolve-Path "dist\offsechub-setup-$version.exe").Path
    $dir = Join-Path $env:RUNNER_TEMP "OffsecHub"
    $log = Join-Path $env:RUNNER_TEMP "setup.log"
    $p = Start-Process $setup -Wait -PassThru -ArgumentList "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/CURRENTUSER", "/DIR=`"$dir`"", "/LOG=`"$log`""
    if ($p.ExitCode -ne 0) { Get-Content $log; throw "setup exited with $($p.ExitCode)" }
    if ($signed) {
        Assert-Signed @($setup, "$dir\offsechub.exe", "$dir\offsechub-cli.exe", "$dir\unins000.exe")
        $unsigned = Get-UnsignedBinaries $dir
        if ($unsigned) { throw "unsigned binaries were installed: $($unsigned -join ', ')" }
    }

    python packaging/smoke_test.py --app "$dir\offsechub.exe" --cli "$dir\offsechub-cli.exe"
    if ($LASTEXITCODE -ne 0) { throw "smoke test failed" }

    # The uninstaller relaunches itself from %TEMP%, so wait for the files to go.
    Start-Process "$dir\unins000.exe" -Wait -ArgumentList "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"
    for ($i = 0; ($i -lt 60) -and (Test-Path "$dir\offsechub.exe"); $i++) { Start-Sleep 1 }
    if (Test-Path "$dir\offsechub.exe") { throw "uninstall left the app behind" }
} finally {
    if ($testCert) {
        $root = [System.Security.Cryptography.X509Certificates.X509Store]::new("Root", "LocalMachine")
        $root.Open("ReadWrite"); $root.Remove($testCert); $root.Close()
        Remove-Item "Cert:\CurrentUser\My\$($testCert.Thumbprint)"
        Remove-Item Env:\WINDOWS_SIGN_CERT_THUMBPRINT
    }
}
