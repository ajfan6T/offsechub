# Authenticode signing for the Windows build. Dot-source it: . packaging\windows\sign.ps1
#
# The signer is picked from the environment:
#
#   Azure Artifact Signing (releases)
#     ARTIFACT_SIGNING_ENDPOINT   e.g. https://eus.codesigning.azure.net/
#     ARTIFACT_SIGNING_ACCOUNT    the Artifact Signing account name
#     ARTIFACT_SIGNING_PROFILE    the certificate profile name
#     Azure credentials come from DefaultAzureCredential: in CI, `azure/login`
#     with OpenID Connect, so no long-lived secret is stored in GitHub.
#
#   A certificate in the current user's store
#     WINDOWS_SIGN_CERT_THUMBPRINT
#     CI signs with a throwaway self-signed certificate this way, to test the
#     whole signing pipeline on every push.
#
# With neither, the build is unsigned.

$ArtifactSigningClientVersion = "1.0.128"  # NuGet: Microsoft.ArtifactSigning.Client
$TimestampUrl = "http://timestamp.acs.microsoft.com"

function Test-SigningConfigured {
    return [bool](($env:ARTIFACT_SIGNING_ENDPOINT -and $env:ARTIFACT_SIGNING_ACCOUNT -and $env:ARTIFACT_SIGNING_PROFILE) -or
        $env:WINDOWS_SIGN_CERT_THUMBPRINT)
}

function Find-SignTool {
    $kits = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
    $tool = Get-ChildItem $kits -Directory -ErrorAction SilentlyContinue |
        Where-Object Name -Match '^\d+(\.\d+){3}$' |
        Sort-Object { [version]$_.Name } -Descending |
        ForEach-Object { Join-Path $_.FullName "x64\signtool.exe" } |
        Where-Object { Test-Path $_ } |
        Select-Object -First 1
    if (-not $tool) { throw "signtool.exe not found: install the Windows SDK" }
    return $tool
}

# Returns the signtool command (tool + arguments, without files), or $null if unsigned.
function Get-SigningConfig {
    if (-not (Test-SigningConfigured)) { return $null }
    $signtool = Find-SignTool
    if ($env:ARTIFACT_SIGNING_ENDPOINT) {
        $dir = Join-Path $PWD "build\artifact-signing"
        New-Item -ItemType Directory -Force $dir | Out-Null
        $v = $ArtifactSigningClientVersion
        $package = Join-Path $dir "client.zip"
        Invoke-WebRequest -OutFile $package `
            "https://api.nuget.org/v3-flatcontainer/microsoft.artifactsigning.client/$v/microsoft.artifactsigning.client.$v.nupkg"
        Expand-Archive $package -DestinationPath (Join-Path $dir "client") -Force
        $dlib = Join-Path $dir "client\bin\x64\Azure.CodeSigning.Dlib.dll"
        $metadata = Join-Path $dir "metadata.json"
        @{
            Endpoint               = $env:ARTIFACT_SIGNING_ENDPOINT
            CodeSigningAccountName = $env:ARTIFACT_SIGNING_ACCOUNT
            CertificateProfileName = $env:ARTIFACT_SIGNING_PROFILE
            # GitHub runners have no managed identity; probing for one only adds a timeout.
            ExcludeCredentials     = @("ManagedIdentityCredential")
        } | ConvertTo-Json | Set-Content -Encoding utf8 $metadata
        $signArgs = @("sign", "/fd", "SHA256", "/tr", $TimestampUrl, "/td", "SHA256", "/dlib", $dlib, "/dmdf", $metadata)
        $kind = "Azure Artifact Signing ($env:ARTIFACT_SIGNING_ACCOUNT / $env:ARTIFACT_SIGNING_PROFILE)"
    } else {
        $signArgs = @("sign", "/fd", "SHA256", "/sha1", $env:WINDOWS_SIGN_CERT_THUMBPRINT, "/s", "My")
        $kind = "certificate $env:WINDOWS_SIGN_CERT_THUMBPRINT"
    }
    Write-Host "Signing with $kind"
    return [pscustomobject]@{ SignTool = $signtool; Args = $signArgs }
}

function Invoke-Signing($config, [string[]]$files) {
    for ($i = 0; $i -lt $files.Count; $i += 25) {  # keeps the command line short
        $batch = $files[$i..([Math]::Min($i + 24, $files.Count - 1))]
        & $config.SignTool @($config.Args) @batch
        if ($LASTEXITCODE -ne 0) { throw "signtool failed ($LASTEXITCODE)" }
    }
}

# Executables and libraries in the bundle that nobody signed yet (python3xx.dll
# and the VC runtime already carry their vendors' signatures). Signing them all,
# not only offsechub.exe, keeps Smart App Control from blocking unsigned DLLs.
function Get-UnsignedBinaries([string]$dir) {
    return @(Get-ChildItem $dir -Recurse -File -Include *.exe, *.dll, *.pyd |
        Where-Object { (Get-AuthenticodeSignature $_.FullName).Status -eq "NotSigned" } |
        ForEach-Object FullName)
}

# The same command for Inno Setup, which signs Setup.exe and the uninstaller with
# it. ISCC replaces $f with the quoted file name and $q with a double quote.
function Get-IsccSignCommand($config) {
    $quote = { param($s) if ($s -match '\s') { '$q' + $s + '$q' } else { $s } }
    $parts = @(& $quote $config.SignTool) + @($config.Args | ForEach-Object { & $quote $_ })
    return ($parts -join " ") + ' $f'
}

function Assert-Signed([string[]]$files) {
    foreach ($file in $files) {
        $sig = Get-AuthenticodeSignature $file
        if ($sig.Status -ne "Valid") { throw "$file is not validly signed: $($sig.Status) $($sig.StatusMessage)" }
        Write-Host "signed: $(Split-Path $file -Leaf) by $($sig.SignerCertificate.Subject)"
    }
}
