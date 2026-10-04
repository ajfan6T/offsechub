# Code signing

Unsigned installers trigger warnings: Windows SmartScreen says *"Windows protected your PC"* (publisher: *Unknown*), and macOS refuses to open the app until the user approves it in System Settings. Those warnings go away only when the files are signed by an identity that Microsoft and Apple have verified. That identity has to be yours, so it can't be created by this repository.

The pipeline is already built. Once the credentials below are in the repository's protected `release` environment, every version tag produces signed (and, on macOS, notarized) installers automatically.

| | Unsigned (now) | Signed |
|---|---|---|
| **Windows** | SmartScreen: *Unknown publisher*, *More info → Run anyway* | Your verified name as publisher. See [SmartScreen reputation](#smartscreen-reputation) for the remaining caveat. |
| **macOS** | Blocked until *System Settings → Privacy & Security → Open Anyway* | Opens normally, with the standard "downloaded from the internet" prompt only |
| **Linux** | No signature prompt for `.deb` files; verify with `SHA256SUMS` | Same |

## What the pipeline does

- **Windows** ([`packaging/windows/sign.ps1`](../packaging/windows/sign.ps1)): signs every unsigned `.exe`, `.dll` and `.pyd` in the bundle, then `Setup.exe` and the uninstaller (through Inno Setup's `SignTool`). It uses SHA-256 with an RFC 3161 timestamp, so signatures stay valid after the short-lived signing certificate expires. Signing the libraries too keeps Windows 11 Smart App Control from blocking them.
- **macOS** ([`packaging/macos/`](../packaging/macos/)):
  - signs every Mach-O file inside the app, then the app itself, with the hardened runtime and a secure timestamp;
  - notarizes the app with Apple and staples the ticket, so it opens even offline;
  - builds the disk image, then signs, notarizes and staples it too;
  - checks both with `spctl`, as Gatekeeper would.
- **Every push rehearses this without real credentials:**
  - **Windows:** the whole Windows chain runs with a throwaway self-signed certificate that is trusted only on the CI runner. CI installs the result, checks that every installed binary is validly signed, and runs the smoke test.
  - **macOS:** the app is signed ad hoc with the hardened runtime, and the smoke test runs against that build.

  The only parts a rehearsal can't reach are Microsoft's and Apple's services themselves.

### Where the credentials live

- **Only tag builds can use them.** They are stored in a GitHub *environment* called `release`, and only the `release-installers` job references it. That job runs for tags like `v0.2.1`, never for branches or pull requests.
- **Restrict the environment.** In *Settings → Environments → release*, add a deployment rule for tags matching `v*`. Optionally, require a reviewer before each release. A tag-only rule blocks the manual *Run workflow* route below, which runs on a branch; to keep that route, also allow the default branch, or rely on the required reviewer.
- **Windows stores no secret at all.** GitHub's OpenID Connect token is exchanged for a short-lived Azure token that only the `release` environment can obtain. The private key never leaves Microsoft's HSMs.
- **The macOS certificate is temporary on CI.** It is imported into a throwaway keychain on the runner and disappears with it.

## Windows: Azure Artifact Signing

Artifact Signing (renamed from Trusted Signing in 2026) is Microsoft's code-signing service. It is the cheapest option and the one designed for CI: there is no certificate file to buy, store or renew.

**Eligibility.** At the time of writing, these can apply:
- organizations in the US, Canada, the EU and the UK;
- self-employed individuals in the US and Canada.

**Cost.** The Basic tier is about US$10 a month and includes 5,000 signatures; a release signs a few dozen files. Check Azure's current pricing before you sign up.

1. **Subscription.** In the [Azure portal](https://portal.azure.com), use or create a subscription. Register the `Microsoft.CodeSigning` resource provider.
2. **Account.** Create an **Artifact Signing account**. Note its region endpoint, for example `https://eus.codesigning.azure.net/` for East US.
3. **Identity validation.** Under *Identity validation*, request a **Public** validation, as an individual or an organization. Microsoft verifies your identity; this can take a few days.
4. **Certificate profile.** Once you're validated, create a **Public Trust** certificate profile.
5. **Entra app for GitHub.**
   1. Go to *Microsoft Entra ID → App registrations → New registration*, for example `offsechub-release-signing`.
   2. Under *Certificates & secrets → Federated credentials → Add*, choose *GitHub Actions deploying Azure resources*.
   3. Enter organization `ajfan6T`, repository `offsechub`, entity type **Environment**, and environment name `release`.
6. **Role.** On the Artifact Signing account, open *Access control (IAM)*. Assign the role **Artifact Signing Certificate Profile Signer** to that app.
7. **GitHub variables.** In *GitHub → Settings → Environments → `release` → Environment variables*, add these. None of them are secrets.

   | Variable | Value |
   |---|---|
   | `AZURE_CLIENT_ID` | the app registration's *Application (client) ID* |
   | `AZURE_TENANT_ID` | your *Directory (tenant) ID* |
   | `ARTIFACT_SIGNING_ENDPOINT` | the account's endpoint from step 2 |
   | `ARTIFACT_SIGNING_ACCOUNT` | the account name |
   | `ARTIFACT_SIGNING_PROFILE` | the certificate profile name |

**Not eligible?** Since 2023, code-signing keys must be stored on hardware, so certificate authorities no longer issue `.pfx` files. Buy an OV certificate from a CA that offers cloud signing, for example DigiCert KeyLocker or SSL.com eSigner. Then change the `signtool` arguments in `Get-SigningConfig` in `sign.ps1` to that vendor's. Open-source projects can also apply to the SignPath Foundation for free signing; that requires an OSI-approved license, which this repository doesn't have yet.

### SmartScreen reputation

Signing changes the publisher from *Unknown* to your verified name straight away. SmartScreen's blue screen can still appear for the first downloads of a new signer, until Microsoft has seen enough clean installs to build reputation for it. Since 2024 no certificate type skips this, EV included. The reputation attaches to your signing identity, so it carries over from one release to the next.

## macOS: Developer ID and notarization

You need the [Apple Developer Program](https://developer.apple.com/programs/), which costs US$99 a year (individual or organization).

1. **Certificate.** Create a **Developer ID Application** certificate, either in *Xcode → Settings → Accounts → Manage Certificates*, or at developer.apple.com with a CSR from Keychain Access.
2. **Export.** In Keychain Access, export the certificate *with its private key* as a `.p12` file with a password.
3. **API key.** In *App Store Connect → Users and Access → Integrations → App Store Connect API → Team Keys*, generate a key with **Developer** access. Download the `AuthKey_XXXX.p8` file (you can download it only once) and note the Key ID and the Issuer ID.
4. **GitHub secrets.** In *GitHub → Settings → Environments → `release` → Environment secrets*, add:

   | Secret | Value |
   |---|---|
   | `MACOS_CERTIFICATE` | `base64 -i DeveloperID.p12 \| pbcopy` |
   | `MACOS_CERTIFICATE_PASSWORD` | the `.p12` password |
   | `APPLE_API_KEY` | the full text of the `.p8` file |
   | `APPLE_API_KEY_ID` | the Key ID |
   | `APPLE_API_ISSUER_ID` | the Issuer ID |

The hardened runtime makes two exceptions for the embedded Python, listed in [`entitlements.plist`](../packaging/macos/entitlements.plist): callbacks through libffi (ctypes, cffi and PyObjC) need executable memory. Library validation stays on, because every bundled library carries the same Developer ID.

## Releasing

1. Set the new version in `backend/app/__init__.py` and commit.
2. Start the release in one of two ways:
   - Tag and push: `git tag v0.2.1 && git push origin v0.2.1`. The tag must match the version.
   - Or, without pushing a tag: *Actions → CI → Run workflow*, tick **Publish a release**. CI creates the `v<version>` tag on that commit itself.
3. CI builds, signs, notarizes, installs and smoke-tests on all three systems. It then publishes a GitHub release with the installers, version-less copies of them (so the website's `releases/latest/download/…` links keep working), and `SHA256SUMS`.

If you tag before the credentials are set up, the release is published unsigned and the run shows a warning.

To sign locally:
- **Windows:** set the same `ARTIFACT_SIGNING_*` variables (after `az login`) and run `packaging\build.ps1`.
- **macOS:** set `MACOS_SIGN_IDENTITY` and the `APPLE_API_KEY_*` variables and run `packaging/macos/build_dmg.sh`.
