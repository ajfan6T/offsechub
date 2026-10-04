# OffsecHub

**A local-first, encrypted workspace for penetration testers.** Scope, targets, recon imports, testing checklists, evidence, findings, operator logs and client-ready reports, all in **one encrypted vault on your own disk**. No server, no account, no network.

**Website and downloads: [ajfan6t.github.io/offsechub](https://ajfan6t.github.io/offsechub/)**

> A portfolio project in security engineering. The interesting parts are the [vault format](docs/VAULT_FORMAT.md), the [threat model](docs/THREAT_MODEL.md), and the [case study](docs/CASE_STUDY.md) of what adversarial review found in the first design.

![OffsecHub dashboard: engagements, open findings by severity and the latest findings](docs/screenshots/dashboard.png)

## Why

Pentest data is a client's attack map. Multi-user platforms (PlexTrac, Dradis, Ghostwriter, SysReptor) put that data on a server someone has to run, patch and trust. OffsecHub makes the opposite trade: a private operator workspace whose entire state is a folder of ciphertext you control. It works offline, on a Kali VM or inside a client network without egress, and it answers a client's "where is our data?" in one sentence.

## What it does

| Area | |
|---|---|
| **Engagements** | Clients, engagements, testing windows, rules of engagement, status workflow, dashboard |
| **Scope guard** | Include/exclude rules (IP, CIDR, range, host, `*.wildcard`, URL prefix). A scope checker. Every target shows live scope status. Imports never ingest excluded hosts. |
| **Recon** | Import Nmap XML, nuclei JSON/JSONL and host lists; nuclei results become grouped draft findings; the raw output is kept as evidence |
| **Testing** | OWASP WSTG, OWASP API Top 10, external, internal/AD and AWS checklists, per engagement or per target |
| **Evidence** | Streamed straight into the vault, each file under its own key, with a SHA-256 fingerprint |
| **Findings** | CVSS 3.1 calculator, CWE, draft → confirmed → remediated workflow, a reusable finding library |
| **Reports** | Readiness checks, then print-ready HTML/PDF, Markdown or JSON, with an evidence-fingerprint appendix |
| **Operator log** | Who ran what, from where, against what, with the outcome, for SOC deconfliction. Exports to CSV. |
| **CLI** | `offsechub import ACME-EXT-26 scan.xml --tool nmap` pushes results into the running app |

## Screenshots

All taken from the real app running the sample engagement (`offsechub demo`).

### Running an engagement

| | |
|---|---|
| ![Engagement overview](docs/screenshots/overview.png) | ![Scope rules](docs/screenshots/scope.png) |
| **Overview**: scope, targets, findings by severity, test coverage and rules of engagement | **Scope**: include and exclude rules (CIDR, host, wildcard, URL) that imports respect |
| ![Targets](docs/screenshots/targets.png) | ![Recon imports](docs/screenshots/recon.png) |
| **Targets** with live scope status, open services and findings | **Recon**: Nmap, nuclei and host-list imports, also from the terminal |
| ![Testing checklists](docs/screenshots/testing.png) | ![Operator log](docs/screenshots/op-log.png) |
| **Testing**: methodology checklists with coverage | **Operator log**: who ran what, from where, against what, for SOC deconfliction |

### Findings, evidence and reports

| | |
|---|---|
| ![Findings](docs/screenshots/findings.png) | ![Finding editor](docs/screenshots/finding-editor.png) |
| **Findings** with CVSS scores and triage status | **Finding editor**: CVSS 3.1 calculator, affected assets, linked evidence |
| ![Evidence locker](docs/screenshots/evidence.png) | ![Finding library](docs/screenshots/library.png) |
| **Evidence**: encrypted into the vault as it streams in, SHA-256 recorded | **Finding library**: reusable write-ups with CVSS and CWE |

![Report readiness checks and preview](docs/screenshots/report.png)

**Report**: readiness checks, then a sandboxed preview of the client report (HTML/PDF, Markdown or JSON).

### The vault

| | |
|---|---|
| ![Vault picker](docs/screenshots/welcome.png) | ![Recovery key](docs/screenshots/recovery-key.png) |
| **Vault picker**: recent vaults, open or create | **Recovery key**, shown once at creation, with a downloadable recovery kit |
| ![Locked vault](docs/screenshots/locked.png) | ![Settings](docs/screenshots/settings.png) |
| **Locked** after idle time or a lock from elsewhere, with an explanation | **Settings**: password, recovery key, rekey, auto-lock, encrypted backup, evidence verification |

## Security at a glance

- **Encryption at rest.**
  - A random master key protected by Argon2id (64 MiB, t=3) and a 256-bit recovery key.
  - AES-256-GCM in the STREAM construction for the database and every evidence file.
  - A fresh key for every snapshot and every file.
- **Tamper evidence.** Every byte is authenticated.
  - A whole-header MAC and revision counter detect deleted or rolled-back keyslots.
  - A per-machine high-water mark detects vault rollback.
  - A damaged database is quarantined, never silently swapped for its backup.
- **Crash safety.**
  - Atomic, fsynced saves, platform-aware: `F_FULLFSYNC` on macOS, write-through renames on Windows.
  - Group commit, so a saved change really is on disk.
  - A failed save never discards data.
  - Evidence files are deleted only once no snapshot references them.
- **Recovery.**
  - A recovery key with a check symbol that catches every single typo.
  - A recovery kit that restores access even if the vault header is lost.
  - A rekey operation for suspected compromise.
- **Local API hardening.** A one-time launch token, an exact Host allow-list against DNS rebinding, CSRF and Origin checks, and a strict CSP (no inline script, no `eval`).
- **A three-function JS bridge.** pywebview's dispatcher walks dotted attribute paths from page script. OffsecHub replaces it with exact allow-listed names and rebuilds the bridge without `eval`, so it works under the CSP. All three functions open a native dialog the user has to confirm.
- **Plaintext stays off disk.** In-memory SQLite with in-memory temp storage, streaming uploads (no multipart spooling), no access logs, and no core dumps.
- **No lock-in.** [`tools/ohvault_decrypt.py`](tools/ohvault_decrypt.py) is an independent decoder written only from the spec. It decrypts your vault without OffsecHub.

What it does **not** protect against (for example, malware running as you while the vault is unlocked) is spelled out in the [threat model](docs/THREAT_MODEL.md#6-out-of-scope-stated-plainly).

## Install

Installers for each release are on the [Releases page](https://github.com/ajfan6T/offsechub/releases), with a `SHA256SUMS` file. Every CI run also attaches them as build artifacts.

| System | Installer | How |
|---|---|---|
| Windows 10 or 11, x64 | `offsechub-setup-<version>.exe` | Run it. It installs for your user without administrator rights (or for all users, if you choose), adds a Start menu entry and an uninstaller, and installs the Microsoft WebView2 Runtime if it is missing. Optionally adds a desktop icon and puts `offsechub-cli` on your PATH. |
| macOS 11 or later, Apple silicon | `OffsecHub-<version>-macOS-arm64.dmg` | Open it and drag OffsecHub to Applications. |
| Debian, Ubuntu, Kali and derivatives, x64 | `offsechub_<version>_amd64.deb` | `sudo apt install ./offsechub_<version>_amd64.deb` (pulls in WebKitGTK and PyGObject from your distribution). |

Release builds are signed and notarized once the signing credentials are set up; see [docs/CODE_SIGNING.md](docs/CODE_SIGNING.md). Until then, the first launch needs one confirmation:
- **Windows SmartScreen:** click *More info*, then *Run anyway*.
- **macOS:** open *System Settings > Privacy & Security*, then click *Open Anyway*.

Check the download against `SHA256SUMS` first.

Uninstalling removes the app only. Your vaults and settings stay where they are.

To build the installers yourself, run `packaging/build.sh` on Linux or macOS, or `packaging\build.ps1` on Windows.

## Run from source

Requirements: Python 3.11+, Node 20+ (to build the UI). On Linux, the native window needs WebKitGTK; without it, use `--browser`.

```bash
# Build the UI once
cd frontend && npm install && npm run build && cd ..

# Install and launch
cd backend
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"            # add ".[gtk]" on Linux for the native window
offsechub                          # opens the desktop window
offsechub --browser                # no WebKit (e.g. minimal Kali/WSL): reduced-security browser mode
offsechub open                     # a fresh one-time browser link to the running app
```

Try it with sample data:

```bash
offsechub demo ~/OffsecHub/Demo.ohvault     # prompts for a password, prints the recovery key once
offsechub                                  # then open the Demo vault from the welcome screen
```

Push tool output from a terminal while the app is running:

```bash
nmap -sV -oX scan.xml 203.0.113.0/24
offsechub import ACME-EXT-26 scan.xml --tool nmap
nuclei -l hosts.txt -jsonl -o nuclei.jsonl && offsechub import ACME-EXT-26 nuclei.jsonl --tool nuclei
```


## Development

```bash
cd backend && pytest -q                    # vault, local API, domain, desktop shell, fuzzing
cd frontend && npm run build               # type-check + production build
offsechub --dev                            # API on :8000; run `npm run dev` in frontend/ and open the printed link
e2e/run.sh                                 # the real app end to end: Chromium (Playwright) and the native window
packaging/build.sh                         # installer for this OS: .deb or .dmg (build.ps1 on Windows: setup.exe)
```

```
backend/app/vault/         encrypted vault: crypto, header, manager, durable I/O, hardening
backend/app/localauth.py   localhost API authentication (launch token, Host/Origin/CSRF)
backend/app/desktop.py     pywebview shell, hardened JS bridge, server lifecycle
backend/app/cli.py         offsechub command (app, open, import, demo)
backend/app/api/           FastAPI routers (single operator)
backend/app/services/      scope matcher, CVSS, importers, reporting, evidence storage
frontend/                  React 19 + TypeScript + TanStack Query
packaging/                 installers: PyInstaller spec, Inno Setup (Windows), disk image (macOS), .deb (Linux), smoke test
tools/                     independent vault decoder
e2e/                       end-to-end scenarios: browser.cjs (Playwright), native.py (pywebview under Xvfb)
website/                   the project website (GitHub Pages, .github/workflows/pages.yml)
docs/                      vault format, threat model, architecture, case study
```

## Documentation

- [Vault format](docs/VAULT_FORMAT.md): the normative on-disk spec, with test vectors
- [Threat model](docs/THREAT_MODEL.md): adversaries, controls mapped to tests, out-of-scope items, plaintext artifacts
- [Architecture](docs/ARCHITECTURE.md): process model, concurrency and persistence, API contract, ADRs
- [Case study](docs/CASE_STUDY.md): the pivot, design principles, and what adversarial review found
- [Code signing](docs/CODE_SIGNING.md): signed and notarized releases, and how to set up the credentials
