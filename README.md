# OffsecHub

**A local-first, encrypted workspace for penetration testers.** Scope, targets, recon imports, testing checklists, evidence, findings, operator logs and client-ready reports, all in **one encrypted vault on your own disk**. No server, no account, no network.

> A portfolio project in security engineering. The interesting parts are the [vault format](docs/VAULT_FORMAT.md), the [threat model](docs/THREAT_MODEL.md), and the [case study](docs/CASE_STUDY.md) of what adversarial review found in the first design.

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
- **Local API hardening.** A one-time launch token, an exact Host allow-list against DNS rebinding, CSRF and Origin checks, and a pywebview JS bridge patched to an allow-list.
- **Plaintext stays off disk.** In-memory SQLite with in-memory temp storage, streaming uploads (no multipart spooling), no access logs, and no core dumps.
- **No lock-in.** [`tools/ohvault_decrypt.py`](tools/ohvault_decrypt.py) is an independent decoder written only from the spec. It decrypts your vault without OffsecHub.

What it does **not** protect against (for example, malware running as you while the vault is unlocked) is spelled out in the [threat model](docs/THREAT_MODEL.md#6-out-of-scope-stated-plainly).

## Install and run

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

Standalone desktop bundles (PyInstaller) for Linux, macOS and Windows are built by CI; see [`packaging/`](packaging/).

## Development

```bash
cd backend && pytest -q                    # backend + vault + security suites
cd frontend && npm run build               # type-check + production build
offsechub --dev                            # with `npm run dev` in frontend/ for hot reload
```

```
backend/app/vault/         encrypted vault: crypto, header, manager, durable I/O, hardening
backend/app/localauth.py   localhost API authentication (launch token, Host/Origin/CSRF)
backend/app/desktop.py     pywebview shell, hardened JS bridge, server lifecycle
backend/app/api/           FastAPI routers (single operator)
backend/app/services/      scope matcher, CVSS, importers, reporting, evidence storage
frontend/                  React 19 + TypeScript + TanStack Query
tools/                     independent vault decoder
docs/                      vault format, threat model, architecture, case study
```

## Documentation

- [Vault format](docs/VAULT_FORMAT.md): the normative on-disk spec, with test vectors
- [Threat model](docs/THREAT_MODEL.md): adversaries, controls mapped to tests, out-of-scope items, plaintext artifacts
- [Architecture](docs/ARCHITECTURE.md): process model, concurrency and persistence, API contract, ADRs
- [Case study](docs/CASE_STUDY.md): the pivot, design principles, and what adversarial review found
