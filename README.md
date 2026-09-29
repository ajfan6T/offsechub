# OffsecHub

OffsecHub is a workspace for offensive security teams. One engagement holds everything from the signed scope to the delivered report:

**case management → scope → targets → recon → testing → evidence → findings → reporting**

It is built for pentest consultancies, internal red teams and security teams who today juggle spreadsheets, note apps, screenshot folders and a Word template.

![Engagement overview](docs/screenshots/engagement-overview.png)

> For the product view, positioning and the roadmap to a complete commercial product, see
> [docs/PRODUCT_STRATEGY.md](docs/PRODUCT_STRATEGY.md).

## What's in the box

| Area | What it does |
|---|---|
| **Case management** | Clients and engagements (type, status workflow, testing window, rules of engagement), per-engagement teams with lead/tester/viewer roles, and a dashboard of what's due and what's open. |
| **Scope** | Include/exclude rules for IPs, CIDRs, IP ranges, hostnames, wildcards, URL prefixes and free-text identifiers such as cloud account IDs. Exclusions always win. A **scope checker** answers "can I touch this?" before you do. Bulk entry auto-detects the rule type. |
| **Targets** | Hosts, domains and web apps with services (port/proto/product/version), OS, tags and status (new → in progress → tested → compromised). Every target shows a live scope status and out-of-scope assets are flagged. |
| **Recon** | Import **Nmap XML**, **nuclei JSON/JSONL** and plain host/URL lists (subfinder, amass, httpx). A **scope guard** never imports excluded hosts and skips out-of-scope hosts by default. nuclei results become *draft findings* grouped per template, with every affected asset attached. The raw tool output is kept as hashed evidence. |
| **Testing** | Built-in checklists: OWASP WSTG (54 checks), OWASP API Top 10 2023, External Network, Internal Network & AD, and AWS Cloud. Apply them per engagement or per target, assign checks, record notes, and raise a finding straight from a failed check. Coverage feeds the report. |
| **Evidence** | Upload screenshots or files, or paste text (HTTP request/response pairs, shell output). Each item gets a SHA-256 on upload for chain of custody and can be linked to a finding, target or test case. Active content (HTML/SVG) is only ever served as a download. |
| **Findings** | Sequential IDs per engagement (`ACME-EXT-26-004`), a CVSS v3.1 calculator (severity follows the score unless overridden), CWE, affected assets, and a draft → confirmed → reported → remediated / risk accepted / false positive workflow. |
| **Finding library** | 14 reviewed write-ups ship by default (SQLi, XSS, IDOR, SSRF, SMB signing, Kerberoasting, and more). Create a finding from a template, or promote a polished finding into the library. |
| **Reporting** | Report readiness checks (untriaged drafts, missing remediation/evidence, incomplete methodology), an executive summary editor, and export to print-ready **HTML/PDF**, **Markdown** and **JSON**. Screenshots are embedded, and the report includes scope, methodology coverage, findings and an asset appendix. |
| **Operator log** | A timestamped record of who ran what, from where, against what, with the outcome, for deconfliction with the client's SOC. Exports to CSV. |
| **Audit trail** | Every sign-in, change, import, export and deletion is recorded per engagement and globally. |
| **Automation** | Personal API tokens let you push scan output from an attack box or CI with a single `curl`. |

<p>
  <img src="docs/screenshots/finding-editor.png" width="49%" alt="Finding editor with CVSS calculator" />
  <img src="docs/screenshots/report-findings.png" width="49%" alt="Generated report" />
</p>

## Quick start

### Docker (recommended)

```bash
cp .env.example .env            # set POSTGRES_PASSWORD and OFFSECHUB_ADMIN_PASSWORD
docker compose up -d --build
docker compose exec app python -m app.cli seed-demo   # optional demo engagement
open http://127.0.0.1:8000
```

If `OFFSECHUB_ADMIN_PASSWORD` is empty, a random admin password is printed once in `docker compose logs app`.

### Local development

Requirements: Python 3.11+ and Node 20+.

```bash
# Backend (API on :8000)
cd backend
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
OFFSECHUB_ADMIN_PASSWORD=change-me-now-please python -m app.cli seed-demo
uvicorn app.main:app --reload

# Frontend (Vite on :5173, proxies /api to :8000)
cd frontend
npm install
npm run dev
```

Demo accounts use the password `offsechub-demo-password`:

- `lead@offsechub.local`: engagement lead
- `tester@offsechub.local`: tester
- `viewer@offsechub.local`: read-only stakeholder
- `admin@offsechub.local`: admin, using the password you set

To serve the built UI from FastAPI without Vite, run `npm run build` in `frontend/` and open `http://127.0.0.1:8000`.

### Tests

```bash
cd backend && pytest -q                         # SQLite
OFFSECHUB_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost/offsechub_test pytest -q
cd frontend && npm run build                    # type-check + production build
```

CI (`.github/workflows/ci.yml`) runs the backend suite on SQLite and PostgreSQL, and builds the frontend.

## Pushing tool output from the command line

Create a token under **Settings → API tokens**, then:

```bash
export OFFSECHUB=https://offsechub.example.internal
export OFFSECHUB_TOKEN=ohub_...

nmap -sV -oX scan.xml 203.0.113.0/24
curl -H "Authorization: Bearer $OFFSECHUB_TOKEN" -F tool=nmap -F file=@scan.xml \
     $OFFSECHUB/api/engagements/1/imports

nuclei -l hosts.txt -jsonl -o nuclei.jsonl
curl -H "Authorization: Bearer $OFFSECHUB_TOKEN" -F tool=nuclei -F file=@nuclei.jsonl \
     $OFFSECHUB/api/engagements/1/imports

# Before touching anything new:
curl -H "Authorization: Bearer $OFFSECHUB_TOKEN" -H 'Content-Type: application/json' \
     -d '{"values":["10.0.0.5","portal.example.com"]}' $OFFSECHUB/api/engagements/1/scope/check
```

Interactive API docs are served at `/api/docs` (spec at `/api/openapi.json`; disable with `OFFSECHUB_API_DOCS=false`).

## Architecture

```
backend/                 FastAPI + SQLAlchemy 2 (SQLite for dev, PostgreSQL for prod)
  app/api/               one router per area (auth, engagements, scope, targets, recon, testing,
                         evidence, findings, reports, activity)
  app/services/          domain logic with no HTTP: scope matcher, CVSS 3.1, importers,
                         evidence storage, reporting, audit
  app/data/              methodology checklists and the default finding library (JSON)
  app/templates/         Jinja2 report templates (HTML, Markdown)
  tests/                 pytest suite (auth, access control, scope, CVSS, importers, evidence, reports)
frontend/                React 19 + TypeScript + Vite + TanStack Query
samples/                 sample Nmap / nuclei / host-list output used by tests and the demo
```

In production a single container serves the API under `/api` and the built SPA at `/`.

## Security model

OffsecHub stores the most sensitive data a client has: a map of how to break in. The design reflects that.

- **Authentication.** Passwords are hashed with scrypt, and parameters are stored per hash so they can be raised later. Sessions are random tokens stored only as SHA-256, sent in an `HttpOnly`, `SameSite=Strict` cookie with a 12h default lifetime. Personal API tokens are hashed the same way, can expire, and can be revoked. Failed logins are throttled per IP and per email, and responses don't reveal whether an account exists.
- **CSRF.** Every cookie-authenticated state change must carry an `X-Requested-With` header, which browsers won't send cross-site without a CORS preflight that is never granted. Login is protected the same way.
- **Authorisation.** Global roles are admin, lead, tester and viewer. Non-admins only see engagements they are members of; everything else returns 404 so engagement existence doesn't leak. Scope changes and team management are restricted to engagement leads, and every object lookup is checked against its engagement. Viewers never receive draft findings in reports.
- **Untrusted input.** Scanner output is parsed with `defusedxml`, which rejects XXE and entity expansion. Evidence is stored under random keys, never user-supplied paths. Only raster images are served inline; everything else goes out as `application/octet-stream` attachments with a sandboxing CSP. Reports are autoescaped and served with a no-script CSP.
- **Headers.** Strict CSP, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, and HSTS when `OFFSECHUB_COOKIE_SECURE=true`.
- **Accountability.** An append-only audit trail keeps each user, action and IP, and survives engagement deletion.

**Before production:** serve it behind TLS with `OFFSECHUB_COOKIE_SECURE=true`, use PostgreSQL, and put the evidence volume on encrypted storage. Also read the hardening items in the [roadmap](docs/PRODUCT_STRATEGY.md#phase-1-production-foundations-must-have-before-real-client-data): MFA/SSO, encryption at rest, and migrations.

## Configuration

All settings are environment variables with the `OFFSECHUB_` prefix (see `.env.example` and `backend/app/config.py`):

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | SQLite in `backend/data/runtime/` | e.g. `postgresql+psycopg://user:pass@db/offsechub` |
| `STORAGE_DIR` | `backend/data/runtime/evidence` | Evidence file store |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | `admin@offsechub.local` / random | First-run admin account |
| `COOKIE_SECURE` | `false` | Set `true` behind HTTPS |
| `SESSION_TTL_HOURS` | `12` | Browser session lifetime |
| `MAX_UPLOAD_MB` | `50` | Evidence and import size limit |
| `LOGIN_MAX_ATTEMPTS` / `LOGIN_WINDOW_SECONDS` | `10` / `300` | Login throttling |
| `CORS_ORIGINS` | `[]` | Only needed if the UI is served from another origin |
| `API_DOCS` | `true` | Serve interactive API docs at `/api/docs` |

## CLI

```bash
python -m app.cli create-user alice@example.com "Alice Doe" --role lead
python -m app.cli seed-demo
```
