# OffsecHub: product view and roadmap

## 1. The short version

**The problem is real, and the market has already shown that people pay to solve it.** Offensive security work is run out of a patchwork today: a spreadsheet for scope, a notes app for recon, a folder of screenshots, a Word template, and email threads with the client. The hardest parts of an engagement often aren't technical:

- **Staying in scope.** Touching an asset you weren't authorised to test is the biggest legal and reputational risk a tester carries.
- **Writing the report.** It's widely cited as one of the most time-consuming, least-loved parts of an engagement, and it's the only thing the client actually receives.
- **Proving what you did.** When the SOC calls, or a client disputes a finding, you need timestamps, commands and evidence with integrity.

**But "a pentest management tool" is not differentiated by itself.** There are established players:

- **Commercial reporting and collaboration platforms:** PlexTrac, AttackForge, Dradis Pro.
- **Open-source tools:** Ghostwriter (SpecterOps), SysReptor, PwnDoc, Faraday, Dradis CE, Reconmap.
- **Services with their own platforms:** PTaaS providers such as Cobalt, Synack and NetSPI.

A new entrant wins on a sharp wedge, not on feature parity.

**Where OffsecHub can win:**

1. **Safety as a product feature.** Scope is enforced, not just recorded. This MVP already checks targets live, guards imports, and keeps exclusions ahead of inclusions. The next step is DNS resolution and ownership validation, plus a hard gate that stops an engagement going active without signed authorisation. No competitor makes "you cannot accidentally test the wrong thing" the headline.
2. **Tool output → triaged findings, fast.** Scanners are noisy. The loop of import, group, triage as draft, promote with a library write-up, then attach evidence is where hours are saved. Owning the best version of that pipeline matters more than having the prettiest editor.
3. **Red-team-grade accountability.** The operator log, deconfliction export, chain-of-custody hashes and an audit trail that survives deletion. Internal red teams and regulated clients care about these, and most reporting tools treat them as an afterthought.
4. **Deployment and data posture.** Many consultancies and most internal red teams will not put client vulnerability data in someone else's multi-tenant SaaS. A credible self-hosted and air-gapped edition is a real differentiator, not a checkbox.

**The biggest risks:**

- **You become the target.** The platform concentrates every client's attack path. A breach ends the company. Security engineering (encryption at rest, MFA/SSO, isolation, audit, an external pentest of the product itself) has to lead the roadmap, not trail it.
- **"Our Word template" inertia.** Every consultancy has a branded template that clients are used to. Without **DOCX template export** you won't displace Word, however good the web UI is.
- **Integration breadth.** Testers live in Burp, Nessus, BloodHound and their C2. Every missing importer is a reason to keep the spreadsheet.
- **Enterprise sales friction.** SOC 2 and security questionnaires come with the territory.

## 2. What exists today (MVP in this repository)

| Area | Status |
|---|---|
| Case management | ✅ Clients, engagements, status workflow, dates, rules of engagement, team roles, dashboard |
| Scope definition | ✅ IP/CIDR/range/host/wildcard/URL/other rules, exclusions, scope checker, bulk entry |
| Target tracking | ✅ Hosts/domains/web apps, services, tags, status incl. compromised, live scope status |
| Reconnaissance | ✅ Nmap XML, nuclei JSON/JSONL, host lists; scope guard; raw output kept as evidence |
| Testing | ✅ 5 methodologies (WSTG, API Top 10, external, internal/AD, AWS), per-target checklists, assignment |
| Evidence | ✅ Uploads + pasted text, SHA-256, safe serving, linking to findings/targets/tests |
| Findings | ✅ CVSS 3.1 calculator, CWE, workflow, affected assets, library (14 templates) |
| Reporting | ✅ Readiness checks, exec summary, HTML/PDF (print), Markdown, JSON |
| Accountability | ✅ Operator log + CSV, audit trail, API tokens for automation |
| Platform | ✅ RBAC, CSRF protection, hardened headers, Docker/compose, CI on SQLite + PostgreSQL |

**Known MVP limitations** (deliberate, and listed so nobody mistakes the MVP for production-ready):

- Schema is created with `create_all`. There are no migrations yet.
- Evidence sits on local disk unencrypted. Uploads are read into memory, up to a 50 MB cap.
- Login throttling is in-process (single node).
- Scope checks don't resolve DNS, so a hostname in scope that points at a third-party IP isn't flagged.
- Findings are plain text (no rich formatting or inline images inside the narrative).
- PDF means "print the HTML". There is no DOCX export.
- The *viewer* role sees draft findings in the UI; only reports are filtered. A proper client portal fixes this.

## 3. Roadmap to a complete product

### Phase 1: Production foundations (must-have before real client data)

- **Migrations:** Alembic, with upgrade tests in CI.
- **Identity:** TOTP and WebAuthn MFA (enforceable per org), OIDC/SAML SSO, SCIM provisioning, session management UI.
- **Encryption at rest:** envelope encryption with one data key per engagement, wrapped by a KMS/Vault master key. This enables **crypto-shredding** when a contract's retention period ends.
- **Object storage:** S3/MinIO, streaming multipart uploads, malware scanning of uploads (e.g. ClamAV), per-file retention.
- **Background jobs:** a worker queue (arq/Celery + Redis) for large imports and report rendering. The login throttle moves to Redis too.
- **Tamper-evident audit:** hash-chain audit events, with export to SIEM (syslog/HTTP).
- **Supply chain and assurance:** SAST, dependency scanning, container scanning, SBOM and signed images in CI, and **an independent pentest of OffsecHub** before launch.
- **Operations:** structured logs, metrics, health/readiness probes, backups with tested restores.

### Phase 2: Reporting that replaces Word (the reason teams switch)

- **DOCX export from customer templates** (docxtpl), plus server-side PDF (headless Chromium). Branded cover pages, tables of contents, and appendices.
- **Rich finding content:** sanitised Markdown, code blocks, and inline screenshots with captions and redaction (blur/box).
- **QA workflow:** peer review per finding (comments, approve/request changes), report versions, sign-off, and a delivery log recording who sent what, when.
- **Library 2.0:** variables (`{{affected_host}}`), per-client overrides, versioned templates, multilingual write-ups.
- **Risk models:** CVSS 4.0 alongside 3.1, OWASP Risk Rating, custom likelihood × impact matrices.
- **Retest reports:** a delta view showing fixed, partially fixed and not fixed, with retest evidence.

### Phase 3: Integrations and automation

- **Importers:** Burp Suite, Nessus, Qualys, OpenVAS, OWASP ZAP, masscan, httpx JSON, BloodHound, Prowler/ScoutSuite (cloud), MobSF (mobile).
- **Automatic operator log:** ingest Cobalt Strike, Mythic, Sliver or Havoc event logs so the op log fills itself.
- **Tester tooling:** an `ohub` CLI, a Burp extension that sends a request/response straight to a finding, and a screenshot capture helper.
- **Outbound:** Jira, ServiceNow, Azure DevOps and GitHub issues for remediation, Slack/Teams notifications, and signed webhooks.
- **Scope intelligence:** resolve DNS continuously and warn when an in-scope name points outside scope (CDNs, third-party SaaS). Also show WHOIS/ASN ownership hints and certificate transparency for discovery.
- **Enrichment:** NVD, EPSS and CISA KEV for CVEs; MITRE ATT&CK mapping for red team activity.

### Phase 4: Collaboration and the client side

- **Pre-engagement:** scoping questionnaire, SOW/quote, and e-signed authorisation letter. Scope is imported from the signed document, and an engagement **cannot become Active without authorisation on file**.
- **Testing window enforcement:** warn on (or block) imports and op-log entries outside the agreed window.
- **Client portal:** clients see delivered findings only, comment, upload remediation evidence, request retests, and track severity-based SLAs.
- **Team operations:** scheduling and capacity planning, time tracking, real-time presence, comments and @mentions.
- **Credential vault:** encrypted, access-logged storage for credentials captured during internal and red team tests.

### Phase 5: Intelligence (and AI, carefully)

- **Analytics:** recurring findings per client, time-to-remediate, trends across engagements, and team throughput.
- **De-duplication:** merge findings across tools and engagements.
- **Attack path view:** a graph of targets, credentials and compromises for red team narratives.
- **AI assistance:** draft write-ups from evidence and tool output, first-draft executive summaries, and severity suggestions. This is only viable with strict controls: opt-in per client, a self-hosted model option, no training on customer data, automatic redaction, and mandatory human review. For this audience, getting data handling wrong costs more than having no AI at all.

### Phase 6: Business and compliance

- **Tenancy:** multi-tenant SaaS with PostgreSQL row-level security, single-tenant hosted, self-hosted, and an **air-gapped** offline bundle.
- **Compliance:** SOC 2 Type II and ISO 27001, plus report formats that satisfy PCI DSS 11.4 and CREST/CHECK-style requirements.
- **Packaging:** a free self-hosted Community edition for a single team, to drive adoption among practitioners. A paid Team/Enterprise edition adds SSO, the client portal, DOCX templates, audit export, support and SLAs.

## 4. Who to build for first

**Primary:** boutique and mid-size pentest consultancies (roughly 5-50 testers). They feel the reporting pain most, buy quickly, and value self-hosting.

**Secondary:** internal red teams and offensive security teams in regulated enterprises. Deconfliction, audit and on-prem matter most to them.

**Later:** MSSPs and PTaaS providers, who need multi-tenancy, client portals and SLAs.

Positioning: *"The offensive security workspace that keeps you in scope and gets the report out the door."*

## 5. Suggested next 90 days

1. **Weeks 1-4: production foundations.** Migrations, MFA, encrypted object storage, background jobs, backup/restore.
2. **Weeks 5-8: DOCX template reporting and a QA review workflow.** This is the adoption unlock.
3. **Weeks 9-10: Burp and Nessus importers, and the `ohub` CLI.**
4. **Weeks 11-12: design partners.** Put it in front of 3-5 consultancies and measure before building the client portal.

**Metrics to watch:**

- Days from last testing day to report delivered.
- Share of findings created from the library.
- Imported results triaged within 48h.
- Scope incidents, which should be zero.
- Weekly active testers per team.
