# Changelog

## 0.3.0 (2026-11-12)

### Reports
- **PDF export**, built directly (no printing from a browser), with a linked table of contents, bookmarks and "Page X of Y".
- **Word export** from a built-in template, or from your own: download the built-in one, restyle it in Word and upload it. Templates render in a sandbox. See [docs/REPORT_TEMPLATES.md](https://github.com/ajfan6T/offsechub/blob/HEAD/docs/REPORT_TEMPLATES.md).
- **Branding** for every format: logo, accent colour, classification and footer text, stored inside the vault.
- **Formatted finding text:** bold, italic, code, links, lists, headings and code blocks, with a preview in the editor and the same rendering in every report format.

### Findings
- **CVSS 4.0** scoring and calculator, next to CVSS 3.1. Nuclei imports keep 4.0 vectors.
- **Retest tracking:** record each retest (resolved, partially resolved, not resolved) with its date, tester and notes. A resolved retest marks the finding remediated. Reports show a retest column and the history.
- **Exports for ticketing:** CSV for Jira (safe against spreadsheet formulas), SARIF 2.1.0 and DefectDojo JSON.

### Imports
- **Burp Suite** issues (XML) and **Nessus** (`.nessus`) results, from the app or with `offsechub import … --tool burp|nessus`.

### Working with others
- **Engagement hand-off:** export an engagement, evidence included, as one file encrypted with a passphrase. A colleague imports it into their own vault. The format is in [docs/VAULT_FORMAT.md §9](https://github.com/ajfan6T/offsechub/blob/HEAD/docs/VAULT_FORMAT.md#9-hand-off-files-ohengagement).

### Installers and trust
- Installers for **Intel Macs** and **Linux arm64**, alongside Apple silicon, Windows x64 and Linux x64.
- **MIT licence**, with the bundled components listed in [THIRD_PARTY_NOTICES.md](https://github.com/ajfan6T/offsechub/blob/HEAD/THIRD_PARTY_NOTICES.md).
- **Check for updates** in Settings. It is the app's only network request, made only when you click it, and it downloads nothing.

### Upgrading
- Vaults from 0.2.0 are upgraded when you unlock them. After that, 0.2.0 can no longer open them, so upgrade every machine you use the vault on.
