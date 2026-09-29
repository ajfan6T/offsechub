# OffsecHub: product direction

## Position

**A private, encrypted workspace for the individual operator,** not another team reporting platform.

The multi-user web space (PlexTrac, AttackForge, Dradis, Ghostwriter, SysReptor, PwnDoc) is mature and crowded, and every entrant carries the same central liability: a server that aggregates many clients' attack maps. OffsecHub competes on a different axis: **data custody and zero infrastructure.**

- **For freelancers and small consultancies.** Nothing to host, patch or pay for. It answers "where is our data stored?" in a client security questionnaire with one sentence and a public format spec.
- **For internal red-teamers.** It works inside restricted networks and on air-gapped test laptops, and it keeps a deconfliction-grade operator log.
- **For anyone.** One encrypted folder per client or per year. Archive it, back it up, or crypto-erase it when the retention period ends.

## Principles

1. **Local-first:** no account, no telemetry, no network by default.
2. **Security claims are testable claims:** every control maps to a test, and every limit is written down ([threat model](THREAT_MODEL.md)).
3. **No lock-in:** an open, fully specified [format](VAULT_FORMAT.md) with an independent decoder.
4. **Never lose the operator's work:** durability bugs count as security bugs.

## Roadmap

**Near term**

- DOCX export from custom report templates (the thing that replaces Word in practice).
- More importers: Burp Suite, Nessus, BloodHound, ffuf/httpx JSON; C2 event logs (Sliver, Mythic) into the op log.
- Lock on OS sleep and session-lock events; draft autosave inside the vault.
- Signed releases, an SBOM, and reproducible PyInstaller builds.

**Collaboration without a server**

- **Encrypted engagement hand-off:** export one engagement as a single file encrypted to a colleague's public key (age-compatible), and import it on their side.
- Fork detection for vaults synced between machines (per-snapshot ids and an ancestry list).

**Assurance**

- Signed, timestamped evidence manifests (Ed25519 plus RFC 3161) to move from integrity fingerprints towards provenance.
- The unlocked vault in a short-lived child process, so locking returns memory to the OS.
- Property-based and fuzz testing of the importers and the vault reader.
