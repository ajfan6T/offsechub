# Word report templates

OffsecHub writes Word reports from a template: a normal `.docx` file with tags in it. You can use the built-in template, or make your own with your company's layout, fonts, boilerplate and sections.

The easiest start is the built-in template. In **Settings > Word report templates**, click **Download the built-in template**, open it in Word, change what you like, and upload it again. Pick the default template in the same place, or choose one per export on the Report page.

Templates use [docxtpl](https://docxtpl.readthedocs.io/) tags, which are Jinja tags typed into the document. Type them as plain text. Word sometimes splits a tag across formatting runs, so if a tag doesn't work, retype it in one go without changing its formatting halfway.

## Tags

| Tag | Use it for |
|---|---|
| `{{ engagement.name }}` | Inserts a value. |
| `{% if draft %}…{% endif %}` | A condition or loop inside one paragraph. |
| `{%p if f.impact %}` … `{%p endif %}` | A condition or loop around **whole paragraphs**. Each tag goes in a paragraph of its own, which is removed from the output. |
| `{%tr for f in findings %}` … `{%tr endfor %}` | Repeats **table rows**. Each tag goes in a row of its own: the rows between them repeat. |
| `{{p f.rt.description }}` | **Formatted text** as real Word paragraphs: headings, lists, code blocks, bold, italic, links. Give it a paragraph of its own. |
| `{{r r.notes_rt }}` | Formatted text squeezed into one paragraph, for table cells. |
| `{% cellbg f.severity_fill %}` | Colours the table cell the tag is in, for example by severity. |
| `{{ img.inline }}` | A screenshot, sized to the page. Give it a paragraph of its own. |

Filters work as in Jinja: `{{ f.targets|join(', ') }}`, `{{ f.targets|length }}`, `{{ f.cwe or '-' }}`.

## What a template can use

Text values are inserted as plain text. A value that contains `<`, `&` or tags from a scanner stays literal.

**Engagement and client**

| Name | Value |
|---|---|
| `engagement.name`, `engagement.code`, `engagement.type`, `engagement.status` | The engagement. `type` is a label, such as "External Network Penetration Test". |
| `engagement.start_date`, `engagement.end_date` | `YYYY-MM-DD`, or empty |
| `engagement.executive_summary`, `engagement.description`, `engagement.rules_of_engagement` | The text as typed, with Markdown marks. For formatting, use `rt.*`. |
| `rt.executive_summary`, `rt.description`, `rt.rules_of_engagement` | The same text formatted, for `{{p … }}` |
| `client.name`, `client.contact_name` | The client |
| `prepared_by.name`, `prepared_by.organization`, `prepared_by.email` | Your profile (Settings > Profile) |
| `prepared_by_line` | "Name, Organisation", whichever parts are set |
| `generated_at` | The time the report was made, for example `2026-11-12 09:30 UTC` |
| `draft` | True when drafts are included, or the engagement isn't delivered or closed yet |

**Branding** (Settings > Report branding)

| Name | Value |
|---|---|
| `branding.organization`, `branding.classification`, `branding.footer` | Text. An empty classification means none. |
| `branding.accent` | The accent colour as `#rrggbb`. The built-in template uses it for headings; in your own template, set colours in Word's styles. |
| `logo` | Your logo as a picture, up to 55 × 22 mm, or empty. Give it a paragraph of its own: `{{ logo }}`. |

**Totals, scope and coverage**

| Name | Value |
|---|---|
| `total_findings` | How many findings the report contains |
| `severity_counts.critical`, `.high`, `.medium`, `.low`, `.info` | How many of each |
| `retested` | True if any finding has a retest |
| `scope.include`, `scope.exclude` | Lists of `kind`, `value`, `notes` |
| `targets` | In-scope targets: `value`, `hostname`, `ip`, `os`, `status`, `status_label`, `services` (a list of text such as `443/tcp https nginx 1.25`) |
| `coverage` | One row per checklist: `methodology`, `total`, `passed`, `failed`, `not_applicable`, `blocked`, `incomplete` |
| `evidence_fingerprints` | Every evidence file: `finding` (its reference), `filename`, `size`, `sha256` |

**Findings** (`{%p for f in findings %}`, ordered by severity, then CVSS score)

| Name | Value |
|---|---|
| `f.ref`, `f.title` | For example `ACME-EXT-001` and its title |
| `f.severity`, `f.severity_label`, `f.severity_short`, `f.severity_fill` | `high`; `High` (`Informational` for info); `High` (`Info`); the colour for `cellbg` |
| `f.status`, `f.status_label` | `confirmed`; `Confirmed` |
| `f.cvss_score`, `f.cvss_score_text`, `f.cvss_vector`, `f.cvss_version` | `7.5` or empty; `7.5` or `-`; the vector; `3.1` or `4.0` |
| `f.cvss_text` | For example `7.5 (CVSS v3.1) CVSS:3.1/AV:N/…`, or `-` |
| `f.cwe` | For example `CWE-79` |
| `f.description`, `f.impact`, `f.steps_to_reproduce`, `f.remediation` | The text as typed |
| `f.rt.description`, `f.rt.impact`, `f.rt.steps_to_reproduce`, `f.rt.remediation` | The same, formatted, for `{{p … }}`. Steps to reproduce without any formatting become a code block, since they are usually a raw request. |
| `f.references` | A list of lines |
| `f.targets` | A list of affected assets |
| `f.images` | Screenshots: `inline` (the picture), `filename`, `description`, `sha256`, `size`, `content_type` |
| `f.attachments` | Other evidence: `filename`, `description`, `sha256`, `size`, `content_type`, and `problem` when a picture couldn't be used |
| `f.retests` | Retests, oldest first: `tested_on`, `result`, `label` (such as `Not resolved`), `tester`, `notes`, `notes_rt` (formatted, for `{{r … }}`) |
| `f.retest_status`, `f.retest_label` | The latest result: `resolved`, `partially_resolved`, `not_resolved` or empty; its label, or `-` |

## Styles for formatted text

`{{p … }}` gives each block a paragraph style by name. A template that lacks a style uses Word's default paragraph style for it.

| Block | Style |
|---|---|
| Paragraph | the paragraph's own style |
| Heading (`#` to `######`) | `Heading 4` |
| Bulleted list | `List Bullet` |
| Numbered list | `OH Numbered` (the number and a tab are part of the text) |
| Code block | `OH Code` |

Links are blue and underlined. Code inside a line uses Consolas.

## Safety

A template can come from anyone, so OffsecHub treats it as untrusted:

- It must be a `.docx` of at most 5 MB, and no larger than 64 MB unpacked.
- Its parts must not contain `<!DOCTYPE` or `<!ENTITY` (pictures aside).
- Its tags must be valid. Errors are shown when you upload it.
- It renders in Jinja's sandbox: it can read the values above, but not reach Python, files, or the insides of pictures and formatted text. Enormous repetitions, powers and padding, such as `{{ 'x' * 10**9 }}` or `{{ 'x'.center(10**9) }}`, are refused.
- It renders in a separate process, which is stopped if it takes more than two minutes.

Templates are stored inside the encrypted vault, like the logo.

## Values that are not available

Values that the HTML report gets as data URIs (`img.data_uri`, `branding.logo_data_uri`) or raw bytes are not passed to Word templates. Use `img.inline` and `logo` instead.
