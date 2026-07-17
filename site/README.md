# AgentLint public site

This directory is the framework-free GitHub Pages surface for the AgentLint
Build Week demo. It is deliberately self-contained: no network fonts,
third-party JavaScript, analytics, or live scanning is required to open
`index.html`.

## Local asset expectations

The site source contains the landing-page shell only. A public-site build or
deployment should place these generated, safe-to-share assets alongside it:

- `reports/unsafe-report.html` — static `BLOCK` report generated from the
  deliberately unsafe fake fixture.
- `reports/safe-report.html` — static `PASS` report generated from the safe
  fake fixture.
- `fixtures/unsafe-project/README.md` — source README for the deliberately
  unsafe fake fixture.
- `assets/report-preview.png` — optional product-report preview used by the
  landing page; it must be an approved screenshot from the fake fixture, not a
  personal scan.

Keep report paths relative and portable. Do not publish a report generated from
a personal repository, because even redacted output can reveal project
structure.

## Public claims preserved by this page

- AgentLint is local and zero-execution: it does not start MCP servers, import
  scanned code, run scanned scripts, or contact endpoints discovered in a scan.
- The linked `BLOCK`, `PASS`, and fixture artifacts are generated fake-fixture
  snapshots, not a live remote scan.
- A `PASS` means no current deterministic rule or known coverage gap matched;
  it is not proof that every behavior is safe.
- The copy control only copies a command. It never invokes a local scan from
  the browser.

The visual system follows the project's warm-paper editorial identity using
system serif, sans-serif, and monospace fallbacks so the page remains usable
offline and without external fonts.
