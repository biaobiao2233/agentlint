# AgentLint — submission draft

## Project name and tagline

**AgentLint**

**Preflight the agent infrastructure that will actually govern your repository.**

## Track

Developer Tools

## Problem

Agent repositories increasingly contain `AGENTS.md`, nested instructions, skills, Codex plugins, and MCP configuration. Reviewing each file independently misses the effective relationship: nearer instructions can change parent guidance, while a plugin can bundle skills and MCP settings that collectively request more authority than their individual files make obvious. Developers need a fast preflight before they install, share, or trust that configuration.

## What it does

AgentLint is a Codex-native local CLI and Codex plugin for a zero-execution preflight. It builds an Effective Instruction Graph from normative instruction facts, performs a Codex Plugin Contract Audit, and draws a Capability-to-Authority Map from supported manifest references and parsed configuration. It produces terminal, JSON, and self-contained HTML reports with `BLOCK`, `REVIEW`, or `PASS` verdicts. The same offline HTML report defaults to English without JavaScript and supports automatic or manual Simplified Chinese browsing when JavaScript is available.

It never starts a discovered MCP server, imports scanned code, runs scanned scripts, contacts endpoints in a scanned repository, or modifies scanned configuration/input files. It creates or overwrites reports only at output paths explicitly requested by the user. Known literal credential patterns are redacted before report serialization, subject to heuristic limits. `PASS` means no current deterministic rule matched; it is not a security certification.

**Live judge demo:** [open the static fake-fixture snapshot](https://biaobiao2233.github.io/agentlint/). It is not a hosted scanner; it links to the generated `BLOCK`/`PASS` reports, fixture source, repository, and video. Its current unsafe-fixture baseline is `BLOCK` with 5 errors and 6 warnings.

## How it was built

Built during OpenAI Build Week with Codex and GPT-5.6. Codex accelerated implementation iteration, code navigation, test/fixture design, plugin packaging, bilingual offline-report delivery, report verification, and English delivery writing. Human decisions set the product boundaries: local-only scanning, zero execution, explicit redaction, evidence-bound language, and no automatic remediation.

The runtime uses local Python parsing and has no OpenAI API dependency. The Build Week `$100 / 2,500` Codex credit grant is for building and iterating on AgentLint, not for scanning projects.

## Challenges

The hardest design constraint was being useful without becoming an execution path. The scanner must understand configuration relationships well enough to show instruction precedence and declared authority, while treating every scanned file as untrusted data. Another challenge was keeping the unsafe demonstration realistic enough to explain risks without shipping real credentials, active infrastructure, or instructions that should be run.

## Accomplishments

- A working local CLI with JSON and self-contained HTML evidence.
- A bilingual offline HTML report: English fallback without JavaScript, Simplified Chinese auto-selection/manual switching with JavaScript, and original-language technical evidence.
- Explicit effective-instruction chains for Codex guidance.
- Cross-component mapping from plugins to skills and MCP configuration.
- An installable Codex plugin with a bounded, zero-execution audit skill.
- Runnable safe and deliberately unsafe fake fixtures for judges.

## What I learned

Agent tooling is configuration infrastructure. The important review unit is often not a file or a single rule; it is the effective relationship among inheritance, packaging, declared tools, and approval boundaries. Codex and GPT-5.6 were most valuable as a disciplined implementation partner when prompts specified scope, evidence, and a validation target.

## What’s next

Expand parser coverage for additional configuration shapes, improve report navigation for larger repositories, add carefully versioned rule packs, and validate findings against representative real-world plugin repositories without changing the zero-execution threat model.

## Testing path

Designed for Python 3.11+ on Windows, macOS, or Linux. Independent acceptance testing has run on Windows (Python 3.14); macOS and Linux still require runtime verification:

```bash
python -m pip install -e ".[dev]"
pytest
agentlint scan examples/safe-project --fail-on error
agentlint scan examples/unsafe-project --fail-on never --html reports/unsafe.html
```

The `safe-project` should PASS. `unsafe-project` is a clearly labeled fake fixture; it should report BLOCK findings and must not be executed. The README also documents plugin and skill validation commands.

The Pages artifact is reproducible with `python scripts/build_public_site.py --output public-demo`; it regenerates both public reports from the repository fixtures and refuses to overwrite an existing output directory.

## Privacy and limitations

AgentLint runs locally and does not call an API or send scanned configuration to a service. JSON, HTML, and terminal reports use a portable `.` scan root and relative evidence paths by default; URL query values are removed before report serialization. Reports can still contain relative project structure and redacted excerpts, so review them before sharing. Public screenshots, committed artifacts, and the demo use the portable `examples/unsafe-project` fixture rather than a personal scan output. A skipped supported configuration, skipped link/reparse directory, or project instruction byte limit is surfaced as `COVERAGE002` rather than returning PASS. AgentLint is deterministic and cannot prove runtime behavior, intent, or safety; it does not replace Codex approval settings, a sandbox, secret management, or human security review.
