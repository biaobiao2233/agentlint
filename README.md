# AgentLint

> [简体中文使用说明](README.zh-CN.md)

**AgentLint is a Codex-native, local, zero-execution preflight for the agent configuration that will actually govern a repository.**

[▶ Watch the 2:53 OpenAI Build Week demo on YouTube](https://youtu.be/WxO-wCy0a8E)

It answers three practical questions before an agent configuration is installed, shared, or trusted:

1. What instructions are effective at this directory, and which nearer instruction changes an ancestor rule?
2. Does a Codex plugin and its skills meet the plugin/skill contract?
3. Which declared capabilities connect instructions, skills, plugins, and MCP configuration?

AgentLint produces an **Effective Instruction Graph**, a **Codex Plugin Contract Audit**, and a **Capability-to-Authority Map**. It reads configuration as untrusted data and never starts MCP servers, imports scanned code, executes scripts, or contacts endpoints found in a scan.

## Why this exists

Agent configuration is infrastructure: `AGENTS.md`, `SKILL.md`, plugin manifests, and MCP settings can change what an agent is instructed or allowed to do. A nested instruction can weaken a parent boundary; a plugin can bundle a skill and MCP configuration with a larger effective authority than a quick file-by-file review reveals.

AgentLint makes that relationship inspectable before execution. It is not a security certification, a sandbox, a secrets manager, or a replacement for Codex approvals and human review.

## Install and run

AgentLint is designed for Windows, macOS, and Linux with Python 3.11+ through its standard-library `pathlib` implementation. Independent acceptance testing has run on Windows (Python 3.14); macOS and Linux still require independent runtime verification.

```bash
# uv (recommended)
uv venv
uv pip install -e ".[dev]"

# or pip
python -m pip install -e ".[dev]"

# from a source checkout without relying on the console-script entry point
python -m agentlint --version
```

The runtime has no OpenAI API dependency and does **not** consume OpenAI API credits. The Build Week `$100 / 2,500` Codex credit grant is for construction and iteration of this project, not for AgentLint scans.

## Quickstart

```bash
# start with the included safe fixture; it should PASS and exit 0
agentlint scan examples/safe-project --fail-on error

# generate portable evidence from the deliberately unsafe fake fixture
# (the report is expected to be BLOCK; --fail-on never keeps this demo command successful)
agentlint scan examples/unsafe-project --json reports/unsafe.json --html reports/unsafe.html --fail-on never

# discover the deterministic rule catalog
agentlint rules
```

To audit another repository, point the command at that repository's root. The
AgentLint source checkout intentionally contains an unsafe fake fixture, so
`agentlint scan .` is expected to BLOCK unless you exclude `examples`.

`--json` is the machine-readable source of truth. `--html` creates a self-contained report that can be opened locally. Use `--exclude DIR` (repeatable) to skip directory names, `--no-color` for plain terminals, and `--quiet` to suppress console findings.

The same self-contained HTML report supports bilingual browsing. With JavaScript disabled it defaults to English. With JavaScript enabled, it automatically selects Simplified Chinese when `navigator.language` is Chinese and no saved preference exists; use the in-page **中文 / EN** control to switch manually. The choice is saved in `localStorage`. Technical evidence—messages not covered by UI translations, paths, line numbers, excerpts, rule/action/node IDs, and scanned source text—remains in its original language so the report stays traceable; unknown rule IDs use an honest fallback.

AgentLint never modifies scanned configuration or input files. It writes only the report paths explicitly passed through `--json` and/or `--html`; those selected output files may be created or overwritten. The Codex plugin follows the same boundary when a user requests report files.

Local reports intentionally retain the actual scan root and related paths so a developer can locate the evidence. That is useful local audit context, not a defect. Review a real report before sharing it outside the repository. For public screenshots, demos, or committed artifacts, use the portable [`examples/unsafe-project`](examples/unsafe-project) fixture rather than a personal scan output.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No findings at the requested `--fail-on` threshold, or `--fail-on never`. |
| `1` | Findings reached the requested threshold (`error` by default; `warning` is stricter). Reports may still have been written. |
| `2` | AgentLint could not scan the target or write/read a required path. |

The report verdict is `BLOCK` when it has errors, `REVIEW` when it has warnings only, and `PASS` when no deterministic rule matched. `PASS` is not proof of safety.

## Try the included fixtures

Install once from the repository root, then run:

```bash
agentlint scan examples/safe-project --json reports/safe.json --html reports/safe.html
agentlint scan examples/unsafe-project --json reports/unsafe.json --html reports/unsafe.html --fail-on never
```

`safe-project` is designed to **PASS**. `unsafe-project` is a deliberately unsafe **fake fixture**, never a deployment recipe: its `.test` endpoint, `EXAMPLE_*` token, and shell/deploy language are inert sample text. It demonstrates a parent/child instruction conflict and a plugin → skill → MCP authority chain; AgentLint only reads it.

Open `reports/unsafe.html` and inspect the Effective Instruction Graph and Capability-to-Authority Map. The current fixture baseline is `BLOCK`: 5 errors, 6 warnings, and 0 info findings. Its IDs are `MCP001`, `MCP002`, `MCP003`, `MCP004`, `MCP005`, `POLICY001`, `POLICY002`, `POLICY003`, `POLICY004`, `AUTH001`, and `SKILL003`. The fixture deliberately includes inert fake text for secret disclosure and high-risk skill authority; it never contains a real credential, reachable endpoint, or executable deployment file.

## Rules and limits

Current deterministic checks cover supported configuration formats, Codex plugin and skill contracts, instruction facts, and selected MCP declarations. The Effective Instruction Graph records normative instruction facts; the Capability-to-Authority Map records evidence-bound edges from supported manifest references and parsed configuration. It does not verify every possible runtime relationship. `agentlint rules --json` exposes the exact catalog.

Limits matter: AgentLint does not execute, dynamically interpret, prove intent, verify a server's behavior, discover configuration it cannot read, or replace a code/security review. Known literal credential patterns are redacted before report serialization, but redaction is heuristic and cannot guarantee that every sensitive value is detected. Nested directory symlinks and Windows junction/reparse-point entries are not followed and are recorded as coverage gaps. A scan root that is a symlink or Windows reparse point is rejected with the CLI failure path (exit code `2`), rather than followed. Plugin and skill component references through a symlink or reparse point are rejected as invalid local targets. Treat findings as evidence for a bounded human decision.

## Codex plugin

The distributable plugin is in [`plugin/plugins/agentlint`](plugin/plugins/agentlint). It contains the `audit-agent-config` skill, which is appropriate before installing, sharing, or debugging `AGENTS.md`, `AGENTS.override.md`, `SKILL.md`, `.codex-plugin/plugin.json`, `.mcp.json`, or `.codex/config.toml`.

The repository includes an official repo-marketplace layout at [`plugin/.agents/plugins/marketplace.json`](plugin/.agents/plugins/marketplace.json), with the plugin at `plugin/plugins/agentlint`. With a current Codex CLI, run these commands from the repository root:

```bash
codex plugin marketplace add ./plugin
codex plugin list --marketplace agentlint-local --available --json
codex plugin add agentlint --marketplace agentlint-local
```

The CLI installs the local snapshot. In the Codex desktop app, restart or open a new task after installation, then enable the plugin if the Plugins directory shows it disabled. After changing plugin files, run `codex plugin remove agentlint`, re-add it with the last command, and restart/open a new task so the cached local copy reloads. This flow applies to the Codex CLI and desktop app marketplace surface; support can vary by Codex version and workspace policy.

Then invoke the installed skill with a request such as:

```text
Use $audit-agent-config to audit this repository and explain the effective agent policy.
```

The skill requires a confirmed target, invokes the local CLI, reads the generated JSON report, and never authorizes executing scanned MCP servers, scripts, or code.

## Test path

```bash
python -m pip install -e ".[dev]"
pytest
# Maintainers: macOS/Linux, with CODEX_SKILLS set to Codex's bundled skill directory
python "$CODEX_SKILLS/plugin-creator/scripts/validate_plugin.py" plugin/plugins/agentlint
python "$CODEX_SKILLS/skill-creator/scripts/quick_validate.py" plugin/plugins/agentlint/skills/audit-agent-config

# Maintainers: Windows PowerShell, with $env:CODEX_SKILLS set to the same directory
python "$env:CODEX_SKILLS\plugin-creator\scripts\validate_plugin.py" plugin/plugins/agentlint
python "$env:CODEX_SKILLS\skill-creator\scripts\quick_validate.py" plugin/plugins/agentlint/skills/audit-agent-config
agentlint scan examples/safe-project --fail-on error
agentlint scan examples/unsafe-project --fail-on never
```

Set `CODEX_SKILLS` to the directory containing Codex's bundled `plugin-creator` and `skill-creator` skills (the local validation record identifies the path used in this workspace). The last two commands provide a judge-friendly runnable test path without rebuilding the product. See [`docs/validation.md`](docs/validation.md) for the commands and recorded results from this workspace.

## Architecture

```text
non-executing discovery; no scanned-input modification
  ├─ AGENTS.md / AGENTS.override.md ──> Effective Instruction Graph
  ├─ plugin.json + SKILL.md ──────────> Codex Plugin Contract Audit
  └─ .mcp.json + config.toml ─────────> Capability-to-Authority Map
                                      └> JSON, self-contained HTML, terminal evidence
```

Parsing and reporting are local. The graph records declared relationships, not runtime behavior or authorization grants.

## Built with Codex and GPT-5.6

AgentLint was built and iterated with Codex and GPT-5.6 during OpenAI Build Week. Codex accelerated repository exploration, fixture design, CLI/report validation, plugin packaging, and documentation drafting. The human author made the product-scope decisions: make the scanner zero-execution, keep claims evidence-bound, preserve review/approval boundaries, and distinguish a deterministic preflight from a security guarantee.

## Difference from adjacent tools

Tools such as agnix, Snyk Agent Scan, Cisco Skill/MCP Scanner, skillcheck, and Promptfoo address valuable parts of the agent-security and evaluation landscape. AgentLint's focus is narrower and Codex-specific: it explains inherited Codex instructions and maps the cross-component relationship between a plugin, its skills, MCP configuration, and the authority each asks for. It does not claim to replace those tools or to be a complete security solution.

## License

MIT. See [`LICENSE`](LICENSE).
