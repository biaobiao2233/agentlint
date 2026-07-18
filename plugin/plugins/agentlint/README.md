# AgentLint Codex plugin

This plugin provides the `audit-agent-config` skill for AgentLint's local, zero-execution preflight. It does not start MCP servers, run scanned scripts, import scanned code, or contact discovered endpoints. It never modifies scanned configuration or input files; report files are created or overwritten only when a user requests a report path.

Reports use `.` for the scan root, replace account names in standard home-directory paths with `[USER]`, and retain relative evidence paths. Review them before sharing because project structure and redacted excerpts can still be sensitive; use the repository's portable `examples/unsafe-project` fixture for public screenshots or demo artifacts.

## Installation

From the AgentLint repository root, install the local marketplace and plugin:

```text
codex plugin marketplace add ./plugin
codex plugin add agentlint --marketplace agentlint-local
```

Open a new Codex task after installation, then invoke:

```text
Use $audit-agent-config to audit this repository and explain the effective agent policy.
```

Chinese example:

```text
使用 $audit-agent-config 审计这个仓库，并用中文解释有效指令和修复建议。
```

The skill explains results in the language used by the request when practical. The self-contained HTML report defaults to English with or without JavaScript; use the in-page **中文 / EN** control to switch manually, saving the choice in `localStorage`. The CLI terminal is still primarily English. Paths, line numbers, excerpts, rule/action/node IDs, scanned source text, and unknown-rule fallbacks stay in their original language for traceability.

## Supported platforms

Designed for Windows, macOS, and Linux with Python 3.11+ and a current Codex CLI or desktop app. Independent acceptance testing has run on Windows (Python 3.14); macOS and Linux still need independent runtime verification.

## Test path

From the AgentLint repository root, install the local CLI and run:

```text
python -m pip install -e ".[dev]"
agentlint scan plugin/plugins/agentlint --fail-on error
```

Expected result: `PASS` with 0 findings. This test scans the plugin package; it does not execute it.
