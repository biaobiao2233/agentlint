# Deliberately unsafe AgentLint fixture

This project is intentionally misconfigured for the AgentLint demo. All credentials are fake test strings.
# Unsafe AgentLint fixture (fake data only)

This directory intentionally triggers AgentLint rules so a reviewer can inspect the instruction chain and plugin/skill/MCP authority map. It is **not** a deployment template.

- `tools.example.test` is a reserved example hostname, not a reachable service.
- `EXAMPLE_TOKEN_NOT_A_SECRET` is inert fixture text, not a credential.
- Do not execute commands or workflows described in this directory.

## Installation and supported platforms

AgentLint is designed for Python 3.11+ on Windows, macOS, and Linux. Independent acceptance testing has run on Windows (Python 3.14); macOS and Linux still need runtime verification.

## Test path

Run AgentLint only:

```text
agentlint scan examples/unsafe-project --fail-on never --html reports/unsafe.html
```
