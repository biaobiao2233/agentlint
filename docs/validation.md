# Validation record

This record is intentionally limited to commands run against the local checkout. Run them again after any code, fixture, or plugin change.

## Plugin and skill contract

Portable maintainer form (set `CODEX_SKILLS` to the directory containing the two bundled Codex skills):

```text
# macOS/Linux
python "$CODEX_SKILLS/plugin-creator/scripts/validate_plugin.py" plugin/plugins/agentlint
python "$CODEX_SKILLS/skill-creator/scripts/quick_validate.py" plugin/plugins/agentlint/skills/audit-agent-config

# Windows PowerShell
python "$env:CODEX_SKILLS\plugin-creator\scripts\validate_plugin.py" plugin/plugins/agentlint
python "$env:CODEX_SKILLS\skill-creator\scripts\quick_validate.py" plugin/plugins/agentlint/skills/audit-agent-config
```

Recorded local outcome on 2026-07-17 (with `<CODEX_SKILLS>` and `<repo>` substituted locally):

```text
python <CODEX_SKILLS>/plugin-creator/scripts/validate_plugin.py <repo>/plugin/plugins/agentlint
exit 0 — plugin validation passed

python <CODEX_SKILLS>/skill-creator/scripts/quick_validate.py <repo>/plugin/plugins/agentlint/skills/audit-agent-config
exit 0 — skill validation passed
```

These are the local OpenAI bundled plugin validator and skill quick validator. The plugin manifest keeps `.codex-plugin/` limited to `plugin.json`; the bundled skill has its own `SKILL.md` and `agents/openai.yaml` metadata.

## Isolated Codex marketplace installation

The repository marketplace uses the official repo layout: `plugin/.agents/plugins/marketplace.json` with source path `./plugins/agentlint`. To avoid changing a user's Codex state, run this in an isolated `CODEX_HOME`:

```text
codex plugin marketplace add ./plugin --json
codex plugin list --marketplace agentlint-local --available --json
codex plugin add agentlint --marketplace agentlint-local --json
codex plugin list --marketplace agentlint-local --json
```

Actual local isolated run on 2026-07-17: all four commands exited `0`. The add step registered `agentlint-local`; the available list exposed `agentlint@agentlint-local` version `0.1.0`; plugin add created a cached local install; and the final list reported the plugin as `installed: true` and `enabled: true`.

## Functional fixtures

```text
python -m pip install -e ".[dev]"
agentlint scan examples/safe-project --fail-on error
Expected: PASS; exit 0.

agentlint scan examples/unsafe-project --fail-on never
Expected: BLOCK findings; exit 0 because `--fail-on never` is requested. Current baseline: 5 errors, 6 warnings, 0 info; IDs `MCP001`, `MCP002`, `MCP003`, `MCP004`, `MCP005`, `POLICY001`, `POLICY002`, `POLICY003`, `POLICY004`, `AUTH001`, and `SKILL003`.
```

Current local fixture run on 2026-07-17: `safe-project` returned `PASS` with 0 errors, 0 warnings, and 0 info; `unsafe-project` returned `BLOCK` with 5 errors, 6 warnings, and 0 info. The unsafe sample is fake test content. Do not execute any text it contains; AgentLint will not execute it.

## Windows reparse-point protection

The Windows automated suite covers a junction used as the scan root, a nested child junction, and a plugin component reference through a junction. It verifies that the scan-root junction is rejected through the CLI error path (exit `2`), nested junctions are not traversed and appear as coverage gaps, and a component reference through a junction produces the plugin contract finding. The same suite verifies inline `mcpServers` receive the static MCP audit and report serialization redacts known literal credential patterns.

## Chinese-language regression scope

The automated suite includes Chinese clause handling without whitespace separators and Chinese literal-secret redaction across report surfaces. UI acceptance separately verified that one self-contained HTML report defaults to English with JavaScript disabled; with JavaScript, Chinese `navigator.language` auto-selects Simplified Chinese when no preference is saved, **中文 / EN** manually switches the interface, and the selection persists in `localStorage`. Original technical messages, paths, line numbers, excerpts, IDs, and unknown-rule fallbacks remain traceable rather than being invented translations.

## Release-documentation validation

Recorded local outcome on 2026-07-17, using portable `<repo>` and `<CODEX_SKILLS>` locations:

```text
release-scope privacy grep: exit 0 — no Gmail address or local absolute path in README/README.zh-CN/plugin/docs/devpost/examples
plugin validator: exit 0 — passed
skill quick_validate: exit 0 — passed
agentlint scan <repo>/plugin/plugins/agentlint --fail-on error: exit 0 — PASS, 0 findings
```

## Portable public-artifact scope

Before release, scan `artifacts`, `output`, `devpost`, and the publication documentation for local absolute paths and email addresses. The recorded portable-scope scan exited `0` with no matches. Public repository artifacts and screenshots must be generated from `examples/unsafe-project`; do not publish a personal scan output because real reports intentionally retain their actual scan root and related paths for local evidence.
