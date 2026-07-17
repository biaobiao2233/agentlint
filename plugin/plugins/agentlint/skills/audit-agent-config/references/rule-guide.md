# AgentLint rule guide

AgentLint is a deterministic, zero-execution preflight. It does not start MCP servers, import scanned code, contact endpoints, modify scanned configuration/input files, or claim to prove safety. It writes a report only to a path explicitly requested through `--json` or `--html`.

## Rule families

- `STRUCT`: malformed JSON, TOML, or unreadable configuration.
- `PLUGIN`: Codex plugin manifest contract and component paths.
- `SKILL`: SKILL.md frontmatter, identity, and local references.
- `POLICY`: priority bypasses, destructive actions, secret disclosure, and high-confidence AGENTS.md conflicts.
- `AUTH`: high-risk authority requested by reusable skills without an approval step.
- `MCP`: plaintext remote transports, embedded credentials, unpinned launch packages, broad paths, and disabled approval.
- `DOC`: installation, supported platforms, and reproducible test paths.

## Interpretation limits

Natural-language policy extraction recognizes a deliberately small set of actions and modalities. Supported manifest references and normative instruction facts create evidence-bound graph edges; they do not verify all runtime relationships. Nested symlink and Windows junction/reparse-point entries are not followed and are recorded as coverage gaps. A scan root that is a symlink or Windows reparse point is rejected with exit code `2`; plugin and skill component references through those entries are invalid local targets. Known literal credential patterns are redacted before serialization, but this heuristic cannot guarantee every sensitive value is detected. A warning is evidence for review, not proof of malicious intent. `PASS` means that no current deterministic rule matched.
