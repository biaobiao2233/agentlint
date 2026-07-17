# Safe AgentLint fixture

This minimal sample is designed to PASS. It contains no live MCP endpoint, credential, or executable deployment instruction. AgentLint does not modify scanned fixture files; explicit report paths are the only files a scan may create or overwrite.

## Installation and supported platforms

AgentLint is designed for Python 3.11+ on Windows, macOS, and Linux. Independent acceptance testing has run on Windows (Python 3.14); macOS and Linux still need runtime verification.

## Test path

From the repository root, run:

```text
agentlint scan examples/safe-project --fail-on error
```
