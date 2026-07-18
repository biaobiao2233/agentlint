import io
import json

from agentlint.models import Finding, Inventory, Location, ScanResult, redact_text
from agentlint.reporters import render_console, render_html


def test_local_home_paths_redact_user_identity_but_keep_diagnostic_shape() -> None:
    samples = {
        r"C:\Users\alice\workspace\AGENTS.md": r"C:\Users\[USER]\workspace\AGENTS.md",
        r"C:\\Users\\alice\\workspace\\AGENTS.md": r"C:\\Users\\[USER]\\workspace\\AGENTS.md",
        "C:/Users/alice/workspace/AGENTS.md": "C:/Users/[USER]/workspace/AGENTS.md",
        "/home/bob/workspace/AGENTS.md": "/home/[USER]/workspace/AGENTS.md",
        "/Users/carol/workspace/AGENTS.md": "/Users/[USER]/workspace/AGENTS.md",
    }

    for source, expected in samples.items():
        assert redact_text(source) == expected


def test_all_report_surfaces_remove_home_directory_usernames() -> None:
    result = ScanResult(
        root=r"C:\Users\runner\private-project",
        findings=[
            Finding(
                "MCP004",
                "warning",
                "Broad path",
                r"Server receives C:\Users\alice\private-data and /home/bob/secrets.",
                "Broad access needs review.",
                "Use a repository-relative path.",
                Location(".mcp.json", 2, 2, r'"args": ["C:\Users\alice\private-data"]'),
            )
        ],
        inventory=Inventory(files_scanned=1),
    ).finalize()
    stream = io.StringIO()
    render_console(result, color=False, stream=stream)
    report = json.dumps(result.to_dict()) + render_html(result) + stream.getvalue()

    assert "runner" not in report
    assert "alice" not in report
    assert "bob" not in report
    assert "[USER]" in report
    assert '"root": "."' in json.dumps(result.to_dict())
