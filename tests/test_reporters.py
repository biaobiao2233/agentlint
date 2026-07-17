import io
import json

from agentlint.models import Finding, GraphEdge, GraphNode, Inventory, Location, PolicyFact, ScanResult, redact_text
from agentlint.reporters import ZH_RULES, render_console, render_html, write_json


def _result(*findings: Finding) -> ScanResult:
    return ScanResult(root=r"C:\audit\project", findings=list(findings), inventory=Inventory(files_scanned=1))


def test_exports_use_a_portable_root_and_keep_relative_evidence(tmp_path) -> None:
    scanned_root = "/private/alice/private-audit-root"
    evidence_path = "nested/AGENTS.md"
    result = ScanResult(
        root=scanned_root,
        findings=[
            Finding(
                "TESTROOT", "warning", "Portable report", "message", "impact", "fix",
                Location(evidence_path, 4, 4),
            )
        ],
        inventory=Inventory(files_scanned=1),
    )

    json_path = write_json(result, tmp_path / "report.json")
    json_payload = json_path.read_text(encoding="utf-8")
    page = render_html(result)
    stream = io.StringIO()
    render_console(result, color=False, stream=stream)
    console = stream.getvalue()

    assert json.loads(json_payload)["root"] == "."
    assert "Target: ." in console
    for report in (json_payload, page, console):
        assert scanned_root not in report
        assert evidence_path in report


def test_policy_scope_graph_path_and_mcp_url_detail_are_sanitized() -> None:
    scope_secret = "POLICY_SCOPE_SECRET_123"
    path_secret = "GRAPH_PATH_SECRET_123"
    userinfo_secret = "USERINFO_SECRET_123"
    query_secret = "ARBITRARY_QUERY_SECRET_123"
    fragment_secret = "FRAGMENT_SECRET_123"
    mcp_node = GraphNode(
        "mcp:remote",
        "mcp-server",
        "remote",
        "",
        (
            "https://alice:"
            f"{userinfo_secret}@mcp.example.test:8443/mcp?trace={query_secret}"
            f"&token=TOKEN_QUERY_SECRET_123#{fragment_secret}"
        ),
    )
    result = ScanResult(
        root="/private/project",
        policy_facts=[
            PolicyFact(
                "files.write", "require", f"services/token={scope_secret}", "agents",
                Location("AGENTS.md", 1), "Require a write", 0,
            )
        ],
        nodes=[
            GraphNode("mcp-config:remote", "mcp-config", "MCP config", f"config/secret={path_secret}", "1 server"),
            mcp_node,
        ],
        edges=[GraphEdge("mcp-config:remote", "mcp:remote", "configures")],
    )

    payload = result.to_dict()
    json_payload = json.dumps(payload)
    page = render_html(result)
    mcp_detail = next(node["detail"] for node in payload["graph"]["nodes"] if node["node_id"] == "mcp:remote")

    for secret in (scope_secret, path_secret, userinfo_secret, query_secret, fragment_secret):
        assert secret not in json_payload
        assert secret not in page
    assert "[REDACTED]" in json_payload
    assert mcp_detail == "https://mcp.example.test:8443/mcp"
    assert mcp_detail in page
    assert "config/secret=[REDACTED]" in page


def test_report_strings_neutralize_terminal_control_characters() -> None:
    finding = Finding(
        "TESTCONTROL", "warning", "unsafe\x1b[2J", "message", "impact", "fix",
        Location("AGENTS.md", 1, 1, "excerpt\x07"),
    )
    result = _result(finding)
    stream = io.StringIO()
    render_console(result, color=False, stream=stream)
    report = json.dumps(result.to_dict()) + render_html(result) + stream.getvalue()

    assert "\x1b" not in report
    assert "\x07" not in report
    assert r"\x1b" in report
    assert r"\x07" in report


def test_url_redaction_drops_arbitrary_query_values() -> None:
    secret = "SIGNED_QUERY_VALUE_123"
    redacted = redact_text(f"https://mcp.example.test/mcp?trace={secret}&mode=debug")

    assert secret not in redacted
    assert "trace=%5BREDACTED%5D" in redacted
    assert "mode=%5BREDACTED%5D" in redacted


def test_html_escapes_script_and_handles_long_cross_platform_path() -> None:
    path = "C:/very/long/" + ("nested/" * 80) + "<script>.md"
    finding = Finding(
        "TEST001", "error", "<script>alert(1)</script>", "message", "impact", "fix",
        Location(path, 7, 7, "<script>unsafe()</script>"),
    )
    page = render_html(_result(finding))
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "&lt;script&gt;unsafe()&lt;/script&gt;" in page
    assert path.replace("<", "&lt;").replace(">", "&gt;") in page


def test_html_has_honest_empty_state_without_findings() -> None:
    page = render_html(_result())
    assert "No deterministic findings" in page
    assert "data-empty-state" in page


def test_html_includes_a_hidden_filter_empty_state_and_live_status() -> None:
    page = render_html(_result())
    assert 'data-filter-empty hidden' in page
    assert "No findings match these filters." in page
    assert "Clear search or choose All." in page
    assert 'data-filter-status aria-live="polite" aria-atomic="true"' in page
    assert "previousVisible === 0" in page


def test_html_uses_placeholder_when_excerpt_is_missing() -> None:
    finding = Finding("TEST002", "warning", "Missing excerpt", "message", "impact", "fix", Location("AGENTS.md", 1))
    page = render_html(_result(finding))
    assert "(no excerpt)" in page


def test_chinese_rule_dictionary_covers_catalog_and_html_contracts() -> None:
    expected = {"STRUCT001", "PLUGIN001", "PLUGIN002", "SKILL001", "SKILL002", "SKILL003", "POLICY001", "POLICY002", "POLICY003", "POLICY004", "COVERAGE001", "COVERAGE002", "AUTH001", "MCP001", "MCP002", "MCP003", "MCP004", "MCP005", "DOC001"}
    assert expected <= set(ZH_RULES)
    page = render_html(_result(Finding("UNKNOWN999", "warning", "<script>x</script>", "message", "impact", "fix", Location("x", excerpt="<script>"))))
    assert "data-language=\"zh\"" in page
    assert "agentlint-report-language" in page
    assert "data-rule-id" in page
    assert "&lt;script&gt;" in page


def test_html_defaults_to_english_and_keeps_manual_language_preference_contract() -> None:
    page = render_html(_result())
    assert '<html lang="en">' in page
    assert 'data-language="en" aria-pressed="true"' in page
    assert "localStorage.getItem('agentlint-report-language') || 'en'" in page
    assert "navigator.language" not in page


def test_chinese_ui_hooks_cover_aria_empty_and_skipped_states() -> None:
    result = _result()
    result.inventory.skipped_files.append("ignored/<script>.md")
    page = render_html(result)
    for hook in ("data-i18n-aria=\"language\"", "data-i18n-aria=\"audit_totals\"", "data-i18n-aria=\"finding_filters\"", "data-i18n-aria=\"search_label\"", "data-i18n=\"empty_report_title\"", "data-i18n=\"skipped_files\""):
        assert hook in page
    assert "&lt;script&gt;" in page


def test_chinese_hooks_cover_empty_graph_tags_live_status_and_verdict_layout() -> None:
    finding = Finding(
        "TEST003", "error", "Tagged finding", "message", "impact", "fix",
        Location("AGENTS.md", 1), tags=("mcp", "policy", "unknown.action"),
    )
    empty_page = render_html(_result())
    page = render_html(_result(finding))

    assert 'data-i18n="none_policy"' in empty_page
    assert 'data-i18n="none_graph"' in empty_page
    assert 'data-tag="mcp"' in page
    assert 'data-tag="policy"' in page
    assert 'data-tag="unknown.action"' in page
    assert 'text.tags[node.dataset.tag] || node.dataset.en' in page
    assert 'const apply = (forceStatus = false)' in page
    assert 'apply(true)' in page
    assert 'data-verdict-label' in page
    assert 'data-verdict-code' in page
    assert 'html[lang^="zh"] .verdict-code' in page
