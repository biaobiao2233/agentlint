from agentlint.models import Finding, Inventory, Location, ScanResult
from agentlint.reporters import ZH_RULES, render_html


def _result(*findings: Finding) -> ScanResult:
    return ScanResult(root=r"C:\audit\project", findings=list(findings), inventory=Inventory(files_scanned=1))


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
    expected = {"STRUCT001", "PLUGIN001", "PLUGIN002", "SKILL001", "SKILL002", "SKILL003", "POLICY001", "POLICY002", "POLICY003", "POLICY004", "COVERAGE001", "AUTH001", "MCP001", "MCP002", "MCP003", "MCP004", "MCP005", "DOC001"}
    assert expected <= set(ZH_RULES)
    page = render_html(_result(Finding("UNKNOWN999", "warning", "<script>x</script>", "message", "impact", "fix", Location("x", excerpt="<script>"))))
    assert "data-language=\"zh\"" in page
    assert "agentlint-report-language" in page
    assert "data-rule-id" in page
    assert "&lt;script&gt;" in page


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
