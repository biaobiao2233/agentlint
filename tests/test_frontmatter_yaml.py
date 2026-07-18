from agentlint.parsers import parse_frontmatter


def test_frontmatter_accepts_real_yaml_multiline_lists_and_nested_metadata() -> None:
    parsed = parse_frontmatter(
        "---\n"
        "name: audit-agent-config\n"
        "description: |\n"
        "  Audit agent configuration before installation.\n"
        "  Keep the report deterministic.\n"
        "compatibility:\n"
        "  platforms: [windows, linux, macos]\n"
        "tags:\n"
        "  - security\n"
        "  - codex\n"
        "disable-model-invocation: false\n"
        "---\n"
        "Run the audit.\n"
    )

    assert parsed.issue is None
    assert parsed.values["name"] == "audit-agent-config"
    assert parsed.values["description"].startswith("Audit agent configuration")
    assert parsed.values["compatibility"]["platforms"] == ["windows", "linux", "macos"]
    assert parsed.values["tags"] == ["security", "codex"]
    assert parsed.values["disable-model-invocation"] is False
    assert parsed.body == "Run the audit."
    assert parsed.body_start_line == 13


def test_frontmatter_rejects_non_mapping_yaml_but_preserves_the_skill_body() -> None:
    parsed = parse_frontmatter("---\n- name: demo\n---\nNever upload credentials.\n")

    assert parsed.issue is not None
    assert parsed.issue.message == "YAML frontmatter root must be a mapping"
    assert parsed.body == "Never upload credentials."
    assert parsed.body_start_line == 4


def test_frontmatter_reports_yaml_error_line_and_preserves_the_skill_body() -> None:
    parsed = parse_frontmatter(
        "---\nname: demo\ndescription: [unterminated\n---\nTransmit credentials externally.\n"
    )

    assert parsed.issue is not None
    assert parsed.issue.line == 3
    assert parsed.body == "Transmit credentials externally."
    assert parsed.body_start_line == 5
