from __future__ import annotations

import json
from pathlib import Path

from agentlint.cli import main
from agentlint.scanner import scan


def _write(root: Path, relative: str, contents: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")


def test_explicit_exclude_is_relative_coverage_gap_and_prunes_subtree(tmp_path: Path) -> None:
    _write(tmp_path, "service/vendor/AGENTS.md", "- Always delete generated files.\n")
    _write(tmp_path, "service/vendor/nested/SKILL.md", "---\nname: hidden\n---\n")

    result = scan(tmp_path, excludes=("vendor",))
    gaps = [finding for finding in result.findings if finding.rule_id == "COVERAGE002"]

    assert result.verdict == "REVIEW"
    assert [finding.primary.path for finding in gaps] == ["service/vendor"]
    assert not Path(gaps[0].primary.path).is_absolute()
    assert result.inventory.skipped_files == ["service/vendor (user-requested exclusion)"]
    assert result.inventory.files_scanned == 0
    assert result.policy_facts == []


def test_cli_exclude_surfaces_coverage_gap_in_json_report(tmp_path: Path) -> None:
    _write(tmp_path, "private/AGENTS.md", "- Never reveal tokens.\n")
    report_path = tmp_path / "report.json"

    exit_code = main(
        [
            "scan",
            str(tmp_path),
            "--exclude",
            "private",
            "--json",
            str(report_path),
            "--quiet",
            "--fail-on",
            "warning",
        ]
    )
    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert exit_code == 1
    assert report["verdict"] == "REVIEW"
    assert [
        finding["primary"]["path"]
        for finding in report["findings"]
        if finding["rule_id"] == "COVERAGE002"
    ] == ["private"]


def test_builtin_ignore_stays_silent_when_also_explicitly_excluded(tmp_path: Path) -> None:
    _write(tmp_path, "node_modules/AGENTS.md", "- Always delete generated files.\n")

    for result in (scan(tmp_path), scan(tmp_path, excludes=("node_modules",))):
        assert result.verdict == "PASS"
        assert not any(finding.rule_id == "COVERAGE002" for finding in result.findings)
        assert result.inventory.skipped_files == []
        assert result.inventory.files_scanned == 0


def test_unmatched_explicit_exclude_does_not_create_coverage_gap(tmp_path: Path) -> None:
    result = scan(tmp_path, excludes=("not-present",))

    assert result.verdict == "PASS"
    assert not any(finding.rule_id == "COVERAGE002" for finding in result.findings)
    assert result.inventory.skipped_files == []
