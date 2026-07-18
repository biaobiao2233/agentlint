from __future__ import annotations

import json

import pytest

from agentlint import __version__
from scripts.build_public_site import SITE_SOURCE, build_public_site


@pytest.fixture()
def public_site(tmp_path):
    return build_public_site(tmp_path / "agentlint-public-demo")


def test_public_site_builds_portable_fake_fixture_reports(public_site) -> None:
    unsafe = json.loads((public_site / "reports" / "unsafe-report.json").read_text(encoding="utf-8"))
    safe = json.loads((public_site / "reports" / "safe-report.json").read_text(encoding="utf-8"))
    manifest = json.loads((public_site / "data" / "fixture-manifest.json").read_text(encoding="utf-8"))
    unsafe_html = (public_site / "reports" / "unsafe-report.html").read_text(encoding="utf-8")

    assert (public_site / "index.html").is_file()
    assert (public_site / "reports" / "unsafe-report.html").is_file()
    assert (public_site / "reports" / "safe-report.html").is_file()
    assert (public_site / "assets" / "report-preview.png").is_file()
    assert (public_site / "fixtures" / "unsafe-project" / "README.md").is_file()
    assert (public_site / "fixtures" / "safe-project" / "README.md").is_file()
    assert unsafe["root"] == "."
    assert unsafe["verdict"] == "BLOCK"
    assert unsafe["counts"] == {"error": 5, "warning": 6, "info": 0}
    assert "localStorage.getItem('agentlint-report-language') || 'en'" in unsafe_html
    assert "navigator.language" not in unsafe_html
    assert safe["root"] == "."
    assert safe["verdict"] == "PASS"
    assert safe["counts"] == {"error": 0, "warning": 0, "info": 0}
    assert manifest["agentlint_version"] == __version__
    assert manifest["kind"] == "generated-static-fake-fixture-snapshot"
    assert manifest["fixtures"]["unsafe-project"]["report_html"] == "reports/unsafe-report.html"


def test_public_site_does_not_embed_this_machine_or_account(public_site) -> None:
    public_text = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in public_site.rglob("*")
        if path.is_file() and path.suffix.lower() in {".html", ".json", ".md", ".txt"}
    )

    assert "E:\\AGENT" not in public_text
    assert "C:\\Users\\asus" not in public_text
    assert "nsbbabbavww@gmail.com" not in public_text


def test_public_site_source_has_the_expected_judge_links() -> None:
    page = (SITE_SOURCE / "index.html").read_text(encoding="utf-8")

    for link in (
        "reports/unsafe-report.html",
        "reports/safe-report.html",
        "fixtures/unsafe-project/README.md",
        "https://github.com/biaobiao2233/agentlint",
        "https://youtu.be/WxO-wCy0a8E",
    ):
        assert link in page
