#!/usr/bin/env python3
"""Build the self-contained public demo that GitHub Pages deploys.

The page is deliberately a static evidence viewer, not a hosted scan service.
Every report and fixture it contains is regenerated from the repository's
portable sample data during the build.
"""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Sequence

from agentlint import __version__
from agentlint.reporters import write_html, write_json
from agentlint.scanner import scan


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SITE_SOURCE = REPOSITORY_ROOT / "site"
FIXTURES_SOURCE = REPOSITORY_ROOT / "examples"
REPORT_PREVIEW_SOURCE = REPOSITORY_ROOT / "output" / "playwright" / "agentlint-report-1440.png"
FIXTURE_NAMES = ("unsafe-project", "safe-project")


def build_public_site(output: str | Path) -> Path:
    """Create a new static demo tree at *output* from known fake fixtures.

    Refusing an existing destination avoids silently deleting or overwriting a
    user-selected directory. The GitHub Actions workflow supplies a fresh
    runner-temp directory, and local maintainers can choose a new path.
    """

    destination = Path(output).expanduser().absolute()
    if destination.exists():
        raise FileExistsError(f"public-site output already exists: {destination}")
    if _is_inside(destination, SITE_SOURCE) or _is_inside(destination, FIXTURES_SOURCE):
        raise ValueError("public-site output must not be inside the source site or fixture directories")
    if not SITE_SOURCE.is_dir():
        raise FileNotFoundError(f"site source directory is missing: {SITE_SOURCE}")

    shutil.copytree(SITE_SOURCE, destination)
    if not REPORT_PREVIEW_SOURCE.is_file():
        raise FileNotFoundError(f"approved report preview is missing: {REPORT_PREVIEW_SOURCE}")
    assets_directory = destination / "assets"
    assets_directory.mkdir(parents=True, exist_ok=True)
    shutil.copy2(REPORT_PREVIEW_SOURCE, assets_directory / "report-preview.png")
    reports_directory = destination / "reports"
    fixture_directory = destination / "fixtures"
    reports_directory.mkdir(parents=True, exist_ok=True)
    fixture_directory.mkdir(parents=True, exist_ok=True)

    summaries: dict[str, dict[str, object]] = {}
    for fixture_name in FIXTURE_NAMES:
        source = FIXTURES_SOURCE / fixture_name
        if not source.is_dir():
            raise FileNotFoundError(f"fixture source directory is missing: {source}")
        _assert_regular_fixture_tree(source)
        shutil.copytree(source, fixture_directory / fixture_name)

        result = scan(source)
        report_stem = f"{fixture_name.removesuffix('-project')}-report"
        write_json(result, reports_directory / f"{report_stem}.json")
        write_html(result, reports_directory / f"{report_stem}.html")
        summaries[fixture_name] = {
            "verdict": result.verdict,
            "counts": result.counts,
            "report_html": f"reports/{report_stem}.html",
            "report_json": f"reports/{report_stem}.json",
            "fixture_readme": f"fixtures/{fixture_name}/README.md",
        }

    data_directory = destination / "data"
    data_directory.mkdir(parents=True, exist_ok=True)
    (data_directory / "fixture-manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "agentlint_version": __version__,
                "kind": "generated-static-fake-fixture-snapshot",
                "fixtures": summaries,
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    return destination


def _is_inside(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent.absolute())
        return True
    except ValueError:
        return False


def _assert_regular_fixture_tree(source: Path) -> None:
    """Keep a Pages build from following a future fixture symlink by accident."""

    for path in source.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"fixture contains a symlink and cannot be published: {path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a static AgentLint fake-fixture demo for GitHub Pages."
    )
    parser.add_argument(
        "--output",
        required=True,
        metavar="DIRECTORY",
        help="new destination directory; it must not already exist",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        destination = build_public_site(args.output)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"build_public_site: {exc}") from exc
    print(f"Public static demo written to {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
