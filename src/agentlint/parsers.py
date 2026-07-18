from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .discovery import MAX_FILE_SIZE


@dataclass(frozen=True)
class ParseIssue:
    message: str
    line: int = 1


@dataclass(frozen=True)
class Frontmatter:
    values: dict[str, Any]
    body: str
    body_start_line: int
    issue: ParseIssue | None = None


def read_text(path: Path) -> str:
    raw = path.read_bytes()
    if len(raw) > MAX_FILE_SIZE:
        raise ValueError(f"file exceeds {MAX_FILE_SIZE} byte safety limit")
    return raw.decode("utf-8-sig", errors="replace")


def parse_json(path: Path) -> tuple[Any | None, ParseIssue | None]:
    try:
        return json.loads(read_text(path)), None
    except json.JSONDecodeError as exc:
        return None, ParseIssue(exc.msg, exc.lineno)
    except (OSError, ValueError) as exc:
        return None, ParseIssue(str(exc), 1)


def parse_toml(path: Path) -> tuple[Any | None, ParseIssue | None]:
    try:
        return tomllib.loads(read_text(path)), None
    except tomllib.TOMLDecodeError as exc:
        line = _line_from_exception(str(exc))
        return None, ParseIssue(str(exc).split(" (at line", 1)[0], line)
    except (OSError, ValueError) as exc:
        return None, ParseIssue(str(exc), 1)


def parse_frontmatter(text: str) -> Frontmatter:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return Frontmatter({}, text, 1, ParseIssue("missing opening YAML frontmatter fence", 1))

    closing = None
    for index in range(1, min(len(lines), 200)):
        if lines[index].strip() == "---":
            closing = index
            break
    if closing is None:
        return Frontmatter({}, text, 1, ParseIssue("missing closing YAML frontmatter fence", 1))

    body = "\n".join(lines[closing + 1 :])
    body_start_line = closing + 2
    header = "\n".join(lines[1:closing])
    try:
        loaded = yaml.safe_load(header)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        line = int(getattr(mark, "line", 0)) + 2
        message = getattr(exc, "problem", None) or "invalid YAML frontmatter"
        return Frontmatter({}, body, body_start_line, ParseIssue(str(message), line))

    if loaded is None:
        values: dict[str, Any] = {}
    elif isinstance(loaded, dict):
        values = loaded
    else:
        return Frontmatter(
            {},
            body,
            body_start_line,
            ParseIssue("YAML frontmatter root must be a mapping", 2),
        )
    return Frontmatter(values, body, body_start_line)


def line_excerpt(text: str, line: int) -> str:
    lines = text.splitlines()
    if not lines:
        return ""
    index = max(0, min(len(lines) - 1, line - 1))
    return lines[index].strip()[:240]


def find_line(text: str, needle: str) -> int:
    for index, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return index
    return 1


def markdown_local_references(text: str) -> list[tuple[str, int]]:
    references: list[tuple[str, int]] = []
    patterns = [
        re.compile(r"\[[^\]]*\]\(([^)]+)\)"),
        re.compile(r"`((?:scripts|references|assets)/[^`]+)`"),
    ]
    for line_number, line in enumerate(text.splitlines(), start=1):
        for pattern in patterns:
            for match in pattern.finditer(line):
                value = match.group(1).strip().split("#", 1)[0]
                if not value or value.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                references.append((value.replace("\\", "/"), line_number))
    return references


def _line_from_exception(message: str) -> int:
    match = re.search(r"line (\d+)", message)
    return int(match.group(1)) if match else 1
