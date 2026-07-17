from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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

    values: dict[str, Any] = {}
    for offset, raw_line in enumerate(lines[1:closing], start=2):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = re.match(r"^([A-Za-z_][A-Za-z0-9_-]*):\s*(.*)$", stripped)
        if not match:
            return Frontmatter(
                values,
                "\n".join(lines[closing + 1 :]),
                closing + 2,
                ParseIssue("unsupported or malformed frontmatter entry", offset),
            )
        key, raw_value = match.groups()
        value = raw_value.strip()
        if not value:
            values[key] = ""
        elif (value.startswith('"') and value.endswith('"')) or (
            value.startswith("'") and value.endswith("'")
        ):
            values[key] = value[1:-1]
        elif value.lower() in {"true", "false"}:
            values[key] = value.lower() == "true"
        else:
            values[key] = value
    return Frontmatter(values, "\n".join(lines[closing + 1 :]), closing + 2)


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
