from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


IGNORED_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
}

MAX_FILE_SIZE = 1_000_000


@dataclass(frozen=True)
class SkippedPath:
    """A path deliberately excluded from the scan, with enough context for coverage checks."""

    path: Path
    reason: str
    is_directory: bool


@dataclass
class DiscoveredFiles:
    root: Path
    agents: list[Path] = field(default_factory=list)
    skills: list[Path] = field(default_factory=list)
    plugins: list[Path] = field(default_factory=list)
    mcp_json: list[Path] = field(default_factory=list)
    codex_toml: list[Path] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    coverage_gaps: list[SkippedPath] = field(default_factory=list)

    @property
    def all_files(self) -> list[Path]:
        return sorted(
            set(self.agents + self.skills + self.plugins + self.mcp_json + self.codex_toml),
            key=lambda path: path.as_posix().lower(),
        )


def discover(
    root: Path,
    extra_excludes: tuple[str, ...] = (),
    instruction_fallback_filenames: tuple[str, ...] = (),
) -> DiscoveredFiles:
    # Do not turn a supplied symlink into a trusted scan root.  Apart from
    # making reports surprising, resolving it would violate the zero-follow
    # promise made by the scanner.
    root = root.absolute()
    if _has_unsafe_path_component(root):
        raise ValueError(f"scan root must not be a symlink or reparse point: {root}")
    found = DiscoveredFiles(root=root)
    excludes = IGNORED_DIRECTORIES | set(extra_excludes)
    instruction_names = {"AGENTS.md", "AGENTS.override.md", *instruction_fallback_filenames}

    for current, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        kept_dirs: list[str] = []
        for dirname in sorted(dirnames):
            candidate = current_path / dirname
            if dirname in excludes:
                continue
            if candidate.is_symlink() or _is_reparse_point(candidate):
                _record_skip(found, root, candidate, "symlink/reparse point", is_directory=True)
                continue
            kept_dirs.append(dirname)
        dirnames[:] = kept_dirs

        for filename in sorted(filenames):
            path = current_path / filename
            if path.is_symlink() or _is_reparse_point(path):
                _record_skip(
                    found,
                    root,
                    path,
                    "symlink/reparse point",
                    is_directory=False,
                    supported_config=_is_supported_config(path, instruction_names),
                )
                continue
            try:
                if path.stat().st_size > MAX_FILE_SIZE:
                    _record_skip(
                        found,
                        root,
                        path,
                        "too large",
                        is_directory=False,
                        supported_config=_is_supported_config(path, instruction_names),
                    )
                    continue
            except OSError:
                _record_skip(
                    found,
                    root,
                    path,
                    "unreadable",
                    is_directory=False,
                    supported_config=_is_supported_config(path, instruction_names),
                )
                continue

            if filename in instruction_names:
                found.agents.append(path)
            elif filename == "SKILL.md":
                found.skills.append(path)
            elif filename == "plugin.json" and path.parent.name == ".codex-plugin":
                found.plugins.append(path)
            elif filename == ".mcp.json":
                found.mcp_json.append(path)
            elif filename == "config.toml" and path.parent.name == ".codex":
                found.codex_toml.append(path)

    for collection in (
        found.agents,
        found.skills,
        found.plugins,
        found.mcp_json,
        found.codex_toml,
    ):
        collection.sort(key=lambda path: path.as_posix().lower())
    found.skipped.sort()
    found.coverage_gaps.sort(key=lambda item: (item.path.as_posix().lower(), item.reason, item.is_directory))
    return found


def _relative(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _is_reparse_point(path: Path) -> bool:
    try:
        # stat() follows junctions.  lstat() reports the directory entry we
        # are about to traverse, which is the only safe object to classify.
        return bool(getattr(path.lstat(), "st_file_attributes", 0) & 0x400)
    except OSError:
        return True


def _has_unsafe_path_component(path: Path) -> bool:
    """Reject roots reached through a link/reparse ancestor as well as the final entry."""

    current = path.absolute()
    while True:
        if current.is_symlink() or _is_reparse_point(current):
            return True
        parent = current.parent
        if parent == current:
            return False
        current = parent


def _is_supported_config(path: Path, instruction_names: set[str]) -> bool:
    return (
        path.name in instruction_names
        or path.name == "SKILL.md"
        or path.name == ".mcp.json"
        or (path.name == "plugin.json" and path.parent.name == ".codex-plugin")
        or (path.name == "config.toml" and path.parent.name == ".codex")
    )


def _record_skip(
    found: DiscoveredFiles,
    root: Path,
    path: Path,
    reason: str,
    *,
    is_directory: bool,
    supported_config: bool = False,
) -> None:
    found.skipped.append(f"{_relative(root, path)} ({reason})")
    # A skipped directory could contain any supported configuration.  In
    # contrast, ordinary ignored directories are intentionally omitted before
    # this point and must not turn routine scans into coverage noise.
    if is_directory or supported_config:
        found.coverage_gaps.append(SkippedPath(path, reason, is_directory))
