from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2}


@dataclass(frozen=True)
class Location:
    path: str
    line_start: int = 1
    line_end: int = 1
    excerpt: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", redact_text(self.path))
        # Evidence is useful only when it is safe to write into a terminal,
        # JSON report, or HTML report.  Rules intentionally operate on source
        # text, so sanitize at the report-model boundary as a last defence.
        object.__setattr__(self, "excerpt", _redact_excerpt(self.excerpt))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    message: str
    why_it_matters: str
    remediation: str
    primary: Location
    confidence: str = "high"
    related: tuple[Location, ...] = ()
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("title", "message", "why_it_matters", "remediation"):
            object.__setattr__(self, name, redact_text(getattr(self, name)))

    def sort_key(self) -> tuple[Any, ...]:
        return (
            SEVERITY_ORDER.get(self.severity, 9),
            self.primary.path.lower(),
            self.primary.line_start,
            self.rule_id,
            self.title,
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["related"] = [item.to_dict() for item in self.related]
        data["tags"] = list(self.tags)
        return data


@dataclass(frozen=True)
class PolicyFact:
    action: str
    modality: str
    scope: str
    source_kind: str
    location: Location
    phrase: str
    depth: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "scope", redact_text(self.scope))
        object.__setattr__(self, "phrase", redact_text(self.phrase))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class GraphNode:
    node_id: str
    kind: str
    label: str
    path: str = ""
    detail: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "node_id", redact_text(self.node_id))
        object.__setattr__(self, "kind", redact_text(self.kind))
        object.__setattr__(self, "label", redact_text(self.label))
        object.__setattr__(self, "path", redact_text(self.path))
        if self.kind == "mcp-server":
            object.__setattr__(self, "detail", redact_text(_safe_mcp_url_detail(self.detail)))
        else:
            object.__setattr__(self, "detail", redact_text(self.detail))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class GraphEdge:
    source: str
    target: str
    relation: str
    risk: str = "neutral"

    def __post_init__(self) -> None:
        object.__setattr__(self, "source", redact_text(self.source))
        object.__setattr__(self, "target", redact_text(self.target))
        object.__setattr__(self, "relation", redact_text(self.relation))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Inventory:
    agents_files: int = 0
    skills: int = 0
    plugins: int = 0
    mcp_configs: int = 0
    mcp_servers: int = 0
    files_scanned: int = 0
    skipped_files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    root: str
    findings: list[Finding] = field(default_factory=list)
    policy_facts: list[PolicyFact] = field(default_factory=list)
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    inventory: Inventory = field(default_factory=Inventory)
    instruction_chains: list[dict[str, Any]] = field(default_factory=list)
    schema_version: str = "1.1"
    tool_version: str = "0.1.1"

    def finalize(self) -> "ScanResult":
        self.root = redact_text(self.root)
        self.inventory.skipped_files = [redact_text(item) for item in self.inventory.skipped_files]
        self.findings.sort(key=Finding.sort_key)
        self.policy_facts.sort(
            key=lambda item: (
                item.scope.lower(),
                item.action,
                item.depth,
                item.location.path.lower(),
                item.location.line_start,
            )
        )
        self.nodes.sort(key=lambda item: (item.kind, item.label.lower(), item.node_id))
        self.edges.sort(key=lambda item: (item.source, item.target, item.relation))
        self.instruction_chains.sort(key=lambda item: str(item.get("scope", "")).lower())
        return self

    @property
    def public_root(self) -> str:
        """Return a portable marker for report output without exposing the scan host."""
        return "."

    @property
    def counts(self) -> dict[str, int]:
        counts = {"error": 0, "warning": 0, "info": 0}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    @property
    def verdict(self) -> str:
        counts = self.counts
        if counts.get("error"):
            return "BLOCK"
        if counts.get("warning"):
            return "REVIEW"
        return "PASS"

    def relative_path(self, path: Path) -> str:
        root = Path(self.root)
        try:
            return path.resolve().relative_to(root.resolve()).as_posix()
        except (OSError, ValueError):
            return path.as_posix()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "tool_version": self.tool_version,
            "root": self.public_root,
            "verdict": self.verdict,
            "counts": self.counts,
            "inventory": self.inventory.to_dict(),
            "findings": [item.to_dict() for item in self.findings],
            "effective_policy": [item.to_dict() for item in self.policy_facts],
            # Added in schema 1.1.  Keep effective_policy for consumers of 1.0
            # and make the actual Codex source order explicit for new ones.
            "effective_instruction_graph": _sanitize_json(self.instruction_chains),
            "graph": {
                "nodes": [item.to_dict() for item in self.nodes],
                "edges": [item.to_dict() for item in self.edges],
            },
        }


def _redact_excerpt(value: str) -> str:
    return redact_text(value)[:240]


def redact_text(value: str) -> str:
    """Remove credentials and terminal control characters from report-model text."""
    import re
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

    def redact_url(match: re.Match[str]) -> str:
        raw = match.group(0)
        try:
            parsed = urlsplit(raw)
            netloc = parsed.hostname or ""
            if parsed.port:
                netloc += f":{parsed.port}"
            if parsed.username is not None:
                netloc = "[REDACTED]@" + netloc
            # Query values frequently carry signed URLs, opaque session data,
            # or provider-specific credentials whose key names are not known to
            # this linter.  Keep only the key names for diagnostics.
            pairs = [(key, "[REDACTED]") for key, _ in parse_qsl(parsed.query, keep_blank_values=True)]
            return urlunsplit((parsed.scheme, netloc, parsed.path, urlencode(pairs), parsed.fragment))
        except (ValueError, TypeError):
            # A malformed port must not turn a redaction failure into a leak.
            return "[REDACTED-URI]"

    # Keep normal line and tab formatting, but render the remaining C0 controls
    # visibly so untrusted source text cannot alter terminal output.
    value = re.sub(
        r"[\x00-\x08\x0b-\x1f\x7f]",
        lambda match: f"\\x{ord(match.group(0)):02x}",
        value,
    )
    value = re.sub(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s'\"<>]+", redact_url, value)
    value = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{6,}", r"\1[REDACTED]", value)
    value = re.sub(r"\b(?:sk|ghp|github_pat|xox[baprs])[-_][A-Za-z0-9_-]{8,}\b", "[REDACTED]", value)
    value = re.sub(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", "[REDACTED]", value)
    value = re.sub(
        r"(?i)([\"']?(?:api[ _-]?key|access[ _-]?key(?:[ _-]?id)?|aws[ _-]?(?:secret[ _-]?access[ _-]?key|access[ _-]?key[ _-]?id)|token|session[ _-]?token|secret|password|authorization|credential|private[ _-]?key|access[ _-]?token|令牌|访问令牌|密钥|api\s*密钥|密码|口令|凭据)[\"']?\s*[:=：]\s*[\"']?)[^\s\"',。；;，}\]]+",
        r"\1[REDACTED]",
        value,
    )
    return value


def _safe_mcp_url_detail(value: str) -> str:
    """Display an MCP endpoint without its userinfo, query, or fragment."""
    from urllib.parse import urlsplit, urlunsplit

    try:
        parsed = urlsplit(value)
        if not parsed.scheme or not parsed.netloc:
            return value
        host = parsed.hostname
        if not host:
            return "[REDACTED-URI]"
        port = parsed.port
    except (TypeError, ValueError):
        return "[REDACTED-URI]"

    # urlsplit() removes IPv6 brackets from hostname; restore them for a valid
    # human-readable authority while deliberately omitting any userinfo.
    authority = f"[{host}]" if ":" in host and not host.startswith("[") else host
    if port is not None:
        authority += f":{port}"
    return urlunsplit((parsed.scheme, authority, parsed.path, "", ""))


def _sanitize_json(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [_sanitize_json(item) for item in value]
    if isinstance(value, dict):
        return {redact_text(str(key)): _sanitize_json(item) for key, item in value.items()}
    return value
