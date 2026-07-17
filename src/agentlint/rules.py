from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .models import Finding, Location, PolicyFact


@dataclass(frozen=True)
class RuleSpec:
    rule_id: str
    default_severity: str
    title: str
    category: str


RULES: tuple[RuleSpec, ...] = (
    RuleSpec("STRUCT001", "error", "Configuration cannot be parsed", "structure"),
    RuleSpec("PLUGIN001", "error", "Plugin manifest violates the Codex contract", "plugin"),
    RuleSpec("PLUGIN002", "error", "Plugin component path is invalid", "plugin"),
    RuleSpec("SKILL001", "error", "Skill frontmatter is invalid", "skill"),
    RuleSpec("SKILL002", "warning", "Skill identity is inconsistent", "skill"),
    RuleSpec("SKILL003", "error", "Skill references an invalid local file", "skill"),
    RuleSpec("POLICY001", "warning", "Effective instructions conflict", "policy"),
    RuleSpec("POLICY002", "error", "Instruction attempts to bypass higher-priority policy", "policy"),
    RuleSpec("POLICY003", "warning", "Destructive action lacks an approval boundary", "policy"),
    RuleSpec("POLICY004", "error", "Instruction requests secret disclosure", "policy"),
    RuleSpec("COVERAGE001", "warning", "Long instruction needs review", "coverage"),
    RuleSpec("COVERAGE002", "warning", "Scanner coverage is incomplete", "coverage"),
    RuleSpec("AUTH001", "warning", "Skill requests high-risk authority without approval", "authority"),
    RuleSpec("MCP001", "error", "Remote MCP endpoint uses plaintext HTTP", "mcp"),
    RuleSpec("MCP002", "error", "MCP configuration contains an embedded secret", "mcp"),
    RuleSpec("MCP003", "warning", "MCP package execution is not version-pinned", "mcp"),
    RuleSpec("MCP004", "warning", "MCP server receives an overly broad filesystem path", "mcp"),
    RuleSpec("MCP005", "warning", "MCP calls explicitly disable approval", "mcp"),
    RuleSpec("DOC001", "warning", "Plugin test path is not documented", "documentation"),
)


ACTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "secrets.output",
        re.compile(
            r"(?i)(?:print|output|upload|send|share|expose|copy|log|输出|上传|发送|分享|暴露|复制|记录)"
            r".{0,80}(?:secret|credential|api[ _-]?key|token|password|passphrase|environment variable|密钥|凭据|令牌|密码|口令|环境变量)"
        ),
    ),
    (
        "credentials.read",
        re.compile(
            r"(?i)(?:read|access|get|load|inspect|读取|访问|获取|加载|检查)"
            r".{0,80}(?:secret|credential|api[ _-]?key|token|password|\.env|密钥|凭据|令牌|密码|环境变量)"
        ),
    ),
    (
        "git.force",
        re.compile(r"(?i)(?:git\s+reset\s+--hard|git\s+push\s+--force|force[- ]push|强制推送|硬重置)"),
    ),
    (
        "filesystem.delete",
        re.compile(
            r"(?i)(?:rm\s+-rf|remove-item\b.{0,30}-recurse|del\s+/[sq]|delete|remove|erase|删除|移除)"
        ),
    ),
    ("git.push", re.compile(r"(?i)(?:git\s+push|push\s+(?:the\s+)?commit|推送)")),
    (
        "network.access",
        re.compile(r"(?i)(?:internet|network|curl\b|wget\b|download|http[s]?://|联网|网络|下载)"),
    ),
    (
        "shell.execute",
        re.compile(r"(?i)(?:powershell|bash|cmd\.exe|shell|terminal|execute\s+(?:a\s+)?command|运行命令|执行命令|终端)"),
    ),
)


DENY_RE = re.compile(
    r"(?i)(?:\bnever\b|\bdo\s+not\b|\bdon't\b|\bmust\s+not\b|\bforbid(?:den)?\b|禁止|不得|严禁|不要)"
)
APPROVE_RE = re.compile(
    r"(?i)(?:ask(?:\s+the\s+user)?|confirm|approval|permission|consent|询问|确认|批准|同意|许可)"
)
REQUIRE_RE = re.compile(
    r"(?i)(?:\bmust\b|\balways\b|\brequired?\b|\bshould\b|\bneed(?:ed)?\b|\brun\b|\bexecute\b|必须|务必|始终|需要|执行|运行)"
)
ALLOW_RE = re.compile(r"(?i)(?:\bmay\b|\bcan\b|\ballow(?:ed)?\b|可以|允许)" )
IMPERATIVE_COMMAND_RE = re.compile(
    r"(?i)^\s*(?:[-*]\s*)?(?:rm\s+-rf|remove-item\b|del\s+/[sq]|git\s+(?:reset\s+--hard|push\s+--force))"
)

BYPASS_RE = re.compile(
    r"(?i)(?:"
    r"ignore|disregard|override|bypass|disable|circumvent|跳过|忽略|绕过|禁用|无视"
    r").{0,70}(?:"
    r"previous|higher[- ]priority|system|developer|safety|security|approval|permission|"
    r"上级|此前|系统|开发者|安全|审批|许可"
    r").{0,30}(?:instruction|rule|policy|prompt|check|指令|规则|策略|提示|检查)?"
)

SECRET_OUTPUT_RE = ACTION_PATTERNS[0][1]


def classify_action(line: str) -> str | None:
    for action, pattern in ACTION_PATTERNS:
        if pattern.search(line):
            return action
    return None


def classify_modality(line: str) -> str | None:
    if DENY_RE.search(line):
        return "deny"
    if APPROVE_RE.search(line):
        return "approve-before"
    if REQUIRE_RE.search(line) or IMPERATIVE_COMMAND_RE.search(line):
        return "require"
    if ALLOW_RE.search(line):
        return "allow"
    return None


def clause_modality(line: str, action: str | None) -> str | None:
    modality = classify_modality(line)
    if modality is None and action and re.match(r"(?i)^\s*(?:[-*]\s*)?(?:upload|send|share|print|output|copy|delete|remove|rm\b|上传|发送|分享|输出|打印|复制|删除)", line):
        return "require"
    return modality


def extract_policy_facts(
    text: str,
    *,
    relative_path: str,
    scope: str,
    source_kind: str,
    depth: int,
) -> list[PolicyFact]:
    facts: list[PolicyFact] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        for clause in _clauses(raw_line):
            action = classify_action(clause)
            modality = clause_modality(clause, action)
            if not action or not modality:
                continue
            facts.append(PolicyFact(action, modality, scope, source_kind,
                Location(relative_path, line_number, line_number, _safe_excerpt(clause)), clause[:300], depth))
    return facts


def instruction_safety_findings(
    text: str,
    *,
    relative_path: str,
    source_kind: str,
) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        if not raw_line.strip():
            continue
        if len(raw_line) > 500:
            findings.append(Finding("COVERAGE001", "warning", "Long instruction needs review",
                "This instruction exceeds the normal concise-rule boundary; AgentLint still checks clauses but cannot prove every natural-language interaction.",
                "Very long instruction lines make authority boundaries harder to review and can hide conflicting clauses.",
                "Split the instruction into short, single-purpose rules and review the original text.",
                Location(relative_path, line_number, line_number, _safe_excerpt(raw_line)), confidence="medium", tags=("coverage", source_kind)))
        for line in _clauses(raw_line):
            location = Location(relative_path, line_number, line_number, _safe_excerpt(line))
            if BYPASS_RE.search(line) and classify_modality(line) != "deny":
                findings.append(
                    Finding(
                        "POLICY002", "error", "Instruction attempts to bypass a higher-priority boundary",
                        "This text tells the agent to ignore or disable another instruction, policy, or approval check.",
                        "Agent configuration is executable control text. Priority-bypass language is a common injection and policy-confusion pattern.",
                        "Remove the bypass directive. Express the intended behavior as a scoped rule that preserves system, developer, and approval boundaries.",
                        location, tags=("policy", "prompt-injection", source_kind),
                    )
                )

            action = classify_action(line)
            modality = clause_modality(line, action)
            if action in {"filesystem.delete", "git.force"} and modality in {"require", "allow"} and not APPROVE_RE.search(line):
                findings.append(
                    Finding(
                        "POLICY003", "warning", "Destructive instruction has no approval boundary",
                        f"The instruction permits or requires `{action}` without asking the user first.",
                        "A mistaken interpretation can irreversibly delete work or rewrite repository history.",
                        "Require explicit user confirmation and a verified target before the destructive action.",
                        location, tags=("policy", "destructive-action", source_kind),
                    )
                )

            if SECRET_OUTPUT_RE.search(line) and modality != "deny":
                findings.append(
                    Finding(
                        "POLICY004", "error", "Instruction requests secret disclosure",
                        "The instruction combines a disclosure action with credentials, tokens, passwords, or environment variables.",
                        "Following it could exfiltrate credentials through chat, logs, files, or a remote service.",
                        "Remove the disclosure request. Refer to secret names only, redact values, and use scoped secret stores.",
                        location, tags=("policy", "secrets", source_kind),
                    )
                )
    return _dedupe_findings(findings)


def policy_conflict_findings(facts: Iterable[PolicyFact]) -> list[Finding]:
    ordered = sorted(
        (fact for fact in facts if fact.source_kind == "agents"),
        key=lambda fact: (fact.action, fact.depth, fact.location.path, fact.location.line_start),
    )
    findings: list[Finding] = []
    for index, earlier in enumerate(ordered):
        for later in ordered[index + 1 :]:
            if earlier.action != later.action:
                if later.action > earlier.action:
                    break
                continue
            if not _scopes_related(earlier.scope, later.scope):
                continue
            if not _modalities_conflict(earlier.modality, later.modality):
                continue
            primary, related = (later, earlier) if later.depth >= earlier.depth else (earlier, later)
            same_scope = primary.scope == related.scope
            severity = "error" if same_scope else "warning"
            if same_scope:
                title = f"Contradictory {primary.action} instructions in the same scope"
                message = (
                    f"The same scope says `{related.modality}` and `{primary.modality}` for `{primary.action}`. "
                    "Codex receives both statements, so the intended policy is ambiguous."
                )
            else:
                title = f"Nearer instructions weaken the {primary.action} boundary"
                message = (
                    f"The nearer `{primary.scope}` instruction says `{primary.modality}` while its ancestor "
                    f"`{related.scope}` says `{related.modality}`. The nearer rule is later in the Codex instruction chain."
                )
            findings.append(
                Finding(
                    "POLICY001",
                    severity,
                    title,
                    message,
                    "Codex concatenates AGENTS guidance from root to the current directory; nearer guidance appears later and can change the effective policy.",
                    "Make the override explicit and preserve the stricter safety boundary, or narrow it to a clearly named safe exception.",
                    primary.location,
                    confidence="high",
                    related=(related.location,),
                    tags=("policy", "instruction-precedence", primary.action),
                )
            )
    return _dedupe_findings(findings)


def _modalities_conflict(left: str, right: str) -> bool:
    pair = {left, right}
    return bool(
        ("deny" in pair and pair.intersection({"allow", "require"}))
        or ("approve-before" in pair and "require" in pair)
    )


def _scopes_related(left: str, right: str) -> bool:
    left_path = Path(left or ".")
    right_path = Path(right or ".")
    try:
        return left_path == right_path or left_path.is_relative_to(right_path) or right_path.is_relative_to(left_path)
    except (OSError, ValueError):
        return False


def _safe_excerpt(value: str) -> str:
    value = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1[REDACTED]", value)
    value = re.sub(r"\b(?:sk|ghp|github_pat|xox[baprs])[-_][A-Za-z0-9_-]{8,}\b", "[REDACTED]", value)
    return value[:240]


def _clauses(raw_line: str) -> list[str]:
    """Split normative clauses without treating a denial elsewhere as global."""
    prefix_stripped = re.sub(r"^\s*(?:[-*+]\s+|\d+[.)]\s+|>\s*)", "", raw_line).lstrip()
    if prefix_stripped.lower().startswith(("documentation:", "example:", "note:", "文档：", "示例：", "注：")):
        return []
    return [item.strip() for item in re.split(r"(?<=[;；。！？!?])\s*|(?<=\.)\s+(?=[A-Z-])", raw_line) if item.strip()]


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int, str]] = set()
    result: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.primary.path, finding.primary.line_start, finding.title)
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return result
