from __future__ import annotations

import ipaddress
import re
import yaml
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlparse

from .discovery import DiscoveredFiles, _is_reparse_point, discover
from .models import Finding, GraphEdge, GraphNode, Inventory, Location, PolicyFact, ScanResult
from .parsers import (
    find_line,
    line_excerpt,
    markdown_local_references,
    parse_frontmatter,
    parse_json,
    parse_toml,
    read_text,
)
from .rules import (
    APPROVE_RE,
    RULES,
    classify_action,
    classify_modality,
    extract_policy_facts,
    instruction_safety_findings,
    policy_conflict_findings,
)


KEBAB_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SEMVER_RE = re.compile(r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$")
SECRET_KEY_RE = re.compile(r"(?i)(?:token|password|passwd|secret|api[_-]?key|authorization)")
SECRET_VALUE_RE = re.compile(
    r"(?i)(?:\bBearer\s+[A-Za-z0-9._~+/=-]{8,}|\bsk-[A-Za-z0-9_-]{8,}|\bghp_[A-Za-z0-9]{8,}|\bxox[baprs]-[A-Za-z0-9-]{8,})"
)
ENV_REFERENCE_RE = re.compile(
    r"^(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|%[A-Za-z_][A-Za-z0-9_]*%|env:[A-Za-z_][A-Za-z0-9_]*)$"
)
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}
SENSITIVE_ROOT_RE = re.compile(
    r"(?i)^(?:/|/home|/root|~|\$HOME|%USERPROFILE%|[A-Z]:[\\/]|C:\\Users)(?:[\\/].*)?$"
)


def scan(root: str | Path, excludes: Iterable[str] = ()) -> ScanResult:
    root_path = Path(root).expanduser().absolute()
    if not root_path.exists() or not root_path.is_dir():
        raise ValueError(f"scan target is not a directory: {root_path}")
    if root_path.is_symlink() or _is_reparse_point(root_path):
        raise ValueError(f"scan target must not be a symlink or reparse point: {root_path}")

    found = discover(root_path, tuple(excludes))
    result = ScanResult(root=str(root_path))
    result.inventory = Inventory(
        agents_files=len(found.agents),
        skills=len(found.skills),
        plugins=len(found.plugins),
        mcp_configs=len(found.mcp_json) + len(found.codex_toml),
        files_scanned=len(found.all_files),
        skipped_files=found.skipped,
    )

    _inspect_agents(result, found)
    _inspect_skills(result, found)
    _inspect_plugins(result, found)
    _inspect_mcp(result, found)
    _inspect_documentation(result, found)

    result.findings.extend(policy_conflict_findings(result.policy_facts))
    _build_instruction_chains(result, found)
    _build_cross_component_graph(result, found)
    return result.finalize()


def _inspect_agents(result: ScanResult, found: DiscoveredFiles) -> None:
    selected: dict[Path, Path] = {}
    for path in found.agents:
        current = selected.get(path.parent)
        if current is None or path.name == "AGENTS.override.md":
            selected[path.parent] = path

    for directory, path in sorted(selected.items(), key=lambda item: item[1].as_posix().lower()):
        relative = result.relative_path(path)
        text = _read_or_record(result, path, relative)
        if text is None:
            continue
        scope = _scope_relative(found.root, directory)
        depth = 0 if scope == "." else len(Path(scope).parts)
        result.policy_facts.extend(
            extract_policy_facts(
                text,
                relative_path=relative,
                scope=scope,
                source_kind="agents",
                depth=depth,
            )
        )
        result.findings.extend(
            instruction_safety_findings(text, relative_path=relative, source_kind="agents")
        )
        result.nodes.append(GraphNode(f"agents:{relative}", "instructions", path.name, relative, f"scope {scope}"))


def _inspect_skills(result: ScanResult, found: DiscoveredFiles) -> None:
    for path in found.skills:
        relative = result.relative_path(path)
        text = _read_or_record(result, path, relative)
        if text is None:
            continue
        parsed = parse_frontmatter(text)
        if parsed.issue:
            result.findings.append(
                Finding(
                    "SKILL001",
                    "error",
                    "Skill frontmatter cannot be read",
                    parsed.issue.message,
                    "Codex uses `name` and `description` to discover and invoke the skill.",
                    "Add a fenced YAML header containing only a valid `name` and `description`.",
                    Location(relative, parsed.issue.line, parsed.issue.line, line_excerpt(text, parsed.issue.line)),
                    tags=("skill", "structure"),
                )
            )
        else:
            for field in ("name", "description"):
                value = parsed.values.get(field)
                if not isinstance(value, str) or not value.strip():
                    result.findings.append(
                        Finding(
                            "SKILL001",
                            "error",
                            f"Skill frontmatter is missing `{field}`",
                            f"The required `{field}` field is absent or empty.",
                            "Codex initially sees only the skill name, description, and path, so these fields control discovery.",
                            f"Add a concise `{field}` value to the SKILL.md frontmatter.",
                            Location(relative, 2, 2, line_excerpt(text, 2)),
                            tags=("skill", "structure"),
                        )
                    )
            name = parsed.values.get("name")
            if isinstance(name, str) and name:
                line = find_line(text, "name:")
                if not KEBAB_RE.fullmatch(name):
                    result.findings.append(
                        Finding(
                            "SKILL002",
                            "warning",
                            "Skill name is not lower-case kebab-case",
                            f"`{name}` does not match the portable Agent Skills naming convention.",
                            "Non-portable names can be discovered differently across agent clients.",
                            "Use lower-case letters, digits, and single hyphens.",
                            Location(relative, line, line, line_excerpt(text, line)),
                            tags=("skill", "compatibility"),
                        )
                    )
                if name != path.parent.name:
                    result.findings.append(
                        Finding(
                            "SKILL002",
                            "warning",
                            "Skill name does not match its directory",
                            f"Frontmatter name `{name}` differs from directory `{path.parent.name}`.",
                            "Matching identities make packaging, invocation, and debugging predictable.",
                            "Rename the directory or frontmatter so the values match.",
                            Location(relative, line, line, line_excerpt(text, line)),
                            tags=("skill", "identity"),
                        )
                    )

        for reference, line in markdown_local_references(text):
            target = path.parent / reference
            if not _is_safe_local_target(target, path.parent):
                message = f"Local reference `{reference}` escapes the skill directory."
            elif target.exists():
                continue
            else:
                message = f"Local reference `{reference}` does not exist."
            result.findings.append(
                Finding(
                    "SKILL003",
                    "error",
                    "Skill contains an invalid local reference",
                    message,
                    "Codex may pause mid-workflow or read files outside the intended skill package.",
                    "Point the reference at an existing file inside this skill directory.",
                    Location(relative, line, line, line_excerpt(text, line)),
                    tags=("skill", "reference"),
                )
            )

        # Frontmatter is discovery metadata, not an executable authority
        # request.  Only the selected skill body contributes capability facts.
        authority_text = parsed.body if not parsed.issue else ""
        result.findings.extend(
            instruction_safety_findings(authority_text, relative_path=relative, source_kind="skill")
        )
        skill_scope = result.relative_path(path.parent)
        skill_facts = extract_policy_facts(
            authority_text,
            relative_path=relative,
            scope=skill_scope,
            source_kind="skill",
            depth=len(path.parent.parts),
        )
        result.policy_facts.extend(skill_facts)
        for fact in skill_facts:
            if fact.action in {"credentials.read", "secrets.output", "filesystem.delete", "git.force"} and fact.modality in {"require", "allow"} and not APPROVE_RE.search(fact.phrase):
                result.findings.append(
                    Finding(
                        "AUTH001",
                        "warning",
                        "Skill requests high-risk authority without approval",
                        f"The skill requests `{fact.action}` as `{fact.modality}` without an explicit user approval step.",
                        "A skill is reusable executable guidance and may run in repositories with broader permissions than its author expected.",
                        "Add an explicit approval gate, narrow the target, and state which data must never leave the workspace.",
                        fact.location,
                        confidence="medium",
                        tags=("authority", "skill", fact.action),
                    )
                )
        name = parsed.values.get("name") if not parsed.issue else path.parent.name
        result.nodes.append(GraphNode(f"skill:{relative}", "skill", str(name or path.parent.name), relative, "reusable workflow"))


def _inspect_plugins(result: ScanResult, found: DiscoveredFiles) -> None:
    required_strings = ("name", "version", "description")
    interface_strings = (
        "displayName",
        "shortDescription",
        "longDescription",
        "developerName",
        "category",
    )
    for path in found.plugins:
        relative = result.relative_path(path)
        text = _read_or_record(result, path, relative)
        if text is None:
            continue
        data, issue = parse_json(path)
        if issue:
            result.findings.append(_parse_finding(relative, text, issue.line, issue.message, "JSON"))
            continue
        if not isinstance(data, dict):
            result.findings.append(
                _plugin_contract_finding(relative, text, 1, "The manifest root must be a JSON object.")
            )
            continue
        plugin_root = path.parent.parent
        allowed = {"id", "name", "version", "description", "skills", "apps", "mcpServers", "interface", "author", "homepage", "repository", "license", "keywords"}
        for key in sorted(set(data) - allowed):
            result.findings.append(_plugin_contract_finding(relative, text, find_line(text, f'"{key}"'), f"Unsupported manifest field `{key}`."))
        if _contains_todo(data):
            result.findings.append(_plugin_contract_finding(relative, text, find_line(text, "[TODO:"), "Manifest contains a `[TODO: ...]` placeholder."))

        for field in required_strings:
            if not isinstance(data.get(field), str) or not data[field].strip():
                result.findings.append(
                    _plugin_contract_finding(relative, text, 1, f"Required string field `{field}` is missing or empty.")
                )
        author = data.get("author")
        if not isinstance(author, dict) or not isinstance(author.get("name"), str) or not author["name"].strip():
            result.findings.append(
                _plugin_contract_finding(relative, text, find_line(text, '"author"'), "Required `author` object with non-empty `author.name` is missing or invalid.")
            )
        elif set(author) - {"name", "email", "url"}:
            result.findings.append(_plugin_contract_finding(relative, text, find_line(text, '"author"'), "`author` contains unsupported fields."))
        elif ("email" in author and (not isinstance(author["email"], str) or not author["email"].strip())) or ("url" in author and not _is_https_url(author["url"])):
            result.findings.append(_plugin_contract_finding(relative, text, find_line(text, '"author"'), "`author.email` must be non-empty and `author.url` must be an absolute HTTPS URL when present."))
        interface = data.get("interface")
        if not isinstance(interface, dict):
            result.findings.append(
                _plugin_contract_finding(relative, text, find_line(text, '"interface"'), "Required `interface` object is missing or invalid.")
            )
        elif isinstance(interface, dict):
            allowed_interface = {"displayName", "shortDescription", "longDescription", "developerName", "category", "capabilities", "websiteURL", "privacyPolicyURL", "termsOfServiceURL", "brandColor", "composerIcon", "logo", "logoDark", "screenshots", "defaultPrompt", "default_prompt"}
            if set(interface) - allowed_interface:
                result.findings.append(_plugin_contract_finding(relative, text, find_line(text, '"interface"'), "`interface` contains unsupported fields."))
            for field in interface_strings:
                if not isinstance(interface.get(field), str) or not interface[field].strip():
                    result.findings.append(
                        _plugin_contract_finding(relative, text, find_line(text, f'"{field}"'), f"Required interface string `{field}` is missing or empty.")
                    )
            if not isinstance(interface.get("capabilities"), list) or not all(isinstance(v, str) and v.strip() for v in interface.get("capabilities", [])):
                result.findings.append(
                    _plugin_contract_finding(relative, text, find_line(text, '"capabilities"'), "`interface.capabilities` must be an array.")
                )
            prompts = interface.get("defaultPrompt", interface.get("default_prompt"))
            if not isinstance(prompts, (str, list)):
                result.findings.append(
                    _plugin_contract_finding(relative, text, find_line(text, '"defaultPrompt"'), "`interface.defaultPrompt` must be a string or array.")
                )
            for field in ("websiteURL", "privacyPolicyURL", "termsOfServiceURL"):
                if field in interface and not _is_https_url(interface[field]):
                    result.findings.append(_plugin_contract_finding(relative, text, find_line(text, f'"{field}"'), f"`interface.{field}` must be an absolute HTTPS URL."))
            if "brandColor" in interface and (not isinstance(interface["brandColor"], str) or not re.fullmatch(r"#[0-9A-Fa-f]{6}", interface["brandColor"])):
                result.findings.append(_plugin_contract_finding(relative, text, find_line(text, '"brandColor"'), "`interface.brandColor` must use `#RRGGBB`."))
            for field in ("composerIcon", "logo", "logoDark"):
                if field in interface and not _safe_plugin_asset(plugin_root=path.parent.parent, value=interface[field]):
                    result.findings.append(_plugin_contract_finding(relative, text, find_line(text, f'"{field}"'), f"`interface.{field}` must name an existing safe plugin asset."))
            shots = interface.get("screenshots", [])
            if not isinstance(shots, list) or any(not _safe_plugin_asset(path.parent.parent, item) for item in shots):
                result.findings.append(_plugin_contract_finding(relative, text, find_line(text, '"screenshots"'), "`interface.screenshots` must be an array of existing safe plugin assets."))

        name = data.get("name")
        if isinstance(name, str) and not KEBAB_RE.fullmatch(name):
            line = find_line(text, '"name"')
            result.findings.append(
                _plugin_contract_finding(relative, text, line, "Plugin `name` must use lower-case kebab-case.")
            )
        version = data.get("version")
        if isinstance(version, str) and not SEMVER_RE.fullmatch(version):
            line = find_line(text, '"version"')
            result.findings.append(
                _plugin_contract_finding(relative, text, line, "Plugin `version` must use strict semantic versioning.")
            )

        for field in ("skills", "apps"):
            value = data.get(field)
            if value is None:
                continue
            expected = "skills" if field == "skills" else ".app.json"
            line = find_line(text, f'"{field}"')
            if not isinstance(value, str) or value.replace("\\", "/").rstrip("/").removeprefix("./") != expected:
                message = f"`{field}` must be the string path `./{expected}`."
            elif not _is_safe_local_target(plugin_root / value, plugin_root):
                message = f"`{field}` path `{value}` escapes the plugin root."
            elif not (plugin_root / value).exists():
                message = f"`{field}` path `{value}` does not exist."
            else:
                continue
            result.findings.append(
                Finding(
                    "PLUGIN002",
                    "error",
                    "Plugin component path is invalid",
                    message,
                    "Codex packages plugin components relative to the plugin root.",
                    "Use a `./` relative path that resolves to an existing file or directory inside the plugin.",
                    Location(relative, line, line, line_excerpt(text, line)),
                    tags=("plugin", "path"),
                )
            )
        if data.get("apps") is not None and isinstance(data.get("apps"), str) and _is_safe_local_target(plugin_root / data["apps"], plugin_root):
            _validate_app_companion(result, relative, text, plugin_root / data["apps"])
        mcp_value = data.get("mcpServers")
        if mcp_value is not None:
            line = find_line(text, '"mcpServers"')
            valid_inline = isinstance(mcp_value, dict) and all(isinstance(name, str) and name.strip() and isinstance(config, dict) for name, config in mcp_value.items())
            valid_path = isinstance(mcp_value, str) and mcp_value.replace("\\", "/").rstrip("/").removeprefix("./") == ".mcp.json" and _is_safe_local_target(plugin_root / mcp_value, plugin_root)
            if not (valid_inline or valid_path):
                result.findings.append(_plugin_contract_finding(relative, text, line, "`mcpServers` must be an object of server objects or the existing path `./.mcp.json`."))
            elif valid_inline:
                _audit_mcp_servers(result, relative, text, mcp_value, f"plugin:{relative}", "inline mcpServers")
            elif valid_path:
                _validate_mcp_companion(result, relative, text, plugin_root / mcp_value)
        _validate_plugin_skill_tree(result, relative, text, plugin_root)
        result.nodes.append(
            GraphNode(f"plugin:{relative}", "plugin", str(name or path.parent.parent.name), relative, str(version or "unknown version"))
        )


def _inspect_mcp(result: ScanResult, found: DiscoveredFiles) -> None:
    config_paths = [(path, "json") for path in found.mcp_json] + [
        (path, "toml") for path in found.codex_toml
    ]
    for path, kind in sorted(config_paths, key=lambda item: item[0].as_posix().lower()):
        relative = result.relative_path(path)
        text = _read_or_record(result, path, relative)
        if text is None:
            continue
        data, issue = parse_json(path) if kind == "json" else parse_toml(path)
        if issue:
            result.findings.append(_parse_finding(relative, text, issue.line, issue.message, kind.upper()))
            continue
        servers = _extract_mcp_servers(data, kind)
        _audit_mcp_servers(result, relative, text, servers, None, path.name)


def _audit_mcp_servers(result: ScanResult, relative: str, text: str, servers: dict[str, Any], plugin_node: str | None, label: str) -> None:
    """Audit an external or manifest-inline MCP configuration without executing it."""
    result.inventory.mcp_servers += len(servers)
    inline = plugin_node is not None
    suffix = "#inline" if inline else ""
    config_node = f"mcp-config:{relative}{suffix}"
    if inline:
        result.inventory.mcp_configs += 1
    result.nodes.append(GraphNode(config_node, "mcp-config", label, relative, f"{len(servers)} server(s)"))
    if plugin_node is not None:
        result.edges.append(GraphEdge(plugin_node, config_node, "bundles"))
    for server_name, config in sorted(servers.items()):
        if not isinstance(config, dict):
            continue
        node = f"mcp:{relative}{suffix}:{server_name}"
        result.nodes.append(GraphNode(node, "mcp-server", server_name, relative, _mcp_summary(config)))
        result.edges.append(GraphEdge(config_node, node, "configures"))
        for key in ("url", "server_url"):
            url = config.get(key)
            transport_severity = _insecure_transport_severity(url) if isinstance(url, str) else None
            if transport_severity:
                line = find_line(text, url)
                result.findings.append(Finding("MCP001", transport_severity, "Remote MCP endpoint lacks secure transport", f"Server `{server_name}` connects to `{url}` without TLS.", "Tool definitions, arguments, results, and credentials can cross this transport.", "Use an `https://` or `wss://` endpoint. Plain HTTP is acceptable only for a loopback development server.", Location(relative, line, line, line_excerpt(text, line)), tags=("mcp", "transport")))
            if isinstance(url, str) and _url_contains_credential(url):
                line = find_line(text, url)
                result.findings.append(Finding("MCP002", "error", "MCP configuration contains an embedded secret", f"Server `{server_name}` embeds credentials in `{key}`.", "URLs are frequently logged and copied into reports, process listings, and telemetry.", "Move credentials to a scoped environment variable or secret manager.", Location(relative, line, line, line_excerpt(text, line)), tags=("mcp", "secrets")))
        for key_path, value in _walk_values(config):
            if isinstance(value, str) and _looks_like_embedded_secret(key_path[-1] if key_path else "", value):
                line = find_line(text, value)
                result.findings.append(Finding("MCP002", "error", "MCP configuration contains an embedded secret", f"Server `{server_name}` stores a literal credential at `{'.'.join(key_path)}`: {_redact(value)}", "Agent configuration is often committed, copied, indexed, and loaded into model context.", "Move the value to a scoped environment variable or secret manager and rotate the exposed credential.", Location(relative, line, line, _redact(line_excerpt(text, line))), tags=("mcp", "secrets")))
        command, args = config.get("command"), config.get("args")
        package = _first_package_argument(args) if isinstance(command, str) and command.lower() in {"npx", "uvx", "pipx", "bunx"} else None
        if package and not _package_is_pinned(package):
            line = find_line(text, package)
            result.findings.append(Finding("MCP003", "warning", "MCP package execution is not version-pinned", f"Server `{server_name}` launches `{package}` through `{command}` without an immutable version.", "A future package release or registry compromise can change code that the agent launches.", "Pin an exact package version or immutable commit and update it deliberately.", Location(relative, line, line, line_excerpt(text, line)), tags=("mcp", "supply-chain")))
        for arg in args if isinstance(args, list) else []:
            if isinstance(arg, str) and SENSITIVE_ROOT_RE.match(arg.strip()):
                line = find_line(text, arg)
                result.findings.append(Finding("MCP004", "warning", "MCP server receives an overly broad filesystem path", f"Server `{server_name}` is launched with broad path `{arg}`.", "A compromised or confused tool may read or write much more than the current project.", "Pass the narrowest repository or data directory required by this server.", Location(relative, line, line, line_excerpt(text, line)), tags=("mcp", "least-privilege")))
        approval_key = _disabled_approval_key(config)
        if approval_key:
            line = find_line(text, approval_key)
            result.findings.append(Finding("MCP005", "warning", "MCP calls explicitly disable approval", f"Server `{server_name}` sets `{approval_key}` to `never`.", "OpenAI requests approval by default before data is shared with remote MCP servers; disabling it removes that visibility boundary.", "Require approval globally or for sensitive tools, and constrain the allowed tool list.", Location(relative, line, line, line_excerpt(text, line)), tags=("mcp", "approval")))


def _inspect_documentation(result: ScanResult, found: DiscoveredFiles) -> None:
    if not found.plugins:
        return
    readme = found.root / "README.md"
    if not readme.exists():
        missing = "README.md is missing; installation, supported platforms, and a reproducible test path are undocumented."
        line = 1
        excerpt = ""
        relative = "README.md"
    else:
        try:
            text = read_text(readme)
        except (OSError, ValueError):
            text = ""
        checks = {
            "installation": re.search(r"(?i)\b(install|installation|setup)\b", text),
            "supported platforms": re.search(r"(?i)\b(platform|windows|macos|linux)\b", text),
            "test path": re.search(r"(?i)\b(test|demo|try it|quickstart|quick start)\b", text),
        }
        absent = [label for label, match in checks.items() if not match]
        if not absent:
            return
        missing = "README.md does not clearly document: " + ", ".join(absent) + "."
        line = 1
        excerpt = line_excerpt(text, 1)
        relative = "README.md"
    result.findings.append(
        Finding(
            "DOC001",
            "warning",
            "Plugin test path is not fully documented",
            missing,
            "Reviewers and users need to install the plugin, know whether their platform is supported, and reproduce one real workflow.",
            "Add installation commands, supported platforms, and a copy-paste test or demo path.",
            Location(relative, line, line, excerpt),
            tags=("documentation", "plugin"),
        )
    )


def _build_cross_component_graph(result: ScanResult, found: DiscoveredFiles) -> None:
    node_ids = {node.node_id for node in result.nodes}
    capability_nodes: dict[str, str] = {}
    for fact in result.policy_facts:
        capability_id = capability_nodes.setdefault(fact.action, f"capability:{fact.action}")
        if capability_id not in node_ids:
            result.nodes.append(GraphNode(capability_id, "capability", fact.action, detail="requested authority"))
            node_ids.add(capability_id)
        source_prefix = "skill" if fact.source_kind == "skill" else "agents"
        source_id = f"{source_prefix}:{fact.location.path}"
        if source_id in node_ids:
            risk = "danger" if fact.action in {"secrets.output", "git.force"} else "neutral"
            result.edges.append(GraphEdge(source_id, capability_id, fact.modality, risk))

    plugins = [node for node in result.nodes if node.kind == "plugin"]
    skills = [node for node in result.nodes if node.kind == "skill"]
    mcp_configs = [node for node in result.nodes if node.kind == "mcp-config"]
    for plugin in plugins:
        plugin_root = Path(plugin.path).parent.parent.as_posix()
        manifest_path = found.root / plugin.path
        manifest, issue = parse_json(manifest_path)
        if issue or not isinstance(manifest, dict):
            continue
        skills_ref = manifest.get("skills")
        mcp_ref = manifest.get("mcpServers")
        skills_path = f"{plugin_root}/skills/"
        mcp_path = f"{plugin_root}/.mcp.json"
        for skill in skills:
            if skills_ref in {"./skills", "./skills/", "skills", "skills/"} and skill.path.startswith(skills_path):
                result.edges.append(GraphEdge(plugin.node_id, skill.node_id, "bundles"))
        for config in mcp_configs:
            if isinstance(mcp_ref, str) and mcp_ref in {"./.mcp.json", ".mcp.json"} and config.path == mcp_path:
                result.edges.append(GraphEdge(plugin.node_id, config.node_id, "bundles"))

    agents = sorted((node for node in result.nodes if node.kind == "instructions"), key=lambda n: (len(Path(n.path).parts), n.path))
    for parent in agents:
        parent_scope = Path(parent.path).parent
        for child in agents:
            if parent.node_id == child.node_id:
                continue
            child_scope = Path(child.path).parent
            try:
                if child_scope.is_relative_to(parent_scope) and len(child_scope.parts) == len(parent_scope.parts) + 1:
                    result.edges.append(GraphEdge(parent.node_id, child.node_id, "precedes"))
            except ValueError:
                continue


def _build_instruction_chains(result: ScanResult, found: DiscoveredFiles) -> None:
    """Expose the per-directory chain Codex would load, without guessing text semantics.

    At each directory Codex chooses override first, then AGENTS.  For every
    discovered instruction scope we report that selected root-to-scope chain
    and the last deterministic fact for each known action.  A consumer can
    therefore see both the competing locations and the mechanically effective
    rule, while POLICY001 handles contradictions separately.
    """
    selected: dict[Path, Path] = {}
    for path in found.agents:
        previous = selected.get(path.parent)
        if previous is None or path.name == "AGENTS.override.md":
            selected[path.parent] = path
    for scope_dir in sorted(selected, key=lambda item: _scope_relative(found.root, item).lower()):
        chain: list[Path] = []
        for directory, source in selected.items():
            try:
                directory.relative_to(found.root)
                scope_dir.relative_to(directory)
            except ValueError:
                continue
            chain.append(source)
        chain.sort(key=lambda source: (len(source.parent.relative_to(found.root).parts), source.as_posix().lower()))
        chain_paths = [result.relative_path(source) for source in chain]
        scope = _scope_relative(found.root, scope_dir)
        effective: dict[str, PolicyFact] = {}
        for fact in result.policy_facts:
            if fact.source_kind != "agents":
                continue
            if fact.location.path in chain_paths:
                effective[fact.action] = fact
        result.instruction_chains.append(
            {
                "scope": scope,
                "sources": chain_paths,
                "effective_rules": [effective[action].to_dict() for action in sorted(effective)],
            }
        )


def _read_or_record(result: ScanResult, path: Path, relative: str) -> str | None:
    try:
        return read_text(path)
    except (OSError, ValueError) as exc:
        result.findings.append(
            Finding(
                "STRUCT001",
                "error",
                "Configuration file cannot be read safely",
                str(exc),
                "The audit cannot establish the effective configuration without reading this file.",
                "Make the file UTF-8, readable, and smaller than the documented safety limit.",
                Location(relative, 1, 1, ""),
                tags=("structure",),
            )
        )
        return None


def _parse_finding(relative: str, text: str, line: int, message: str, kind: str) -> Finding:
    return Finding(
        "STRUCT001",
        "error",
        f"{kind} configuration cannot be parsed",
        message,
        "Malformed configuration can prevent Codex from loading the intended policy or tool boundary.",
        f"Correct the {kind} syntax and run AgentLint again.",
        Location(relative, line, line, line_excerpt(text, line)),
        tags=("structure", kind.lower()),
    )


def _plugin_contract_finding(relative: str, text: str, line: int, message: str) -> Finding:
    return Finding(
        "PLUGIN001",
        "error",
        "Plugin manifest violates the Codex contract",
        message,
        "Codex uses `.codex-plugin/plugin.json` as the required plugin entry point and install-surface metadata.",
        "Match the current OpenAI plugin manifest contract, then validate the package with `plugin-creator`.",
        Location(relative, line, line, line_excerpt(text, line)),
        tags=("plugin", "manifest"),
    )


def _extract_mcp_servers(data: Any, kind: str) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    if kind == "toml":
        value = data.get("mcp_servers", {})
        return value if isinstance(value, dict) else {}
    value = data.get("mcpServers")
    if isinstance(value, dict):
        return value
    value = data.get("mcp_servers")
    if isinstance(value, dict):
        return value
    if all(isinstance(value, dict) for value in data.values()):
        return data
    return {}


def _walk_values(value: Any, path: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _walk_values(child, path + (str(key),))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_values(child, path + (str(index),))
    else:
        yield path, value


def _looks_like_embedded_secret(key: str, value: str) -> bool:
    stripped = value.strip()
    if not stripped or ENV_REFERENCE_RE.fullmatch(stripped):
        return False
    if SECRET_VALUE_RE.search(stripped):
        return True
    return bool(SECRET_KEY_RE.search(key) and len(stripped) >= 8 and not stripped.startswith(("${", "$", "%")))


def _redact(value: str) -> str:
    # A prefix/suffix is still credential material and adds no diagnostic
    # value: key path and server name already identify the remediation site.
    return "[REDACTED]"


def _insecure_transport_severity(url: str) -> str | None:
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme in {"https", "wss"}:
        return None
    if scheme not in {"http", "ws", "ftp"}:
        return "warning" if scheme else None
    host = (parsed.hostname or "").lower()
    if scheme == "http" and host in LOOPBACK_HOSTS:
        return None
    try:
        if scheme == "http" and ipaddress.ip_address(host).is_loopback:
            return None
    except ValueError:
        pass
    return "error" if scheme == "http" else "warning"


def _url_contains_credential(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.username is not None or parsed.password is not None:
            return True
        return any(re.search(r"(?i)(token|secret|key|password|auth|credential|令牌|密钥|密码|口令|凭据)", key) for key, _ in parse_qsl(parsed.query, keep_blank_values=True))
    except (ValueError, TypeError):
        return bool(re.search(r"(?i)(?:@|token|secret|key|password|auth|credential|令牌|密钥|密码|口令|凭据)", url))


def _first_package_argument(args: Any) -> str | None:
    if not isinstance(args, list):
        return None
    for value in args:
        if isinstance(value, str) and value and not value.startswith("-"):
            return value
    return None


def _package_is_pinned(package: str) -> bool:
    if package.endswith("@latest"):
        return False
    if package.startswith("@"):
        return bool(re.fullmatch(r"@[^/@]+/[^/@]+@\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", package))
    return bool(re.fullmatch(r"[^@]+@\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", package))


def _mcp_summary(config: dict[str, Any]) -> str:
    if isinstance(config.get("url"), str):
        return config["url"]
    command = config.get("command")
    return f"stdio: {command}" if command else "configured server"


def _scope_relative(root: Path, directory: Path) -> str:
    try:
        value = directory.resolve().relative_to(root.resolve()).as_posix()
        return value or "."
    except ValueError:
        return directory.as_posix()


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _is_safe_local_target(target: Path, root: Path) -> bool:
    """Return true only for an existing, lexical child with no symlink hop."""
    try:
        relative = target.relative_to(root)
    except ValueError:
        return False
    current = root
    for part in relative.parts:
        if part in {"", ".", ".."}:
            return False
        current = current / part
        if current.is_symlink() or _is_reparse_point(current):
            return False
    return target.exists()


def _is_https_url(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urlparse(value)
    return parsed.scheme == "https" and bool(parsed.netloc)


def _safe_plugin_asset(plugin_root: Path, value: Any) -> bool:
    if not isinstance(value, str) or not value or value.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", value):
        return False
    target = plugin_root / value
    return _is_safe_local_target(target, plugin_root) and target.is_file()


def _contains_todo(value: Any) -> bool:
    if isinstance(value, str):
        return "[TODO:" in value
    if isinstance(value, list):
        return any(_contains_todo(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_todo(item) for item in value.values())
    return False


def _companion_object(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    data, issue = parse_json(path)
    if issue:
        return None, issue.message
    if not isinstance(data, dict):
        return None, "must contain a JSON object"
    return data, None


def _validate_app_companion(result: ScanResult, relative: str, text: str, path: Path) -> None:
    data, error = _companion_object(path)
    if error:
        result.findings.append(_plugin_contract_finding(relative, text, find_line(text, '"apps"'), f"`.app.json` {error}."))
        return
    if set(data) != {"apps"} or not isinstance(data.get("apps"), dict):
        result.findings.append(_plugin_contract_finding(relative, text, find_line(text, '"apps"'), "`.app.json` must contain only an `apps` object."))
        return
    for name, app in data["apps"].items():
        if not isinstance(app, dict) or set(app) - {"id", "category"} or not isinstance(app.get("id"), str) or not app["id"].strip() or ("category" in app and (not isinstance(app["category"], str) or not app["category"].strip())):
            result.findings.append(_plugin_contract_finding(relative, text, find_line(text, '"apps"'), f"`.app.json` app `{name}` must be an object with non-empty `id` and optional non-empty `category`."))


def _validate_mcp_companion(result: ScanResult, relative: str, text: str, path: Path) -> None:
    data, error = _companion_object(path)
    if error:
        result.findings.append(_plugin_contract_finding(relative, text, find_line(text, '"mcpServers"'), f"`.mcp.json` {error}."))
        return
    servers = data.get("mcpServers")
    if set(data) != {"mcpServers"} or not isinstance(servers, dict) or any(not isinstance(name, str) or not name.strip() or not isinstance(config, dict) for name, config in servers.items()):
        result.findings.append(_plugin_contract_finding(relative, text, find_line(text, '"mcpServers"'), "`.mcp.json` must contain only an object of non-empty server names mapped to objects."))


def _validate_plugin_skill_tree(result: ScanResult, relative: str, text: str, plugin_root: Path) -> None:
    skills_root = plugin_root / "skills"
    if not skills_root.is_dir() or _is_reparse_point(skills_root):
        return
    for skill_root in sorted(skills_root.iterdir(), key=lambda item: item.name.lower()):
        if skill_root.name.startswith(".") or not skill_root.is_dir() or skill_root.is_symlink() or _is_reparse_point(skill_root):
            continue
        skill_md = skill_root / "SKILL.md"
        if not skill_md.is_file() or skill_md.is_symlink() or _is_reparse_point(skill_md):
            result.findings.append(_skill_contract_finding(relative, text, f"Skill `{skill_root.name}` has a missing or unsafe `SKILL.md`."))
            continue
        body = _read_or_record(result, skill_md, result.relative_path(skill_md))
        if body is None:
            continue
        frontmatter = parse_frontmatter(body)
        if frontmatter.issue or not isinstance(frontmatter.values.get("name"), str) or not frontmatter.values["name"].strip() or not isinstance(frontmatter.values.get("description"), str) or not frontmatter.values["description"].strip():
            result.findings.append(_skill_contract_finding(relative, text, f"Skill `{skill_root.name}` frontmatter requires non-empty `name` and `description`."))
        for key in ("disable-model-invocation", "disable_model_invocation"):
            if key in frontmatter.values and frontmatter.values[key] is not False:
                result.findings.append(_skill_contract_finding(relative, text, f"Skill `{skill_root.name}` field `{key}` must be false when present."))
        agents_dir = skill_root / "agents"
        if agents_dir.exists() and (agents_dir.is_symlink() or _is_reparse_point(agents_dir)):
            result.findings.append(_skill_contract_finding(relative, text, f"Skill `{skill_root.name}` has an unsafe agents directory; its agent manifest was not read."))
            continue
        agent_path = agents_dir / "openai.yaml"
        if agent_path.exists() and (agent_path.is_symlink() or _is_reparse_point(agent_path)):
            result.findings.append(_skill_contract_finding(relative, text, f"Skill `{skill_root.name}` has an unsafe `agents/openai.yaml`; it was not read."))
        elif agent_path.is_file():
            _validate_skill_agent_yaml(result, relative, text, plugin_root, skill_root, agent_path)


def _skill_contract_finding(relative: str, text: str, message: str) -> Finding:
    return Finding("SKILL001", "error", "Skill contract is invalid", message, "A malformed skill package cannot be loaded predictably by Codex.", "Match the documented SKILL.md and agent manifest contract.", Location(relative, 1, 1, line_excerpt(text, 1)), tags=("skill", "contract"))


def _validate_skill_agent_yaml(result: ScanResult, relative: str, text: str, plugin_root: Path, skill_root: Path, path: Path) -> None:
    try:
        data = yaml.safe_load(read_text(path))
    except (OSError, yaml.YAMLError, ValueError) as exc:
        result.findings.append(_skill_contract_finding(relative, text, f"Skill `{skill_root.name}` agent YAML cannot be parsed: {exc}.")); return
    if not isinstance(data, dict) or set(data) - {"interface", "policy", "dependencies"}:
        result.findings.append(_skill_contract_finding(relative, text, f"Skill `{skill_root.name}` agent YAML has an invalid root shape.")); return
    interface = data.get("interface")
    allowed = {"display_name", "short_description", "icon_small", "icon_large", "brand_color", "default_prompt"}
    if not isinstance(interface, dict) or set(interface) - allowed or any(not isinstance(interface.get(key), str) or not interface[key].strip() for key in ("display_name", "short_description")):
        result.findings.append(_skill_contract_finding(relative, text, f"Skill `{skill_root.name}` agent `interface` is invalid."))
    elif ("brand_color" in interface and (not isinstance(interface["brand_color"], str) or not re.fullmatch(r"#[0-9A-Fa-f]{6}", interface["brand_color"]))) or ("default_prompt" in interface and (not isinstance(interface["default_prompt"], str) or not interface["default_prompt"].strip())) or any(key in interface and not _safe_skill_asset(plugin_root, skill_root, interface[key]) for key in ("icon_small", "icon_large")):
        result.findings.append(_skill_contract_finding(relative, text, f"Skill `{skill_root.name}` agent interface asset or optional field is invalid."))
    policy = data.get("policy")
    if policy is not None and (not isinstance(policy, dict) or set(policy) - {"allow_implicit_invocation"} or ("allow_implicit_invocation" in policy and not isinstance(policy["allow_implicit_invocation"], bool))):
        result.findings.append(_skill_contract_finding(relative, text, f"Skill `{skill_root.name}` agent policy is invalid."))
    dependencies = data.get("dependencies")
    if dependencies is not None and (not isinstance(dependencies, dict) or set(dependencies) - {"tools"}):
        result.findings.append(_skill_contract_finding(relative, text, f"Skill `{skill_root.name}` agent dependencies are invalid."))


def _safe_skill_asset(plugin_root: Path, skill_root: Path, value: Any) -> bool:
    if not isinstance(value, str):
        return False
    target = skill_root / value
    return _is_safe_local_target(target, skill_root) and _is_safe_local_target(target, plugin_root) and target.is_file()


def _disabled_approval_key(config: dict[str, Any]) -> str | None:
    """Recognize legacy and current static approval settings only."""
    for key in ("require_approval", "default_tools_approval_mode", "approval_mode"):
        if str(config.get(key, "")).lower() == "never":
            return key
    return None


def rule_catalog() -> list[dict[str, str]]:
    return [
        {
            "id": rule.rule_id,
            "severity": rule.default_severity,
            "title": rule.title,
            "category": rule.category,
        }
        for rule in RULES
    ]
