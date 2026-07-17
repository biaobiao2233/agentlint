from __future__ import annotations

import html
import json
import os
import sys
from pathlib import Path
from typing import TextIO

from .models import Finding, ScanResult


ANSI = {
    "reset": "\033[0m", "bold": "\033[1m", "muted": "\033[2m", "error": "\033[31m",
    "warning": "\033[33m", "info": "\033[36m", "pass": "\033[32m",
}


ZH_RULES = {
    "STRUCT001": ("配置文件无法解析", "审计无法可靠建立有效配置边界。", "修正配置语法后重新运行 AgentLint。"),
    "PLUGIN001": ("插件清单不符合 Codex 约定", "插件入口元数据可能阻止正确安装或加载。", "按当前 Codex 插件清单约定修正字段与路径。"),
    "PLUGIN002": ("插件组件路径无效", "组件路径可能越出插件边界或指向不存在的内容。", "使用插件根目录内存在的 ./ 相对路径。"),
    "SKILL001": ("Skill frontmatter 无效", "Skill 可能无法被可靠识别和加载。", "修正 YAML frontmatter 及必需字段。"),
    "SKILL002": ("Skill 标识信息不一致", "不一致的名称或描述会降低可发现性和复用可靠性。", "让目录名、frontmatter 名称和用途保持一致。"),
    "SKILL003": ("Skill 引用了无效的本地文件", "工作流可能中途停止或读取到预期边界之外。", "改为 skill 目录内真实存在的相对文件。"),
    "POLICY001": ("有效指令存在冲突", "较近的指令可能改变上层安全边界。", "明确覆盖关系，并保留更严格的安全限制。"),
    "POLICY002": ("指令试图绕过高优先级策略", "绕过语句会造成提示注入或策略混淆风险。", "移除绕过措辞，改为保留系统与审批边界的范围规则。"),
    "POLICY003": ("破坏性操作缺少审批边界", "误解指令可能导致不可恢复的数据删除或历史改写。", "要求明确用户确认并验证具体目标。"),
    "POLICY004": ("指令请求披露秘密信息", "执行后可能经聊天、日志、文件或远程服务泄露凭据。", "移除披露请求，仅引用秘密名称并使用受限秘密存储。"),
    "COVERAGE001": ("过长指令需要复核", "过长的控制文本更难审阅其有效边界和例外。", "拆分为可审阅的范围规则，并记录优先级。"),
    "COVERAGE002": ("扫描覆盖范围不完整", "至少一处可能影响有效配置的路径没有被完整读取，因此结果不能视为完全覆盖。", "让相关配置可安全读取，移除链接或 reparse point，或调整项目指令的字节上限后重新扫描。"),
    "AUTH001": ("Skill 请求高风险权限但未设审批", "可复用工作流可能在权限更广的项目中执行。", "增加明确审批关口并缩小目标和数据范围。"),
    "MCP001": ("远程 MCP 端点缺少安全传输", "工具定义、参数、结果和凭据可能经不安全链路传输。", "使用 https:// 或 wss://；仅回环开发服务可使用明文。"),
    "MCP002": ("MCP 配置包含内嵌秘密", "配置常被提交、复制、索引并进入模型上下文。", "移至受限环境变量或秘密管理器，并轮换暴露值。"),
    "MCP003": ("MCP 包执行未固定版本", "未来发布或供应链事件可能改变被启动的代码。", "固定精确版本或不可变提交，并有计划地更新。"),
    "MCP004": ("MCP 服务获得了过宽文件系统路径", "受损或混淆的工具可能读写远超当前项目的内容。", "只传递该服务实际需要的最窄目录。"),
    "MCP005": ("MCP 调用显式关闭审批", "这会移除向远程 MCP 共享数据前的可见性边界。", "为敏感工具保留审批，并限制允许的工具列表。"),
    "DOC001": ("插件测试路径未完整记录", "用户和评审者无法可靠安装并复现实用流程。", "补充安装、支持平台和可复制的测试路径。"),
}


ZH_TEXT = {
    "audit_ledger": "AgentLint / 审计记录", "offline": "离线报告 · 扫描输入未改动 · 不执行", "effective_audit": "有效指令审计",
    "lede": "静态读取会塑造智能体有效权限的指令、Skill、插件和 MCP 配置。", "verdict": "结论", "scope": "范围",
    "errors": "错误", "warnings": "警告", "error": "错误", "warning": "警告", "info": "信息", "high": "高", "medium": "中", "low": "低", "instructions": "指令", "skills": "技能", "plugins": "插件", "mcp_servers": "MCP 服务",
    "precedence": "01 · 优先级", "instruction_graph": "有效指令图", "policy_intro": "指令按项目根目录到工作目录的顺序生效；更近的指令可能改变有效边界。",
    "authority": "02 · 权限", "authority_map": "能力与权限映射", "authority_intro": "下列证据关联路径表示有扫描依据的关系，而非位置对应；不会调用工具。",
    "evidence_routes": "证据关联的多步路径", "other_edges": "其他证据关联边", "evidence": "03 · 证据", "findings": "发现项",
    "findings_intro": "筛选审计列表，搜索已转义的证据，再展开条目查看影响和限定修复建议。", "all": "全部", "search": "搜索规则、文件或证据",
    "empty_filter": "没有发现项匹配这些筛选条件。", "clear_filter": "清空搜索或选择“全部”。", "technical": "技术详情", "primary_evidence": "主要证据", "related_evidence": "关联证据", "why": "风险说明。", "fix": "建议修复", "confidence": "置信度", "language": "语言", "audit_totals": "审计汇总", "finding_filters": "发现项筛选", "search_label": "搜索发现项", "notice": "AgentLint 是确定性预检工具，不是安全认证。没有规则或已知覆盖缺口匹配，并不表示所有行为都安全。", "empty_report_title": "没有确定性发现项", "empty_report_copy": "扫描配置没有命中当前规则或已知覆盖缺口；这不代表所有行为都安全。", "skipped_files": "跳过的文件", "shown": "条发现项已显示。",
    "coverage": "04 · 覆盖范围", "inventory": "清单", "coverage_intro": "本次扫描包含的配置范围。", "config_files": "配置文件", "agents_files": "AGENTS 文件", "mcp_configs": "MCP 配置",
    "footer": "自包含报告 · 系统字体回退 · 无外部脚本、字体或遥测", "none_graph": "未发现跨组件图关系。", "none_policy": "未识别出可操作的 AGENTS.md 策略语句。",
    "block": "阻断 BLOCK", "review": "复核 REVIEW", "pass": "通过 PASS", "verdict_labels": {"block": "阻断", "review": "复核", "pass": "通过"}, "modalities": {"deny": "禁止", "require": "要求", "configures": "配置", "bundles": "打包", "precedes": "先于"},
    "tags": {"mcp": "MCP", "policy": "策略", "skill": "技能", "coverage": "覆盖范围", "discovery": "发现", "byte-limit": "字节上限", "transport": "传输", "approval": "审批", "plugin": "插件", "documentation": "文档", "secrets": "秘密信息", "supply-chain": "供应链", "least-privilege": "最小权限", "authority": "权限", "prompt-injection": "提示注入", "instruction-precedence": "指令优先级", "destructive-action": "破坏性操作", "agents": "AGENTS 指令", "reference": "引用", "path": "路径", "manifest": "清单", "structure": "结构"},
    "verdict_block": "请在安装或分享该智能体配置前解决确定性错误。", "verdict_review": "没有阻断错误，但高影响权限边界或覆盖缺口仍需人工复核。", "verdict_pass": "当前没有确定性规则或已知覆盖缺口匹配；投产前仍应复核高影响行为。",
}


def render_console(result: ScanResult, *, color: bool = True, stream: TextIO = sys.stdout) -> None:
    use_color = color and hasattr(stream, "isatty") and stream.isatty()

    def styled(value: str, style: str) -> str:
        return ANSI.get(style, "") + value + ANSI["reset"] if use_color else value

    counts = result.counts
    verdict_style = "error" if result.verdict == "BLOCK" else "warning" if result.verdict == "REVIEW" else "pass"
    print(styled("AGENTLINT", "bold") + "  effective agent policy audit", file=stream)
    print(f"{styled(result.verdict, verdict_style)}  {counts['error']} error(s)  {counts['warning']} warning(s)  {counts['info']} info  · {result.inventory.files_scanned} config file(s)", file=stream)
    print(f"Target: {_public_root(result)}", file=stream)
    if not result.findings:
        print("\nNo findings. Static checks cannot certify that a project is secure.", file=stream)
        return
    for finding in result.findings:
        marker = {"error": "E", "warning": "W", "info": "I"}.get(finding.severity, "-")
        print(f"\n{styled(f'{marker} {finding.rule_id}', finding.severity)}  {finding.title}", file=stream)
        print(f"  {finding.primary.path}:{finding.primary.line_start}  {finding.message}", file=stream)
        if finding.primary.excerpt:
            print(styled(f"  > {finding.primary.excerpt}", "muted"), file=stream)
        for related in finding.related:
            print(f"  related: {related.path}:{related.line_start}  {related.excerpt}", file=stream)
        print(f"  Fix: {finding.remediation}", file=stream)


def write_json(result: ScanResult, output: str | Path) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def write_html(result: ScanResult, output: str | Path) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(result), encoding="utf-8")
    return path


def render_html(result: ScanResult) -> str:
    """Render a portable, no-network audit report from the scanner's real evidence."""
    counts = getattr(result, "counts", {})
    inventory = getattr(result, "inventory", None)
    findings = list(getattr(result, "findings", []) or [])
    verdict = str(getattr(result, "verdict", "REVIEW"))
    root = _public_root(result)
    target_name = Path(root).name or root
    verdict_class = verdict.lower() if verdict.lower() in {"block", "review", "pass"} else "review"
    finding_rows = "".join(_finding_row(finding, index) for index, finding in enumerate(findings, 1))
    if not finding_rows:
        finding_rows = '<div class="empty-state" data-empty-state><span aria-hidden="true">✓</span><div><strong data-i18n="empty_report_title">No deterministic findings</strong><p data-i18n="empty_report_copy">The scanned configuration passed the current rule set. This does not certify that every behavior is safe.</p></div></div>'
    skipped_items = list(getattr(inventory, "skipped_files", []) or [])
    skipped = "".join(f"<li><code>{_e(item)}</code></li>" for item in skipped_items)
    skipped_block = f'<details class="skipped"><summary><span>{len(skipped_items)}</span> <span data-i18n="skipped_files">skipped file(s)</span></summary><ul>{skipped}</ul></details>' if skipped_items else ""
    stat_items = (
        ("Errors", "errors", counts.get("error", 0), "error"), ("Warnings", "warnings", counts.get("warning", 0), "warning"),
        ("Instructions", "instructions", _attr(inventory, "agents_files"), ""), ("Skills", "skills", _attr(inventory, "skills"), ""),
        ("Plugins", "plugins", _attr(inventory, "plugins"), ""), ("MCP servers", "mcp_servers", _attr(inventory, "mcp_servers"), ""),
    )
    stats = "".join(f'<div class="stat {tone}"><span data-i18n="{key}">{label}</span><strong>{value}</strong></div>' for label, key, value, tone in stat_items)
    tool_version = _e(getattr(result, "tool_version", "unknown"))
    translations = json.dumps({"text": ZH_TEXT, "rules": ZH_RULES}, ensure_ascii=False).replace("</", "<\\/")
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <link rel="icon" href="data:,">
  <title>AgentLint · {_e(target_name)}</title>
  <style>
    :root {{ --paper:#EFE7D2; --paper-soft:#F7F1DE; --paper-deep:#E1D5B8; --ink:#17150F; --muted:#625B4E; --faint:#8D8575; --coral:#EF6C5B; --coral-deep:#D95A49; --mustard:#E7B848; --line:rgba(23,21,15,.20); --line-soft:rgba(23,21,15,.105); --radius:14px; --sans:Inter,"Segoe UI",Arial,sans-serif; --display:"Arial Narrow",Impact,"Segoe UI",sans-serif; --serif:Georgia,"Times New Roman",serif; --cjk-serif:"Songti SC",STSong,SimSun,serif; --mono:"JetBrains Mono",Consolas,"SFMono-Regular",monospace; }}
    * {{ box-sizing:border-box; }} html {{ background:var(--paper); color:var(--ink); font-family:var(--sans); }} body {{ min-width:280px; margin:0; background:linear-gradient(120deg,rgba(255,255,255,.34),transparent 36%),linear-gradient(315deg,rgba(120,83,28,.045),transparent 42%),repeating-linear-gradient(0deg,rgba(23,21,15,.022) 0 1px,transparent 1px 5px),var(--paper); }}
    button,input {{ font:inherit; }} button {{ color:inherit; }} button:focus-visible,input:focus-visible,summary:focus-visible {{ outline:3px solid var(--coral); outline-offset:3px; }}
    .shell {{ width:min(1480px,calc(100% - 48px)); margin:auto; padding:18px 0 56px; }} .masthead {{ display:flex; justify-content:space-between; align-items:center; gap:18px; padding-bottom:15px; border-bottom:1px solid var(--line); }} .brand {{ display:flex; align-items:baseline; gap:10px; min-width:0; }} .brand-mark {{ display:grid; place-items:center; width:28px; height:28px; border:1px solid var(--ink); border-radius:50%; font-family:var(--display); font-weight:900; }} .kicker,.meta {{ font:700 .70rem/1.25 var(--mono); letter-spacing:.13em; text-transform:uppercase; color:var(--faint); }} .masthead .meta {{ text-align:right; }} .language-switch {{ display:flex; gap:4px; align-items:center; }} .language-switch button {{ min-height:30px; border:1px solid var(--line); border-radius:5px; background:transparent; padding:4px 7px; cursor:pointer; font:700 .67rem/1 var(--mono); }} .language-switch button[aria-pressed="true"] {{ background:var(--paper-deep); border-color:var(--ink); }}
    .layout {{ display:grid; grid-template-columns:minmax(290px,390px) minmax(0,1fr); gap:46px; margin-top:34px; }} .aside {{ padding-right:46px; border-right:1px solid var(--line); }} .report-title {{ margin:14px 0 17px; font:900 clamp(3.35rem,6.9vw,6.9rem)/.78 var(--display); letter-spacing:normal; text-transform:uppercase; }} .report-title em {{ color:var(--coral); font:italic 500 .60em/.8 var(--serif); text-transform:none; white-space:nowrap; }} .lede {{ max-width:35ch; margin:0; color:var(--muted); line-height:1.65; }}
    .verdict {{ margin-top:32px; padding:17px 0 19px; border-top:1px solid var(--ink); border-bottom:1px solid var(--line); }} .verdict strong {{ display:block; margin:9px 0 7px; font:900 clamp(2.6rem,5.3vw,4.5rem)/.82 var(--display); letter-spacing:.01em; }} .verdict-label {{ display:inline-block; }} .verdict-code {{ display:none; }} html[lang^="zh"] .verdict-label {{ font-family:var(--cjk-serif); font-weight:700; line-height:1; }} html[lang^="zh"] .verdict-code {{ display:block; margin-top:11px; color:var(--muted); font:800 .74rem/1 var(--mono); letter-spacing:.10em; }} .verdict small {{ display:block; color:var(--muted); line-height:1.5; }} .verdict.block strong {{ color:var(--coral-deep); }} .verdict.review strong {{ color:#9A6915; }} .verdict.pass strong {{ color:#39754c; }} .verdict strong::before {{ content:"◆ "; font-size:.38em; vertical-align:middle; }}
    .sidebar-note {{ margin-top:22px; color:var(--muted); font-size:.87rem; line-height:1.55; }} .sidebar-note strong {{ color:var(--ink); }} .report-root {{ display:block; margin-top:9px; color:var(--faint); font:500 .76rem/1.55 var(--mono); overflow-wrap:anywhere; }}
    .main {{ min-width:0; }} .overview {{ display:grid; grid-template-columns:repeat(6,minmax(0,1fr)); border-top:1px solid var(--ink); border-bottom:1px solid var(--line); }} .stat {{ min-width:0; min-height:104px; padding:15px 13px 13px; border-right:1px solid var(--line-soft); }} .stat:last-child {{ border:0; }} .stat span {{ display:block; color:var(--faint); font:700 .65rem/1.3 var(--mono); letter-spacing:.08em; text-transform:uppercase; overflow-wrap:anywhere; }} .stat strong {{ display:block; margin-top:13px; font:800 2.15rem/.9 var(--display); }} .stat.error strong {{ color:var(--coral-deep); }} .stat.warning strong {{ color:#9A6915; }}
    section {{ margin-top:45px; }} .section-head {{ display:grid; grid-template-columns:minmax(0,1fr) minmax(220px,.72fr); gap:20px; align-items:end; margin-bottom:14px; }} h2 {{ margin:7px 0 0; font:500 clamp(1.6rem,3vw,2.55rem)/1 var(--cjk-serif); }} .section-head p {{ max-width:48ch; margin:0; color:var(--muted); font-size:.9rem; line-height:1.55; }} .sheet {{ border:1px solid var(--line); border-radius:var(--radius); background:rgba(247,241,222,.72); box-shadow:0 8px 20px rgba(65,43,16,.045); overflow:hidden; }}
    .flow {{ padding:8px 18px; }} .policy-row {{ display:grid; grid-template-columns:minmax(150px,.36fr) 28px minmax(0,1fr); gap:14px; align-items:center; padding:14px 0; border-bottom:1px solid var(--line-soft); }} .policy-row:last-child {{ border:0; }} .source,.policy {{ min-width:0; }} .source strong,.policy strong {{ display:block; overflow-wrap:anywhere; }} .source small,.policy small {{ display:block; margin-top:4px; color:var(--muted); font:.76rem/1.45 var(--mono); overflow-wrap:anywhere; }} .arrow {{ color:var(--coral); font-weight:900; text-align:center; }} .badge {{ display:inline-block; margin-bottom:6px; padding:2px 5px; border:1px solid var(--line); border-radius:4px; color:var(--muted); font:700 .63rem/1.1 var(--mono); letter-spacing:.08em; text-transform:uppercase; }} .empty-inline {{ padding:25px; color:var(--muted); }}
    .authority {{ display:grid; }} .edge-route {{ display:grid; grid-template-columns:minmax(0,1fr) 115px minmax(0,1fr); gap:12px; align-items:center; padding:14px 17px; border-bottom:1px solid var(--line-soft); }} .edge-route:last-child {{ border:0; }} .edge-route strong {{ overflow-wrap:anywhere; }} .edge-route .relation {{ color:var(--coral-deep); font:700 .68rem/1.35 var(--mono); letter-spacing:.05em; text-align:center; text-transform:uppercase; }} .edge-route .relation::before {{ content:"→ "; }} .edge-route small {{ display:block; margin-top:4px; color:var(--muted); font:.75rem/1.45 var(--mono); overflow-wrap:anywhere; }} .edge-route.chain {{ grid-template-columns:minmax(0,1fr) 40px minmax(0,1fr) 40px minmax(0,1fr); }} .edge-route.chain .arrow {{ color:var(--coral); transform:none; }} .edge-route.chain .node {{ min-width:0; }} .edge-label {{ padding:11px 17px 7px; color:var(--faint); font:700 .68rem/1.2 var(--mono); letter-spacing:.1em; text-transform:uppercase; }}
    .toolbar {{ display:flex; flex-wrap:wrap; gap:8px; align-items:center; padding:13px; border-bottom:1px solid var(--line); }} .filter {{ min-height:36px; border:1px solid var(--line); border-radius:7px; background:transparent; padding:7px 10px; cursor:pointer; font-size:.82rem; }} .filter:hover,.filter[aria-pressed="true"] {{ border-color:var(--ink); background:var(--paper-deep); }} .filter[aria-pressed="true"] {{ box-shadow:inset 3px 0 var(--coral); }} .search {{ flex:1 1 220px; min-width:0; min-height:38px; margin-left:auto; border:1px solid var(--line); border-radius:7px; background:var(--paper-soft); color:var(--ink); padding:8px 10px; }} .finding {{ border-bottom:1px solid var(--line-soft); }} .finding:last-child {{ border:0; }} .finding[hidden] {{ display:none; }} .finding summary {{ display:grid; grid-template-columns:88px minmax(0,1fr) 18px; gap:14px; align-items:center; padding:17px 18px; cursor:pointer; list-style:none; }} .finding summary::-webkit-details-marker {{ display:none; }} .severity {{ display:inline-flex; align-items:center; gap:6px; width:max-content; padding:4px 6px; border:1px solid currentColor; border-radius:4px; font:800 .65rem/1 var(--mono); letter-spacing:.06em; text-transform:uppercase; }} .severity::before {{ content:""; width:7px; height:7px; border-radius:50%; background:currentColor; }} .severity.error {{ color:var(--coral-deep); }} .severity.warning {{ color:#8A6015; }} .severity.info {{ color:#436a74; }} .finding-title {{ min-width:0; }} .finding-title strong,.finding-title small {{ display:block; overflow-wrap:anywhere; }} .finding-title small {{ margin-top:5px; color:var(--muted); font:.73rem/1.45 var(--mono); }} .chevron {{ color:var(--faint); transition:transform .16s ease; }} .finding[open] .chevron {{ transform:rotate(90deg); }} .finding-body {{ padding:0 18px 21px 120px; }} .finding-body p {{ color:var(--muted); line-height:1.62; }} .evidence {{ margin:13px 0; padding:12px; border-left:3px solid var(--paper-deep); background:rgba(225,213,184,.35); overflow-wrap:anywhere; }} .evidence.related {{ border-left-color:var(--coral); }} .evidence small {{ color:var(--faint); font:.69rem/1.4 var(--mono); }} code {{ font-family:var(--mono); font-size:.79rem; white-space:pre-wrap; overflow-wrap:anywhere; }} .fix {{ padding:12px; border:1px solid rgba(57,117,76,.28); border-radius:7px; background:rgba(223,236,208,.35); line-height:1.55; }} .tags {{ display:flex; flex-wrap:wrap; gap:6px; margin-top:13px; }} .tag {{ padding:3px 6px; border:1px solid var(--line); border-radius:4px; color:var(--muted); font:.67rem/1 var(--mono); }} .empty-state {{ display:flex; gap:13px; align-items:center; padding:28px; }} .empty-state>span {{ display:grid; place-items:center; width:34px; height:34px; border:1px solid #39754c; border-radius:50%; color:#39754c; }} .empty-state p {{ margin:5px 0 0; color:var(--muted); line-height:1.5; }}
    .filter-empty {{ display:flex; align-items:center; gap:13px; min-height:142px; padding:27px 18px; border-top:1px solid var(--line-soft); }} .filter-empty[hidden] {{ display:none; }} .filter-empty .empty-mark {{ display:grid; place-items:center; flex:0 0 auto; width:30px; height:30px; border:1px solid var(--coral); border-radius:50%; color:var(--coral-deep); font:700 .95rem/1 var(--mono); }} .filter-empty strong {{ display:block; }} .filter-empty p {{ margin:4px 0 0; color:var(--muted); font-size:.88rem; line-height:1.5; }} .sr-only {{ position:absolute; width:1px; height:1px; padding:0; margin:-1px; overflow:hidden; clip:rect(0,0,0,0); white-space:nowrap; border:0; }} .inventory {{ display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); }} .inventory div {{ min-width:0; padding:17px; border-right:1px solid var(--line-soft); }} .inventory div:last-child {{ border:0; }} .inventory strong {{ display:block; font:800 2rem/.9 var(--display); }} .inventory span {{ display:block; margin-top:8px; color:var(--faint); font:.68rem/1.35 var(--mono); text-transform:uppercase; letter-spacing:.07em; }} .skipped {{ padding:13px 17px; border-top:1px solid var(--line-soft); color:var(--muted); }} .skipped summary {{ cursor:pointer; font:.78rem var(--mono); }} .skipped ul {{ padding-left:20px; overflow-wrap:anywhere; }} .notice {{ display:flex; gap:9px; margin-top:13px; padding:11px 0; border-top:1px solid var(--line); color:var(--muted); font-size:.82rem; line-height:1.5; }} footer {{ display:flex; justify-content:space-between; gap:18px; margin-top:36px; padding-top:14px; border-top:1px solid var(--line); color:var(--faint); font:.72rem/1.5 var(--mono); }}
    @media (max-width:1180px) {{ .layout {{ grid-template-columns:minmax(250px,330px) minmax(0,1fr); gap:30px; }} .aside {{ padding-right:30px; }} .overview {{ grid-template-columns:repeat(3,minmax(0,1fr)); }} .stat:nth-child(3) {{ border-right:0; }} .stat:nth-child(-n+3) {{ border-bottom:1px solid var(--line-soft); }} }}
    @media (max-width:900px) {{ .layout {{ grid-template-columns:1fr; gap:0; }} .aside {{ padding:0 0 30px; border:0; border-bottom:1px solid var(--line); }} .lede {{ max-width:60ch; }} .verdict {{ display:grid; grid-template-columns:135px 1fr; column-gap:16px; align-items:center; }} .verdict .kicker {{ grid-column:1; }} .verdict strong {{ grid-column:1; margin:5px 0; }} .verdict small {{ grid-column:2; grid-row:1 / span 2; }} .main {{ padding-top:0; }} }}
    @media (max-width:640px) {{ .shell {{ width:min(100% - 28px,1480px); padding-top:13px; }} .masthead .meta {{ display:none; }} .report-title {{ font-size:clamp(3.15rem,19vw,5.2rem); }} .overview {{ grid-template-columns:repeat(2,minmax(0,1fr)); }} .stat {{ min-height:86px; }} .stat:nth-child(n) {{ border-right:1px solid var(--line-soft); border-bottom:1px solid var(--line-soft); }} .stat:nth-child(2n) {{ border-right:0; }} .stat:nth-last-child(-n+2) {{ border-bottom:0; }} .section-head {{ grid-template-columns:1fr; gap:9px; }} .policy-row {{ grid-template-columns:1fr; gap:7px; }} .arrow {{ transform:rotate(90deg); text-align:left; }} .edge-route,.edge-route.chain {{ grid-template-columns:1fr; gap:5px; }} .edge-route .relation {{ text-align:left; }} .edge-route.chain .arrow {{ transform:rotate(90deg); }} .finding summary {{ grid-template-columns:1fr 18px; gap:10px; }} .severity {{ grid-row:1; }} .finding-title {{ grid-column:1; }} .chevron {{ grid-column:2; grid-row:1 / span 2; }} .finding-body {{ padding:0 16px 19px; }} .inventory {{ grid-template-columns:repeat(2,minmax(0,1fr)); }} .inventory div:nth-child(n) {{ border-right:1px solid var(--line-soft); border-bottom:1px solid var(--line-soft); }} .inventory div:nth-child(2n) {{ border-right:0; }} .inventory div:last-child {{ grid-column:span 2; border-bottom:0; }} footer {{ display:block; }} footer span {{ display:block; margin-top:4px; }} }}
    @media (max-width:640px) {{ .verdict {{ display:block; }} .verdict small {{ margin-top:9px; }} }}
    @media (prefers-reduced-motion:reduce) {{ *,*::before,*::after {{ scroll-behavior:auto!important; transition:none!important; animation:none!important; }} }}
  </style>
</head>
<body>
  <main class="shell">
    <header class="masthead"><div class="brand"><span class="brand-mark" aria-hidden="true">A</span><span class="kicker" data-i18n="audit_ledger">AgentLint / audit ledger</span></div><div class="language-switch" role="group" aria-label="Language" data-i18n-aria="language"><button type="button" data-language="zh" aria-pressed="false">中文</button><button type="button" data-language="en" aria-pressed="true">EN</button></div><span class="meta" data-i18n="offline">Offline report · scanned input unchanged · no execution</span></header>
    <div class="layout">
      <aside class="aside"><div class="kicker" data-i18n="effective_audit">Effective instruction audit</div><h1 class="report-title">Agent <em>Lint</em>.</h1><p class="lede" data-i18n="lede">A static reading of the instructions, skills, plugins, and MCP configuration that shape an agent’s effective authority.</p><div class="verdict {verdict_class}"><span class="kicker" data-i18n="verdict">Verdict</span><strong data-verdict="{_e(verdict)}"><span class="verdict-label" data-verdict-label>{_e(verdict)}</span><span class="verdict-code" data-verdict-code>{_e(verdict)}</span></strong><small data-verdict-copy="{_e(verdict)}">{_e(_verdict_copy(verdict))}</small></div><p class="sidebar-note"><strong data-i18n="scope">Scope</strong><span class="report-root">{_e(root)}</span></p></aside>
      <div class="main">
        <div class="overview" aria-label="Audit totals" data-i18n-aria="audit_totals">{stats}</div>
        <section aria-labelledby="policy-title"><div class="section-head"><div><span class="kicker" data-i18n="precedence">01 · Precedence</span><h2 id="policy-title" data-i18n="instruction_graph">Effective Instruction Graph</h2></div><p data-i18n="policy_intro">Instructions are ordered from project root toward the working directory. Nearer guidance may alter the effective boundary.</p></div><div class="sheet"><div class="flow">{_policy_rows(result)}</div></div></section>
        <section aria-labelledby="authority-title"><div class="section-head"><div><span class="kicker" data-i18n="authority">02 · Authority</span><h2 id="authority-title" data-i18n="authority_map">Capability-to-Authority Map</h2></div><p data-i18n="authority_intro">Evidence-linked routes below show supported scanned relationships, never positional correspondence. No tool is invoked.</p></div><div class="sheet"><div class="authority">{_capability_rows(result)}</div></div></section>
        <section aria-labelledby="findings-title"><div class="section-head"><div><span class="kicker" data-i18n="evidence">03 · Evidence</span><h2 id="findings-title" data-i18n="findings">Findings</h2></div><p data-i18n="findings_intro">Filter the audit list, search its escaped evidence, then expand a row for impact and a bounded remediation.</p></div><div class="sheet"><div class="toolbar" role="group" aria-label="Finding filters" data-i18n-aria="finding_filters"><button class="filter" type="button" data-filter="all" aria-pressed="true"><span data-i18n="all">All</span> {len(findings)}</button><button class="filter" type="button" data-filter="error" aria-pressed="false"><span data-i18n="errors">Errors</span> {counts.get('error', 0)}</button><button class="filter" type="button" data-filter="warning" aria-pressed="false"><span data-i18n="warnings">Warnings</span> {counts.get('warning', 0)}</button><button class="filter" type="button" data-filter="info" aria-pressed="false"><span data-i18n="info">Info</span> {counts.get('info', 0)}</button><input class="search" type="search" placeholder="Search rule, file, or evidence" aria-label="Search findings" data-i18n-placeholder="search" data-i18n-aria="search_label" data-search></div><p class="sr-only" data-filter-status aria-live="polite" aria-atomic="true">{len(findings)} findings shown.</p><div class="findings" data-findings>{finding_rows}<div class="filter-empty" data-filter-empty hidden><span class="empty-mark" aria-hidden="true">—</span><div><strong data-i18n="empty_filter">No findings match these filters.</strong><p data-i18n="clear_filter">Clear search or choose All.</p></div></div></div></div><div class="notice"><span aria-hidden="true">ⓘ</span><span data-i18n="notice">AgentLint is a deterministic preflight, not a security certification. A clean report means no current rule matched—not that every behavior is safe.</span></div></section>
        <section aria-labelledby="inventory-title"><div class="section-head"><div><span class="kicker" data-i18n="coverage">04 · Coverage</span><h2 id="inventory-title" data-i18n="inventory">Inventory</h2></div><p data-i18n="coverage_intro">The configuration surface included in this scan.</p></div><div class="sheet"><div class="inventory"><div><strong>{_attr(inventory, 'files_scanned')}</strong><span data-i18n="config_files">config files</span></div><div><strong>{_attr(inventory, 'agents_files')}</strong><span data-i18n="agents_files">AGENTS files</span></div><div><strong>{_attr(inventory, 'skills')}</strong><span data-i18n="skills">skills</span></div><div><strong>{_attr(inventory, 'plugins')}</strong><span data-i18n="plugins">plugins</span></div><div><strong>{_attr(inventory, 'mcp_configs')}</strong><span data-i18n="mcp_configs">MCP configs</span></div></div>{skipped_block}</div></section>
      </div>
    </div>
    <footer><strong>AgentLint v{tool_version}</strong><span data-i18n="footer">Self-contained report · system-font fallbacks only · no external scripts, fonts, or telemetry</span></footer>
  </main>
  <script>
    (() => {{
      const I18N = {translations}; const cards = [...document.querySelectorAll('[data-finding]')]; const buttons = [...document.querySelectorAll('[data-filter]')]; const search = document.querySelector('[data-search]'); const empty = document.querySelector('[data-filter-empty]'); const status = document.querySelector('[data-filter-status]'); const languageButtons = [...document.querySelectorAll('[data-language]')]; let active = 'all'; let previousVisible = cards.length;
      const text = I18N.text; const setText = (key, fallback) => text[key] || fallback;
      const applyLanguage = (language) => {{ const zh = language === 'zh'; document.documentElement.lang = zh ? 'zh-CN' : 'en'; document.querySelectorAll('[data-i18n]').forEach((node) => {{ if (!node.dataset.en) node.dataset.en = node.textContent; node.textContent = zh ? setText(node.dataset.i18n, node.dataset.en) : node.dataset.en; }}); document.querySelectorAll('[data-i18n-placeholder]').forEach((node) => {{ if (!node.dataset.enPlaceholder) node.dataset.enPlaceholder = node.placeholder; node.placeholder = zh ? setText(node.dataset.i18nPlaceholder, node.dataset.enPlaceholder) : node.dataset.enPlaceholder; }}); document.querySelectorAll('[data-rule-id]').forEach((card) => {{ const rule = I18N.rules[card.dataset.ruleId]; if (!rule) return; const title = card.querySelector('[data-rule-title]'); const why = card.querySelector('[data-rule-why]'); const fix = card.querySelector('[data-rule-fix]'); if (title) {{ if (!title.dataset.en) title.dataset.en = title.textContent; title.textContent = zh ? rule[0] : title.dataset.en; }} if (why) {{ if (!why.dataset.en) why.dataset.en = why.textContent; why.textContent = zh ? rule[1] : why.dataset.en; }} if (fix) {{ if (!fix.dataset.en) fix.dataset.en = fix.textContent; fix.textContent = zh ? rule[2] : fix.dataset.en; }} }}); document.querySelectorAll('[data-modality]').forEach((node) => {{ if (!node.dataset.en) node.dataset.en = node.textContent; node.textContent = zh ? (text.modalities[node.dataset.modality] || node.dataset.en) : node.dataset.en; }}); document.querySelectorAll('[data-tag]').forEach((node) => {{ if (!node.dataset.en) node.dataset.en = node.textContent; node.textContent = zh ? (text.tags[node.dataset.tag] || node.dataset.en) : node.dataset.en; }}); document.querySelectorAll('[data-verdict]').forEach((node) => {{ const value = node.dataset.verdict; const label = node.querySelector('[data-verdict-label]'); if (label) label.textContent = zh ? (text.verdict_labels[value.toLowerCase()] || value) : value; }}); languageButtons.forEach((button) => button.setAttribute('aria-pressed', String(button.dataset.language === language))); try {{ localStorage.setItem('agentlint-report-language', language); }} catch (_) {{}} apply(true); }};
      const verdictCopy = (zh) => {{ document.querySelectorAll('[data-verdict-copy]').forEach((node) => {{ if (!node.dataset.en) node.dataset.en = node.textContent; node.textContent = zh ? (text['verdict_' + node.dataset.verdictCopy.toLowerCase()] || node.dataset.en) : node.dataset.en; }}); }};
      const translateAria = (zh) => {{ document.querySelectorAll('[data-i18n-aria]').forEach((node) => {{ if (!node.dataset.enAria) node.dataset.enAria = node.getAttribute('aria-label') || ''; node.setAttribute('aria-label', zh ? setText(node.dataset.i18nAria, node.dataset.enAria) : node.dataset.enAria); }}); }};
      const apply = (forceStatus = false) => {{ const query = (search?.value || '').trim().toLowerCase(); let visible = 0; cards.forEach((card) => {{ const severityMatch = active === 'all' || card.dataset.severity === active; const searchMatch = !query || card.textContent.toLowerCase().includes(query); const show = severityMatch && searchMatch; card.hidden = !show; if (show) visible += 1; }}); if (empty) empty.hidden = visible !== 0; const zh = document.documentElement.lang.startsWith('zh'); verdictCopy(zh); translateAria(zh); if (status && (forceStatus || visible === 0 || previousVisible === 0)) status.textContent = visible === 0 ? (zh ? text.empty_filter : 'No findings match these filters.') : (zh ? String(visible) + ' ' + text.shown : String(visible) + ' finding' + (visible === 1 ? '' : 's') + ' shown.'); previousVisible = visible; }};
      buttons.forEach((button) => button.addEventListener('click', () => {{ active = button.dataset.filter || 'all'; buttons.forEach((item) => item.setAttribute('aria-pressed', String(item === button))); apply(); }})); search?.addEventListener('input', apply); languageButtons.forEach((button) => button.addEventListener('click', () => applyLanguage(button.dataset.language || 'en'))); let preferred = 'en'; try {{ preferred = localStorage.getItem('agentlint-report-language') || (navigator.language?.toLowerCase().startsWith('zh') ? 'zh' : 'en'); }} catch (_) {{ preferred = navigator.language?.toLowerCase().startsWith('zh') ? 'zh' : 'en'; }} applyLanguage(preferred === 'zh' ? 'zh' : 'en');
    }})();
  </script>
</body>
</html>"""


def _finding_row(finding: Finding, index: int) -> str:
    related = "".join(f'<div class="evidence related"><small data-i18n="related_evidence">Related evidence</small> · <small>{_e(item.path)}:{item.line_start}</small><br><code>{_e(item.excerpt or "(no excerpt)")}</code></div>' for item in finding.related)
    tags = "".join(f'<span class="tag" data-tag="{_e(tag)}">{_e(tag)}</span>' for tag in finding.tags)
    return f'''<details class="finding" data-finding data-rule-id="{_e(finding.rule_id)}" data-severity="{_e(finding.severity)}" id="finding-{index}"><summary><span class="severity {_e(finding.severity)}" data-i18n="{_e(finding.severity)}">{_e(finding.severity)}</span><span class="finding-title"><strong data-rule-title>{_e(finding.title)}</strong><small>{_e(finding.rule_id)} · {_e(finding.primary.path)}:{finding.primary.line_start} · <span data-i18n="{_e(finding.confidence)}">{_e(finding.confidence)}</span> <span data-i18n="confidence">confidence</span></small></span><span class="chevron" aria-hidden="true">›</span></summary><div class="finding-body"><p><strong data-i18n="technical">Technical details</strong> <span>{_e(finding.message)}</span></p><div class="evidence"><small data-i18n="primary_evidence">Primary evidence</small> · <small>{_e(finding.primary.path)}:{finding.primary.line_start}</small><br><code>{_e(finding.primary.excerpt or "(no excerpt)")}</code></div>{related}<p><strong data-i18n="why">Why it matters.</strong> <span data-rule-why>{_e(finding.why_it_matters)}</span></p><div class="fix"><strong data-i18n="fix">Recommended fix</strong><br><span data-rule-fix>{_e(finding.remediation)}</span></div><div class="tags">{tags}</div></div></details>'''


def _policy_rows(result: ScanResult) -> str:
    facts = [fact for fact in getattr(result, "policy_facts", []) if getattr(fact, "source_kind", "") == "agents"]
    if not facts:
        return '<div class="empty-inline" data-i18n="none_policy">No actionable AGENTS.md policy statements were recognized.</div>'
    return "".join(f'<div class="policy-row"><div class="source"><strong>{_e(fact.scope)}</strong><small>{_e(fact.location.path)}:{fact.location.line_start}</small></div><div class="arrow" aria-hidden="true">→</div><div class="policy"><span class="badge" data-modality="{_e(fact.modality)}">{_e(fact.modality)}</span><strong>{_e(fact.action)}</strong><small>{_e(fact.phrase)}</small></div></div>' for fact in facts)


def _capability_rows(result: ScanResult) -> str:
    nodes = {node.node_id: node for node in getattr(result, "nodes", []) or []}
    edges = list(getattr(result, "edges", []) or [])
    outgoing: dict[str, list[object]] = {}
    for edge in edges:
        outgoing.setdefault(edge.source, []).append(edge)

    def node_text(node_id: str) -> tuple[str, str]:
        node = nodes.get(node_id)
        if node is None:
            return node_id, "missing graph node"
        detail = node.path or node.detail or node.kind
        return str(node.label), str(detail)

    routes: list[str] = []
    consumed: set[tuple[str, str, str]] = set()
    for first in edges:
        if first.relation != "bundles":
            continue
        for second in outgoing.get(first.target, []):
            if second.relation not in {"configures", "deny", "require"}:
                continue
            a_label, a_detail = node_text(first.source)
            b_label, b_detail = node_text(first.target)
            c_label, c_detail = node_text(second.target)
            routes.append(
                f'<div class="edge-route chain"><span class="node"><strong>{_e(a_label)}</strong><small>{_e(a_detail)}</small></span><span class="arrow" aria-hidden="true">→</span><span class="node"><strong>{_e(b_label)}</strong><small>{_e(b_detail)}</small></span><span class="arrow" aria-hidden="true">→</span><span class="node"><strong>{_e(c_label)}</strong><small><span data-modality="{_e(second.relation)}">{_e(second.relation)}</span> · {_e(c_detail)}</small></span></div>'
            )
            consumed.add((first.source, first.target, first.relation))
            consumed.add((second.source, second.target, second.relation))

    remaining: list[str] = []
    for edge in edges:
        identity = (edge.source, edge.target, edge.relation)
        if identity in consumed:
            continue
        source_label, source_detail = node_text(edge.source)
        target_label, target_detail = node_text(edge.target)
        remaining.append(
            f'<div class="edge-route"><span><strong>{_e(source_label)}</strong><small>{_e(source_detail)}</small></span><span class="relation" data-modality="{_e(edge.relation)}">{_e(edge.relation)}</span><span><strong>{_e(target_label)}</strong><small>{_e(target_detail)}</small></span></div>'
        )
    if not routes and not remaining:
        return '<div class="empty-inline" data-i18n="none_graph">No cross-component graph edges were discovered.</div>'
    route_block = '<div class="edge-label" data-i18n="evidence_routes">Evidence-linked multi-step routes</div>' + "".join(routes) if routes else ""
    other_block = '<div class="edge-label" data-i18n="other_edges">Other evidence-linked edges</div>' + "".join(remaining) if remaining else ""
    return route_block + other_block


def _verdict_copy(verdict: str) -> str:
    return {"BLOCK": "Resolve deterministic errors before installing or sharing this agent configuration.", "REVIEW": "No blocking errors, but the highlighted authority boundaries or coverage gaps need human review.", "PASS": "No current deterministic rule or known coverage gap matched. Review high-impact behavior before production use."}.get(verdict, "The available audit evidence needs human review.")


def _attr(value: object, name: str) -> int:
    return int(getattr(value, name, 0) or 0)


def _public_root(result: ScanResult) -> str:
    """Use the report-safe root marker, even for compatible result-like inputs."""
    return str(getattr(result, "public_root", "."))


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)
