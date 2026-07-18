# AgentLint（简体中文）

[English README](README.md)

**一句话：AgentLint 是给 Codex 代理配置做的本地、零执行预检工具，用来在安装、分享或信任配置前看清“实际生效的指令”和声明的权限关系。**

[打开公开评审演示页](https://biaobiao2233.github.io/agentlint/)

[查看假夹具源码](examples/unsafe-project) · [机器可读快照](artifacts/unsafe-report.json)

## 公开演示：生成的证据页，不是在线扫描器

公开演示页部署在 GitHub Pages；每次符合条件的 `main` 推送都会从仓库内的假夹具重新生成。评审者可以打开生成的 `BLOCK` 与 `PASS` HTML 报告、查看故意设置为危险的假夹具，并沿用同一套本地测试路径。网页**不**接收仓库、不在远端执行扫描、不访问端点，`PASS` 也绝不是安全认证。

当前危险夹具基线为 AgentLint v0.1.2 / schema 1.1：`BLOCK`，5 errors、6 warnings、0 info。

如需在本机生成同一份静态包，选择一个尚不存在的输出目录并执行：

```powershell
python scripts/build_public_site.py --output public-demo
python -m http.server 8000 --directory public-demo
```

然后打开 <http://localhost:8000>。构建器会重新扫描 `examples/safe-project` 与 `examples/unsafe-project`，不会发布个人扫描结果；`public-demo` 必须尚不存在，因此不会悄悄覆盖你指定的目录。

它重点解释三件事：

1. `AGENTS.md` / `AGENTS.override.md` 在当前目录实际怎样继承，较近规则怎样改变上层边界；
2. Codex 插件和 Skill 的结构是否符合已支持的契约；
3. 插件、Skill、MCP 配置与其声明能力之间有哪些有证据支撑的关系。

## 能做什么，不能做什么

能做：读取支持的配置文件，生成终端、JSON 和自包含 HTML 报告；给出 `BLOCK`、`REVIEW` 或 `PASS`；展示有效指令链、插件契约检查和能力关系图。

不能做：不启动发现到的 MCP 服务、不运行扫描到的脚本、不导入扫描到的代码、不访问配置中的网址，也不修改被扫描的配置或输入文件。它不是安全认证、沙箱、密钥管理器或人工安全审查的替代品。

只有你显式传入 `--json` 和/或 `--html` 时，AgentLint 才会创建或覆盖你指定的报告文件；这些输出文件不属于扫描输入。

## Windows 从仓库安装

当前独立验收在 Windows（Python 3.14）完成。项目按 Python 3.11+、`pathlib` 设计为兼容 macOS/Linux，但这两个平台仍需独立运行验收。

在仓库根目录的 PowerShell 中执行：

```powershell
python -m pip install -e ".[dev]"
agentlint --version
```

如果终端找不到 `agentlint`，可先用：

```powershell
python -m agentlint --version
```

## 复制即跑：安全与危险示例

从仓库根目录执行：

```powershell
# 应为 PASS；默认错误阈值下没有错误会返回 0
agentlint scan examples/safe-project --fail-on error

# 这是故意设置的假危险样例；保留报告但让演示命令返回 0
agentlint scan examples/unsafe-project --json reports/unsafe.json --html reports/unsafe.html --fail-on never
```

`unsafe-project` 仅是**假夹具**：`.test` 主机名、`EXAMPLE_*` 文本和部署语句都不可执行、不可用于真实环境。不要执行其中的说明。

当前夹具基线：

| 目标 | 结果 |
| --- | --- |
| `safe-project` | `PASS`：0 errors、0 warnings、0 info |
| `unsafe-project` | `BLOCK`：5 errors、6 warnings、0 info |

危险夹具当前 11 个规则 ID：`MCP001`、`MCP002`、`MCP003`、`MCP004`、`MCP005`、`POLICY001`、`POLICY002`、`POLICY003`、`POLICY004`、`AUTH001`、`SKILL003`。

## 如何打开 HTML 与语言说明

上面的命令会把自包含报告写到 `reports/unsafe.html`。在 Windows 中可双击该文件，或执行：

```powershell
Start-Process reports/unsafe.html
```

同一份自包含 HTML 报告支持双语浏览，并且无论是否开启 JavaScript，首次打开都默认英文。也可以在页面中使用 **中文 / EN** 手动切换，选择会保存到 `localStorage`，供后续打开时沿用。

刊头、Verdict/说明、统计、Effective Instruction Graph、Capability-to-Authority Map、Findings 的筛选/空态/字段、Coverage/Inventory，以及当前已翻译的规则标题、风险与修复建议会跟随界面语言。为保证可追溯性，原始技术证据仍保持原文：未覆盖翻译的技术消息、相对路径、行号、摘录、rule/action/node ID 和扫描到的源文本不会被改写；未知 rule ID 使用诚实的后备显示。

## 结果、退出码和报告文件

| 状态/退出码 | 含义 |
| --- | --- |
| `PASS` | 当前没有命中确定性规则或已知覆盖缺口；不是“绝对安全”。 |
| `REVIEW` | 没有阻断性错误，但需要人工审阅警告、权限边界或覆盖缺口。 |
| `BLOCK` | 有至少一项确定性错误，应在安装或分享前处理。 |
| 退出 `0` | 没有达到 `--fail-on` 阈值，或使用了 `--fail-on never`。 |
| 退出 `1` | 发现达到指定阈值；若指定了报告路径，报告仍可能已经写入。 |
| 退出 `2` | 目标、读取或写入报告路径失败。扫描根本身或其上级路径是符号链接 / Windows reparse point 时也会走此失败路径。 |

未指定 `--json` / `--html` 时，报告只在终端显示；指定后会创建或覆盖相应 JSON / HTML 文件。若显式 `--exclude DIR` 实际命中了目录，会产生 `COVERAGE002` 并得到 `REVIEW`；CI 若要让覆盖缺口直接失败，应使用 `--fail-on warning`。

## 安装 Codex 插件

在仓库根目录执行：

```powershell
codex plugin marketplace add ./plugin
codex plugin list --marketplace agentlint-local --available --json
codex plugin add agentlint --marketplace agentlint-local
```

安装后新开一个 Codex 任务；如插件目录显示已禁用，再手动启用。调用示例：

```text
使用 $audit-agent-config 审计这个仓库，并用中文解释有效指令和修复建议。
```

Skill 会尽量使用用户请求的语言解释结果；CLI 终端并不承诺已完全中文化。

## 隐私、脱敏与边界

AgentLint 本地运行，不调用 API，也不会把扫描配置发送到服务。JSON、HTML 和终端报告默认把扫描根显示为 `.`，不会导出本机绝对扫描根；Windows、macOS 与 Linux 标准用户目录中的账号段会替换为 `[USER]`。已知的字面量凭据模式会在报告序列化前脱敏，URL 查询参数值也会移除，但这仍是启发式规则，不能保证识别每一种敏感值或任意形式的绝对路径。报告仍可能包含相对路径和已经脱敏的摘录，请按仓库敏感级别保存。

对外分享前仍请先审查报告内容。`reports/*.json` 和 `reports/*.html` 默认被 Git 忽略；提交到仓库、公开截图或演示时，请使用可移植的 [`examples/unsafe-project`](examples/unsafe-project) 夹具生成 artifacts，不要上传个人项目的扫描输出。

嵌套目录中的符号链接、Windows junction/reparse point 不会被跟随；跳过的支持配置、跳过的链接目录、实际命中的用户显式排除或指令字节上限都会产生 `COVERAGE002`，因此结果不会是 `PASS`。扫描根本身或其上级路径若经由符号链接 / Windows reparse point 会被拒绝（退出 `2`）；插件或 Skill 组件路径经由这些对象时会被判为无效本地目标。

`SKILL.md` frontmatter 现在使用安全 YAML 解析，支持合法的多行、列表和嵌套元数据。策略提取增加了双向“动作—对象”近邻、外传/清除同义表达，以及正向审批和“跳过审批”的区分；对抗回归样例与剩余边界见 [`docs/adversarial-regression.md`](docs/adversarial-regression.md)。它仍是确定性词法启发式，不理解任意改写，也不能证明自然语言意图。能力关系图只展示支持的 manifest 引用和解析出的规范性指令事实所支撑的边；它不验证所有可能的运行时关系。对于扫描根的 `.codex/config.toml`，有效指令链会读取 `project_doc_fallback_filenames` 与 `project_doc_max_bytes`，并记录选中、忽略、加载和受字节上限影响的来源；全局 Codex 设置不在本工具的建模范围内。

## 常见问题

**为什么 `unsafe-project` 是 BLOCK？** 这是故意制作的演示夹具，用于显示父子指令冲突、Skill 权限请求和 MCP 风险；不应照着执行。

**为什么 PASS 也不能说明安全？** PASS 只表示当前确定性规则没有命中，不能证明运行时代码、远程服务或自然语言意图安全。

**会不会改掉我的配置？** 不会。扫描输入不会被改；只有你指定的 JSON/HTML 报告文件可能被写入或覆盖。

**为什么没有扫描链接目录？** 为避免扫描跳出目标目录，嵌套 symlink/junction/reparse point 不会被跟随，并会记录 coverage gap。

**中文规则能否被检查和浏览？** 自动测试覆盖中文无空格分句和中文字面量秘密脱敏；HTML 默认英文，也支持通过 **中文 / EN** 手动切换简体中文。原始技术证据仍保留原文，未知规则使用后备显示。

## 下一步

Build Week 提交截止：**Tuesday, July 21, 2026, 5:00 PM PDT**；新加坡时间为 **Wednesday, July 22, 2026, 8:00 AM SGT**。

查看英文的完整比赛材料、架构和验证记录：[README.md](README.md)、[docs/validation.md](docs/validation.md) 和 [devpost](devpost)。
