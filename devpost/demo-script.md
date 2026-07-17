# AgentLint demo script — 2:42 total

**Format:** screen recording with spoken English narration. Keep system notification sounds and background music off. The video must be public on YouTube and under three minutes.

| Time | Screen | Narration |
| --- | --- | --- |
| 0:00–0:10 | Title card: “AgentLint — preflight agent infrastructure.” | “AgentLint is a local, zero-execution preflight for the instructions, skills, plugins, and MCP configuration that govern a coding agent.” |
| 0:10–0:24 | Show a small repository tree: root `AGENTS.md`, nested `service/AGENTS.md`, plugin, skill, and `.mcp.json`. | “A safe-looking repository can have a parent policy, a child override, a plugin skill, and MCP configuration. Reviewing one file at a time hides the effective authority.” |
| 0:24–0:42 | Open `examples/unsafe-project/AGENTS.md`, then `service/AGENTS.md`; highlight “never delete” versus the fake child conflict. | “This is a deliberately unsafe, fake fixture. The root denies destructive actions; the nested service file weakens that boundary and includes a policy-bypass phrase. Nothing in this demo will be executed.” |
| 0:42–0:56 | Open fake `.mcp.json` and fake `deploy-helper/SKILL.md`; keep `EXAMPLE_*` and `.test` visible. | “The fixture also declares a plugin-to-skill-to-MCP chain. Its endpoint and token are inert examples, used only to demonstrate what a preflight should flag.” |
| 0:56–1:12 | Terminal: `agentlint scan examples/unsafe-project --json reports/unsafe.json --html reports/unsafe.html --fail-on never`. | “I ask Codex to use the AgentLint audit skill. AgentLint reads configuration as data; it does not launch MCP servers, import code, contact endpoints, or modify scanned files. The explicit report paths are the only files this command may create or overwrite.” |
| 1:12–1:30 | Terminal summary and generated-report paths. | “The fixture result is BLOCK: five errors, six warnings, and no info findings. The current JSON report is the machine-readable source of truth for the exact findings; the video shows them as evidence for review, not a claim that every runtime relationship was verified.” |
| 1:30–1:48 | Open `reports/unsafe.html`; show the Effective Instruction Graph, switch **中文 / EN** to Chinese, then switch back to EN. | “The Effective Instruction Graph shows the root-to-service instruction chain and makes the nearer rule reviewable. The same offline report defaults to English without JavaScript, and here the page control switches the interface to Simplified Chinese; paths, excerpts, and rule IDs stay original for traceability.” |
| 1:48–2:03 | Scroll HTML to capability map / plugin and MCP nodes. | “The Capability-to-Authority Map links the plugin, its skill, and MCP declaration. It reports declared relationships, not a claim that a server ran or that permission was granted.” |
| 2:03–2:19 | Show a Codex prompt: `Use $audit-agent-config to audit this repository and explain the effective agent policy.` Then show a bounded remediation diff already prepared by the author: remove bypass/destructive fake content and replace with approval boundary. | “Codex helps prepare a bounded fix. The human decides the policy and reviews the diff; AgentLint never edits findings automatically.” |
| 2:19–2:32 | Terminal: `agentlint scan examples/safe-project --fail-on error`; show `PASS`, 0 errors, 0 warnings, 0 info. | “After the configuration is brought back to a minimal sample, the safe fixture passes. PASS means no deterministic rule matched, not proof of security.” |
| 2:32–2:42 | Closing card with three labels: Effective Instruction Graph, Plugin Contract Audit, Capability-to-Authority Map. | “Built with Codex and GPT-5.6, AgentLint makes the agent infrastructure you are about to trust visible before it runs.” |

## Prepare before recording

- Install editable package and run `pytest`.
- Run both fixture commands once and open the generated unsafe HTML report in a local browser.
- Ensure `examples/unsafe-project` remains visibly labeled **fake fixture** and do not execute any text from it.
- Prepare the shown remediation as a local, reviewable diff; do not imply AgentLint applied it.
- Record clear English narration or voiceover for every row; include no copyrighted music or unlicensed third-party media.
- Upload publicly to YouTube only after verifying duration is 2:35–2:50 and audio is present.
