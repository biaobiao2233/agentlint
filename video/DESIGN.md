# AgentLint Build Week demo — design direction

## Audience and purpose

OpenAI Build Week judges and developers evaluating a local security/developer
tool. The video must make one idea immediately clear: before an AI agent acts,
AgentLint makes its real configuration authority inspectable without executing
untrusted content.

## Visual identity

Use the established **warm paper editorial** identity from AgentLint's report,
adapted for a 1920×1080 video frame rather than copied as a web page.

| Token | Value | Role |
| --- | --- | --- |
| Paper | `#EFE7D2` | persistent background |
| Paper soft | `#F7F1DE` | report sheets and terminal panels |
| Paper deep | `#E1D5B8` | structural rules and panels |
| Ink | `#17150F` | headlines and code |
| Muted | `#625B4E` | explanations |
| Faint | `#8D8575` | metadata |
| Coral | `#EF6C5B` | BLOCK / risk evidence accent |
| Coral deep | `#D95A49` | emphatic warning detail |
| Mustard | `#E7B848` | REVIEW / relationship accent |

Typography is deliberately editorial versus technical: **Fraunces** for the
few human-facing claims, **IBM Plex Mono** for commands, paths, IDs, counts,
and labels. Use high contrast and a tangible printed-ledger feeling.

## Composition rules

- 16:9, 1920×1080; no external embeds, gradients, blue/purple SaaS styling,
  glass cards, stock imagery, or copyrighted music.
- Each beat has a warm paper/grain background, a structural rule/grid, a real
  product artifact or terminal output, and one coral or mustard focal detail.
- Use large, readable type: 72px+ display; 30px+ supporting copy; 22px+
  terminal labels. Keep all voice captions inside the lower safe area.
- Motion is purposeful and editorial: page-turn horizontal pushes between
  concepts, decisive small stamps for verdicts, and calm breathing grain.
- The report screenshot and command results are evidence, not decorative mock
  data. Never claim a scanned fixture was executed or that PASS is proof of
  security.

## Avoid

- Any real secret, personal scan path, user email, or machine-specific path.
- Unreadably dense code, fake dashboards, fake usage numbers, or exaggerated
  security guarantees.
- AI-generated imagery, artificial presenter avatars, or synthetic claims.
