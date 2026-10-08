# skill-lint

Static analyzer for [Bankr](https://bankr.bot) agent skills. Validates the `catalog.json` + `SKILL.md` format against the [BankrBot/skills](https://github.com/BankrBot/skills) catalog spec and the [official SKILL.md format reference](https://docs.bankr.bot/skills/in-bankr/skill-format), then runs security and quality analysis over the skill's content: prompt-injection patterns, embedded secrets, exfiltration endpoints, dangerous commands, hidden content, and egress transparency.

A skill folder whose `catalog.json` is missing or invalid is skipped by the Bankr Discover catalog. This tool tells you exactly why, before you push.

## What it checks

### Format (from the Bankr spec)

- `catalog.json` is valid JSON, `schemaVersion` is 1, `slug` equals the folder name
- `install` block: `type` is `bankr` or `external`, required fields present, command follows the documented form
- `SKILL.md` has YAML frontmatter with `name` and `description` (frontmatter-less skills are accepted with a warning — Bankr synthesizes them)
- Optional frontmatter fields: `tags`, `visibility` (private/public), `version` (number)
- `SKILL.md` size limit: 1 MB (Bankr rejects oversized files)
- Reference files: 100 KB limit (Bankr skips oversized ones)
- `logo.svg` or `logo.png` present (recommended)

### Security

- Prompt-injection patterns in `SKILL.md`, `scripts/`, and `references/` ("ignore previous instructions", "hide this from the user", etc.)
- Security skills that document injection patterns are recognized and downgraded to info
- Embedded secrets: PEM blocks, Anthropic/GitHub/AWS tokens, 64-char hex keys
- Exfiltration: webhook drop-offs (Discord, Telegram, pastebin), credential directory reads (`~/.ssh`, `~/.aws`)
- Dangerous commands: `rm -rf /`, `curl | sh`, `chmod -R 777`
- Hidden content: zero-width Unicode characters, imperative HTML comments, large base64 blobs

### Quality

- Description has trigger conditions ("Use when...") and negative triggers ("Do NOT use for...")
- SKILL.md has a real instruction body, not just frontmatter
- Egress transparency: every network endpoint and environment-variable access is listed

## Install

```bash
cargo install --git https://github.com/latent-9/skill-lint
```

## Usage

```bash
# Lint one skill
skill-lint ./my-skill

# Lint every skill in a repo
skill-lint --repo ./skills

# Machine-readable output for CI
skill-lint --json ./my-skill

# Fail on warnings too
skill-lint --strict ./my-skill
```

Example output:

```
my-skill: INVALID (2 errors, 1 warnings)
  [x] slug: slug must equal the folder name: slug is "my-skill", folder is "other-name"
  [x] dangerous_command: SKILL.md: pipes a remote script into a shell
  [!] logo: logo.svg (or logo.png) is recommended

--- 148 skills: 138 valid, 10 invalid, 17 errors, 318 warnings ---
```

Exit codes: `0` valid, `1` invalid, `2` no skills found.

## Validated against the live catalog

skill-lint has been run against all 148 skills in the [BankrBot/skills](https://github.com/BankrBot/skills) repository. It found 10 invalid skills, 17 format errors, and 318 warnings — including missing `schemaVersion`, legacy `install`-as-string, and `curl | sh` in a skill body.

## Library

The validation logic lives in a library crate so it can be embedded in other tools:

```rust
use skill_lint::lint_skill;

let report = lint_skill(std::path::Path::new("./my-skill"));
assert!(report.is_valid());
```

## Bankr ecosystem

- [Bankr](https://bankr.bot) — AI agents that fund themselves
- [BankrBot/skills](https://github.com/BankrBot/skills) — the public skill catalog
- [SKILL.md format reference](https://docs.bankr.bot/skills/in-bankr/skill-format) — the official spec

## License

MIT
