# skill-lint

Static analyzer for [Bankr](https://bankr.bot) agent skills. Validates the `catalog.json` + `SKILL.md` format against the [BankrBot/skills](https://github.com/BankrBot/skills) catalog spec, then runs security and quality analysis over the skill's content: prompt-injection patterns, embedded secrets, exfiltration endpoints, dangerous commands, hidden content, and egress transparency.

A skill folder whose `catalog.json` is missing or invalid is skipped by the Bankr Discover catalog. This tool tells you exactly why, before you push.

## What it checks

**Format** (from the documented spec):
- `catalog.json` is valid JSON, `schemaVersion` is 1, `slug` equals the folder name
- `install` block: `type` is `bankr` or `external`, required fields present, command follows the documented form
- `SKILL.md` has YAML frontmatter with `name` and `description`
- `logo.svg` or `logo.png` present (recommended)

**Security**:
- Prompt-injection patterns in `SKILL.md`, `scripts/`, and `references/` ("ignore previous instructions", "hide this from the user", etc.)
- Embedded secrets: PEM blocks, Anthropic/GitHub/AWS tokens, 64-char hex keys
- Exfiltration: webhook drop-offs (Discord, Telegram, pastebin), credential directory reads (`~/.ssh`, `~/.aws`)
- Dangerous commands: `rm -rf /`, `curl | sh`, `chmod -R 777`
- Hidden content: zero-width Unicode characters, imperative HTML comments, large base64 blobs

**Quality**:
- Description has trigger conditions ("Use when...") and negative triggers ("Do NOT use for...")
- SKILL.md has a real instruction body, not just frontmatter
- Egress transparency: every network endpoint and environment-variable access is listed

## Install

```bash
cargo install --git https://github.com/Souna-Research/skill-lint
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
my-skill: INVALID
  [x] slug: slug must equal the folder name: slug is "my-skill", folder is "other-name"
  [!] logo: logo.svg (or logo.png) is recommended
  [-] egress: SKILL.md: network endpoint referenced: https://api.example.com/v1
```

Exit codes: `0` valid, `1` invalid, `2` no skills found.

## Library

The validation logic lives in a library crate so it can be embedded in other tools:

```rust
use skill_lint::lint_skill;

let report = lint_skill(std::path::Path::new("./my-skill"));
assert!(report.is_valid());
```

## License

MIT
