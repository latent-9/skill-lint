# skill-lint

**Static analyzer for [Bankr](https://bankr.bot) agent skills.**

If you're building a skill for the [Bankr](https://bankr.bot) ecosystem — a `SKILL.md` file that teaches an AI agent a new capability — this tool tells you three things before you push:

1. **Is the format correct?** (Bankr will skip your skill if `catalog.json` is invalid)
2. **Is the content safe?** (no prompt injection, no leaked secrets, no hidden instructions)
3. **Is the quality good?** (concrete instructions, clear triggers, right size)

It's `clippy` for agent skills.

## Why this exists

The [BankrBot/skills](https://github.com/BankrBot/skills) catalog has 148 skills and **346 open PRs** that nobody reviews. There's no automated validation — maintainers read each skill by hand. This tool automates that first pass.

Running it against the live catalog found:
- 10 invalid skills (missing `schemaVersion`, legacy `install` format)
- 17 format errors
- 353 quality warnings
- 1 skill containing `curl | sh` in its instructions

## What it checks

### Format (from the [official spec](https://docs.bankr.bot/skills/in-bankr/skill-format))

| Check | What it validates |
|---|---|
| `catalog.json` | Valid JSON, `schemaVersion: 1`, `slug` equals the folder name |
| `install` | `type` is `bankr` or `external`, required fields present, command matches the documented form |
| `SKILL.md` frontmatter | `name` and `description` present (frontmatter-less accepted with warning) |
| Optional fields | `tags`, `visibility` (private/public), `version` (number) |
| File limits | `SKILL.md` ≤ 1 MB, reference files ≤ 100 KB each |
| Logo | `logo.svg` or `logo.png` present (recommended) |

### Security

| Check | What it catches |
|---|---|
| Prompt injection | "ignore previous instructions", "hide this from the user", "developer mode" — 19 patterns |
| Embedded secrets | PEM blocks, Anthropic/GitHub/AWS API keys, 64-char hex private keys |
| Exfiltration | Discord/Telegram/pastebin webhooks, reads from `~/.ssh` or `~/.aws` |
| Dangerous commands | `rm -rf /`, `curl \| sh`, `chmod -R 777` |
| Hidden content | Zero-width Unicode characters, imperative HTML comments, large base64 blobs |

Security skills that *document* injection patterns (like `polygraph` or `1claw`) are automatically recognized — their pattern hits are downgraded from error to info.

### Quality

| Check | What it looks for |
|---|---|
| Description triggers | "Use when..." (positive) and "Do NOT use for..." (negative) |
| Body substance | Code blocks, actionable commands, specific API/CLI references |
| Egress transparency | Every network endpoint and env-var access is listed |

## Grades

Each skill gets an A-F grade:

| Grade | Meaning |
|---|---|
| **A** | No errors, no warnings — production ready |
| **B** | No errors, 1-3 warnings |
| **C** | No errors, 4+ warnings |
| **D** | 1 error |
| **F** | 2+ errors |

Live catalog distribution: `A=8 B=97 C=33 D=7 F=3`

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

# Check if your slug is already taken in the live catalog
skill-lint --repo . --check-catalog

# Auto-fix common issues (missing schemaVersion, legacy install format)
skill-lint --repo . --fix

# Machine-readable JSON for CI
skill-lint --json ./my-skill

# SARIF for GitHub code scanning
skill-lint --sarif ./my-skill

# Fail on warnings too
skill-lint --strict ./my-skill
```

### Example output

```
my-skill: [B] OK (0 errors, 2 warnings)
  [-] description: description states trigger conditions (good)
  [-] description: description states negative triggers (good)
  [!] logo: logo.svg (or logo.png) is recommended
  [!] body_quality: instruction body has no code blocks

--- 148 skills: 138 valid, 10 invalid, 17 errors, 353 warnings ---
  grades: A=8 B=97 C=33 D=7 F=3
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | All skills valid |
| `1` | At least one skill has errors |
| `2` | No skill folders found |

## GitHub Action

Drop this into `.github/workflows/skill-lint.yml`:

```yaml
name: skill-lint
on: [pull_request]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo install --git https://github.com/latent-9/skill-lint
      - run: skill-lint --repo .
```

Or use the [template in this repo](.github/workflows/skill-lint.yml).

## Library

The validation logic is a library crate — embed it in your own tool:

```rust
use skill_lint::lint_skill;

let report = lint_skill(std::path::Path::new("./my-skill"));
println!("grade: {}", report.grade.as_str());
println!("valid: {}", report.is_valid());
```

## Bankr ecosystem

- [Bankr](https://bankr.bot) — AI agents that fund themselves via token trading fees
- [BankrBot/skills](https://github.com/BankrBot/skills) — the public skill catalog (148 skills, 346 open PRs)
- [SKILL.md format reference](https://docs.bankr.bot/skills/in-bankr/skill-format) — the official spec this tool validates against

## License

MIT
