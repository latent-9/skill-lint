//! Extracts top-level string keys from YAML frontmatter.
//!
//! Handles folded (`>`) and literal (`|`) block scalars and skips nested
//! mappings, which is all a linter needs from SKILL.md frontmatter.

pub fn parse(source: &str) -> Option<Vec<(String, String)>> {
    let lines: Vec<&str> = source.lines().collect();
    if lines.is_empty() || lines.first()?.trim() != "---" {
        return None;
    }

    let mut out: Vec<(String, String)> = Vec::new();
    let mut i = 1;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim_end();
        if trimmed == "---" || trimmed == "..." {
            break;
        }
        i += 1;
        if trimmed.is_empty() || trimmed.trim_start().starts_with('#') {
            continue;
        }
        if trimmed.starts_with(char::is_whitespace) {
            continue;
        }
        let Some((key, rest)) = split_key(trimmed) else {
            continue;
        };
        let rest = rest.trim();

        if is_block_indicator(rest) {
            let (block, next) = read_block(&lines, i);
            i = next;
            out.push((key.to_string(), block));
        } else if rest.is_empty() {
            let next = skip_nested(&lines, i);
            i = next;
            out.push((key.to_string(), String::new()));
        } else {
            out.push((key.to_string(), unquote(rest)));
        }
    }
    Some(out)
}

/// Returns the body of the document with the frontmatter block removed.
pub fn body(source: &str) -> &str {
    let rest = source.strip_prefix("---").unwrap_or(source);
    match rest.find("\n---") {
        Some(idx) => &rest[idx + 4..],
        None => "",
    }
}

fn split_key(line: &str) -> Option<(&str, &str)> {
    let idx = line.find(':')?;
    let (key, rest) = line.split_at(idx);
    if key.is_empty() || key.contains(char::is_whitespace) {
        return None;
    }
    Some((key, &rest[1..]))
}

fn is_block_indicator(rest: &str) -> bool {
    matches!(rest, ">" | "|" | ">-" | "|-" | ">+" | "|+")
}

fn read_block(lines: &[&str], mut i: usize) -> (String, usize) {
    let mut parts: Vec<String> = Vec::new();
    while i < lines.len() {
        let line = lines[i];
        if line.trim() == "---" {
            break;
        }
        if line.is_empty() {
            parts.push(String::new());
            i += 1;
            continue;
        }
        if !line.starts_with(char::is_whitespace) {
            break;
        }
        parts.push(line.trim().to_owned());
        i += 1;
    }
    (parts.join(" ").trim().to_owned(), i)
}

fn skip_nested(lines: &[&str], mut i: usize) -> usize {
    while i < lines.len() {
        let line = lines[i];
        if line.trim() == "---" || (!line.is_empty() && !line.starts_with(char::is_whitespace)) {
            break;
        }
        i += 1;
    }
    i
}

fn unquote(value: &str) -> String {
    let value = value.trim();
    for quote in ['"', '\''] {
        if let Some(stripped) = value.strip_prefix(quote).and_then(|v| v.strip_suffix(quote)) {
            return stripped.to_owned();
        }
    }
    value.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_keys() {
        let front = parse("---\nname: my-skill\ndescription: short one\n---\nbody").unwrap();
        assert!(front.iter().any(|(k, v)| k == "name" && v == "my-skill"));
        assert!(front.iter().any(|(k, v)| k == "description" && v == "short one"));
    }

    #[test]
    fn parses_folded_description() {
        let src = "---\nname: x\ndescription: >\n  Use when the user wants to test.\n  Do NOT use for GitHub.\n---\n";
        let front = parse(src).unwrap();
        let desc = front.iter().find(|(k, _)| k == "description").unwrap();
        assert!(desc.1.contains("Use when the user wants to test."));
        assert!(desc.1.contains("Do NOT use for GitHub."));
    }

    #[test]
    fn skips_nested_metadata() {
        let src = "---\nname: x\nmetadata:\n  clawdbot:\n    emoji: \"x\"\n---\n";
        let front = parse(src).unwrap();
        assert_eq!(front.len(), 2);
        assert!(front.iter().any(|(k, _)| k == "name"));
        assert!(front.iter().any(|(k, v)| k == "metadata" && v.is_empty()));
    }

    #[test]
    fn missing_frontmatter_is_none() {
        assert!(parse("# just a heading\n").is_none());
        assert!(parse("").is_none());
    }

    #[test]
    fn body_excludes_frontmatter() {
        let src = "---\nname: x\n---\n\n# Instructions\nDo things.\n";
        assert_eq!(body(src).trim(), "# Instructions\nDo things.");
    }
}
