use {
    skill_lint::{lint_repo, lint_skill, Grade, Severity, SkillReport},
    std::{path::PathBuf, process::ExitCode},
};

/// Lint Bankr agent skills: catalog.json + SKILL.md format, security, quality.
#[derive(argh::FromArgs)]
struct Args {
    /// lint every skill folder under this repo root instead of a single skill
    #[argh(option, short = 'r')]
    repo: Option<PathBuf>,

    /// emit machine-readable JSON
    #[argh(switch, long = "json")]
    json: bool,

    /// treat warnings as errors
    #[argh(switch)]
    strict: bool,

    /// emit SARIF output for GitHub code scanning
    #[argh(switch)]
    sarif: bool,

    /// check for duplicate slugs against the live BankrBot/skills catalog
    #[argh(switch)]
    check_catalog: bool,

    /// auto-fix fixable issues (missing schemaVersion, legacy install format)
    #[argh(switch)]
    fix: bool,

    /// watch for file changes and re-lint
    #[argh(switch)]
    watch: bool,

    /// the skill folder to lint (or the repo root with --repo)
    #[argh(positional)]
    path: Option<PathBuf>,
}

fn main() -> ExitCode {
    let args: Args = argh::from_env();

    let default_path = PathBuf::from(".");
    let reports: Vec<SkillReport> = match &args.repo {
        Some(root) => lint_repo(root),
        None => {
            let path = args.path.as_ref().unwrap_or(&default_path);
            vec![lint_skill(path)]
        }
    };

    if reports.is_empty() {
        eprintln!("no skill folders found");
        return ExitCode::from(2);
    }

    // Auto-fix mode
    if args.fix {
        for report in &reports {
            fix_skill(report);
        }
    }

    // Watch mode: re-lint on file change
    if args.watch {
        return watch_mode(&reports, &args);
    }

    // Check for duplicate slugs against the live catalog
    if args.check_catalog {
        check_duplicate_slugs(&reports);
    }

    if args.sarif {
        print_sarif(&reports);
    } else if args.json {
        print_json(&reports);
    } else {
        for report in &reports {
            print_report(report);
        }
        print_summary(&reports);
    }

    let failed = reports.iter().any(|r| {
        r.findings.iter().any(|f| {
            f.severity == Severity::Error || (args.strict && f.severity == Severity::Warning)
        })
    });
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn print_report(report: &SkillReport) {
    let name = report
        .path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| report.path.display().to_string());
    let status = if report.is_valid() { "OK" } else { "INVALID" };
    let error_count = report.errors().count();
    let warn_count = report.warnings().count();
    println!("{}: [{}] {status} ({error_count} errors, {warn_count} warnings)", name, report.grade.as_str());
    for f in &report.findings {
        let icon = match f.severity {
            Severity::Error => "x",
            Severity::Warning => "!",
            Severity::Info => "-",
        };
        println!("  [{icon}] {}: {}", f.check, f.message);
    }
    println!();
}

fn print_summary(reports: &[SkillReport]) {
    if reports.len() < 2 {
        return;
    }
    let valid = reports.iter().filter(|r| r.is_valid()).count();
    let invalid = reports.len() - valid;
    let total_errors: usize = reports.iter().map(|r| r.errors().count()).sum();
    let total_warnings: usize = reports.iter().map(|r| r.warnings().count()).sum();

    let mut grades = [0usize; 5]; // A B C D F
    for r in reports {
        let idx = match r.grade {
            Grade::A => 0,
            Grade::B => 1,
            Grade::C => 2,
            Grade::D => 3,
            Grade::F => 4,
        };
        grades[idx] += 1;
    }

    println!("--- {} skills: {} valid, {} invalid, {} errors, {} warnings ---",
        reports.len(), valid, invalid, total_errors, total_warnings);
    println!("  grades: A={} B={} C={} D={} F={}",
        grades[0], grades[1], grades[2], grades[3], grades[4]);
}

/// Auto-fixes common issues in a skill's catalog.json:
/// - Adds missing schemaVersion: 1
/// - Converts legacy install-as-string to install-as-object
fn watch_mode(_reports: &[SkillReport], args: &Args) -> ExitCode {
    let root = args.repo.clone().unwrap_or_else(|| {
        args.path.clone().unwrap_or_else(|| PathBuf::from("."))
    });

    println!("watching {} for changes (Ctrl+C to stop)...", root.display());
    let mut last_run = std::time::Instant::now();

    loop {
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Check if any skill file changed since last lint
        let mut changed = false;
        if let Ok(entries) = std::fs::read_dir(&root) {
            for entry in entries.filter_map(|e| e.ok()) {
                let path = entry.path();
                if path.is_dir() {
                    for file in ["SKILL.md", "catalog.json"] {
                        let fp = path.join(file);
                        if let Ok(meta) = std::fs::metadata(&fp) {
                            if let Ok(modified) = meta.modified() {
                                if let Ok(elapsed) = modified.elapsed() {
                                    if elapsed.as_secs() < 2 {
                                        changed = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                if changed { break; }
            }
        }

        if changed && last_run.elapsed().as_secs() >= 2 {
            println!("\n--- re-linting ---");
            let fresh = match &args.repo {
                Some(r) => lint_repo(r),
                None => vec![lint_skill(&root)],
            };
            for report in &fresh {
                print_report(report);
            }
            print_summary(&fresh);
            last_run = std::time::Instant::now();
        }
    }
}

fn fix_skill(report: &SkillReport) {
    let catalog_path = report.path.join("catalog.json");
    let Ok(source) = std::fs::read_to_string(&catalog_path) else {
        return;
    };
    let Ok(mut catalog) = serde_json::from_str::<serde_json::Value>(&source) else {
        return;
    };

    let mut changed = false;

    // Fix missing schemaVersion
    if catalog.get("schemaVersion").is_none() {
        if let Some(obj) = catalog.as_object_mut() {
            obj.insert("schemaVersion".into(), serde_json::json!(1));
            changed = true;
            println!("  fixed: added schemaVersion: 1");
        }
    }

    // Fix legacy install-as-string
    if let Some(install_str) = catalog.get("install").and_then(|v| v.as_str()).map(String::from) {
        let folder = report.path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if let Some(obj) = catalog.as_object_mut() {
            obj.insert("install".into(), serde_json::json!({
                "type": "bankr",
                "repoPath": folder,
                "command": install_str
            }));
            changed = true;
            println!("  fixed: converted install string to object");
        }
    }

    if changed {
        let pretty = serde_json::to_string_pretty(&catalog).unwrap();
        if std::fs::write(&catalog_path, pretty).is_ok() {
            println!("  wrote: {}", catalog_path.display());
        }
    }
}

fn check_duplicate_slugs(reports: &[SkillReport]) {
    // Fetch the live catalog listing
    let Ok(output) = std::process::Command::new("curl")
        .args(["-s", "https://api.github.com/repos/BankrBot/skills/contents/"])
        .output()
    else {
        eprintln!("  [!] catalog: cannot reach GitHub API to check for duplicate slugs");
        return;
    };

    let Ok(listing) = serde_json::from_slice::<serde_json::Value>(&output.stdout) else {
        eprintln!("  [!] catalog: cannot parse GitHub API response");
        return;
    };

    let Some(entries) = listing.as_array() else {
        eprintln!("  [!] catalog: unexpected API response format");
        return;
    };

    let existing: std::collections::HashSet<String> = entries
        .iter()
        .filter_map(|e| e.get("name").and_then(|n| n.as_str()).map(String::from))
        .collect();

    println!("--- catalog check: {} existing skills ---", existing.len());
    for report in reports {
        if let Some(slug) = &report.slug {
            if existing.contains(slug) {
                eprintln!(
                    "  [!] {}: slug {:?} already exists in the BankrBot/skills catalog",
                    report.path.display(),
                    slug
                );
            }
        }
    }
}

fn print_sarif(reports: &[SkillReport]) {
    use serde_json::json;
    let results: Vec<serde_json::Value> = reports
        .iter()
        .flat_map(|r| {
            r.findings.iter().map(|f| {
                json!({
                    "ruleId": f.check,
                    "level": match f.severity {
                        Severity::Error => "error",
                        Severity::Warning => "warning",
                        Severity::Info => "note",
                    },
                    "message": { "text": f.message },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": { "uri": r.path.display().to_string() }
                        }
                    }]
                })
            })
        })
        .collect();

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "skill-lint",
                    "informationUri": "https://github.com/latent-9/skill-lint",
                    "version": "0.1.0"
                }
            },
            "results": results
        }]
    });
    println!("{}", serde_json::to_string_pretty(&sarif).unwrap());
}

fn print_json(reports: &[SkillReport]) {
    let mut out = String::from("[");
    for (i, report) in reports.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&serde_json::to_string(&json_report(report)).unwrap());
    }
    out.push(']');
    println!("{out}");
}

fn json_report(report: &SkillReport) -> serde_json::Value {
    use serde_json::json;
    json!({
        "path": report.path.display().to_string(),
        "slug": report.slug,
        "valid": report.is_valid(),
        "grade": report.grade.as_str(),
        "findings": report.findings.iter().map(|f| json!({
            "severity": match f.severity {
                Severity::Error => "error",
                Severity::Warning => "warning",
                Severity::Info => "info",
            },
            "check": f.check,
            "message": f.message,
        })).collect::<Vec<_>>(),
    })
}
