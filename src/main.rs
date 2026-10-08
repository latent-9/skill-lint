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
