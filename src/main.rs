use {
    skill_lint::{lint_repo, lint_skill, Severity, SkillReport},
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

    /// the skill folder to lint (or the repo root with --repo)
    #[argh(positional)]
    path: PathBuf,
}

fn main() -> ExitCode {
    let args: Args = argh::from_env();

    let reports: Vec<SkillReport> = match &args.repo {
        Some(root) => lint_repo(root),
        None => vec![lint_skill(&args.path)],
    };

    if reports.is_empty() {
        eprintln!("no skill folders found");
        return ExitCode::from(2);
    }

    if args.json {
        print_json(&reports);
    } else {
        for report in &reports {
            print_report(report);
        }
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
    println!("{}: {status}", name);
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
