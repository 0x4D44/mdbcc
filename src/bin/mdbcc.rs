use std::process::ExitCode;

use mdbcc::link::Subsystem;
use mdbcc::progress::{Painter, fmt_num};
use mdbcc::project::{self, BuildReport, CliAction};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cwd = match std::env::current_dir() {
        Ok(path) => path,
        Err(e) => {
            error_line(&format!("cannot determine current directory: {e}"));
            return ExitCode::FAILURE;
        }
    };

    match project::run_cli(&args, &cwd) {
        Ok(CliAction::Help(text)) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
        Ok(CliAction::Version(text)) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Ok(CliAction::Build(report)) => {
            print_build_summary(&report);
            ExitCode::SUCCESS
        }
        Err(e) => {
            error_line(&format!("{e}"));
            ExitCode::FAILURE
        }
    }
}

fn print_build_summary(report: &BuildReport) {
    let p = Painter::stdout();
    println!(
        "{} {}  {}",
        p.green("built"),
        p.bold(&report.output.display().to_string()),
        p.dim(&format!(
            "({}, {})",
            report.target,
            subsystem_name(report.subsystem)
        )),
    );
    println!(
        "  {}",
        p.dim(&format!(
            "{} {}, {} lines, {} {}, {} {}, {} {}",
            report.source_count,
            plural(report.source_count, "source"),
            fmt_num(report.lines_total),
            report.resource_count,
            plural(report.resource_count, "resource"),
            report.object_count,
            plural(report.object_count, "object"),
            report.lib_count,
            plural(report.lib_count, "lib"),
        )),
    );
    println!(
        "  {}",
        p.dim(&format!("config {}", report.manifest_path.display()))
    );
    if let Some(log_path) = &report.log_path {
        let total = report.notes_deferred + report.notes_pruned;
        println!(
            "  {}",
            p.yellow(&format!(
                "notes: {} diagnostics ({} deferred, {} pruned) -> {}",
                fmt_num(total as u64),
                fmt_num(report.notes_deferred as u64),
                fmt_num(report.notes_pruned as u64),
                log_path.display(),
            )),
        );
    }
}

fn plural(n: usize, word: &str) -> String {
    if n == 1 {
        word.to_string()
    } else {
        format!("{word}s")
    }
}

fn error_line(message: &str) {
    let p = Painter::stderr();
    eprintln!("mdbcc: {}: {message}", p.red("error"));
}

fn subsystem_name(subsystem: Subsystem) -> &'static str {
    match subsystem {
        Subsystem::Console => "console",
        Subsystem::Gui => "gui",
    }
}
