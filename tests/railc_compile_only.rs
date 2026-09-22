#![cfg(windows)]

//! Explicit RailC compile-only harness for Milestone 1.
//!
//! Run with:
//! `mdtimeout 600s -- cargo test -q --test railc_compile_only -- --ignored --nocapture`

use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};

use mdbcc::codegen::target::TargetKind;
use mdbcc::coff::Machine;
use mdbcc::compile::{CompileError, compile_to_object_with_target_defines};
use mdbcc::pp::{DefaultResolver, IncludeResolver, SearchPathResolver};

const RAILC_ROOT: &str = r"C:\language\railc";

const RAILC_TUS: &[&str] = &[
    "RAILC.CPP",
    "DEPARTUR.CPP",
    "LOCOYARD.CPP",
    "ARRIVALS.CPP",
    "FINISH.CPP",
    "ABOUT.CPP",
    "STARTUP.CPP",
    "START.CPP",
    "CONFIGUR.CPP",
    "LAYOUT.CPP",
    "SELECTOR.CPP",
    "PLATFORM.CPP",
    "TOOLBAR.CPP",
    "TOOLBUTT.CPP",
    "STATBAR.CPP",
    "SECTION.CPP",
    "PLATDATA.CPP",
    "ovlpdata.cpp",
    "ROUTES.CPP",
    "LOCOS.CPP",
    "TIMETABL.CPP",
];

#[derive(Debug)]
enum TuStatus {
    Pass { bytes: usize },
    Fail { phase: String, message: String },
}

#[derive(Debug)]
struct TuReport {
    tu: &'static str,
    status: TuStatus,
}

#[test]
#[ignore = "depends on Arthur's local RailC corpus at C:\\language\\railc"]
fn railc_21_tus_compile_to_win32_objects() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let railc_root = PathBuf::from(RAILC_ROOT);
    let bc45_include = manifest_dir
        .join("wrk_oracle")
        .join("bc452")
        .join("BC45")
        .join("INCLUDE");
    let out_dir = manifest_dir.join("wrk_probe").join("railc_compile_only");
    let object_dir = out_dir.join("objects");

    assert!(
        railc_root.is_dir(),
        "missing RailC source directory: {}",
        railc_root.display()
    );
    assert!(
        bc45_include.is_dir(),
        "missing BC45 include directory: {}",
        bc45_include.display()
    );
    std::fs::create_dir_all(&object_dir).expect("create RailC compile-only object directory");

    let mut reports = Vec::with_capacity(RAILC_TUS.len());
    for (idx, tu) in RAILC_TUS.iter().enumerate() {
        let source = railc_root.join(tu);
        let object_path = object_dir.join(object_name(idx, tu));
        let status = compile_tu(&source, &railc_root, &bc45_include, &object_path);
        reports.push(TuReport { tu, status });
    }

    let mut summary = String::new();
    let mut passed = 0usize;
    let mut failed = 0usize;
    for report in &reports {
        match &report.status {
            TuStatus::Pass { bytes } => {
                passed += 1;
                let line = format!("{:<13} PASS {:>8} bytes", report.tu, bytes);
                println!("{line}");
                summary.push_str(&line);
                summary.push('\n');
            }
            TuStatus::Fail { phase, message } => {
                failed += 1;
                let line = format!("{:<13} FAIL {}: {}", report.tu, phase, message);
                println!("{line}");
                summary.push_str(&line);
                summary.push('\n');
            }
        }
    }
    let footer = format!(
        "SUMMARY ok={} fail={} objects={}",
        passed,
        failed,
        object_dir.display()
    );
    println!("{footer}");
    summary.push_str(&footer);
    summary.push('\n');

    let summary_path = out_dir.join("summary.txt");
    std::fs::write(&summary_path, summary).expect("write RailC compile-only summary");

    assert_eq!(
        failed,
        0,
        "RailC compile-only failed; summary written to {}",
        summary_path.display()
    );
}

fn compile_tu(
    source: &Path,
    railc_root: &Path,
    bc45_include: &Path,
    object_path: &Path,
) -> TuStatus {
    let src = match std::fs::read(source) {
        Ok(src) => src,
        Err(e) => {
            return TuStatus::Fail {
                phase: "input".to_string(),
                message: format!("cannot read {}: {e}", source.display()),
            };
        }
    };
    let fallback = DefaultResolver {
        base_dir: source
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(railc_root)
            .to_path_buf(),
    };
    let resolver = SearchPathResolver {
        dirs: vec![railc_root.to_path_buf(), bc45_include.to_path_buf()],
        fallback,
    };
    let file_name = source.display().to_string();
    let compiled = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let resolver: &dyn IncludeResolver = &resolver;
        compile_to_object_with_target_defines(
            &src,
            &file_name,
            resolver,
            TargetKind::Win32,
            &[("__WIN32__".to_string(), "1".to_string())],
        )
    }));

    let object = match compiled {
        Ok(Ok(object)) => object,
        Ok(Err(err)) => {
            return TuStatus::Fail {
                phase: compile_phase(&err).to_string(),
                message: err.to_string(),
            };
        }
        Err(_) => {
            return TuStatus::Fail {
                phase: "panic".to_string(),
                message: "compiler panicked".to_string(),
            };
        }
    };

    if object.machine != Machine::I386 {
        return TuStatus::Fail {
            phase: "codegen".to_string(),
            message: format!("expected I386 object, got {:?}", object.machine),
        };
    }

    let bytes = object.write();
    match std::fs::write(object_path, &bytes) {
        Ok(()) => TuStatus::Pass { bytes: bytes.len() },
        Err(e) => TuStatus::Fail {
            phase: "output".to_string(),
            message: format!("cannot write {}: {e}", object_path.display()),
        },
    }
}

fn compile_phase(err: &CompileError) -> &'static str {
    match err {
        CompileError::Lex(_) => "lexer",
        CompileError::Preprocess(_) => "preprocessor/header",
        CompileError::Parse(_) => "parser/language",
        CompileError::Codegen(_) => "codegen",
        CompileError::Link(_) => "link",
    }
}

fn object_name(index: usize, tu: &str) -> String {
    let stem = Path::new(tu)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("input")
        .to_ascii_lowercase();
    format!("{index:04}-{stem}.obj")
}
