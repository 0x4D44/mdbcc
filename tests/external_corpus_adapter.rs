//! Q3 external runnable corpus adapter.
//!
//! No third-party sources are vendored here. The manifest points at a curated
//! 20-file slice of LLVM's copy of GCC C torture execute tests under
//! `SingleSource/Regression/C/gcc-c-torture/execute`. To run the ignored pilot,
//! set `MDBCC_LLVM_TEST_SUITE` to an `llvm-test-suite` checkout, or place one at
//! `wrk_oracle/external_c/llvm-test-suite`.

#![cfg(windows)]

mod support;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use support::{Lang, RunOutcome, Verdict, compare, mdbcc_run, msvc_ref, o2_active};

const DEFAULT_LLVM_TEST_SUITE: &str = "wrk_oracle/external_c/llvm-test-suite";
const GCC_TORTURE_PREFIX: &str = "SingleSource/Regression/C/gcc-c-torture/execute/";
const GCC_TORTURE_RUNTIME_PRELUDE: &str = r#"
void __stdcall ExitProcess(unsigned int code);
void exit(int code) { ExitProcess((unsigned int)code); }
void abort(void) { ExitProcess(1); }
"#;

#[derive(Clone, Copy)]
struct ExternalCase {
    name: &'static str,
    rel_path: &'static str,
    class: &'static str,
}

const LLVM_GCC_TORTURE_PILOT: &[ExternalCase] = &[
    ExternalCase {
        name: "gcc_20000113_bitfield_update",
        rel_path: "SingleSource/Regression/C/gcc-c-torture/execute/20000113-1.c",
        class: "bitfield arithmetic",
    },
    ExternalCase {
        name: "gcc_20000205_do_while_recursion",
        rel_path: "SingleSource/Regression/C/gcc-c-torture/execute/20000205-1.c",
        class: "control flow",
    },
    ExternalCase {
        name: "gcc_20000217_pointer_compare",
        rel_path: "SingleSource/Regression/C/gcc-c-torture/execute/20000217-1.c",
        class: "pointer/control",
    },
    ExternalCase {
        name: "gcc_20000224_integer_branch",
        rel_path: "SingleSource/Regression/C/gcc-c-torture/execute/20000224-1.c",
        class: "integer branch",
    },
    ExternalCase {
        name: "gcc_20000225_shift_compare",
        rel_path: "SingleSource/Regression/C/gcc-c-torture/execute/20000225-1.c",
        class: "shift/compare",
    },
    ExternalCase {
        name: "gcc_20000227_short_circuit",
        rel_path: "SingleSource/Regression/C/gcc-c-torture/execute/20000227-1.c",
        class: "short circuit",
    },
    ExternalCase {
        name: "gcc_20000313_loop_index",
        rel_path: "SingleSource/Regression/C/gcc-c-torture/execute/20000313-1.c",
        class: "loop index",
    },
    ExternalCase {
        name: "gcc_20000314_1_expr_fold",
        rel_path: "SingleSource/Regression/C/gcc-c-torture/execute/20000314-1.c",
        class: "expression fold",
    },
    ExternalCase {
        name: "gcc_20000314_3_struct_alias",
        rel_path: "SingleSource/Regression/C/gcc-c-torture/execute/20000314-3.c",
        class: "struct alias",
    },
    ExternalCase {
        name: "gcc_20000403_array_loop",
        rel_path: "SingleSource/Regression/C/gcc-c-torture/execute/20000403-1.c",
        class: "array loop",
    },
    ExternalCase {
        name: "gcc_20000412_1_signed_compare",
        rel_path: "SingleSource/Regression/C/gcc-c-torture/execute/20000412-1.c",
        class: "signed compare",
    },
    ExternalCase {
        name: "gcc_20000412_2_bool_expr",
        rel_path: "SingleSource/Regression/C/gcc-c-torture/execute/20000412-2.c",
        class: "boolean expression",
    },
    ExternalCase {
        name: "gcc_20000412_3_loop_condition",
        rel_path: "SingleSource/Regression/C/gcc-c-torture/execute/20000412-3.c",
        class: "loop condition",
    },
    ExternalCase {
        name: "gcc_20000412_4_nested_loop",
        rel_path: "SingleSource/Regression/C/gcc-c-torture/execute/20000412-4.c",
        class: "nested loop",
    },
    ExternalCase {
        name: "gcc_20000412_5_condition_fold",
        rel_path: "SingleSource/Regression/C/gcc-c-torture/execute/20000412-5.c",
        class: "condition fold",
    },
    ExternalCase {
        name: "gcc_20000412_6_for_loop",
        rel_path: "SingleSource/Regression/C/gcc-c-torture/execute/20000412-6.c",
        class: "for loop",
    },
    ExternalCase {
        name: "gcc_20000419_call_result",
        rel_path: "SingleSource/Regression/C/gcc-c-torture/execute/20000419-1.c",
        class: "call result",
    },
    ExternalCase {
        name: "gcc_20000422_pointer_arith",
        rel_path: "SingleSource/Regression/C/gcc-c-torture/execute/20000422-1.c",
        class: "pointer arithmetic",
    },
    ExternalCase {
        name: "gcc_20000503_sizeof_cond",
        rel_path: "SingleSource/Regression/C/gcc-c-torture/execute/20000503-1.c",
        class: "sizeof/conditional",
    },
    ExternalCase {
        name: "gcc_20000511_struct_return",
        rel_path: "SingleSource/Regression/C/gcc-c-torture/execute/20000511-1.c",
        class: "struct/control",
    },
];

fn llvm_test_suite_root() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("MDBCC_LLVM_TEST_SUITE").map(PathBuf::from) {
        if path.exists() {
            return Some(path);
        }
    }
    let default = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DEFAULT_LLVM_TEST_SUITE);
    default.exists().then_some(default)
}

fn join_rel(root: &Path, rel_path: &str) -> PathBuf {
    rel_path
        .split('/')
        .fold(root.to_path_buf(), |path, component| path.join(component))
}

fn fixture_boundary_reason(src: &str) -> Option<String> {
    let banned = [
        ("__attribute__", "GCC attribute"),
        ("__builtin", "compiler builtin"),
        (" asm", "inline asm"),
        ("\tasm", "inline asm"),
        ("long long", "long long dialect"),
        ("_Complex", "complex arithmetic"),
        ("#include", "header-dependent fixture"),
        ("setjmp", "setjmp/longjmp"),
        ("signal", "signal handling"),
        ("alloca", "stack allocation builtin"),
    ];
    for (needle, reason) in banned {
        if src.contains(needle) {
            return Some(reason.to_string());
        }
    }
    None
}

fn adapt_gcc_torture_source(src: &str) -> String {
    format!("{GCC_TORTURE_RUNTIME_PRELUDE}\n{src}")
}

fn gcc_torture_success() -> RunOutcome {
    RunOutcome {
        launched: true,
        exit: Some(0),
        stdout: Vec::new(),
        stdout_overflow: false,
        timed_out: false,
        stderr: Vec::new(),
    }
}

#[test]
fn external_corpus_manifest_has_q3_shape() {
    assert_eq!(
        LLVM_GCC_TORTURE_PILOT.len(),
        20,
        "Q3 pilot should stay intentionally small"
    );

    let mut names = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut classes = BTreeSet::new();
    for case in LLVM_GCC_TORTURE_PILOT {
        assert!(
            names.insert(case.name),
            "duplicate external corpus case name {}",
            case.name
        );
        assert!(
            paths.insert(case.rel_path),
            "duplicate external corpus path {}",
            case.rel_path
        );
        assert!(
            case.rel_path.starts_with(GCC_TORTURE_PREFIX),
            "{} must stay inside the curated GCC torture execute subset",
            case.rel_path
        );
        assert!(
            case.rel_path.ends_with(".c"),
            "{} must be a single C source",
            case.rel_path
        );
        assert!(
            !case.rel_path.contains("/builtins/") && !case.rel_path.ends_with("-lib.c"),
            "{} must not require a multi-file builtins helper",
            case.rel_path
        );
        assert!(!case.class.is_empty(), "{} missing class", case.name);
        classes.insert(case.class);
    }
    assert!(
        classes.len() >= 10,
        "Q3 pilot should cover varied C behaviours, not one narrow trick"
    );
}

#[test]
#[ignore = "requires local llvm-test-suite checkout and MSVC reference compiler"]
fn llvm_gcc_torture_external_corpus_pilot_msvc() {
    let Some(root) = llvm_test_suite_root() else {
        eprintln!(
            "SKIP external corpus: set MDBCC_LLVM_TEST_SUITE or populate {DEFAULT_LLVM_TEST_SUITE}"
        );
        return;
    };
    let msvc_active = o2_active();
    if !msvc_active {
        eprintln!("NOTE external corpus: MSVC absent; using GCC torture exit-0 hand oracle");
    }

    let mut compared = 0usize;
    let mut excluded = Vec::new();
    let mut failures = Vec::new();

    for case in LLVM_GCC_TORTURE_PILOT {
        let path = join_rel(&root, case.rel_path);
        let bytes = std::fs::read(&path).unwrap_or_else(|err| {
            panic!(
                "{} missing or unreadable at {}: {err}",
                case.name,
                path.display()
            )
        });
        let src = match std::str::from_utf8(&bytes) {
            Ok(src) => src,
            Err(_) => {
                excluded.push(format!(
                    "{} excluded at corpus boundary: non-UTF-8 source bytes",
                    case.name
                ));
                continue;
            }
        };
        if let Some(reason) = fixture_boundary_reason(&src) {
            excluded.push(format!(
                "{} excluded at corpus boundary: {reason}",
                case.name
            ));
            continue;
        }

        let adapted = adapt_gcc_torture_source(&src);
        let mdbcc = mdbcc_run(&adapted);
        let mut reference = if msvc_active {
            msvc_ref(&adapted, Lang::C)
        } else {
            gcc_torture_success()
        };
        if msvc_active && !reference.launched {
            excluded.push(format!(
                "{} MSVC reference rejected old-C fixture; using GCC torture hand oracle",
                case.name
            ));
            reference = gcc_torture_success();
        }
        match compare(&mdbcc, &reference) {
            Verdict::Pass => compared += 1,
            Verdict::Exclude(reason) => excluded.push(format!("{} excluded: {reason}", case.name)),
            Verdict::Fail(reason) => {
                compared += 1;
                failures.push(format!("{} [{}]: {reason}", case.name, case.class))
            }
        }
    }

    for item in &excluded {
        eprintln!("[external-corpus] {item}");
    }
    assert!(
        compared > 0,
        "external corpus adapter compared no fixtures; exclusions={excluded:#?}"
    );
    assert!(
        failures.is_empty(),
        "external corpus mismatches:\n{}",
        failures.join("\n")
    );
    println!(
        "[external-corpus] OK: {compared} compared, {} excluded at boundary/reference.",
        excluded.len()
    );
}

#[test]
#[ignore = "known Q3 external corpus reduction: parser rejects C89 implicit-int function definitions"]
fn gcc_torture_reduced_implicit_int_function_definition_regression() {
    let outcome = mdbcc_run("main(){ return 0; }");
    assert!(
        outcome.launched,
        "reduced GCC torture failure: C89 implicit-int `main()` should compile and run"
    );
    assert_eq!(outcome.exit, Some(0));
    assert!(outcome.stdout.is_empty());
}
