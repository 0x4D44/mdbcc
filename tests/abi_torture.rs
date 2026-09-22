//! Generated ABI/calling-convention torture matrix.
//!
//! This is a compact Q5 oracle for historically fragile Win64/i386 call shapes:
//! static members that must not receive `this`, Win64 integer varargs after FP
//! args, positional stack slots, record by-value passing/return, virtual/member
//! dispatch, and i386 reference marshalling. Each case is named and classified so
//! failures land in the quality map as ABI categories instead of one-off tests.

#![cfg(windows)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use mdbcc::codegen::target::TargetKind;
use mdbcc::coff;
use mdbcc::compile::{compile_to_object_with_target, compile_to_pe_with};
use mdbcc::link::{self, Input, LinkOpts, Subsystem};
use mdbcc::pp::DefaultResolver;

static COUNTER: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum AbiTarget {
    Win64,
    I386,
}

impl AbiTarget {
    fn label(self) -> &'static str {
        match self {
            AbiTarget::Win64 => "win64",
            AbiTarget::I386 => "i386",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum AbiFeature {
    StaticMemberNoThis,
    VarargsAfterFloat,
    StackArguments,
    RecordByValueArgument,
    RecordReturn,
    VirtualDispatch,
    ReferenceArgument,
}

impl AbiFeature {
    fn label(self) -> &'static str {
        match self {
            AbiFeature::StaticMemberNoThis => "static-member-no-this",
            AbiFeature::VarargsAfterFloat => "varargs-after-float",
            AbiFeature::StackArguments => "stack-arguments",
            AbiFeature::RecordByValueArgument => "record-by-value-argument",
            AbiFeature::RecordReturn => "record-return",
            AbiFeature::VirtualDispatch => "virtual-dispatch",
            AbiFeature::ReferenceArgument => "reference-argument",
        }
    }
}

#[derive(Clone, Copy)]
struct AbiCase {
    name: &'static str,
    target: AbiTarget,
    feature: AbiFeature,
    expected_exit: i32,
    source: &'static str,
}

fn generated_abi_cases() -> Vec<AbiCase> {
    vec![
        AbiCase {
            name: "win64_static_member_out_of_line_no_this",
            target: AbiTarget::Win64,
            feature: AbiFeature::StaticMemberNoThis,
            expected_exit: 42,
            source: r#"
                struct S { static int f(int a, int b, char* p, int d); };
                int S::f(int a, int b, char* p, int d) {
                  return p == 0 ? a + b + d : 7;
                }
                int main(void) { return S::f(10, 20, 0, 12); }
            "#,
        },
        AbiCase {
            name: "win64_int_vararg_after_double",
            target: AbiTarget::Win64,
            feature: AbiFeature::VarargsAfterFloat,
            expected_exit: 42,
            source: r#"
                #include <stdarg.h>
                static int mixed(int n, ...) {
                  va_list ap;
                  double d;
                  int x;
                  va_start(ap, n);
                  d = va_arg(ap, double);
                  x = va_arg(ap, int);
                  va_end(ap);
                  return (int)d + x;
                }
                int main(void) { return mixed(2, 2.0, 40); }
            "#,
        },
        AbiCase {
            name: "win64_six_integer_args_spill_to_stack",
            target: AbiTarget::Win64,
            feature: AbiFeature::StackArguments,
            expected_exit: 42,
            source: r#"
                int sum6(int a, int b, int c, int d, int e, int f) {
                  return a + b + c + d + e + f;
                }
                int main(void) { return sum6(1, 2, 3, 4, 5, 27); }
            "#,
        },
        AbiCase {
            name: "win64_hiddenptr_struct_by_value_preserves_stack_tail",
            target: AbiTarget::Win64,
            feature: AbiFeature::RecordByValueArgument,
            expected_exit: 42,
            source: r#"
                struct Big { int a[20]; };
                int check(int p0, int p1, int p2, struct Big b, int trailing) {
                  int i;
                  int ok = 1;
                  for (i = 0; i < 20; i++) {
                    if (b.a[i] != (i + 1) * 3) ok = 0;
                  }
                  if (trailing != 0x1234) ok = 0;
                  if (p0 + p1 + p2 != 21) ok = 0;
                  return ok ? 42 : 7;
                }
                int main(void) {
                  struct Big b;
                  int i;
                  for (i = 0; i < 20; i++) b.a[i] = (i + 1) * 3;
                  return check(7, 7, 7, b, 0x1234);
                }
            "#,
        },
        AbiCase {
            name: "win64_hiddenptr_record_return_shifts_real_args",
            target: AbiTarget::Win64,
            feature: AbiFeature::RecordReturn,
            expected_exit: 42,
            source: r#"
                struct S { int a; int b; int c; int d; };
                struct S make(int a, int b) {
                  struct S s;
                  s.a = a;
                  s.b = b;
                  s.c = a + b;
                  s.d = a * b;
                  return s;
                }
                int main(void) {
                  struct S s = make(5, 7);
                  return s.a + s.b + s.c + s.d - 17;
                }
            "#,
        },
        AbiCase {
            name: "win64_virtual_dispatch_keeps_member_this",
            target: AbiTarget::Win64,
            feature: AbiFeature::VirtualDispatch,
            expected_exit: 42,
            source: r#"
                class B { public: virtual int f(int x) { return x + 1; } };
                class D : public B {
                  public: int bias;
                  D(void) { bias = 2; }
                  virtual int f(int x) { return x + bias; }
                };
                int main(void) {
                  D d;
                  B* p = &d;
                  return p->f(40);
                }
            "#,
        },
        AbiCase {
            name: "i386_six_integer_args_all_stack",
            target: AbiTarget::I386,
            feature: AbiFeature::StackArguments,
            expected_exit: 42,
            source: r#"
                int sum6(int a, int b, int c, int d, int e, int f) {
                  return a + b + c + d + e + f;
                }
                int main(void) { return sum6(1, 2, 3, 4, 5, 27); }
            "#,
        },
        AbiCase {
            name: "i386_struct_by_value_arg_inline_not_pointer",
            target: AbiTarget::I386,
            feature: AbiFeature::RecordByValueArgument,
            expected_exit: 42,
            source: r#"
                struct Big { int a; int b; int c; };
                int sum(Big p) { return p.a + p.b + p.c; }
                int main(void) {
                  Big x;
                  x.a = 10;
                  x.b = 11;
                  x.c = 21;
                  return sum(x);
                }
            "#,
        },
        AbiCase {
            name: "i386_record_return_in_edx_eax",
            target: AbiTarget::I386,
            feature: AbiFeature::RecordReturn,
            expected_exit: 42,
            source: r#"
                struct P { int x; int y; };
                P make(int a) {
                  P p;
                  p.x = a;
                  p.y = a * 2;
                  return p;
                }
                int main(void) {
                  P p = make(14);
                  return p.x + p.y;
                }
            "#,
        },
        AbiCase {
            name: "i386_derived_reference_arg_adjusts_base",
            target: AbiTarget::I386,
            feature: AbiFeature::ReferenceArgument,
            expected_exit: 42,
            source: r#"
                struct M { int v; M(int k) : v(k) {} };
                struct D : M { D(void) : M(40) {} virtual int f(void) { return 1; } };
                int take(M& m) { return m.v + 2; }
                int main(void) {
                  D d;
                  return take(d);
                }
            "#,
        },
    ]
}

fn unique_path(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!(
        "mdbcc_abi_torture_{tag}_{}_{n}.exe",
        std::process::id()
    ));
    p
}

fn resolver() -> DefaultResolver {
    DefaultResolver {
        base_dir: PathBuf::from("."),
    }
}

fn link_opts_i386() -> LinkOpts {
    LinkOpts {
        machine: coff::Machine::I386,
        subsystem: Subsystem::Console,
        image_base: 0x0040_0000,
        ..LinkOpts::default()
    }
}

fn compile_case(case: AbiCase) -> Vec<u8> {
    match case.target {
        AbiTarget::Win64 => {
            compile_to_pe_with(case.source.as_bytes(), "abi_torture.cpp", &resolver())
                .unwrap_or_else(|err| {
                    panic!(
                        "{} [{}] compile failed: {err}",
                        case.name,
                        case.feature.label()
                    )
                })
        }
        AbiTarget::I386 => {
            let obj = compile_to_object_with_target(
                case.source.as_bytes(),
                "abi_torture.cpp",
                &resolver(),
                TargetKind::Win32,
            )
            .unwrap_or_else(|err| {
                panic!(
                    "{} [{}] i386 compile failed: {err}",
                    case.name,
                    case.feature.label()
                )
            });
            link::link(&[Input::Object(&obj)], &link_opts_i386()).unwrap_or_else(|err| {
                panic!(
                    "{} [{}] i386 link failed: {err}",
                    case.name,
                    case.feature.label()
                )
            })
        }
    }
}

fn run_exit(pe: &[u8], tag: &str) -> Option<i32> {
    let path = unique_path(tag);
    if std::fs::write(&path, pe).is_err() {
        eprintln!("SKIP ({tag}): could not write temp exe");
        return None;
    }
    let result = match Command::new(&path).spawn() {
        Ok(mut child) => {
            let start = Instant::now();
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => break status.code(),
                    Ok(None) => {
                        if start.elapsed() > Duration::from_secs(5) {
                            let _ = child.kill();
                            panic!("{tag}: PE hung (>5s)");
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(err) => panic!("{tag}: wait failed: {err}"),
                }
            }
        }
        Err(err) => {
            eprintln!("SKIP ({tag}): spawn failed (WOW64 or loader refused image?): {err}");
            None
        }
    };
    let _ = std::fs::remove_file(&path);
    result
}

#[test]
fn abi_torture_generator_emits_stable_unique_matrix() {
    let cases = generated_abi_cases();
    assert!(
        cases.len() >= 10,
        "Q5 ABI torture should cover a useful cross-target matrix"
    );

    let names: Vec<&str> = cases.iter().map(|case| case.name).collect();
    assert_eq!(
        names,
        [
            "win64_static_member_out_of_line_no_this",
            "win64_int_vararg_after_double",
            "win64_six_integer_args_spill_to_stack",
            "win64_hiddenptr_struct_by_value_preserves_stack_tail",
            "win64_hiddenptr_record_return_shifts_real_args",
            "win64_virtual_dispatch_keeps_member_this",
            "i386_six_integer_args_all_stack",
            "i386_struct_by_value_arg_inline_not_pointer",
            "i386_record_return_in_edx_eax",
            "i386_derived_reference_arg_adjusts_base",
        ],
        "ABI torture generator order is part of the matrix contract"
    );
    let mut unique_names = names.clone();
    unique_names.sort_unstable();
    unique_names.dedup();
    assert_eq!(
        unique_names.len(),
        names.len(),
        "ABI torture names must be unique"
    );

    for case in &cases {
        assert_eq!(
            case.expected_exit,
            42,
            "{} [{}:{}] should use the shared success sentinel",
            case.name,
            case.target.label(),
            case.feature.label()
        );
    }

    for feature in [
        AbiFeature::StaticMemberNoThis,
        AbiFeature::VarargsAfterFloat,
        AbiFeature::StackArguments,
        AbiFeature::RecordByValueArgument,
        AbiFeature::RecordReturn,
        AbiFeature::VirtualDispatch,
        AbiFeature::ReferenceArgument,
    ] {
        assert!(
            cases.iter().any(|case| case.feature == feature),
            "missing generated ABI feature class: {}",
            feature.label()
        );
    }
    assert!(cases.iter().any(|case| case.target == AbiTarget::Win64));
    assert!(cases.iter().any(|case| case.target == AbiTarget::I386));
}

#[test]
fn generated_win64_abi_torture_runs_hand_expected() {
    for case in generated_abi_cases()
        .into_iter()
        .filter(|case| case.target == AbiTarget::Win64)
    {
        let pe = compile_case(case);
        let code = run_exit(&pe, case.name).unwrap_or_else(|| {
            panic!(
                "{} [{}] win64 spawn failed",
                case.name,
                case.feature.label()
            )
        });
        assert_eq!(
            code,
            case.expected_exit,
            "{} [{}] win64 exit",
            case.name,
            case.feature.label()
        );
    }
}

#[test]
fn generated_i386_abi_torture_runs_hand_expected_or_skips_wow64() {
    for case in generated_abi_cases()
        .into_iter()
        .filter(|case| case.target == AbiTarget::I386)
    {
        let pe = compile_case(case);
        let Some(code) = run_exit(&pe, case.name) else {
            continue;
        };
        assert_eq!(
            code,
            case.expected_exit,
            "{} [{}] i386 exit",
            case.name,
            case.feature.label()
        );
    }
}
