//! S2b.2 — end-to-end i386: real codegen → link → run → bcc32 differential.
//!
//! Compiles a program through mdbcc's i386 codegen (`-m32` target), links it
//! to a PE32 with the in-tree linker (the same `link::link` + entry-stub path
//! S2d's hand-built fixture used), runs it on Win11 via WOW64, and asserts the
//! exit code. When the BCC 4.52 oracle is present the same source is built
//! with `bcc32 + tlink32` and the two exit codes are compared (O12).

mod support;

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mdbcc::codegen::target::TargetKind;
use mdbcc::coff;
use mdbcc::compile::compile_to_object_with_target;
use mdbcc::link::{self, Input, LinkOpts, Subsystem};
use mdbcc::pp::DefaultResolver;

use support::bcc_oracle::{BccOracle, BuildOpts};

fn link_opts_i386() -> LinkOpts {
    LinkOpts {
        machine: coff::Machine::I386,
        subsystem: Subsystem::Console,
        image_base: 0x0040_0000,
        ..LinkOpts::default()
    }
}

/// Compile `src` through mdbcc's i386 codegen and link to a PE32 image.
fn mdbcc_i386_pe(src: &[u8]) -> Vec<u8> {
    let resolver = DefaultResolver {
        base_dir: std::path::PathBuf::from("."),
    };
    let obj = compile_to_object_with_target(src, "main.c", &resolver, TargetKind::Win32)
        .expect("mdbcc i386 compile");
    link::link(&[Input::Object(&obj)], &link_opts_i386()).expect("link i386 PE32")
}

/// Run a PE image with a 5 s timeout; `Some(code)` on clean exit, `None` if
/// the spawn failed (WOW64 refused the image — diagnostic, not a hard fail).
fn run_pe(pe: &[u8], tag: &str) -> Option<i32> {
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "mdbcc_i386_run_{tag}_{:x}.exe",
        std::process::id() as u64 * 0x1000 + Instant::now().elapsed().as_nanos() as u64,
    ));
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
                            panic!("{tag}: i386 PE hung (>5s)");
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(e) => panic!("{tag}: wait failed: {e}"),
                }
            }
        }
        Err(e) => {
            eprintln!("SKIP ({tag}): spawn failed (WOW64 refused image?): {e}");
            None
        }
    };
    let _ = std::fs::remove_file(&path);
    result
}

/// Run a PE image from a specific current directory. This is for tests where
/// the program opens relative-path fixtures, matching how real Win32 tools run.
fn run_pe_in_dir(pe: &[u8], tag: &str, run_dir: &Path) -> Option<i32> {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = run_dir.join(format!(
        "mdbcc_i386_run_{tag}_{:x}_{unique:x}.exe",
        std::process::id()
    ));
    if std::fs::write(&path, pe).is_err() {
        eprintln!("SKIP ({tag}): could not write temp exe");
        return None;
    }
    let result = match Command::new(&path).current_dir(run_dir).spawn() {
        Ok(mut child) => {
            let start = Instant::now();
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => break status.code(),
                    Ok(None) => {
                        if start.elapsed() > Duration::from_secs(5) {
                            let _ = child.kill();
                            panic!("{tag}: i386 PE hung (>5s)");
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(e) => panic!("{tag}: wait failed: {e}"),
                }
            }
        }
        Err(e) => {
            eprintln!("SKIP ({tag}): spawn failed (WOW64 refused image?): {e}");
            None
        }
    };
    let _ = std::fs::remove_file(&path);
    result
}

struct TempRunDir {
    path: PathBuf,
}

impl TempRunDir {
    fn new(tag: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "mdbcc_i386_{tag}_{:x}_{unique:x}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp run dir");
        Self { path }
    }
}

impl Drop for TempRunDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Compile `src` through mdbcc's i386 backend, run it on WOW64, assert the
/// exit code, and — when the BCC 4.52 oracle is present — assert the
/// bcc32+tlink32 reference exits the same (O12 source-to-behaviour).
///
/// Skips loudly (no CI failure) only on a spawn/write failure of the mdbcc
/// image (environment issue, not a codegen bug). A wrong exit code IS a hard
/// failure.
fn check_i386(tag: &str, src: &str, expected: i32) {
    let pe = mdbcc_i386_pe(src.as_bytes());
    let Some(mdbcc_exit) = run_pe(&pe, tag) else {
        return;
    };
    assert_eq!(mdbcc_exit, expected, "[{tag}] mdbcc i386 exit");

    if let Some(oracle) = BccOracle::discover() {
        let r = oracle.build(src, &BuildOpts::default());
        let bcc_exe = r.exe.unwrap_or_else(|| {
            panic!(
                "[{tag}] bcc32 build failed: exit={:?}\nstderr={}",
                r.output.exit,
                String::from_utf8_lossy(&r.output.stderr)
            )
        });
        let bcc_run = oracle.run(&bcc_exe, &[]);
        assert_eq!(
            bcc_run.output.exit,
            Some(mdbcc_exit),
            "[{tag}] mdbcc i386 exit ({mdbcc_exit}) must match bcc32 reference"
        );
    } else {
        eprintln!("NOTE ({tag}): BCC 4.52 oracle absent — skipped bcc32 diff");
    }
}

/// Compile/run only with mdbcc's i386 backend. Used for extensions the local
/// Borland oracle does not reliably support, such as `long long`.
fn check_i386_mdbcc_only(tag: &str, src: &str, expected: i32) {
    let pe = mdbcc_i386_pe(src.as_bytes());
    let Some(mdbcc_exit) = run_pe(&pe, tag) else {
        return;
    };
    assert_eq!(mdbcc_exit, expected, "[{tag}] mdbcc i386 exit");
}

/// Normalize console line endings: `\r\n` → `\n`. mdbcc emits bytes verbatim
/// via `WriteFile` (no CRT, so a `\n` in the literal stays a single byte),
/// whereas bcc32's `puts`/`printf` go through the cw32 CRT which, in text
/// mode on a pipe, translates `\n` → `\r\n`. Folding CRLF on BOTH sides makes
/// the O12 stdout differential compare the *logical* output, not the OS line
/// discipline. (No `\r` appears in any of our literals, so this is lossless.)
fn norm_eol(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\r' && i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
            out.push(b'\n');
            i += 2;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

/// Run a PE image with a 5 s timeout, **capturing stdout**. `Some((code, out))`
/// on clean exit; `None` if the spawn/write failed (environment issue — a
/// loud skip, not a hard failure, mirroring [`run_pe`]).
fn run_pe_capture(pe: &[u8], tag: &str) -> Option<(i32, Vec<u8>)> {
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "mdbcc_i386_io_{tag}_{:x}.exe",
        std::process::id() as u64 * 0x1000 + Instant::now().elapsed().as_nanos() as u64,
    ));
    if std::fs::write(&path, pe).is_err() {
        eprintln!("SKIP ({tag}): could not write temp exe");
        return None;
    }
    let result = match Command::new(&path).stdout(Stdio::piped()).spawn() {
        Ok(mut child) => {
            let start = Instant::now();
            let code = loop {
                match child.try_wait() {
                    Ok(Some(status)) => break status.code(),
                    Ok(None) => {
                        if start.elapsed() > Duration::from_secs(5) {
                            let _ = child.kill();
                            panic!("{tag}: i386 PE hung (>5s)");
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(e) => panic!("{tag}: wait failed: {e}"),
                }
            };
            // Child has exited; drain whatever it wrote (output is short, so
            // the pipe buffer never blocked the writer).
            let mut buf = Vec::new();
            if let Some(mut so) = child.stdout.take() {
                let _ = so.read_to_end(&mut buf);
            }
            code.map(|c| (c, buf))
        }
        Err(e) => {
            eprintln!("SKIP ({tag}): spawn failed (WOW64 refused image?): {e}");
            None
        }
    };
    let _ = std::fs::remove_file(&path);
    result
}

/// Like [`check_i386`], but also asserts the program's **stdout**. Builds the
/// mdbcc i386 PE, runs it capturing stdout, and checks exit == `expected_exit`
/// AND (CRLF-folded) stdout == `expected_stdout`. When the BCC 4.52 oracle is
/// present this is the O12 stdout differential: bcc32's exit AND stdout must
/// match mdbcc's after the same `\r\n`→`\n` normalization.
fn check_i386_io(tag: &str, src: &str, expected_exit: i32, expected_stdout: &str) {
    let pe = mdbcc_i386_pe(src.as_bytes());
    let Some((mdbcc_exit, mdbcc_out)) = run_pe_capture(&pe, tag) else {
        return;
    };
    assert_eq!(mdbcc_exit, expected_exit, "[{tag}] mdbcc i386 exit");
    let mdbcc_out = norm_eol(&mdbcc_out);
    assert_eq!(
        String::from_utf8_lossy(&mdbcc_out),
        expected_stdout,
        "[{tag}] mdbcc i386 stdout"
    );

    if let Some(oracle) = BccOracle::discover() {
        let r = oracle.build(src, &BuildOpts::default());
        let bcc_exe = r.exe.unwrap_or_else(|| {
            panic!(
                "[{tag}] bcc32 build failed: exit={:?}\nstderr={}",
                r.output.exit,
                String::from_utf8_lossy(&r.output.stderr)
            )
        });
        let bcc_run = oracle.run(&bcc_exe, &[]);
        assert_eq!(
            bcc_run.output.exit,
            Some(mdbcc_exit),
            "[{tag}] mdbcc i386 exit ({mdbcc_exit}) must match bcc32 reference"
        );
        let bcc_out = norm_eol(&bcc_run.output.stdout);
        assert_eq!(
            String::from_utf8_lossy(&bcc_out),
            String::from_utf8_lossy(&mdbcc_out),
            "[{tag}] mdbcc i386 stdout must match bcc32 reference"
        );
    } else {
        eprintln!("NOTE ({tag}): BCC 4.52 oracle absent — skipped bcc32 stdout diff");
    }
}

/// The headline S2 gate (first real-codegen instance): `int main(){return N;}`
/// built by mdbcc's i386 backend runs on WOW64 and matches bcc32.
#[test]
fn i386_main_returns_constant() {
    check_i386("ret42", "int main(void){ return 42; }", 42);
}

/// Locals + integer arithmetic: `int x = 5; return x + 37;` → 42.
#[test]
fn i386_local_and_arithmetic() {
    check_i386(
        "local_arith",
        "int main(void){ int x = 5; return x + 37; }",
        42,
    );
}

/// Control flow + accumulation: sum 1..=10 = 55.
#[test]
fn i386_for_loop_sum() {
    check_i386(
        "for_sum",
        "int main(void){ int s=0; int i; for(i=1;i<=10;i++) s=s+i; return s; }",
        55,
    );
}

// S3: switch / break / continue on i386, diff-tested against bcc32 (the
// `switch`-based WndProc is the HELLOWIN.C shape). Each expected value is the
// C-standard result; `check_i386` additionally asserts it equals bcc32's.
#[test]
fn i386_switch_match_and_break() {
    check_i386(
        "sw_basic",
        "int main(void){ int x=2,r=0; switch(x){ \
         case 1: r=10; break; case 2: r=20; break; default: r=99; } return r; }",
        20,
    );
}

#[test]
fn i386_switch_fallthrough() {
    check_i386(
        "sw_fall",
        "int main(void){ int x=1,r=0; switch(x){ \
         case 1: r+=1; case 2: r+=2; break; case 3: r+=4; } return r; }",
        3,
    );
}

#[test]
fn i386_switch_default_in_middle() {
    check_i386(
        "sw_midflt",
        "int main(void){ int x=9,r=0; switch(x){ \
         case 1: r=1; break; default: r=50; case 2: r+=7; break; } return r; }",
        57,
    );
}

#[test]
fn i386_break_and_continue_in_loop() {
    check_i386(
        "loop_brk_cont",
        "int main(void){ int i,r=0; \
         for(i=0;i<10;i++){ if(i==2) continue; if(i==7) break; r++; } return r; }",
        6,
    );
}

#[test]
fn i386_continue_in_switch_targets_loop() {
    check_i386(
        "sw_cont_loop",
        "int main(void){ int i,r=0; \
         for(i=0;i<6;i++){ switch(i){ \
           case 2: continue; case 4: r+=10; break; default: r+=1; } } return r; }",
        14,
    );
}

// S4.1b: function-template monomorphisation on i386, diff-tested vs bcc32
// (bcc32 4.52 supports templates, so the deduced instantiation must match).
// NB: these use a `.cpp`-shaped TU; check_i386_cpp routes the C++ oracle.
#[test]
fn i386_function_template_deduced() {
    check_i386_cpp(
        "tmpl_maxv",
        "template<class T> T maxv(T a, T b){ return a>b?a:b; } \
         int main(){ return maxv(3, 7); }",
        7,
    );
}

// S4.2h: struct copy-assignment on i386. The copy path emits `lea`/`mov` to set up
// the dst/src addresses for `emit_struct_copy`; those sites previously used 64-bit
// regs unconditionally and PANICKED the x86 encoder. Now width-aware. Diff-tested
// vs bcc32.
#[test]
fn i386_struct_copy_assignment() {
    check_i386_cpp(
        "struct_copy",
        "struct S { int a; int b; int c; }; \
         int main(){ S x; x.a=10; x.b=20; x.c=12; S y; y=x; return y.a+y.b+y.c; }",
        42,
    );
}

// S4.2h: struct RETURN by value on i386. An 8-byte struct returns in EDX:EAX
// (i386 cdecl). The callee packed it into RAX (a silent miscompile: `48 8B 00` is
// `dec eax; mov eax,[eax]` on i386) and the caller-receive stored RAX (panic).
// Both now target-aware; diff-tested vs bcc32 (which uses the same EDX:EAX ABI).
#[test]
fn i386_struct_return_by_value() {
    check_i386_cpp(
        "struct_ret",
        "struct P { int x, y; }; \
         P mk(int a){ P p; p.x=a; p.y=a*2; return p; } \
         int main(){ P p = mk(7); return p.x + p.y; }",
        21,
    );
}

// S4.2h: by-value struct ARGUMENT on i386 (cdecl stack-passing). Caller copies the
// struct's words into the outgoing arg area (high-to-low so field 0 is lowest); the
// callee prologue copies the FULL struct from its incoming slot into the param's
// local slot (not just the first 4 bytes). Diff-tested vs bcc32 (same cdecl ABI).
#[test]
fn i386_struct_by_value_arg() {
    check_i386_cpp(
        "struct_arg",
        "struct P { int x, y; }; \
         int sum(P p){ return p.x + p.y; } \
         int main(){ P p; p.x=10; p.y=11; return sum(p); }",
        21,
    );
}

// W6: i386 record parameters stay inline in the incoming cdecl stack area even
// when they are too large for the Win64 in-register ABI. The caller already
// pushes the full byte image; the callee must not reinterpret the first word as
// a hidden pointer. RailC's TToolbar(Toolbuttondata) hit this with a 0 first
// word and crashed while copying the parameter.
#[test]
fn i386_large_struct_by_value_arg_is_inline_not_hidden_pointer() {
    check_i386_cpp(
        "large_struct_arg_inline",
        "struct Big { int a; int b; int c; }; \
         int sum(Big p){ return p.a + p.b + p.c; } \
         int main(){ Big x; x.a=10; x.b=11; x.c=21; return sum(x); }",
        42,
    );
}

// S4.2i: a conditional expression as an lvalue — `(c ? a : b) = v` stores
// through whichever arm the condition selects. `gen_addr` now has a `Cond` arm
// (mirroring the rvalue branch but leaving each arm's address in RAX). Diff vs
// bcc32: then-arm picks x (x<y true), else-arm picks b (a<b false) → 9 + 7 = 16.
#[test]
fn i386_ternary_as_lvalue() {
    check_i386_cpp(
        "ternary_lvalue",
        "int main(){ int x=1, y=2; (x<y ? x : y) = 9; \
         int a=5, b=2; (a<b ? a : b) = 7; return x + b; }",
        16,
    );
}

// S4.2j: DOUBLE (8-byte FP) arguments on i386 — passed by value on the cdecl
// stack (low word at the lowest address). The caller spills XMM0 to a temp and
// pushes both words high-to-low; the callee prologue copies the full 8-byte image
// into the param's local slot. Exercises a lone double, two doubles, and doubles
// interleaved with int args (cursor accounting). Diff-tested vs bcc32.
#[test]
fn i386_double_arg_single() {
    check_i386_cpp(
        "double_arg_single",
        "double g(double x){ return x * 2.0; } \
         int main(){ return (int)g(3.5); }",
        7,
    );
}

#[test]
fn i386_double_arg_two() {
    check_i386_cpp(
        "double_arg_two",
        "double g(double a, double b){ return a + b; } \
         int main(){ return (int)g(2.5, 4.5); }",
        7,
    );
}

#[test]
fn i386_double_arg_mixed_with_int() {
    // `int` before and `int` after a `double` — verifies the cdecl arg cursor
    // advances by 8 for the double and 4 for each int (both prologue and caller).
    check_i386_cpp(
        "double_arg_mixed",
        "int g(int a, double x, int b){ return a + (int)x + b; } \
         int main(){ return g(1, 2.5, 3); }",
        6,
    );
}

// S4.2k: `do { body } while (cond);` — a fundamental C loop mdbcc did not parse
// at all (the `do` keyword existed but the statement parser ignored it). Lowered
// test-last: the body always runs once, then `cond` jumps back while true.
// `continue` re-tests, `break` exits. Diff-tested vs bcc32.
#[test]
fn i386_do_while_basic() {
    check_i386_cpp(
        "do_while_basic",
        "int main(){ int i=0, s=0; do { s += i; i++; } while(i < 5); return s; }",
        10,
    );
}

#[test]
fn i386_do_while_runs_once_when_false() {
    // The defining property: the body executes even though the condition is false.
    check_i386_cpp(
        "do_while_once",
        "int main(){ int n = 0; do { n++; } while(0); return n; }",
        1,
    );
}

#[test]
fn i386_do_while_break_continue() {
    // `continue` jumps to the condition test (not the body top); `break` exits.
    check_i386_cpp(
        "do_while_break_continue",
        "int main(){ int i=0, s=0; \
         do { i++; if (i == 2) continue; if (i == 5) break; s += i; } while(i < 10); \
         return s; }",
        8, // i=1(+1) skip2 +3 +4 break@5 → 1+3+4 = 8
    );
}

// S4.2l: the comma operator — `a, b` evaluates `a` (discarded), then yields `b`.
// Added at the `expr()` level (full-expression contexts); argument/initialiser
// lists still split on commas. The result TYPE is the rhs type, so a comma
// yielding a double/pointer is read from the right place. Diff-tested vs bcc32.
#[test]
fn i386_comma_operator_value() {
    check_i386_cpp(
        "comma_value",
        "int main(){ int x = (1, 2, 3); return x; }",
        3,
    );
}

#[test]
fn i386_comma_operator_side_effects() {
    // Each left operand's side effects happen; the value is the last operand.
    check_i386_cpp(
        "comma_side_effects",
        "int main(){ int a=0, b=0; int c = (a = 3, b = 4, a + b); return c; }",
        7,
    );
}

#[test]
fn i386_comma_in_for_multi_init_step() {
    // The common real-world use: a for-loop with two induction variables.
    check_i386_cpp(
        "comma_for_multi",
        "int main(){ int s=0, i, j; for (i=0, j=10; i<j; i++, j--) s++; return s; }",
        5,
    );
}

#[test]
fn i386_comma_operator_double_rhs() {
    // The comma's type is its rhs's: a double result must be read from xmm0,
    // not eax (which still holds the discarded int left operand).
    check_i386_cpp(
        "comma_double_rhs",
        "int main(){ int n=2; double d = (n++, 3.5); return (int)(d * 2); }",
        7,
    );
}

// S4.2m: `goto` and labels — `name:` is a flat marker; `goto name;` jumps to it.
// Backward jumps patch immediately; forward jumps are recorded and patched when
// the label is reached (an unresolved one is a clean "undeclared label" error,
// not a wild jump). Diff-tested vs bcc32.
#[test]
fn i386_goto_backward_loop() {
    check_i386_cpp(
        "goto_backward",
        "int main(){ int i=0, s=0; \
         loop: if (i < 5) { s += i; i++; goto loop; } return s; }",
        10,
    );
}

#[test]
fn i386_goto_forward_skip() {
    check_i386_cpp(
        "goto_forward",
        "int main(){ int x = 5; goto skip; x = 99; skip: return x; }",
        5,
    );
}

#[test]
fn i386_goto_escapes_nested_loops() {
    // The classic use: break out of doubly-nested loops. goto fires at i=1,j=2
    // after 5 increments ((0,0)(0,1)(0,2)(1,0)(1,1)), before the 6th.
    check_i386_cpp(
        "goto_nested_escape",
        "int main(){ int s=0; \
         for (int i=0;i<3;i++){ for (int j=0;j<3;j++){ if (i+j==3) goto out; s++; } } \
         out: return s; }",
        5,
    );
}

// S4.2n: calling a function-POINTER data member — `o.f(args)` / `p->f(args)`.
// Previously emitted a direct call to a method symbol "Tag::f" (an unresolved
// external at link time); now detected as a fn-ptr field and lowered as an
// indirect call through the member value. Common in C callback/dispatch tables.
// Diff-tested vs bcc32.
#[test]
fn i386_fnptr_member_call_value() {
    check_i386_cpp(
        "fnptr_member_value",
        "struct Op{ int(*f)(int); }; int dbl(int x){ return x*2; } \
         int main(){ Op o; o.f = dbl; return o.f(21); }",
        42,
    );
}

#[test]
fn i386_fnptr_member_call_via_pointer() {
    check_i386_cpp(
        "fnptr_member_ptr",
        "struct Op{ int(*f)(int,int); }; int add(int a,int b){ return a+b; } \
         int main(){ Op o; o.f = add; Op* p = &o; return p->f(20, 22); }",
        42,
    );
}

#[test]
fn i386_fnptr_member_alongside_method() {
    // A struct with BOTH a method and a fn-ptr field: each dispatches correctly
    // (the method through its symbol, the field through an indirect call).
    check_i386_cpp(
        "fnptr_member_and_method",
        "struct C{ int(*fp)(int); int m(int x){ return x*2; } }; \
         int t(int x){ return x+40; } \
         int main(){ C c; c.fp = t; return c.fp(2) + c.m(0); }",
        42,
    );
}

// S4.2o: function-local `static` variables. Previously the `static` was dropped
// and the local re-initialized every call (a SILENT MISCOMPILE). Now each is a
// uniquely-named module global with static storage duration. Diff-tested vs bcc32.
#[test]
fn i386_static_local_persists() {
    // The defining property: the value persists across calls (1, 2, 3 → 6).
    check_i386_cpp(
        "static_local_persists",
        "int next(){ static int n = 0; return ++n; } \
         int main(){ return next() + next() + next(); }",
        6,
    );
}

#[test]
fn i386_static_local_nonzero_init_once() {
    // The initializer runs ONCE, not on every call (101 + 102 = 203).
    check_i386_cpp(
        "static_local_init_once",
        "int f(){ static int n = 100; return ++n; } \
         int main(){ return f() + f(); }",
        203,
    );
}

#[test]
fn i386_static_local_and_auto_coexist() {
    // A static and an auto local in the same function: the static accumulates,
    // the auto resets each call (10+1=11, 11+1=12 → 11+12 = 23).
    check_i386_cpp(
        "static_and_auto",
        "int f(){ static int s = 10; int a = 1; s += a; return s; } \
         int main(){ return f() + f(); }",
        23,
    );
}

#[test]
fn i386_static_locals_same_name_distinct() {
    // Two functions with a same-named static get DISTINCT globals (unique naming):
    // a()+a() = 1+2 = 3, b() = 1, + 100 = 104.
    check_i386_cpp(
        "static_same_name",
        "int a(){ static int n=0; return ++n; } \
         int b(){ static int n=0; return ++n; } \
         int main(){ return a() + a() + b() + 100; }",
        104,
    );
}

#[test]
fn i386_same_named_block_static_locals_are_distinct() {
    check_i386_cpp(
        "static_same_name_blocks",
        "int pick(int flag){ \
           if(flag){ static int n=10; return ++n; } \
           else { static int n=20; return ++n; } \
         } \
         int main(){ return pick(1) + pick(0) + pick(1) + pick(0); }",
        66,
    );
}

// S4.2p: a method returning `T&` used as an LVALUE — `obj.accessor() = v`. The
// reference-returning method leaves the referent's address in RAX; with the
// address-context flag set, gen_addr uses that address as the lvalue (mirroring
// the operator[] lvalue path). Common in RTL container accessors. vs bcc32.
#[test]
fn i386_member_ref_return_lvalue() {
    check_i386_cpp(
        "member_ref_lvalue",
        "struct B { int v; int& ref(){ return v; } }; \
         int main(){ B b; b.ref() = 42; return b.v; }",
        42,
    );
}

#[test]
fn i386_member_ref_accessor_indexed() {
    // The container-accessor pattern: `a.at(i) = x`.
    check_i386_cpp(
        "member_ref_at",
        "struct Arr { int d[4]; int& at(int i){ return d[i]; } }; \
         int main(){ Arr a; a.at(0) = 40; a.at(1) = 2; return a.at(0) + a.at(1); }",
        42,
    );
}

#[test]
fn i386_member_ref_compound_assign() {
    // Read AND write through the same ref accessor (compound assignment).
    check_i386_cpp(
        "member_ref_compound",
        "struct B { int v; int& ref(){ return v; } }; \
         int main(){ B b; b.ref() = 10; b.ref() += 32; return b.v; }",
        42,
    );
}

// S5 (#8): bind a value-rvalue to a `const T&` parameter on i386 (cdecl). The
// free-call marshalling (marshal_args_cdecl) materialises a temporary for the
// rvalue argument and pushes its address; previously errored "not an lvalue".
// Covers the free-call and method-call (RTL min(_, s.length())) rvalue shapes.
// Diff-tested vs bcc32.
#[test]
fn i386_reference_param_binds_to_a_value_rvalue() {
    check_i386_cpp(
        "ref_rvalue_free",
        "int useref(const int& a){ return a; } \
         int give(){ return 5; } \
         int main(){ return useref(give()); }",
        5,
    );
    check_i386_cpp(
        "ref_rvalue_method",
        "struct S{ int n; int len(){ return n; } }; \
         int useref(const int& a){ return a + 2; } \
         int main(){ S s; s.n = 5; return useref(s.len()); }",
        7,
    );
}

// S4.2h: LARGE (>8-byte) struct return on i386 — the HiddenPtr ABI. The caller
// passes a result-buffer pointer as the cdecl hidden first arg; the callee copies
// its return value there and returns the pointer. The prologue had spilled RCX
// (silent miscompile on i386) and the memcpy setup used 64-bit regs (panic); both
// fixed. Diff-tested vs bcc32.
#[test]
fn i386_large_struct_return() {
    check_i386_cpp(
        "big_ret",
        "struct Big { int a, b, c; }; \
         Big mk(){ Big r; r.a=10; r.b=20; r.c=12; return r; } \
         int main(){ Big b = mk(); return b.a + b.b + b.c; }",
        42,
    );
}

// S4.2t: a LARGE struct with a USER COPY CTOR, returned by value. The callee
// invokes the copy ctor on the caller's result buffer (HiddenPtr) — on i386 via
// the cdecl member-call convention (push src, push `this`/buffer, caller-clean),
// not the Win64 rcx/rdx setup (which panicked). This completes the i386
// struct-return ABI (InReg + HiddenPtr memcpy + HiddenPtr copy-ctor). vs bcc32.
#[test]
fn i386_large_struct_return_with_copy_ctor() {
    check_i386_cpp(
        "big_ret_copyctor",
        "struct Big { int a, b, c; \
           Big(){ a=0; b=0; c=0; } \
           Big(const Big& o){ a = o.a + 1; b = o.b; c = o.c; } }; \
         Big mk(){ Big t; t.a=9; t.b=20; t.c=12; return t; } \
         int main(){ Big r = mk(); return r.a + r.b + r.c; }",
        42, // copy ctor bumps a by 1: 9+1 + 20 + 12
    );
}

/// G58 probe: a HiddenPtr record return with a copy ctor bound immediately to a
/// const reference parameter. OWL's `TXOwl(Msg(...), resId)` uses this shape
/// with Borland `string`; the reference must see the returned buffer, not a
/// stale or raw source object.
#[test]
fn i386_hidden_return_binds_to_const_ref_ctor_arg() {
    check_i386_cpp(
        "hidden_ret_ref_arg",
        "struct Big { int a, b, c; \
           Big(){ a=0; b=0; c=0; } \
           Big(const Big& o){ a = o.a + 1; b = o.b; c = o.c; } }; \
         struct Holder { int sum; Holder(const Big& b){ sum = b.a + b.b + b.c + 1; } }; \
         Big mk(){ Big t; t.a=9; t.b=20; t.c=11; return t; } \
         int main(){ Holder h(mk()); return h.sum; }",
        42,
    );
}

#[test]
fn i386_function_template_two_instantiations() {
    check_i386_cpp(
        "tmpl_two",
        "template<class T> T add(T a, T b){ return a+b; } \
         int main(){ int r=add(3,4); char c=add((char)1,(char)2); return r+c; }",
        10,
    );
}

#[test]
fn i386_function_template_nested_chain() {
    check_i386_cpp(
        "tmpl_nest",
        "template<class T> T add(T a, T b){ return a+b; } \
         template<class T> T dbl(T a){ return add(a, a); } \
         int main(){ return dbl(21); }",
        42,
    );
}

/// Regression (stone-boundary review High #1): `convert(signed int -> ptr)`
/// must not emit the x64-only `movsxd` on i386 (it used to panic). On x86 a
/// pointer is the 4-byte value already in eax, so an int->ptr->int round-trip
/// preserves the value.
#[test]
fn i386_int_to_pointer_cast_roundtrip() {
    check_i386(
        "int2ptr",
        "int main(void){ int i = 100; char *p = (char*)i; return (int)p; }",
        100,
    );
}

/// S2b.5: a 2-arg user-function call via cdecl. The caller pushes the two
/// args right-to-left, `call`s, then cleans `add esp, 8`; the callee reads
/// each param from `[ebp+8+4*i]`.
#[test]
fn i386_call_two_args() {
    check_i386(
        "call_add2",
        "int add(int a,int b){ return a+b; } int main(void){ return add(40,2); }",
        42,
    );
}

#[test]
fn i386_call_args_evaluate_right_to_left() {
    check_i386(
        "call_arg_eval_order",
        "int s;\n\
         int a(void){ s = s * 10 + 1; return s; }\n\
         int b(void){ s = s * 10 + 2; return s; }\n\
         int pack(int x, int y){ return x * 10 + y; }\n\
         int main(void){ return pack(a(), b()) == 212 ? 42 : 7; }",
        42,
    );
}

/// S2b.5: a 3-arg cdecl call (caller cleans `add esp, 12`).
#[test]
fn i386_call_three_args() {
    check_i386(
        "call_add3",
        "int f(int a,int b,int c){ return a+b+c; } int main(void){ return f(10,20,12); }",
        42,
    );
}

/// S2b.5: recursion through the cdecl call path — `fact(5) == 120`. Exercises
/// caller cleanup and callee arg receipt on every nested frame.
#[test]
fn i386_call_recursion() {
    check_i386(
        "call_fact",
        "int fact(int n){ if(n<=1) return 1; return n*fact(n-1); } int main(void){ return fact(5); }",
        120,
    );
}

// =========================================================================
// S2b.5 (stdcall): `__stdcall` user functions are callee-clean on i386 — the
// callee ends `leave; ret N` (pops its own arg bytes) and the caller emits NO
// `add esp` afterwards. The bcc32 differential is the oracle that the two
// halves agree (a per-call imbalance would crash or corrupt the loop case).
// =========================================================================

/// S2b.5: a 2-arg `__stdcall` call. The callee cleans 8 bytes (`ret 8`); the
/// caller pushes both args right-to-left and does NOT clean. `add(40,2) == 42`.
#[test]
fn i386_stdcall_two_args() {
    check_i386(
        "stdcall_add2",
        "int __stdcall add(int a,int b){ return a+b; } \
         int main(void){ return add(40,2); }",
        42,
    );
}

/// S2b.5 — the real point of callee-clean correctness: call a `__stdcall`
/// function 1000 times in a loop and return an accumulator. Any per-call
/// stack imbalance (callee cleans AND caller cleans, or neither) would skew
/// ESP by 4 bytes per iteration and crash or corrupt long before 1000. `f`
/// adds 1, so `s` walks 0→1000; `1000 & 0xff == 232`. bcc32-confirmed.
#[test]
fn i386_stdcall_stack_balance_1000() {
    check_i386(
        "stdcall_balance",
        "int __stdcall f(int x){ return x+1; } \
         int main(void){ int s=0,i; for(i=0;i<1000;i++) s = f(s); return s & 0xff; }",
        232,
    );
}

/// S2b.5: a mixed program — one `__cdecl` (caller-clean) and one `__stdcall`
/// (callee-clean) function, both called and combined. `c` doubles (cdecl:
/// caller does `add esp,4`), `s` adds 3 (stdcall: callee `ret 4`, no caller
/// cleanup). `c(10) + s(9) == 20 + 12 == 32`.
#[test]
fn i386_mixed_cdecl_and_stdcall() {
    check_i386(
        "mixed_conv",
        "int __cdecl c(int x){ return x*2; } \
         int __stdcall s(int x){ return x+3; } \
         int main(void){ return c(10) + s(9); }",
        32,
    );
}

// =========================================================================
// S2b.2c — full scalar integer operator set on i386. Each program exercises
// a different slice of the operator surface (mul/div/mod, bitwise/shift,
// comparisons, signed division + negation, recursion, ternary/recursion).
// The bcc32 differential (when present) is the semantic oracle.
// =========================================================================

/// `*`, `/`, `%` together: 7*3 + 7/3 - 7%3 = 21 + 2 - 1 = 22.
#[test]
fn i386_mul_div_mod() {
    check_i386(
        "mul_div_mod",
        "int main(void){ int a=7,b=3; return a*b + a/b - a%b; }",
        22,
    );
}

/// Bitwise AND, shifts (`>>`, `<<`) and unary `~`: (240>>4) + (3<<2) -
/// (~0 & 7) = 15 + 12 - 7 = 20.
#[test]
fn i386_bitwise_shift_not() {
    check_i386(
        "bitwise_shift_not",
        "int main(void){ int x=240; return (x>>4) + (3<<2) - (~0 & 7); }",
        20,
    );
}

/// Relational + equality operators feeding integer arithmetic:
/// (5>3)*1 + (5<10)*2 + (5==5)*4 + (5!=9)*8 = 1 + 2 + 4 + 8 = 15.
#[test]
fn i386_comparisons_logical() {
    check_i386(
        "comparisons_logical",
        "int main(void){ int a=5; return (a>3) + (a<10)*2 + (a==5)*4 + (a!=9)*8; }",
        15,
    );
}

/// Signed division truncates toward zero, then unary negate: -20/3 = -6
/// (toward zero), -(-6) = 6, + 100 = 106. Verifies the `cdq; idiv` sign
/// path and `neg` on x86.
#[test]
fn i386_signed_div_neg() {
    check_i386(
        "signed_div_neg",
        "int main(void){ int a=-20, b=3; return -(a/b) + 100; }",
        106,
    );
}

/// Recursion + arithmetic across frames: fib(10) = 55.
#[test]
fn i386_fib_recursion() {
    check_i386(
        "fib10",
        "int fib(int n){ if(n<2) return n; return fib(n-1)+fib(n-2);} int main(void){ return fib(10); }",
        55,
    );
}

/// gcd via the ternary `?:` operator + `%` + recursion: gcd(1071,462) = 21.
#[test]
fn i386_gcd_ternary() {
    check_i386(
        "gcd_ternary",
        "int gcd(int a,int b){ return b==0 ? a : gcd(b, a%b);} int main(void){ return gcd(1071,462); }",
        21,
    );
}

// =========================================================================
// S2b.2d — x86 absolute data addressing for file-scope integer globals.
// On x86 a global reference is an absolute `[disp32]` (DIR32 reloc), not
// RIP-relative. The bcc32 differential (when present) is the semantic
// oracle: wrong absolute addressing ⇒ wrong exit code ⇒ test fails.
// =========================================================================

/// Read a file-scope integer global: `int g = 7; return g;` → 7. Exercises
/// `lea eax,[abs g]` + `mov eax,[eax]` with a DIR32 reloc on the lea slot.
#[test]
fn i386_global_read() {
    check_i386("global_read", "int g = 7; int main(void){ return g; }", 7);
}

/// Read AND write a global: `int g = 40; g = g + 2; return g;` → 42. The
/// store path computes the absolute address into ecx and stores `[ecx]`.
#[test]
fn i386_global_read_write() {
    check_i386(
        "global_rw",
        "int g = 40; int main(void){ g = g + 2; return g; }",
        42,
    );
}

/// File-scope integer array — exercises the x86 absolute base + computed
/// index addressing for both WRITE (`a[i] = …`) and READ (`a[i]`):
/// fill a zero-init global array by index, then sum it → 42.
///
/// NB: this fixture drives the per-element-store form; a global *aggregate
/// initializer* (`int a[3] = {10,20,12};`) is now const-evaluated into the
/// `.data` image by `global_image`/`fill_aggregate` (S4.2ac; exercised by
/// `cpp_aggregate_init.rs::global_brace_init_runs`). Both forms drive the
/// same `gen_index_addr` path with the same DIR32 base reloc.
#[test]
fn i386_global_array_index() {
    check_i386(
        "global_array",
        "int a[3]; int main(void){ a[0]=10; a[1]=20; a[2]=12; \
         return a[0]+a[1]+a[2]; }",
        42,
    );
}

// =========================================================================
// S2b.2e — i386 console string output. `puts`/`printf` (no `%d`-style
// conversions) lower to `WriteFile(GetStdHandle(-11), …)` via the Win32
// __stdcall ABI (args pushed right-to-left, callee cleans). The O12 stdout
// differential (when the oracle is present) asserts bcc32's stdout+exit
// match mdbcc's, after `\r\n`→`\n` folding. Plain integer conversions
// (`%d`/`%i`/`%x`/`%X`/`%u`/`%o`) are supported on i386 (S2b.2f); the padded
// specs (width / precision / `-` / `0` for `%d`/`%x`/`%u`/`%s`/`%c`, incl.
// `%ld`/`%lu`) are now supported too — the padded-spec routines grew Win32
// branches (`fmt_int_spec`/`fmt_str_spec`/`fmt_char_spec`). `%f`/`%g` float
// padding remains OUT of scope (a separate later task — float path is x64-only).
// =========================================================================

/// `puts` writes its literal plus a trailing newline. Exercises the full
/// Win32 GetStdHandle + WriteFile stdcall sequence end-to-end.
#[test]
fn i386_puts_hello() {
    check_i386_io(
        "puts_hello",
        "int main(void){ puts(\"Hello, i386!\"); return 0; }",
        0,
        "Hello, i386!\n",
    );
}

/// `printf` with a conversion-free format string. The newline is part of the
/// literal (no `%` processing); we return 0 explicitly so the exit code is
/// stable regardless of printf's byte-count return value.
#[test]
fn i386_printf_literal() {
    check_i386_io(
        "printf_literal",
        "int main(void){ printf(\"literal\\n\"); return 0; }",
        0,
        "literal\n",
    );
}

/// `printf` with a literal `%%` escape → a single `%` on stdout, with no
/// conversion (and thus no varargs). Confirms the `%%` fold reaches the
/// WriteFile path correctly on i386.
#[test]
fn i386_printf_percent() {
    check_i386_io(
        "printf_percent",
        "int main(void){ printf(\"100%%done\\n\"); return 0; }",
        0,
        "100%done\n",
    );
}

// -------------------------------------------------------------------------
// S2b.2f: plain integer conversions (`%d`/`%x`/`%X`/`%u`/`%o`). The Win32
// `int_token` builds the digit string with x86 registers (edi/esi/ecx/bl +
// eax/edx, unsigned `div ecx`); bcc32's stdout is the correctness oracle.
// -------------------------------------------------------------------------

/// `%d` of a small positive value.
#[test]
fn i386_printf_d_basic() {
    check_i386_io(
        "printf_d_basic",
        "int main(void){ printf(\"%d\\n\", 42); return 0; }",
        0,
        "42\n",
    );
}

/// `%d` of zero and a negative value (exercises the sign-flag prepend).
#[test]
fn i386_printf_d_zero_neg() {
    check_i386_io(
        "printf_d_zero_neg",
        "int main(void){ printf(\"%d %d\\n\", 0, -7); return 0; }",
        0,
        "0 -7\n",
    );
}

/// `%d` at the signed 32-bit extremes. INT_MIN is written as
/// `-2147483647 - 1` to sidestep the lexer's unary-minus-on-2147483648
/// issue; the unsigned `div` of neg(0x80000000)=0x80000000 yields the
/// correct "2147483648" with a '-' prepended.
#[test]
fn i386_printf_d_extremes() {
    check_i386_io(
        "printf_d_extremes",
        "int main(void){ printf(\"%d\\n\", 2147483647); \
         printf(\"%d\\n\", -2147483647 - 1); return 0; }",
        0,
        "2147483647\n-2147483648\n",
    );
}

/// `%x`/`%X`/`%u` in one call: lowercase hex, uppercase hex, and an unsigned
/// value above INT_MAX (4000000000 > 2^31-1).
#[test]
fn i386_printf_x_u() {
    check_i386_io(
        "printf_x_u",
        "int main(void){ printf(\"%x %X %u\\n\", 255, 255, 4000000000); return 0; }",
        0,
        "ff FF 4000000000\n",
    );
}

/// `%d` embedded between literal text, fed from a local variable.
#[test]
fn i386_printf_mixed() {
    check_i386_io(
        "printf_mixed",
        "int main(void){ int n=12345; printf(\"n=%d done\\n\", n); return 0; }",
        0,
        "n=12345 done\n",
    );
}

// =========================================================================
// S2 pointer-store fix: storing a pointer/reference *value* through an
// lvalue (`p = a;`, `q = &a;`) must emit a 4-byte `mov [ecx],eax` on Win32,
// not the REX.W `mov [rcx],rax` (8-byte) form. A pointer/reference has AST
// `sizeof == 8` (the x64 width), so `store_at_rcx`'s size-8 arm historically
// prefixed REX.W (0x48). On x86 that 0x48 decodes as a spurious `dec eax`
// that decrements the pointer being stored, corrupting every later
// dereference through that pointer (the pointers.c / structs.c miscompile).
// These two tests lock the specific construct (pointer-typed local assigned,
// then dereferenced) independently of the O12 corpus harness; the bcc32
// differential in `check_i386` is the correctness oracle.
// =========================================================================

/// `int *p; p = a;` (a size-8 pointer store on the AST, 4-byte on x86) then
/// write + read through `p`, and pass the array to a `int*`-param callee that
/// sums `p[i]`. Pre-fix the `p = a` store emitted a leading `dec eax`, so the
/// pointer in `p` was `&a - 1` and every `p[i]` read/wrote one int too low →
/// wrong sum. Sum = 10 + 20 + 12 = 42.
#[test]
fn i386_ptr_local_assign_and_index() {
    check_i386(
        "ptr_local_assign",
        "int sum(int *p, int n){ int i, s; s = 0; \
         for (i = 0; i < n; i++) s += p[i]; return s; } \
         int main(void){ int a[3]; int *p; p = a; \
         p[0] = 10; p[1] = 20; p[2] = 12; return sum(a, 3); }",
        42,
    );
}

/// `struct P *q; q = &a;` (the same size-8 pointer store) then `q->y = 4`
/// writes a field *through* the stored pointer, and a `struct P*`-param callee
/// dereferences `p->x`/`p->y`. Pre-fix the `q = &a` store's stray `dec eax`
/// left `q == &a - 1`, so `q->y = 4` corrupted the struct and `norm` read
/// garbage. Result = a.x + a.y = 3 + 4 = 7.
#[test]
fn i386_struct_ptr_local_assign_and_member() {
    check_i386(
        "struct_ptr_local_assign",
        "struct P { int x; int y; }; \
         int norm(struct P *p){ return p->x + p->y; } \
         int main(void){ struct P a; struct P *q; \
         a.x = 3; q = &a; q->y = 4; return norm(&a); }",
        7,
    );
}

// =========================================================================
// S2: whole-struct assignment (`b = a;`) on i386. The builtin record-
// assignment arm shuffles the source/dest addresses between rax/rcx/rdx,
// then `emit_struct_copy` moves the bytes one at a time (`mov al,[edx+k];
// mov [ecx+k],al` — already REX-free). Pre-fix the three address-shuffle
// moves were hard-coded `mov reg64,reg64`, which have no x86 encoder row and
// panicked the Win32 encoder (NoMatchingRow ⇒ COMPILE-GAP). Making them
// width-aware (reg32 on Win32) lets the copy lower. This locks the construct
// independently of the O12 corpus; the bcc32 4.52 differential is the oracle.
// =========================================================================

/// Whole-struct copy of a pure-int struct: `b = a;` copies both members, then
/// `b.x = 10` mutates only the copy (proving `a` is untouched — a real copy,
/// not an alias). Result = a.x*100 + a.y*10 + b.x = 3*100 + 4*10 + 10 = 350.
/// Matches the `whole_struct_assignment_copies` O12 e2e fixture.
#[test]
fn i386_whole_struct_assignment_copies() {
    check_i386(
        "whole_struct_assign",
        "struct P { int x; int y; }; \
         int main(void){ struct P a; struct P b; \
         a.x = 3; a.y = 4; b = a; b.x = 10; \
         return a.x*100 + a.y*10 + b.x; }",
        350,
    );
}

// =========================================================================
// S2: padded printf specs on i386. `fmt_int_spec` reuses the (already
// x86-correct) `int_token` for digit generation, then pads with REX-free
// ModR/M emits + target-aware helpers; the only x64-isms (an `inc rax`
// pointer bump, a `lea rax,[rbp-cb]`) became width-aware via `wreg`/`wmem`.
// `fmt_str_spec`'s inline strlen got a Win32 branch (ecx walk ptr + edx
// length, mirroring the x64 r9/r11 plan). These tests lock the padded
// integer / string / char behaviour independently of the O12 corpus; the
// expected strings are bcc32 4.52's verbatim stdout (the oracle).
// =========================================================================

/// Padded integers: right/left/zero field width and lowercase/uppercase hex,
/// plus the sign-aware zero-fill cases (`%08d`/`%05d` of a negative — the
/// `-` precedes the zeros and counts toward the width).
#[test]
fn i386_printf_int_padding() {
    check_i386_io(
        "printf_int_padding",
        "int main(void){ \
         printf(\"[%5d|%-5d|%05d|%6x|%-6x|%08X]\\n\", 42, 42, 42, 0xAB, 0xAB, 0x2A); \
         printf(\"[%08d|%05d]\\n\", -42, -42); return 0; }",
        0,
        "[   42|42   |00042|    ab|ab    |0000002A]\n[-0000042|-0042]\n",
    );
}

#[test]
fn i386_printf_sign_and_alternate_flags() {
    check_i386_io(
        "printf_sign_alt_flags",
        "int main(void){ \
         printf(\"[%+05d|% 05d|%#08x|%#X|%#o|%#x|%#o]\\n\", 42, 42, 42u, 171u, 10u, 0u, 0u); \
         return 0; }",
        0,
        "[+0042| 0042|0x00002a|0XAB|012|0|0]\n",
    );
}

/// Padded strings + chars: string precision (max chars) combined with field
/// width and left-justify, and `%c` width (zero/precision do not apply to
/// `%c`/`%s` fill, so the pad is always spaces).
#[test]
fn i386_printf_str_char_padding() {
    check_i386_io(
        "printf_str_char_padding",
        "int main(void){ \
         printf(\"[%8.3s|%-8.3s|%.3s|%3c|%-3c]\\n\", \
         \"hello\", \"hello\", \"hello\", 'Q', 'Q'); return 0; }",
        0,
        "[     hel|hel     |hel|  Q|Q  ]\n",
    );
}

/// Length modifiers `l`/`h` are parsed and ignored (long == int == 4 bytes on
/// Win32), so `%ld`/`%lu`/`%05ld` format identically to `%d`/`%u`/`%05d`. The
/// `%05ld` of -123456 shows width<digits leaves the value untruncated.
#[test]
fn i386_printf_length_mods() {
    check_i386_io(
        "printf_length_mods",
        "int main(void){ \
         printf(\"[%ld|%lu|%05ld]\\n\", -123456L, 4000000000UL, -123456L); return 0; }",
        0,
        "[-123456|4000000000|-123456]\n",
    );
}

// =========================================================================
// Phase F-4 (i386): floating-point printf (`%f`/`%.Nf`). On Win32 an FP
// literal is loaded absolutely (`movsd xmm,[abs flit]`, a new X86Only
// encoder row whose `RipRef::Data` fixup `to_object` maps to Addr32), and
// `float_token` grew a Win32 branch that keeps the value in SSE2 (xmm0-4)
// and pulls digits one at a time — never forming a >32-bit integer, so the
// corpus's `%.10f` works without r64. The expected strings below are bcc32
// 4.52's verbatim stdout (the oracle; confirmed live). The O12 corpus's
// printf_float.c covers the full width/precision/flags matrix — these lock
// the representative default-precision (`%f` → 6) and explicit-precision
// (`%.2f`) paths independently.
// =========================================================================

/// Default-precision `%f` (precision 6): `3.14159` → `3.141590`. The stored
/// double is 3.1415899999…; round-half-up at the 6th fractional digit yields
/// `3.141590`, matching bcc32's cw32 CRT exactly.
#[test]
fn i386_printf_f_default_prec() {
    check_i386_io(
        "printf_f_default_prec",
        "int main(void){ printf(\"%f\\n\", 3.14159); return 0; }",
        0,
        "3.141590\n",
    );
}

/// Mixed explicit + default precision in one call: `%.2f` of 2.5 → `2.50`,
/// and `%f` of 1.0 → `1.000000`. Exercises two FP args (two `.flit.*`
/// globals loaded absolutely) and both precision paths together.
#[test]
fn i386_printf_f_two_args() {
    check_i386_io(
        "printf_f_two_args",
        "int main(void){ printf(\"%.2f %f\\n\", 2.5, 1.0); return 0; }",
        0,
        "2.50 1.000000\n",
    );
}

#[test]
fn i386_printf_f_wide_precision_and_alt_decimal() {
    check_i386_io(
        "printf_f_wide_precision_alt",
        "int main(void){ printf(\"%.16f|%#.0f\\n\", 0.5, 7.0); return 0; }",
        0,
        "0.5000000000000000|7.\n",
    );
}

// =========================================================================
// S2: plain `%s`/`%c` + runtime string handling on i386. `fmt_str` (the
// unpadded `%s`) computes strlen with a Win32 branch (ecx walk ptr + edx
// length, mirroring `fmt_str_spec`'s r9/r11→ecx/edx plan), and `gen_libc`
// (strlen/strcmp/strcpy/strcat/memcpy/memset/atoi) got a Win32 branch that
// walks strings on esi/edi (was r9/r10; callee-saved, push/pop balanced, no
// call inside the loop) with bl as the atoi sign (was r8b). These tests lock
// the new behaviour independently of the O12 corpus (bigcode/strings); the
// expected strings are bcc32 4.52's verbatim stdout (the oracle).
// =========================================================================

/// Plain `%s` (a string literal pointer) and `%c` (a char immediate) in one
/// call — the unpadded `fmt_str`/`fmt_char` paths. Output: `hi/X\n`.
#[test]
fn i386_printf_str_char_plain() {
    check_i386_io(
        "printf_str_char_plain",
        "int main(void){ printf(\"%s/%c\\n\", \"hi\", 'X'); return 0; }",
        0,
        "hi/X\n",
    );
}

/// A NUL-terminated `char[]` walked char-by-char: index each byte in a `for`
/// loop, print `s[i]+1` via `%c`. Exercises char-array indexed reads, a
/// char-by-char loop, and the plain `%c` path. 'a','b','c' → 'b','c','d'.
#[test]
fn i386_char_array_loop() {
    check_i386_io(
        "char_array_loop",
        "int main(void){ char s[4]; int i; \
         s[0]='a'; s[1]='b'; s[2]='c'; s[3]=0; \
         for (i = 0; s[i]; i++) printf(\"%c\", s[i] + 1); \
         printf(\"\\n\"); return 0; }",
        0,
        "bcd\n",
    );
}

/// The libc string builtins behind `strings.c`: `strcpy` into a local buffer,
/// then `strlen`/`strcmp` of it, then plain `%s`. Exercises the Win32
/// `gen_libc` esi/edi walk for all three routines plus `fmt_str`. Output:
/// `3 0 abc\n` (len 3, equal compare 0, the copied string).
#[test]
fn i386_libc_string_builtins() {
    check_i386_io(
        "libc_string_builtins",
        "int main(void){ char buf[16]; strcpy(buf, \"abc\"); \
         printf(\"%d %d %s\\n\", (int)strlen(buf), strcmp(buf, \"abc\"), buf); \
         return 0; }",
        0,
        "3 0 abc\n",
    );
}

#[test]
fn i386_libc_intrinsic_args_evaluate_right_to_left() {
    check_i386(
        "libc_intrinsic_arg_eval_order",
        "int strcmp(char*, char*);\n\
         int s;\n\
         char* a(void){ s = s * 10 + 1; return s == 21 ? \"same\" : \"wrong\"; }\n\
         char* b(void){ s = s * 10 + 2; return \"same\"; }\n\
         int main(void){ return strcmp(a(), b()) == 0 ? 42 : 7; }",
        42,
    );
}

// =========================================================================
// S2: indirect calls through a function-pointer VALUE on i386. On Win32 a
// function pointer is a 4-byte code address, and the call uses cdecl —
// `emit_indirect_call_cdecl` pushes args right-to-left, loads the callee
// into eax, `call eax` (the new `call r32` encoder row, FF D0), then cleans
// `add esp, 4*N`. These lock the indirect-call path independently of the
// O12 corpus (`funcptr.c`); the bcc32 4.52 differential in `check_i386` is
// the correctness oracle (exit codes confirmed against bcc32: 44 and 42).
// =========================================================================

/// A function-pointer variable invoked directly, then reassigned to a second
/// function and invoked again: `fp = add; r = fp(40,2)` (=42), then
/// `fp = sub; return r + fp(5,3)` (=42 + (5-3) = 44). Exercises the 2-arg
/// cdecl indirect call with a swapped target slot.
#[test]
fn i386_funcptr_var_swap() {
    check_i386(
        "funcptr_var_swap",
        "int add(int a,int b){return a+b;} int sub(int a,int b){return a-b;} \
         int main(void){ int (*fp)(int,int) = add; int r = fp(40,2); \
         fp = sub; return r + fp(5,3); }",
        44,
    );
}

#[test]
fn i386_funcptr_args_evaluate_right_to_left() {
    check_i386(
        "funcptr_arg_eval_order",
        "int s;\n\
         int a(void){ s = s * 10 + 1; return s; }\n\
         int b(void){ s = s * 10 + 2; return s; }\n\
         int pack(int x, int y){ return x * 10 + y; }\n\
         int main(void){ int (*fp)(int,int) = pack; return fp(a(), b()) == 212 ? 42 : 7; }",
        42,
    );
}

/// A function pointer passed as a callback PARAMETER and invoked inside the
/// callee (`apply(dbl, 21)` → `dbl(21)` = 42). The fn-ptr arg travels through
/// the cdecl direct-call path into `apply`, which then performs a 1-arg cdecl
/// indirect call through its parameter.
#[test]
fn i386_funcptr_callback_param() {
    check_i386(
        "funcptr_callback_param",
        "int dbl(int x){return x*2;} int apply(int (*f)(int), int v){ return f(v); } \
         int main(void){ return apply(dbl, 21); }",
        42,
    );
}

/// Like [`check_i386_io`], but builds the bcc32 reference as **C++** (the
/// `.cpp` extension makes bcc32 parse classes / virtual dispatch / new+delete).
/// mdbcc parses the C++ subset regardless of extension, so only the oracle
/// side needs the `Lang::Cpp` hint. The same exit + CRLF-folded stdout
/// differential as `check_i386_io`.
fn check_i386_io_cpp(tag: &str, src: &str, expected_exit: i32, expected_stdout: &str) {
    let pe = mdbcc_i386_pe(src.as_bytes());
    let Some((mdbcc_exit, mdbcc_out)) = run_pe_capture(&pe, tag) else {
        return;
    };
    assert_eq!(mdbcc_exit, expected_exit, "[{tag}] mdbcc i386 exit");
    let mdbcc_out = norm_eol(&mdbcc_out);
    assert_eq!(
        String::from_utf8_lossy(&mdbcc_out),
        expected_stdout,
        "[{tag}] mdbcc i386 stdout"
    );

    if let Some(oracle) = BccOracle::discover() {
        let opts = BuildOpts {
            lang: support::bcc_oracle::Lang::Cpp,
            ..BuildOpts::default()
        };
        let r = oracle.build(src, &opts);
        let bcc_exe = r.exe.unwrap_or_else(|| {
            panic!(
                "[{tag}] bcc32 build failed: exit={:?}\nstderr={}",
                r.output.exit,
                String::from_utf8_lossy(&r.output.stderr)
            )
        });
        let bcc_run = oracle.run(&bcc_exe, &[]);
        assert_eq!(
            bcc_run.output.exit,
            Some(mdbcc_exit),
            "[{tag}] mdbcc i386 exit ({mdbcc_exit}) must match bcc32 reference"
        );
        let bcc_out = norm_eol(&bcc_run.output.stdout);
        assert_eq!(
            String::from_utf8_lossy(&bcc_out),
            String::from_utf8_lossy(&mdbcc_out),
            "[{tag}] mdbcc i386 stdout must match bcc32 reference"
        );
    } else {
        eprintln!("NOTE ({tag}): BCC 4.52 oracle absent — skipped bcc32 stdout diff");
    }
}

/// S2 (i386): C++ virtual dispatch through a base pointer. `Animal` declares a
/// virtual `speak()`; `Dog`/`Cat` override it. Two heap objects (`new`) are
/// each addressed through an `Animal*` base pointer and dispatched virtually —
/// proving the call resolves to the *dynamic* type's slot, not the static
/// `Animal::speak`. The interleaved literal lines pin the call order; `delete`
/// exercises the virtual-dtor dispatch + __stdcall HeapFree. bcc32 4.52's
/// stdout is the correctness oracle.
#[test]
fn i386_virtual_dispatch_base_ptr() {
    check_i386_io_cpp(
        "vdisp",
        "#include <stdio.h>\n\
         class Animal { public: virtual int speak(){ return 0; } virtual ~Animal(){} };\n\
         class Dog : public Animal { public: virtual int speak(){ return 1; } };\n\
         class Cat : public Animal { public: virtual int speak(){ return 2; } };\n\
         int main(void){\n\
           Animal *a;\n\
           a = new Dog();  printf(\"dog=%d\\n\", a->speak());  delete a;\n\
           a = new Cat();  printf(\"cat=%d\\n\", a->speak());  delete a;\n\
           return 0;\n\
         }",
        0,
        "dog=1\ncat=2\n",
    );
}

/// W6: the overload-aware vtable rebuild must still map the internal
/// destructor slot key `~` to the real derived function name `Der::~Der`.
/// Otherwise `delete Base*` dispatches straight to `Base::~Base`.
#[test]
fn i386_virtual_destructor_override_survives_vtable_rebuild() {
    check_i386_io_cpp(
        "vdt_override",
        "#include <stdio.h>\n\
         class Base { public: virtual ~Base(){ printf(\"~Base\\n\"); } };\n\
         class Der : public Base { public: ~Der(){ printf(\"~Der\\n\"); } };\n\
         int main(void){ Base* p = new Der(); delete p; return 0; }",
        0,
        "~Der\n~Base\n",
    );
}

// =========================================================================
// S2: i386 RAII / scope-exit destructors. A class destructor is an ordinary
// member call: on Win32 it is cdecl with `this` PUSHED as the sole argument
// and the caller cleaning the stack (`lea ecx,[ebp+obj]; push ecx; call
// ~Tag; add esp,4`). The pre-fix `emit_dtors` delivered `this` via the Win64
// `lea rcx` (REX.W) + RCX-pass form unconditionally, so on i386 the dtor read
// an uninitialised `[ebp+8]` and dereferenced it → 0xC0000005. These two
// tests lock the scope-exit dtor behaviour independently of the O12 corpus:
// an observable printing ctor/dtor pins nested-block LIFO + early-inner-block
// ordering (stdout oracle), and a counter mutated through a pointer pins the
// numeric effect of dtors firing at the right scope boundaries (exit oracle).
// bcc32 4.52 (built as C++) is the correctness oracle in both.
// =========================================================================

/// Nested-block destructor ORDERING (the headline RAII acceptance): a `Trace`
/// class whose ctor prints `+id` and dtor prints `-id`. Objects are built in
/// an outer block with an inner nested block between two outer objects:
///
/// ```text
/// { Trace a(1);            // +1
///   { Trace b(2); Trace c(3); }   // +2 +3, inner '}' -> -3 -2 (LIFO)
///   Trace d(4);            // +4
/// }                        // outer '}' -> -4 -1 (LIFO: a before d)
/// ```
///
/// The interleaving (`-3 -2` appearing BEFORE `+4`, and `-4` before `-1`)
/// proves the inner block destructs early and that each block destructs its
/// objects last-constructed-first. bcc32's stdout is the oracle.
#[test]
fn i386_raii_nested_block_dtor_order() {
    check_i386_io_cpp(
        "raii_nested_order",
        "#include <stdio.h>\n\
         class Trace { int id; public: \
           Trace(int i) { id = i; printf(\"+%d\\n\", id); } \
           ~Trace() { printf(\"-%d\\n\", id); } \
         }; \
         int main(void) { \
           { Trace a(1); \
             { Trace b(2); Trace c(3); } \
             Trace d(4); } \
           return 0; }",
        0,
        "+1\n+2\n+3\n-3\n-2\n+4\n-4\n-1\n",
    );
}

/// Numeric scope-exit effect: a `Bump` dtor folds its `id` into a shared
/// counter (`*p = *p*10 + id`) so the final value ENCODES the destruction
/// order as decimal digits. An inner-block object (`id 2`) destructs at the
/// inner `}` (before the outer object is built), then two outer objects
/// (`id 3`, then `id 1`) destruct at the outer `}` in LIFO order:
///
/// ```text
/// v = 0;
/// { Bump a(p, 1);              // a built first
///   { Bump b(p, 2); }          // inner '}' -> v = 0*10+2 = 2
///   Bump c(p, 3); }            // outer '}' -> v = 2*10+3 = 23, then 23*10+1 = 231
/// ```
///
/// Result 231 proves: inner-block dtor runs first (the `2`), then the outer
/// block destructs c before a (LIFO: `3` then `1`). A wrong `this` (the
/// pre-fix crash) or wrong order would change the value. bcc32 is the oracle.
#[test]
fn i386_raii_counter_mutation_scope_exit() {
    check_i386_cpp(
        "raii_counter_mut",
        "class Bump { int* p; int id; public: \
           Bump(int* q, int i) { p = q; id = i; } \
           ~Bump() { *p = *p * 10 + id; } \
         }; \
         int main(void) { int v; v = 0; int* p; p = &v; \
           { Bump a(p, 1); \
             { Bump b(p, 2); } \
             Bump c(p, 3); } \
           return v; }",
        231,
    );
}

// =========================================================================
// S2e — i386 exception handling (fs:[0] SEH3). A `try`-bearing function
// installs an EXCEPTION_REGISTRATION on the thread's fs:[0] chain in its
// prologue (push handler/catch-pad/frame; push fs:[0]; mov fs:[0],esp) and
// pops it in the epilogue. `throw <int>` calls RaiseException(0xE0000001,
// 0, 1, &value) (__stdcall). The module-wide `.mdbcc_seh3_handler` resumes
// the catch block by editing the trap CONTEXT (Eip→catch pad, Eax→thrown
// int) and returning ExceptionContinueExecution. Minimal int-catch only;
// class throws / nesting / rethrow / dtor-unwind are follow-on ticks. The
// bcc32 4.52 differential (when present) is the correctness oracle: wrong
// SEH ⇒ crash (0xC0000005) or wrong exit ⇒ the test fails.
// =========================================================================

/// Like [`check_i386`] (exit-code only), but builds the bcc32 reference as
/// **C++** — `try`/`throw`/`catch` is rejected by bcc32 in C mode (`.c`).
/// mdbcc parses the C++ subset regardless of extension, so only the oracle
/// side needs the `Lang::Cpp` hint.
fn check_i386_cpp(tag: &str, src: &str, expected: i32) {
    let pe = mdbcc_i386_pe(src.as_bytes());
    let Some(mdbcc_exit) = run_pe(&pe, tag) else {
        return;
    };
    assert_eq!(mdbcc_exit, expected, "[{tag}] mdbcc i386 exit");

    if let Some(oracle) = BccOracle::discover() {
        let opts = BuildOpts {
            lang: support::bcc_oracle::Lang::Cpp,
            ..BuildOpts::default()
        };
        let r = oracle.build(src, &opts);
        let bcc_exe = r.exe.unwrap_or_else(|| {
            panic!(
                "[{tag}] bcc32 build failed: exit={:?}\nstderr={}",
                r.output.exit,
                String::from_utf8_lossy(&r.output.stderr)
            )
        });
        let bcc_run = oracle.run(&bcc_exe, &[]);
        assert_eq!(
            bcc_run.output.exit,
            Some(mdbcc_exit),
            "[{tag}] mdbcc i386 exit ({mdbcc_exit}) must match bcc32 reference"
        );
    } else {
        eprintln!("NOTE ({tag}): BCC 4.52 oracle absent — skipped bcc32 diff");
    }
}

/// `throw 42` caught by `catch (int e) { return e; }` → exit 42. The
/// headline EH acceptance test: the throw raises, the fs:[0] handler unwinds
/// to the catch pad with eax = 42, and the catch returns it.
#[test]
fn i386_try_throw_catch_int() {
    check_i386_cpp(
        "eh_throw_catch",
        "int main(void){ try { throw 42; } catch (int e) { return e; } return 0; }",
        42,
    );
}

/// S2e (class EH): a CLASS throw caught BY REFERENCE. `throw E(5)` copies the
/// object into `.mdbcc_eh_buffer` and raises `EXCEPTION_MDBCC_CLASS` with the
/// type RVA + buffer pointer; `build_seh3_class_handler` matches the thrown
/// type against the catch's expected type and delivers the buffer pointer to
/// the `catch (E& e)` slot. Returns `e.c` = 5. (Diffed against bcc32 when the
/// oracle is present — O12 behavioural parity.)
#[test]
fn i386_try_throw_catch_class_ref() {
    check_i386_cpp(
        "eh_throw_catch_class_ref",
        "struct E { int c; E(int x) : c(x) {} };\n\
         int main() { try { throw E(5); } catch (E& e) { return e.c; } return 0; }",
        5,
    );
}

/// G58 (RailC W6): throwing a non-trivial class must copy-construct the
/// exception object into `.mdbcc_eh_buffer`. A raw byte copy of the thrown
/// temporary would leave `v` as 41; running the copy ctor makes the catch
/// observe 42.
#[test]
fn i386_throw_class_runs_copy_ctor() {
    check_i386_cpp(
        "eh_throw_copy_ctor",
        "struct E { int v; E(int x) : v(x) {} E(const E& o) { v = o.v + 1; } };\n\
         int main() { try { throw E(41); } catch (E& caught) { return caught.v; } return 0; }",
        42,
    );
}

/// S2e (class EH): a CLASS throw caught BY POINTER (`throw &e; catch (E* p)`).
/// Same delivery path; the catch sees the buffer/object pointer. Returns 7.
#[test]
fn i386_try_throw_catch_class_ptr() {
    check_i386_cpp(
        "eh_throw_catch_class_ptr",
        "struct E { int c; E(int x) : c(x) {} };\n\
         int main() { E e(7); try { throw &e; } catch (E* p) { return p->c; } return 0; }",
        7,
    );
}

/// S2e (class EH): a class catch that RE-RAISES (`catch (E& e) { throw; }`)
/// propagates to the CALLER's catch. The class handler pops fs:[0] (its own
/// registration record) before delivering, so the rethrow does NOT re-enter
/// the same handler (which previously infinite-looped). `inner` catches +
/// rethrows; `main` catches the rethrown E → 5. (bcc32-diffed — O12.)
#[test]
fn i386_class_rethrow_propagates_to_caller() {
    check_i386_cpp(
        "eh_class_rethrow",
        "struct E { int c; E(int x) : c(x) {} };\n\
         int inner() { try { throw E(5); } catch (E& e) { throw; } return 0; }\n\
         int main() { try { return inner(); } catch (E& e) { return e.c; } return 9; }",
        5,
    );
}

/// S2e (class EH): an ANONYMOUS class catch that rethrows (`catch (E&) { throw; }`)
/// — the buffer pointer is spilled width-aware (4 bytes on i386) and re-raised.
/// Same caller-catches-it outcome → 5.
#[test]
fn i386_anon_class_rethrow_propagates_to_caller() {
    check_i386_cpp(
        "eh_anon_class_rethrow",
        "struct E { int c; E(int x) : c(x) {} };\n\
         int inner() { try { throw E(5); } catch (E&) { throw; } return 0; }\n\
         int main() { try { return inner(); } catch (E& e) { return e.c; } return 9; }",
        5,
    );
}

/// A `try` that does NOT throw falls through to the normal return value (the
/// SEH record is installed and then cleanly popped in the epilogue; the
/// handler is never invoked). Returns 7.
#[test]
fn i386_try_no_throw_fallthrough() {
    check_i386_cpp(
        "eh_no_throw",
        "int main(void){ int r = 0; try { r = 7; } catch (int e) { r = 99; } return r; }",
        7,
    );
}

/// Throw caught with a printf side effect in the catch body (stdout diff):
/// `try { throw 7; } catch (int e) { printf("caught %d\n", e); }` → `caught 7\n`.
/// Proves the delivered int reaches the catch parameter slot and the catch
/// body (which calls into the cdecl/stdcall IO path) runs with a sane stack.
#[test]
fn i386_try_throw_catch_printf() {
    check_i386_io_cpp(
        "eh_throw_printf",
        "#include <stdio.h>\n\
         int main(void){ try { throw 7; } catch (int e) { printf(\"caught %d\\n\", e); } return 0; }",
        0,
        "caught 7\n",
    );
}

// =========================================================================
// Reference parameters (S2b.5 follow-on): a C++ `T&` parameter is passed in
// cdecl as a 4-byte pointer holding the argument's address. The callee reads
// the pointer from `[ebp+8+4*i]` and dereferences it, so a write through the
// reference mutates the caller's object. mdbcc evaluates the argument's
// ADDRESS (`gen_addr`) instead of its value for a `Type::Ref(_)` parameter,
// mirroring the Win64 marshaller. bcc32 (built as C++) is the oracle.
// =========================================================================

/// The headline reference-parameter acceptance: `void inc(int& r){ r = r+1; }`
/// mutates the caller's `a` through the reference. `a` starts at 41; after
/// `inc(a)` it is 42, which `main` returns. Proves the address is passed and
/// the callee's write lands in the caller's frame slot.
#[test]
fn i386_reference_parameter_mutates_caller() {
    check_i386_cpp(
        "ref_param_inc",
        "void inc(int& r) { r = r + 1; } \
         int main(void){ int x; x = 41; inc(x); return x; }",
        42,
    );
}

/// A `const Cls&` member operator (mirrors the `cxx_operator_*` fixtures but
/// adds `const` on both the parameter and the method, exercising the
/// const-reference marshalling path). `a - b` calls `int operator-(const N&)
/// const`, which reads `o.v` through the passed address: 10 - 3 = 7.
#[test]
fn i386_const_reference_operator_member() {
    check_i386_cpp(
        "ref_param_const_op",
        "class N { \
             int v; \
           public: \
             N(int x) { v = x; } \
             int operator-(const N& o) const { return v - o.v; } \
         }; \
         int main(void){ N a(10); N b(3); return a - b; }",
        7,
    );
}

// =========================================================================
// i386 ILP32 pointer size + byte alignment. On Win32 a pointer / reference /
// function-pointer is 4 bytes (LLP64 is the Win64 default), so `sizeof(T*)`,
// a pointer member's struct offset, an array-of-pointer's index stride, and a
// struct's `sizeof` (bcc32 4.52 defaults to byte alignment, `-a1`) all use the
// 4-byte width. These lock the construct independently of the O12 corpus; the
// bcc32 4.52 differential in `check_i386` is the correctness oracle (the
// expected exit codes are bcc32's). On the Win64 path the same source folds
// `sizeof(int*)` to 8 — the 88 SipHash baselines stay byte-identical.
// =========================================================================

/// `sizeof(int*)` is 4 on Win32 (was 8 — the LLP64 default that masked the
/// ABI gap). bcc32 4.52's i386 pointer is 4 bytes, so this returns 4.
#[test]
fn i386_sizeof_pointer_is_four() {
    check_i386("sizeof_ptr", "int main(void){ return sizeof(int*); }", 4);
}

/// A struct with a pointer member lays the pointer out at a 4-byte offset (not
/// 8). `struct S { int v; int* p; }` is `v@0, p@4` (size 8) on Win32; with the
/// old 8-byte pointer `p` sat at offset 8 (size 16). The test writes through
/// `s.p` and reads the target back, so a wrong offset reads/writes the wrong
/// slot and diverges from bcc32. `x` starts 5, `*s.p = 11` makes it 11.
#[test]
fn i386_struct_pointer_member_offset() {
    check_i386(
        "struct_ptr_member",
        "struct S { int v; int* p; }; \
         int main(void){ int x; struct S s; \
         x = 5; s.v = 7; s.p = &x; *s.p = 11; \
         return s.v + x; }",
        18, // 7 + 11
    );
}

/// `sizeof` of a struct with a pointer member is the byte-packed ILP32 size.
/// `struct S { char c; int* p; }`: bcc32 4.52 byte-aligns (`c@0, p@1`, no gap),
/// so `sizeof` is 1 + 4 = 5. (With natural Win64 alignment + an 8-byte pointer
/// it would be 16.) bcc32 is the oracle.
#[test]
fn i386_struct_with_pointer_sizeof_byte_aligned() {
    check_i386(
        "struct_ptr_sizeof",
        "struct S { char c; int* p; }; \
         int main(void){ return sizeof(struct S); }",
        5,
    );
}

/// An array of pointers is indexed with a 4-byte stride on Win32. `int* a[3]`
/// holds three `int*`; `a[i]` scales `i` by `sizeof(int*)` = 4 (was 8). Each
/// slot points at a distinct int; summing `*a[0] + *a[1] + *a[2]` proves the
/// stride is right (a wrong stride reads an adjacent/overlapping slot). The
/// array-of-function-pointer form is covered by funcptr.c in the corpus stripe.
#[test]
fn i386_array_of_pointers_indexed() {
    check_i386(
        "array_of_ptrs",
        "int main(void){ int x; int y; int z; int* a[3]; \
         x = 10; y = 20; z = 12; \
         a[0] = &x; a[1] = &y; a[2] = &z; \
         return *a[0] + *a[1] + *a[2]; }",
        42, // 10 + 20 + 12
    );
}

// =========================================================================
// S3 (first bounded GUI step): a minimal i386 GUI program. A TU that defines
// `WinMain` (not `main`) links as a GUI-subsystem PE32 (IMAGE_SUBSYSTEM_
// WINDOWS_GUI = 2) and exits with WinMain's return value. The i386 GUI entry
// stub (`write_entry_stub`'s new PE32+Gui branch) pushes 4 zero args, calls
// WinMain, reclaims them (mdbcc emits WinMain CDECL — bare `leave; ret`),
// then `push eax; call [ExitProcess]`. No window / message loop / API calls
// yet — just the GUI entry mechanism, verified by exit code against bcc32.
// =========================================================================

/// GUI PE32 link opts: 32-bit machine + GUI subsystem + the conventional
/// 0x00400000 PE32 image base. Mirrors [`link_opts_i386`] but selects
/// subsystem 2.
fn link_opts_i386_gui() -> LinkOpts {
    LinkOpts {
        machine: coff::Machine::I386,
        subsystem: Subsystem::Gui,
        image_base: 0x0040_0000,
        ..LinkOpts::default()
    }
}

/// Compile `src` through mdbcc's i386 codegen and link to a GUI PE32 image.
/// The subsystem is derived from the object via [`link::auto_subsystem`]
/// (a TU defining `WinMain` ⇒ GUI), asserted to be GUI here so a regression
/// in entry detection fails loudly rather than silently producing a console
/// image.
fn mdbcc_i386_gui_pe(src: &[u8]) -> Vec<u8> {
    let resolver = DefaultResolver {
        base_dir: std::path::PathBuf::from("."),
    };
    let obj = compile_to_object_with_target(src, "main.c", &resolver, TargetKind::Win32)
        .expect("mdbcc i386 compile");
    assert_eq!(
        link::auto_subsystem(&obj),
        Subsystem::Gui,
        "a WinMain-defining TU must auto-detect the GUI subsystem"
    );
    link::link(&[Input::Object(&obj)], &link_opts_i386_gui()).expect("link i386 GUI PE32")
}

/// The PE32 optional-header `Subsystem` field (offset 68 of the optional
/// header). Locks the GUI image to IMAGE_SUBSYSTEM_WINDOWS_GUI = 2 in-process
/// (no run needed), so the gate holds even where WOW64 refuses to spawn.
fn pe32_subsystem(pe: &[u8]) -> u16 {
    let e_lfanew = u32::from_le_bytes(pe[0x3C..0x40].try_into().unwrap()) as usize;
    // PE sig (4) + COFF header (20) → optional header start; Subsystem is at
    // optional-header offset 68 (PE32 layout).
    let opt = e_lfanew + 4 + 20;
    u16::from_le_bytes([pe[opt + 68], pe[opt + 69]])
}

/// Like [`check_i386`], but builds a **GUI** PE32 (subsystem 2, entry via
/// `WinMain`). Asserts the header subsystem is GUI, then runs on WOW64 and
/// — when the BCC 4.52 oracle is present — diffs the exit code against
/// bcc32 (which auto-selects its GUI startup for a `WinMain` program).
/// Skips loudly (no CI failure) on a spawn/write failure of the mdbcc image
/// (WOW64 loader refusal is an environment issue, not a codegen bug),
/// mirroring [`run_pe`].
fn check_i386_gui(tag: &str, src: &str, expected: i32) {
    let pe = mdbcc_i386_gui_pe(src.as_bytes());
    assert_eq!(
        pe32_subsystem(&pe),
        2,
        "[{tag}] GUI PE32 subsystem must be 2"
    );

    let Some(mdbcc_exit) = run_pe(&pe, tag) else {
        return;
    };
    assert_eq!(mdbcc_exit, expected, "[{tag}] mdbcc i386 GUI exit");

    if let Some(oracle) = BccOracle::discover() {
        // `-W` makes the bcc32 driver build a Windows GUI app: it links the
        // GUI CRT startup (`c0w32`, which calls `WinMain`) instead of the
        // console `c0nt` (which references `_main`). Without `-W`, bcc32's
        // default driver links console startup, the link fails with
        // "Unresolved external '_main'", and bcc32 STILL exits 0 leaving a
        // stale/partial `.exe` that crashes (0xC0000005) when run — so the
        // flag is load-bearing for a faithful GUI differential.
        let opts = BuildOpts {
            extra: vec!["-W".into()],
            ..BuildOpts::default()
        };
        let r = oracle.build(src, &opts);
        let bcc_exe = r.exe.unwrap_or_else(|| {
            panic!(
                "[{tag}] bcc32 GUI build failed: exit={:?}\nstderr={}",
                r.output.exit,
                String::from_utf8_lossy(&r.output.stderr)
            )
        });
        let bcc_run = oracle.run(&bcc_exe, &[]);
        assert_eq!(
            bcc_run.output.exit,
            Some(mdbcc_exit),
            "[{tag}] mdbcc i386 GUI exit ({mdbcc_exit}) must match bcc32 reference"
        );
    } else {
        eprintln!("NOTE ({tag}): BCC 4.52 oracle absent — skipped bcc32 GUI diff");
    }
}

/// The headline S3 first-GUI-step acceptance: a self-contained (NO windows.h)
/// `WinMain` returning a constant. `__stdcall` is written directly so the TU
/// needs no headers; the 4 args are plain 4-byte scalars (`int`/`char*`). The
/// program links as a GUI-subsystem PE32 and exits 42, matching bcc32.
#[test]
fn i386_gui_winmain_returns_constant() {
    check_i386_gui(
        "gui_winmain42",
        "int __stdcall WinMain(int hi, int hp, char *cl, int sh){ return 42; }",
        42,
    );
}

/// STRETCH: the same minimal GUI entry but with the **proper** signature via
/// the real `<windows.h>` — `int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR,
/// int)`. This exercises `<windows.h>` *compiling* (not just parsing): the
/// intrinsic header's `WINAPI` (empty macro), `HINSTANCE` (`void*` → 4 bytes
/// on i386) and `LPSTR` (`char*`) must all lower cleanly into the i386 ABI.
/// mdbcc resolves `<windows.h>` intrinsically (no `-I` needed); the bcc32
/// reference uses its on-disk BC45 `<windows.h>` (the oracle already passes
/// `-I<BC45\INCLUDE>`). Both sides exit 42.
#[test]
fn i386_gui_winmain_real_windows_h() {
    check_i386_gui(
        "gui_winmain_winh",
        "#include <windows.h>\n\
         int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, \
         LPSTR lpCmdLine, int nCmdShow){ return 42; }",
        42,
    );
}

// =========================================================================
// S3 — calling a real Win32 API (a recognised DLL import) from i386 code.
// A Win32 API is `__stdcall`: the caller pushes the args RIGHT-TO-LEFT and
// the callee (the DLL) reclaims them (`ret N`). mdbcc's general recognised-
// import path (`emit_win32_call`) was a Win64-only register marshaller; on
// i386 it now pushes scalar int/pointer args via the cdecl push logic and
// emits `call dword ptr [IAT]` (`FF 15` + Addr32 reloc) with NO caller
// cleanup — exactly the convention the hand-coded `GetStdHandle`/`WriteFile`
// IO path already uses. These programs are CONSOLE (`main`) to isolate the
// API call from the GUI entry, and exit-code-verifiable (no window). The
// `lstr*A` helpers are KERNEL32 stdcall string ops with deterministic
// return values; the bcc32 4.52 differential (its on-disk `<windows.h>`
// supplies the real prototypes) is the correctness oracle.
// =========================================================================

/// The headline Win32 API-call acceptance: `lstrlenA("hello")` returns 5
/// (the byte length of the literal). A single-arg `__stdcall` import — the
/// caller pushes the one pointer arg and the DLL cleans it; the result is in
/// EAX, returned as the process exit code. Proves a recognised-import call
/// marshals stdcall (not the Win64 register form) on i386. bcc32-confirmed: 5.
#[test]
fn i386_win32_api_lstrlena() {
    check_i386(
        "win32_lstrlena",
        "#include <windows.h>\n\
         int main(void){ return lstrlenA(\"hello\"); }",
        5,
    );
}

/// A 2-arg `__stdcall` API call, proving the RIGHT-TO-LEFT push order is
/// correct (a 2-arg API is where order first matters). `lstrcmpA(a, b)`
/// returns <0 / 0 / >0 for a<b / a==b / a>b. We encode only the SIGNS (which
/// are deterministic across Windows versions, unlike the magnitude) so the
/// exit code is a stable small int:
///
/// ```text
/// (lstrcmpA("aaa","bbb") < 0) * 1   // a < b  => 1
/// (lstrcmpA("bbb","aaa") > 0) * 2   // a > b  => 2   (args in opposite order)
/// (lstrcmpA("xyz","xyz") == 0) * 4  // equal  => 4
/// ```
///
/// Sum = 7 iff every comparison saw its arguments in the order written. Had
/// the push order been reversed, the first two would each flip sign and
/// contribute 0, yielding 4 — so 7 specifically proves left-to-right operand
/// delivery via right-to-left stack pushes. bcc32-confirmed: 7.
#[test]
fn i386_win32_api_lstrcmpa_order() {
    check_i386(
        "win32_lstrcmpa",
        "#include <windows.h>\n\
         int main(void){ \
           return (lstrcmpA(\"aaa\",\"bbb\") < 0) \
                + (lstrcmpA(\"bbb\",\"aaa\") > 0) * 2 \
                + (lstrcmpA(\"xyz\",\"xyz\") == 0) * 4; }",
        7,
    );
}

/// RailC closure import tail: `lstrcmpiA` (legacy KERNEL32 string helper),
/// `OpenFile` (KERNEL32), and the GDI bitmap creators are direct Win32 imports,
/// not C++ symbols. Only `lstrcmpiA` executes; the others sit in an unreachable
/// branch so this remains headless while still forcing mdbcc to emit/import the
/// names during link.
#[test]
fn i386_win32_api_railc_tail_imports() {
    check_i386_cpp(
        "win32_railc_tail_imports",
        "extern \"C\" int __stdcall lstrcmpiA(const char*, const char*); \
         extern \"C\" void* __stdcall CreateCompatibleBitmap(void*, int, int); \
         extern \"C\" void* __stdcall CreateDiscardableBitmap(void*, int, int); \
         extern \"C\" unsigned int __stdcall OpenFile(const char*, void*, unsigned int); \
         int main(void){ \
           if (0) { \
             CreateCompatibleBitmap(0, 1, 1); \
             CreateDiscardableBitmap(0, 1, 1); \
             OpenFile(\"nope\", 0, 0); \
           } \
           return lstrcmpiA(\"RailC\", \"railc\") == 0 ? 42 : 0; }",
        42,
    );
}

// --- S4.2c: i386 pointer-arithmetic codegen (`ptr_add` + pointer difference) ---
// These exercise the paths that previously emitted 64-bit-only encodings
// (`movsxd rax,eax`, `mov rcx,rax` on Gpr64, `cqo`/`idiv rcx`) and PANICKED the
// x86 encoder (`NoMatchingRow`). On i386 pointers are 32-bit, so the index needs
// no sign-extension and the ops run at word width via `wreg`; pointer difference
// divides at 32-bit width (cdq; idiv ecx). bcc32-confirmed exit codes.

/// `*(p + n)` — pointer-plus-int through `ptr_add` (NOT the array-index path).
#[test]
fn i386_pointer_plus_int_deref() {
    check_i386(
        "ptr_plus_int",
        "int main(){ int a[5]; int* p = a; a[3] = 40; return *(p + 3); }",
        40,
    );
}

/// `*(p - n)` — pointer-minus-int through `ptr_add` with `sub = true`.
#[test]
fn i386_pointer_minus_int_deref() {
    check_i386(
        "ptr_minus_int",
        "int main(){ int a[5]; int* p = &a[3]; a[1] = 22; return *(p - 2); }",
        22,
    );
}

/// `p - q` on `int*` — pointer DIFFERENCE with element size 4, so the result
/// is divided by the scale (`cdq; idiv ecx` on i386). &a[4]-&a[1] == 3.
#[test]
fn i386_pointer_difference_scaled() {
    check_i386(
        "ptr_diff_int",
        "int main(){ int a[5]; int* p = &a[4]; int* q = &a[1]; return p - q; }",
        3,
    );
}

/// `p - q` on `char*` — element size 1, so the scale division is skipped.
/// &s[6]-&s[2] == 4. Guards the scale==1 branch of the difference path.
#[test]
fn i386_pointer_difference_char() {
    check_i386(
        "ptr_diff_char",
        "int main(){ char s[8]; char* p = &s[6]; char* q = &s[2]; return p - q; }",
        4,
    );
}

/// B-06: i386 `unsigned long long` values must be represented as EDX:EAX, not
/// just the low dword in EAX. A high-count shift is the smallest observable
/// repro: 0x1122334455667788 >> 40 == 0x112233.
#[test]
fn i386_u64_shift_right_uses_high_dword() {
    check_i386_mdbcc_only(
        "i386_u64_shr",
        "int main(void){ \
           unsigned long long x = 0x1122334455667788ULL; \
           return ((int)(x >> 40) == 0x112233) ? 42 : 7; \
         }",
        42,
    );
}

/// B-06: addition must carry from the low dword into the high dword.
#[test]
fn i386_u64_add_carries_into_high_dword() {
    check_i386_mdbcc_only(
        "i386_u64_add",
        "int main(void){ \
           unsigned long long a = 0x40000000ULL; \
           unsigned long long x = a + a + a + a; \
           return ((int)(x >> 32) == 1) ? 42 : 7; \
         }",
        42,
    );
}

/// B-06: multiplication must keep the high half of the low 64-bit product.
#[test]
fn i386_u64_mul_keeps_high_product() {
    check_i386_mdbcc_only(
        "i386_u64_mul",
        "int main(void){ \
           unsigned long long a = 0x80000000ULL; \
           unsigned long long x = a * 4ULL; \
           return ((int)(x >> 32) == 2) ? 42 : 7; \
         }",
        42,
    );
}

/// B-06: equality must compare both halves; these values have the same low
/// dword and different high dwords.
#[test]
fn i386_u64_compare_checks_high_dword() {
    check_i386_mdbcc_only(
        "i386_u64_cmp_high",
        "int main(void){ \
           return (0x100000001ULL == 0x200000001ULL) ? 7 : 42; \
         }",
        42,
    );
}

/// B-06: signed right shift and unary negation both need the high dword.
#[test]
fn i386_i64_negate_and_signed_shift_use_high_dword() {
    check_i386_mdbcc_only(
        "i386_i64_neg_sar",
        "int main(void){ \
           long long x = 0x300000000LL; \
           long long y = -x; \
           return ((int)(y >> 33) == -2) ? 42 : 7; \
         }",
        42,
    );
}

/// B-06 review guard: the shift count's unsigned type must not turn a signed
/// `long long` right shift into a logical shift.
#[test]
fn i386_i64_right_shift_signedness_comes_from_lhs() {
    check_i386_mdbcc_only(
        "i386_i64_sar_unsigned_count",
        "int main(void){ \
           long long x = -0x200000000LL; \
           unsigned s = 33U; \
           return ((int)(x >> s) == -1) ? 42 : 7; \
         }",
        42,
    );
}

/// B-06 review guard: `long long` can represent every `unsigned int`, so this
/// comparison is signed, not unsigned.
#[test]
fn i386_i64_compare_unsigned_int_uses_signed_i64_conversion() {
    check_i386_mdbcc_only(
        "i386_i64_cmp_uint",
        "int main(void){ \
           long long x = -1LL; \
           unsigned y = 1U; \
           return (x < y) ? 42 : 7; \
         }",
        42,
    );
}

/// B-06: truthiness must consider EDX as well as EAX.
#[test]
fn i386_u64_truthy_checks_high_dword() {
    check_i386_mdbcc_only(
        "i386_u64_truthy",
        "int main(void){ \
           unsigned long long x = 0x100000000ULL; \
           return x ? 42 : 7; \
         }",
        42,
    );
}

/// B-06: `++` over 0xFFFFFFFF must carry into the high dword.
#[test]
fn i386_u64_increment_carries_into_high_dword() {
    check_i386_mdbcc_only(
        "i386_u64_inc",
        "int main(void){ \
           unsigned long long x = 0xFFFFFFFFULL; \
           ++x; \
           return ((int)(x >> 32) == 1 && (int)x == 0) ? 42 : 7; \
         }",
        42,
    );
}

/// B-06: an i386 `long long` function return is also EDX:EAX; preserving only
/// EAX through the return epilogue drops the high dword before the caller sees it.
#[test]
fn i386_u64_function_return_preserves_high_dword() {
    check_i386_mdbcc_only(
        "i386_u64_return_pair",
        "int sink; \
         struct D { ~D(){ unsigned long long z = 0ULL; sink = (int)(z >> 32); } }; \
         unsigned long long f(void){ D d; return 0x100000000ULL; } \
         int main(void){ return ((int)(f() >> 32) == 1) ? 42 : 7; }",
        42,
    );
}

/// B-06: cdecl passes a `long long` argument as two stack dwords; the callee's
/// following parameter must start after both of them.
#[test]
fn i386_u64_cdecl_argument_passes_both_dwords() {
    check_i386_mdbcc_only(
        "i386_u64_cdecl_arg",
        "int f(unsigned long long x, int y){ \
           return ((int)(x >> 32) == 1 && y == 9) ? 42 : 7; \
         } \
         int main(void){ return f(0x100000000ULL, 9); }",
        42,
    );
}

/// S4.2d (i386): a polymorphic class deriving from a non-polymorphic base with
/// data — exercises the width-aware `convert` upcast add (`add eax,imm32`, no
/// REX.W on Win32) and the base-method `this` adjustment, then diffs vs bcc32.
/// `dp->t()`=11, `dp->getx()`=5, `bp->x`=5, `bp->getx()`=5  ⇒ 26.
#[test]
fn i386_polymorphic_derived_from_nonpoly_base() {
    check_i386_cpp(
        "base_adj",
        "struct Base { int x; int getx(){ return x; } }; \
         struct Derived : public Base { int y; virtual int t(){ return x+y; } }; \
         int main(){ Derived d; d.x=5; d.y=6; Derived* dp=&d; Base* bp=&d; \
         return dp->t() + dp->getx() + bp->x + bp->getx(); }",
        26,
    );
}

/// G64 (RailC shutdown): a `Derived* -> shifted-base*` conversion must preserve
/// NULL. OWL's `delete (TStreamableBase*)DocManager` hit the same shape: the
/// base subobject sits at a non-zero offset, and adding that offset to NULL
/// produced a fake non-null pointer that crashed during delete dispatch.
#[test]
fn i386_shifted_base_upcast_preserves_null() {
    check_i386_cpp(
        "null_base_adj",
        "struct Base { int x; }; \
         struct Derived : public Base { virtual int f(){ return 1; } }; \
         int main(){ Derived* dp = 0; Base* bp = dp; return bp == 0 ? 42 : 1; }",
        42,
    );
}

#[test]
fn i386_virtual_base_upcast_preserves_null() {
    check_i386_cpp(
        "null_vbase_adj",
        "struct V { int x; }; \
         struct D : virtual V { int y; }; \
         int main(){ D* dp = 0; V* vp = dp; return vp == 0 ? 42 : 1; }",
        42,
    );
}

#[test]
fn i386_delete_cast_to_secondary_base_preserves_null() {
    check_i386_cpp(
        "null_delete_secondary",
        "struct A { virtual ~A() {} }; \
         struct B { virtual ~B() {} }; \
         struct D : public A, public B { virtual ~D() {} }; \
         int main(){ D* dp = 0; delete (B*)dp; return 42; }",
        42,
    );
}

/// S2e (i386 RTTI): `dynamic_cast<D*>(b)` — the byte-additive i386 port of the
/// Win64 vtable base-chain walk. Covers all three outcomes against the bcc32
/// oracle in one program: a MATCH (`b1`→`D1*`), a CROSS-cast that must yield
/// null (`b1`→`D2*`), a second MATCH on a different leaf (`b2`→`D2*`), and a
/// NULL input (null→null). Both D1 and D2 are instantiated so their vtables
/// (the `RipRef::Vtable` targets the cast walk references) are emitted.
/// r = 7 (p1->a) + 10 (!pX) + 9 (p2->c) + 100 (!pn) = 126.
#[test]
fn i386_dynamic_cast_match_cross_and_null() {
    check_i386_cpp(
        "dyncast",
        "struct B { virtual int who(){ return 1; } }; \
         struct D1 : B { int a; virtual int who(){ return 2; } }; \
         struct D2 : B { int c; virtual int who(){ return 3; } }; \
         int main(){ \
           D1 d1; d1.a = 7; D2 d2; d2.c = 9; \
           B* b1 = &d1; B* b2 = &d2; B* nb = 0; \
           D1* p1 = dynamic_cast<D1*>(b1); \
           D2* pX = dynamic_cast<D2*>(b1); \
           D2* p2 = dynamic_cast<D2*>(b2); \
           D1* pn = dynamic_cast<D1*>(nb); \
           int r = 0; \
           if (p1) r += p1->a; \
           if (!pX) r += 10; \
           if (p2) r += p2->c; \
           if (!pn) r += 100; \
           return r; }",
        126,
    );
}

#[test]
fn i386_dynamic_cast_to_nonpolymorphic_static_base() {
    check_i386_cpp(
        "dyncast_nonpoly_base",
        "struct A { int a; }; \
         struct B : A { virtual int who(){ return 1; } }; \
         int main(){ B b; B* p = &b; A* a = dynamic_cast<A*>(p); return a ? 42 : 0; }",
        42,
    );
}

/// G62 (OWL OLEFRAME.CPP): `TYPESAFE_DOWNCAST` can target a non-polymorphic
/// mixin side. Full cross-cast pointer adjustment needs richer RTTI; for now
/// compile it and produce null rather than a bogus adjusted pointer.
#[test]
fn i386_dynamic_cast_to_nonpolymorphic_crosscast_compiles() {
    let src = b"struct B { virtual int who(){ return 1; } }; \
                struct M { int m; }; \
                M* f(B* b) { return dynamic_cast<M*>(b); }";
    let resolver = DefaultResolver {
        base_dir: std::path::PathBuf::from("."),
    };
    compile_to_object_with_target(src, "main.cpp", &resolver, TargetKind::Win32)
        .expect("non-polymorphic dynamic_cast target should compile");
}

/// Frontend (complete-class context, [class.mem]/7): an inline member body that
/// references a static DATA member declared lexically LATER must resolve it
/// (OWL's `TClipboard::GetClipboard(){return TheClipboard;}` returns the
/// later-declared `TheClipboard`). Pre-registering the class's own static names
/// up front fixes the "no member named" error. Read-form (the resolution this
/// commit enables): GetVal reads the forward static `v` (=42) and returns it.
/// (Using the returned reference as an *lvalue* is a separate i386 gap.)
#[test]
fn i386_forward_referenced_static_member_resolves() {
    check_i386_cpp(
        "fwd_static",
        "struct C { static int get(){ return v; } static int v; }; \
         int C::v = 42; \
         int main(){ return C::get(); }",
        42,
    );
}

/// S2e (i386 float 4-byte cdecl arg): mdbcc keeps floats as f64 in xmm0, so a
/// `float` parameter's ABI-correct 4-byte single is materialized at the call
/// site via cvtsd2ss + a 4-byte movss push. Verifies the EXACT f32 BITS reach
/// the callee (reinterpreting `&f` as int* avoids the deferred f32->f64 widen-
/// on-use): g(5.0f) -> the f32 image must be 0x40A00000 -> 42. (railc FINISH,
/// LAYOUT pass a float scale factor; this was the last of the 21 TUs to compile.)
#[test]
fn i386_float_4byte_cdecl_argument_bits() {
    check_i386_cpp(
        "float_arg",
        "int g(float f){ int* p = (int*)&f; return (*p == 0x40A00000) ? 42 : 0; } \
         int main(){ return g(5.0f); }",
        42,
    );
}

/// S5 (i386 record→scalar conversion operator at a call arg): a record arg fed
/// to a scalar param via the record's conversion operator (the reverse of the
/// ctor UDC). OWL `strnewdup(const char*)` is called with a `TResId` arg ->
/// `TResId::operator char far*()`. Here f is OVERLOADED (so resolution runs):
/// f(R) picks f(const char*) via R::operator const char*() over f(int), and the
/// marshal applies the conversion. r="hello" -> strlen 5.
#[test]
fn i386_record_to_scalar_conv_op_arg() {
    check_i386_cpp(
        "conv_arg",
        "struct R { const char* p; R(const char* s):p(s){} operator const char*(){ return p; } }; \
         int f(const char* s){ int n=0; while(s[n]) n++; return n; } \
         int f(int x){ return -1; } \
         int main(){ R r(\"hello\"); return f(r); }",
        5,
    );
}

/// W6 RailC WinMain: returning a class-typed member from an `int` function must
/// use the member's conversion operator and then preserve that scalar across
/// scope-exit destructors. OWL's `TApplication::Status` is a `TStatus` record
/// with `operator int() const`; the pre-fix return path preserved
/// `&Manager.Status` and RailC exited with a stack address.
#[test]
fn i386_return_record_member_to_scalar_uses_conversion_operator() {
    check_i386_cpp(
        "return_conv_dtor",
        "int touch(int x){ return x + 1; } \
         struct TStatus { int code; operator int() const { return code; } }; \
         struct Manager { TStatus Status; Manager(){ Status.code = 42; } ~Manager(){ touch(100); } void Run(){} }; \
         int f(){ Manager m; m.Run(); return m.Status; } \
         int main(){ return f(); }",
        42,
    );
}

/// W6 railc/OWL runtime: resource-id wrapper classes such as `TResId` expose
/// `operator char*()` and rely on C++ boolean contexts to test the converted
/// pointer/id value. `TFrameWindow::Init` uses `if (!IconResId)`; treating the
/// record lvalue as its address skips the frame-style initialization and leaves
/// RailC's main window as `WS_CHILD`.
#[test]
fn i386_record_truthiness_uses_scalar_conversion_operator() {
    check_i386_cpp(
        "conv_truthy",
        "struct R { char* p; R(char* s = 0):p(s){} operator char*(){ return p; } }; \
         int main(){ R zero; R one(\"x\"); int n = 0; \
             if (!zero) n += 10; \
             if (one) n += 20; \
             if (one && !zero) n += 12; \
             return n; }",
        42,
    );
}

/// W6 railc/OWL runtime: `new T(args)` storage must start zeroed before the
/// constructor runs. RailC's `TMainWindow` receives `WM_SIZE` before its
/// constructor has assigned `ToolbarExist`/`StatbarExist`/`DisplayExist`; the
/// Borland-built app sees those flags as false. Dirties a raw allocation first
/// so a plain raw `HeapAlloc` reuse would make `S::seen` nonzero.
#[test]
fn i386_new_expression_zero_fills_storage_before_constructor() {
    let pe = mdbcc_i386_pe(
        b"struct S { int flag; int seen; S(){ seen = flag; } }; \
          int main(){ \
            for (int n = 0; n < 64; ++n) { \
              char* p = (char*)::operator new(sizeof(S)); \
              for (unsigned i = 0; i < sizeof(S); ++i) p[i] = 0x7f; \
              ::operator delete(p); \
            } \
            S* s = new S; \
            return s->seen == 0 ? 42 : (s->seen & 255); \
          }",
    );
    assert_eq!(
        run_pe(&pe, "new_zero_before_ctor"),
        Some(42),
        "[new_zero_before_ctor] mdbcc i386 exit"
    );
}

/// S6: record -> class-reference conversion operator at a call argument.
/// OWL BITMAPGA.CPP calls `TMemoryDC::SelectObject(const TBitmap&)` with a
/// `TCelArray`, which exposes `operator TBitmap&()`. Overload resolution must
/// accept the UDC and marshalling must pass the converted referent address.
#[test]
fn i386_record_to_ref_record_conv_op_arg() {
    check_i386_cpp(
        "conv_ref_arg",
        "struct B { int x; B():x(0){} }; \
         struct A { B b; A(){ b.x = 42; } operator B&(){ return b; } }; \
         int f(const B& b){ return b.x; } \
         int f(int){ return -1; } \
         int main(){ A a; return f(a); }",
        42,
    );
}

/// S6: a `const Target&` parameter may bind a temporary built by
/// `Target(const Source&)`. OWL CHGICON.CPP passes a Win32 `RECT` to
/// `TDC::TextRect(const TRect&, TColor)`, relying on `TRect(const RECT&)`.
#[test]
fn i386_record_arg_constructs_ref_param_temp() {
    check_i386_cpp(
        "record_ref_ctor_temp",
        "struct RECT { int left; int top; int right; int bottom; }; \
         struct TRect : RECT { TRect(const RECT& r){ left = r.left; top = r.top; right = r.right; bottom = r.bottom; } }; \
         int f(const TRect& r){ return r.left + r.bottom; } \
         int main(){ RECT r; r.left = 40; r.bottom = 2; return f(r); }",
        42,
    );
}

/// S6: parser lowering turns `a -= b` into `a = a - b`. For class receivers that
/// have `operator-=`, codegen must recover the source compound operator before
/// trying record assignment. OWL RANGEVAL.CPP does `TCharSet : TBitSet;
/// ValidChars -= '-'`, which must call inherited `TBitSet::operator-=(uint8)`.
#[test]
fn i386_compound_assign_uses_inherited_operator() {
    check_i386_cpp(
        "compound_assign_op",
        "typedef unsigned char uint8; \
         struct B { int bits; B():bits(0){} \
           B& operator-=(uint8 c){ bits = c; return *this; } \
           B& operator-=(const B&){ bits = 99; return *this; } }; \
         struct D : B {}; \
         int main(){ D d; d -= '-'; return d.bits; }",
        45,
    );
}

/// S5 (i386 cookie-less delete[]): `delete[] p` on a TRIVIAL element (no
/// ctor/dtor) is a raw HeapFree of the payload — the same as a scalar delete of
/// a trivial type. Previously blanket-rejected on i386; now the cookie-needing
/// (class-element) path stays deferred but the trivial path falls through to the
/// i386 scalar HeapFree. OWL WINDOW/DIALOG/CONTROL `delete[]` their char* Title/
/// Menu strings — exactly this. Verifies the block frees without crashing: 42.
#[test]
fn i386_cookieless_array_delete() {
    check_i386_cpp(
        "del_arr",
        "int main(){ char* p = (char*)::operator new(8); p[0]=42; int r=(int)p[0]; \
           delete[] p; return r; }",
        42,
    );
}

/// S5 (i386 global operator new/delete): `::operator new(size)` /
/// `::operator delete(p)` are provided intrinsically as __stdcall
/// HeapAlloc/HeapFree(GetProcessHeap(),0,arg) — the same allocator the `new`
/// expression uses. railc's RTL string closure (Borland `string`) and OWL
/// containers call these. Verifies the returned block is writable and delete
/// does not crash: p[0]=40, p[1]=2 -> 42.
#[test]
fn i386_global_operator_new_delete() {
    check_i386_cpp(
        "op_new",
        "int main(){ \
           char* p = (char*)::operator new(16); \
           p[0] = 40; p[1] = 2; \
           int r = (int)p[0] + (int)p[1]; \
           ::operator delete(p); \
           return r; }",
        42,
    );
}

#[test]
fn i386_new_scalar_direct_initializer() {
    check_i386_cpp(
        "new_scalar_init",
        "int main(){ int* p = new int(42); int r = *p; delete p; return r; }",
        42,
    );
}

/// S2e (i386 by-value record arg to a VIRTUAL call): emit_virtual_call_cdecl
/// rejected a by-value struct arg; now it pushes the struct bytes on the cdecl
/// stack (mirrors marshal_args_cdecl) and the caller-cleanup sums push_bytes.
/// railc's DEPARTUR/ARRIVALS pass an OWL geometry record to a virtual handler.
/// Dynamic dispatch p->f(s) with s={3,7} by value: D::f reads 3*10+7 = 37.
#[test]
fn i386_by_value_record_arg_to_virtual_call() {
    check_i386_cpp(
        "byval_vcall",
        "struct S { int a; int b; }; \
         struct B { virtual int f(S s){ return 0; } }; \
         struct D : B { int f(S s){ return s.a * 10 + s.b; } }; \
         int main(){ S s; s.a = 3; s.b = 7; B* p = new D(); return p->f(s); }",
        37,
    );
}

/// S2e (qualified in-class METHOD def): Borland allows defining a member with
/// explicit qualification inside the class body — `inline void
/// TMainWindow::CM_FileExit() {...}` (railc RAILC.H:115, an OWL response-table
/// command handler referenced as `&TMyClass::CM_FileExit`). The member loop now
/// strips a leading `Tag::` so it registers under `Tag::member`. c.set(5) -> 15.
#[test]
fn i386_qualified_in_class_method_def() {
    check_i386_cpp(
        "qual_method",
        "struct C { int v; inline void C::set(int x) { v = x * 3; } int get() { return v; } }; \
         int main(){ C c; c.set(5); return c.get(); }",
        15,
    );
}

/// S2e (qualified in-class ctor decl): Borland accepts `Tag::Tag(params);`
/// written INSIDE the class body (railc LAYOUT.H:76 declares
/// `TLayout::TLayout(TWindow*, int, int, int, int);` this way). The ctor
/// detector matched only the unqualified `Tag(`; extend it to the qualified
/// form so the ctor registers (here defined out-of-line). T t(5): T(5) -> v=10.
#[test]
fn i386_qualified_in_class_ctor_declaration() {
    check_i386_cpp(
        "qual_ctor",
        "struct T { int v; T::T(int x); }; \
         T::T(int x){ v = x * 2; } \
         int main(){ T t(5); return t.v; }",
        10,
    );
}

/// S2e (i386 by-value-record UDC arg): a BY-VALUE record parameter fed a
/// non-record arg via a user-defined conversion. OWL's
/// `TDialog(TWindow*, TResId resId, ...)` takes TResId by value; a `char*`/`int`
/// arg converts via TResId's ctor. mdbcc's UDC scorer gated to by-REF params;
/// this adds the by-value path (resolution Win32-gated + i386 cdecl marshal:
/// construct the temp, push by value). Mirrors TDialog (a 2-ctor class -> the
/// overload path). D(&w, 7): 7 -> R(7) by value, callee reads r.v=21.
#[test]
fn i386_by_value_record_udc_argument() {
    check_i386_cpp(
        "byval_udc",
        "struct R { int v; R(int x){ v = x*3; } }; \
         struct W {}; \
         struct D { int got; D(W* p, R r){ got = r.v; } D(const D& o){ got = o.got; } }; \
         int main(){ W w; D d(&w, 7); return d.got; }",
        21,
    );
}

/// S2e (per-class member typedef): a member typedef aliasing the class
/// (`typedef cls TMyClass;`, OWL's DECLARE_RESPONSE_TABLE) is re-declared in
/// many classes; mdbcc's flat typedef map is last-write-wins, so a class-scoped
/// `TMyClass::member` must resolve via the ENCLOSING class, not the global
/// alias. DISCRIMINATING: A::get and B::get each read `TMyClass::v` — must see
/// THEIR OWN v (10 vs 20). A wrong (global last-wins) resolution would read the
/// same v twice. 10 + 20 = 30 proves per-class resolution.
#[test]
fn i386_per_class_member_typedef_resolves_to_enclosing_class() {
    check_i386_cpp(
        "member_typedef",
        "struct A { typedef A TMyClass; static int v; static int get(); }; \
         struct B { typedef B TMyClass; static int v; static int get(); }; \
         int A::v = 10; int B::v = 20; \
         int A::get() { return TMyClass::v; } \
         int B::get() { return TMyClass::v; } \
         int main(){ return A::get() + B::get(); }",
        30,
    );
}

/// S2e (anon-union scalar init): aggregate-initializing a struct whose first
/// member is an ANONYMOUS UNION with a scalar targets the union's first member
/// (offset 0). The static-init lowering emits `g.$anon.0 = 5`; with a tagless
/// (anonymous) record lhs and a scalar rhs, descend to the first member rather
/// than struct-copying the scalar (which gen_addr's a prvalue -> "not an
/// lvalue"). This is the OWL response-table entry shape (`__entries[i].$anon.0 =
/// msgId`). nonconst() forces the dynamic-init path. g.id=5 + g.extra=9 -> 14.
#[test]
fn i386_anon_union_scalar_aggregate_init() {
    check_i386_cpp(
        "anon_union",
        "struct E { union { int id; void* p; }; int extra; }; \
         int nonconst(){ return 9; } \
         E g = { 5, nonconst() }; \
         int main(){ return g.id + g.extra; }",
        14,
    );
}

/// #8 (const T& binds to a cast rvalue): a `const T&` parameter binds to a
/// prvalue cast by materializing a temporary. OWL calls `ToBool(...)`
/// (`template<class T> bool ToBool(const T&)`) pervasively on cast rvalues —
/// `TResId::IsString(){return ToBool(HIWORD(Id));}` = `ToBool((WORD)(int))`.
/// gen_ref_arg previously delegated a Cast to gen_addr, which rejects the
/// prvalue. Non-template int-return form (bcc32 4.52 oracle compatible) of the
/// same binding; verifies the materialized temp holds the right value on BOTH
/// branches: hiword(0x00050000)=5 (nonzero, +7), hiword(3)=0 (zero, +30) -> 37.
#[test]
fn i386_const_ref_binds_to_cast_rvalue() {
    check_i386_cpp(
        "cref_cast",
        "int tb(const unsigned short& t){ return t != 0; } \
         int main(){ unsigned long a=0x00050000UL, b=3UL; int r=0; \
           if (tb((unsigned short)((a>>16)&0xFFFF))) r += 7; \
           if (!tb((unsigned short)((b>>16)&0xFFFF))) r += 30; \
           return r; }",
        37,
    );
}

/// #28 (deduce a function-template argument from a COMPARISON result): OWL's
/// geometry operators are `inline TPoint::operator!=(...) { return ToBool(x !=
/// o.x); }` — they call the function template `ToBool<T>(const T&)` with a
/// relational expression. The template monomorphizer's `type_of_expr` typed
/// arithmetic binaries but routed relational/logical ones to `None`, so `T` was
/// undeducible, `ToBool` was never instantiated, and the calling inline was
/// DEFERRED + DROPPED — leaving `TPoint::operator!=` / `TSize::operator!=` /
/// `TRect::Contains` unresolved across the whole OWL link. Now a comparison
/// types as `int`, `ToBool<int>` instantiates, and the operator is emitted.
/// RUN-verified: 5 != 7 ⇒ ToBool(true) ⇒ 42 (would fail to LINK before the fix).
#[test]
fn i386_template_deduces_from_comparison_arg() {
    check_i386_cpp(
        "tmpl_cmp_deduce",
        "template<class T> int ToBool(const T& t) { return t ? 1 : 0; } \
         struct P { int x; int ne(const P& o) const; }; \
         inline int P::ne(const P& o) const { return ToBool(x != o.x); } \
         int main(void){ P a; a.x = 5; P b; b.x = 7; int r = 0; \
           if (a.ne(b)) r += 42; return r; }",
        42,
    );
}

/// W2 RTL shim (`wrk_rtlshim/rtlshim.c`): mdbcc-built C reimplementations of the
/// Borland RTL primitives that ship only as 32-bit assembly (memmove/strchr/
/// strncmp). This locks the ALGORITHM mdbcc must codegen correctly — exercised
/// here under DIFFERENT names (the real shim keeps the C-linkage CRT names, which
/// would clash with bcc32's own RTL in this differential harness). Mirrors the
/// shim bodies exactly: forward-overlap memmove (dest>src), strchr index, both
/// strncmp branches. Expected 2 + 2 + 4 + 8 = 16, diff-verified against bcc32.
#[test]
fn i386_rtl_shim_primitives_logic() {
    check_i386_cpp(
        "rtlshim_logic",
        "void* sh_memmove(void* dest, const void* src, unsigned int n){ \
           char* d=(char*)dest; const char* s=(const char*)src; \
           if(d==s||n==0) return dest; \
           if(d<s){ while(n--) *d++=*s++; } \
           else { d+=n; s+=n; while(n--) *--d=*--s; } return dest; } \
         char* sh_strchr(const char* s, int c){ char ch=(char)c; \
           while(*s){ if(*s==ch) return (char*)s; s++; } \
           return (ch==0)?(char*)s:(char*)0; } \
         int sh_strncmp(const char* a, const char* b, unsigned int n){ \
           while(n--){ unsigned char ca=(unsigned char)*a++, cb=(unsigned char)*b++; \
             if(ca!=cb) return (int)ca-(int)cb; if(ca==0) return 0; } return 0; } \
         int main(void){ char buf[16]; int i; for(i=0;i<16;i++) buf[i]=0; \
           sh_memmove(buf, \"hello\", 6); \
           char* p = sh_strchr(buf, 'l'); \
           int d = sh_strncmp(buf, \"help\", 3); \
           int e = sh_strncmp(buf, \"help\", 4); \
           sh_memmove(buf+1, buf, 4); \
           int ov = (buf[1]=='h'&&buf[2]=='e'&&buf[3]=='l'&&buf[4]=='l')?8:0; \
           return (int)(p-buf) + (d==0?2:0) + (e<0?4:0) + ov; }",
        16,
    );
}

/// W2 RTL I/O shim (`wrk_rtlshim/rtlio.c`): locks the oflag→(access,disposition)
/// mapping codegen — the bit-logic that translates Borland `<fcntl.h>` open
/// flags into the Win32 `CreateFileA` access mask + creation disposition. (The
/// file round-trip itself is RUN-verified standalone — exit 15 — but exercises
/// real Win32 file I/O, awkward in this differential harness; here we lock the
/// pure decision logic against bcc32.) O_RDONLY⇒(R,OPEN_EXISTING)=0x103;
/// O_RDWR|O_CREAT|O_TRUNC⇒(RW,CREATE_ALWAYS)=0x302; O_WRONLY|O_CREAT⇒
/// (W,OPEN_ALWAYS)=0x204 ⇒ 1+2+4 = 7.
#[test]
fn i386_rtl_io_shim_flag_mapping() {
    check_i386_cpp(
        "rtlio_flagmap",
        "int iomap(int oflag){ int acc=oflag&3; int access; \
           if(acc==0) access=1; else if(acc==1) access=2; else access=3; \
           int disp; \
           if(oflag&0x0100){ if(oflag&0x0400) disp=1; else if(oflag&0x0200) disp=2; else disp=4; } \
           else if(oflag&0x0200) disp=5; else disp=3; \
           return (access<<8)|disp; } \
         int main(void){ return (iomap(0)==0x103?1:0) \
           + (iomap(2|0x100|0x200)==0x302?2:0) \
           + (iomap(1|0x100)==0x204?4:0); }",
        7,
    );
}

/// B-20: `_control87` must affect the real x87 control word, not just a
/// software shadow copy. The private `__mdbcc_fnstcw` probe is mdbcc-only, so
/// this intentionally skips the Borland differential harness.
#[test]
fn i386_control87_updates_x87_control_word() {
    check_i386_mdbcc_only(
        "control87_x87_cw",
        "int __isatty(int handle) { return 0; }\n\
         #include \"wrk_rtlshim/rtlshim.c\"\n\
         void _cvt_init(void) {} \
         void (*_realcvtptr)(void*, int, char*, char, char, int) = 0; \
         void* (*_nextrealptr)(void*, int) = 0; \
         unsigned __mdbcc_fnstcw(void); \
         int main(void){ \
           unsigned old = __mdbcc_fnstcw(); \
           unsigned want = (old & ~0x0C00u) | 0x0400u; \
           _control87(want, 0x0C00u); \
           unsigned now = __mdbcc_fnstcw(); \
           _control87(old, 0xFFFFu); \
           return ((now & 0x0C00u) == 0x0400u) ? 42 : 1; \
         }",
        42,
    );
}

/// W6 RailC startup: Borland file streams open text files in text mode, so the
/// low-level `read` shim must remove CR bytes from CRLF lines. RailC's
/// `strcmpi(szInput, "[SECTIONS]")` probe fails if `getline` sees
/// "[SECTIONS]\r". Binary mode must still return the raw bytes.
#[test]
fn i386_rtl_io_shim_text_read_strips_crlf() {
    let run_dir = TempRunDir::new("rtlio_text_read");
    std::fs::write(
        run_dir.path.join("rtlio_crlf.txt"),
        b"[SELECTOR]\r\n[SECTIONS]\r\n",
    )
    .expect("write CRLF fixture");

    let src = r#"
        #include "wrk_rtlshim/rtlio.c"

        int has_cr(char *p, int n)
        {
            int i;
            for (i = 0; i < n; i = i + 1)
                if (p[i] == '\r')
                    return 1;
            return 0;
        }

        int eq(char *a, char *b, int n)
        {
            int i;
            for (i = 0; i < n; i = i + 1)
                if (a[i] != b[i])
                    return 0;
            return 1;
        }

        int main(void)
        {
            char text[64];
            char raw[64];
            char expect[] = "[SELECTOR]\n[SECTIONS]\n";
            int ft = open("rtlio_crlf.txt", O_RDONLY | O_TEXT);
            int nt;
            int fb;
            int nb;
            if (ft < 0)
                return 1;
            nt = read(ft, text, 64);
            close(ft);
            fb = open("rtlio_crlf.txt", O_RDONLY | O_BINARY);
            if (fb < 0)
                return 2;
            nb = read(fb, raw, 64);
            close(fb);
            if (nt != 22)
                return 3;
            if (!eq(text, expect, nt))
                return 4;
            if (has_cr(text, nt))
                return 5;
            if (nb != 24)
                return 6;
            if (!has_cr(raw, nb))
                return 7;
            return 42;
        }
    "#;

    let pe = mdbcc_i386_pe(src.as_bytes());
    let Some(exit) = run_pe_in_dir(&pe, "rtlio_text_read", &run_dir.path) else {
        return;
    };
    assert_eq!(exit, 42, "[rtlio_text_read] text mode must strip CRLF");
}

/// G42 (W2 RTL variadic ABI): Borland's stdarg.h is ADDRESS ARITHMETIC —
/// `va_start(ap, parmN)` is `ap = (char*)&parmN + sizeof(parmN)` — so the RTL
/// printf family (VPRINTER.C, compiled from unmodified Borland source) only
/// works if `&param` yields the INCOMING cdecl slot ([ebp+8+cum]) with the
/// varargs contiguously above it. mdbcc used to copy i386 params into frame
/// locals, so the walk read neighbouring locals (sprintf("%d %s") printed
/// "0 "). Params are now addressed in place, exactly like bcc32. This locks
/// the Borland-macro shape end-to-end: callee walks &n, caller pushes
/// right-to-left 4-byte cells. 2 + 30 + 10 = 42 (diff vs bcc32).
#[test]
fn i386_borland_stdarg_address_walk() {
    check_i386_cpp(
        "stdarg_walk",
        "int sum(int n, ...) \
         { \
           char *ap = (char *)(&n) + sizeof(n); \
           int a = *(int *)ap; \
           int b = *(int *)(ap + 4); \
           return n + a + b; \
         } \
         int main(void){ return sum(2, 30, 10); }",
        42,
    );
}

/// G42b: the same address walk through a DOUBLE vararg (the %f path —
/// __nextreal advances by 8 over a cdecl-pushed 8-byte double image). The
/// caller must push the full 8-byte double; the callee reads it via the
/// walked pointer. 30 + 12 = 42 (diff vs bcc32).
#[test]
fn i386_borland_stdarg_double_vararg() {
    check_i386_cpp(
        "stdarg_double",
        "int take(int n, ...) \
         { \
           char *ap = (char *)(&n) + sizeof(n); \
           double d = *(double *)ap; \
           int tail = *(int *)(ap + 8); \
           return (int)d + tail; \
         } \
         int main(void){ return take(1, 30.5, 12); }",
        42,
    );
}

/// W6 RailC finish-dialog parity: `sprintf("%.2f ... %d", float, int)` relies
/// on C default argument promotions. A `float` passed through `...` must occupy
/// an 8-byte `double` slot, or the following `%d` is read from the wrong stack
/// cell.
#[test]
fn i386_variadic_float_promotes_to_double_slot() {
    check_i386_cpp(
        "stdarg_float_promotes",
        "int check(int n, ...) \
         { \
           char *ap = (char *)(&n) + sizeof(n); \
           double d = *(double *)ap; \
           int x = *(int *)(ap + 8); \
           return (d > 2.49 && d < 2.51 && x == 17) ? 42 : 7; \
         } \
         int main(void){ float f = 2.5; return check(0, f, 17); }",
        42,
    );
}

/// B-05: mdbcc's intrinsic `<stdarg.h>` path must also work on i386. Unlike
/// the Borland macro tests above, this exercises parser/codegen `va_start` and
/// `va_arg` directly.
#[test]
fn i386_intrinsic_va_arg_int_walks_cdecl_stack() {
    check_i386_cpp(
        "intrinsic_va_arg_int",
        "#include <stdarg.h>\n\
         int sum(int n, ...) \n\
         { \n\
           va_list ap; \n\
           int a; \n\
           int b; \n\
           va_start(ap, n); \n\
           a = va_arg(ap, int); \n\
           b = va_arg(ap, int); \n\
           va_end(ap); \n\
           return n + a + b; \n\
         } \n\
         int main(void){ return sum(2, 30, 10); }",
        42,
    );
}

/// B-05: the i386 intrinsic `va_arg(ap, double)` must read an 8-byte cdecl
/// double image and advance the list by 8 before the following int.
#[test]
fn i386_intrinsic_va_arg_double_walks_cdecl_stack() {
    check_i386_cpp(
        "intrinsic_va_arg_double",
        "#include <stdarg.h>\n\
         int take(int n, ...) \n\
         { \n\
           va_list ap; \n\
           double d; \n\
           int tail; \n\
           va_start(ap, n); \n\
           d = va_arg(ap, double); \n\
           tail = va_arg(ap, int); \n\
           va_end(ap); \n\
           return (int)d + tail; \n\
         } \n\
         int main(void){ return take(1, 30.5, 12); }",
        42,
    );
}

/// G44 (RTL LOCALE/CCONV.C): a file-scope STRUCT whose `char *` members are
/// initialized with STRING LITERALS — `struct lconv _localeconvention =
/// { ".", "", ... }`. `global_image` used to byte-copy the literal INTO the
/// pointer slot (decimal_point held 0x2E — the '.' character — instead of a
/// pointer to "."), so _realcvt's `*_localeconvention.decimal_point` deref
/// crashed every %f/%e/%g printf. A pointer-typed element with a Str
/// initializer now refuses to fold; the enclosing aggregate routes through
/// the #32 dynamic-init fallback (zeroed storage + startup assignments —
/// the same proven path OWL response tables use). 'y' + 'z' - 201 = 42
/// (diff vs bcc32, which emits the relocated constant image).
#[test]
fn i386_global_struct_string_pointer_members() {
    check_i386_cpp(
        "gstruct_strptr",
        "struct S { char *a; char *b; }; \
         struct S s = { \"xy\", \"z\" }; \
         int main(void){ return s.a[1] + s.b[0] - 201; }",
        42,
    );
}

/// G44b: the array shape — `char *t[2] = { \"ab\", \"cd\" };` (string-literal
/// elements of a pointer ARRAY). Same fold-refusal + dynamic-init route as
/// the struct case. 'c' + 'b' - 155 = 42 (diff vs bcc32).
#[test]
fn i386_global_array_of_string_pointers() {
    check_i386_cpp(
        "garr_strptr",
        "char *t[2] = { \"ab\", \"cd\" }; \
         int main(void){ return t[1][0] + t[0][1] - 155; }",
        42,
    );
}

/// G44c (BIDS THREAD.CPP): the STATIC-LOCAL shape. Once G44 makes
/// `global_image` refuse to fold a string-pointer aggregate, a static local
/// `static char *names[2] = {"ab","cd"}` flips to the guarded runtime-init
/// path — whose single `name = <init-list>` Assign was unloweable ("aggregate
/// initializer has no expression type"). The guard body now decomposes the
/// init-list with the same `flatten_aggregate_init` the #32 file-scope
/// fallback uses. Re-entry proves once-only init: 'c' + 'a' - 154 = 42
/// (diff vs bcc32).
#[test]
fn i386_static_local_array_of_string_pointers() {
    check_i386_cpp(
        "slocal_strptr",
        "int pick(int i) { \
           static char *names[2] = { \"ab\", \"cd\" }; \
           return names[i][0]; \
         } \
         int main(void){ return pick(1) + pick(0) - 154; }",
        42,
    );
}

/// G43 (BIDS OBJSTRM.CPP): an unqualified STATIC data member of a SHARED
/// virtual base, referenced inside a derived-class member. `pstream` holds
/// `static TStreamableTypes *types`; `ipstream : virtual public pstream`
/// reads bare `types` in `readPrefix`. Once a diamond joins the hierarchy
/// (`ifpstream : fpbase, ipstream`, both virtually deriving pstream), the
/// Stage-3 model moves pstream into `vbases` (base=None) — and
/// `static_member_global`, which walked only the `rec.base` chain, no longer
/// found the static ("no member named 'types'"). The walk now covers
/// base + extra_bases + vbases (BFS, most-derived first). Statics have no
/// layout component, so resolution is pure naming: 40 + 2 = 42 (diff vs
/// bcc32, which compiles OBJSTRM.CPP's shape unchanged).
#[test]
fn i386_static_member_of_shared_virtual_base_resolves() {
    check_i386_cpp(
        "static_vbase_member",
        "struct T { int Lookup(int m); }; \
         int T::Lookup(int m) { return m + 2; } \
         struct B { static T *types; int state; }; \
         T *B::types = 0; \
         struct D : virtual B { int get(int mid); }; \
         int D::get(int mid) { return types->Lookup(mid); } \
         struct F : virtual B { int buf; }; \
         struct I : F, D { int z; }; \
         int main(){ T t; B::types = &t; D d; return d.get(40); }",
        42,
    );
}

/// G45 (W6, BIDS OBJSTRM.CPP): the ctor EH-cleanup landing pad (Tick-69 /
/// J-11b) is raw x64-only encodings; with exceptions ACTIVE in the TU (a
/// `try` registers the EH save global) every Win32 ctor that owns
/// dtor-bearing members attempted the pad, hit the Gpr64 Mov encoder error,
/// and — when inline/template — was silently S4.2h-DROPPED (OBJSTRM's
/// `TISVectorImp$S917::TISVectorImp$S917` chain → undefined externals in the
/// all-mdbcc OWL link). The pad is now gated off on Win32 (documented v1
/// gap: a base/member dtor leaks if a LATER member's ctor throws); the ctor
/// body itself emits correctly. 30 + 12 = 42 (diff vs bcc32).
#[test]
fn i386_inline_ctor_emits_with_eh_active_in_tu() {
    check_i386_cpp(
        "ctor_eh_active",
        "struct M { int v; M(); ~M(); }; \
         M::M() { v = 30; } \
         M::~M() {} \
         struct H { M m; int extra; H() { extra = 12; } }; \
         int run() { \
           try { H h; return h.m.v + h.extra; } catch (int) { return -1; } \
         } \
         int main(void){ return run(); }",
        42,
    );
}

/// G46 (W6, OWL DIALOG.CPP `StdDlgProc`): an OVERLOADED function is RENAMED
/// to its mangled symbol at emission — but the i386 SEH3 scope-table pushes
/// (fs:[0] frame registration) had already recorded `RipRef::Func(<source
/// name>)` SELF-references. The rename now retargets those riprefs, so the
/// scope table points at the function's own (mangled) symbol instead of a
/// dangling bare name (`StdDlgProc` undefined in the all-mdbcc link). The
/// `try` in the SECOND overload forces the scope-table push. 40 + 2 = 42
/// (diff vs bcc32).
#[test]
fn i386_overloaded_function_with_seh_scope_table() {
    check_i386_cpp(
        "overload_seh_scope",
        "int guard(double d) { return (int)d; } \
         int guard(int x) { \
           try { \
             if (x > 50) throw 1; \
             return x + 2; \
           } catch (int) { return -1; } \
         } \
         int main(void){ return guard(40); }",
        42,
    );
}

/// W6 Bug C layer 2 (OWL FRAMEWIN.CPP:494 / SWINDOW.CPP:47): a recognised
/// Win32 IMPORT taken as a function-pointer VALUE (`wndClass.lpfnWndProc =
/// ::DefWindowProc;`). The extern-proto path registers a Borland-MANGLED
/// reference for any API with record-ptr params (`@DefWindowProcA$q...`,
/// the parked extern-"C" force_cpp gap), and the designator path emitted a
/// `lea` on that undefined symbol. A win32-import designator now LOADS the
/// IAT slot instead (`mov eax,[__imp_Name]`) — the loader-resolved export
/// address, exactly what a WNDPROC value must hold. The record-ptr param
/// (`HWND__*`) reproduces the force_cpp mangling; pre-fix this fails to
/// LINK. GetWindowTextLengthA is in WIN32_IMPORTS. 42 on a non-null load.
#[test]
fn i386_win32_import_as_function_pointer_value() {
    check_i386_cpp(
        "import_fnptr_value",
        "extern \"C\" { \
           struct HWND__ { int unused; }; \
           int __stdcall GetWindowTextLengthA(HWND__ *w); \
         } \
         typedef int (__stdcall *FN)(HWND__ *); \
         int main(void){ \
           FN f = GetWindowTextLengthA; \
           return f ? 42 : 7; }",
        42,
    );
}

/// W6 Bug D (OWL EDITVIEW.CPP `TEditView::VnCommit`): a template argument
/// deduced from a METHOD-call result — `ToBool(outStream->good())`, where
/// `good()` is declared on `ios`, a shared VIRTUAL base of `ostream`.
/// `type_of_expr` had no `Expr::MethodCall` arm, so the argument was
/// un-typeable, `T` undeducible, and the (out-of-line) caller deferred +
/// dropped (an unresolved external in the all-mdbcc link). The new arm
/// types the receiver and walks base + extra_bases + VBASES for the
/// method's declared return type. good()=40 → ToBool→2 → 2+40=42 (diff vs
/// bcc32).
#[test]
fn i386_template_deduces_from_method_call_via_vbase() {
    check_i386_cpp(
        "deduce_methodcall",
        "struct ios { int st; int good() { return st == 0 ? 40 : 0; } }; \
         struct ostream : virtual ios { int pad; }; \
         template <class T> inline int ToBool(const T& t) { return t ? 2 : 0; } \
         int check(ostream* os) { return ToBool(os->good()); } \
         int main(void){ \
           ostream o; o.st = 0; o.pad = 0; \
           return check(&o) + 40; }",
        42,
    );
}

/// G47 (W6, OWL DOCVIEW.H `TInStream : TStream, istream`): a class whose ONLY
/// polymorphism arrives through an EXTRA base over a virtual-inheritance
/// hierarchy. Two coupled gaps (unmasked when G45 revived the join ctors,
/// but pre-existing): (1) `touch_record` walked only `rec.base` — `istream`'s
/// virtual methods were pruned while the join ctor still installed the
/// istream-subobject SECONDARY vtable referencing them; (2) the vtable
/// emission loop nested secondary images under `rec.is_polymorphic()` — the
/// join's PRIMARY chain (TStream) is non-poly, so its own vtable is empty
/// and the secondary image was never emitted (S4.2ae object-writer panic in
/// FILEDOC.CPP/STGDOC.CPP). Virtual dispatch through the secondary vtable
/// proves the emitted image: get()=1 + doc=5 + 36 = 42 (diff vs bcc32).
#[test]
fn i386_mi_join_with_only_extra_base_polymorphism() {
    check_i386_cpp(
        "mi_join_sec_vtable",
        "struct ios { int state; virtual ~ios() {} }; \
         struct istream : virtual ios { virtual int get() { return 1; } }; \
         struct TStream { int doc; TStream(int d) : doc(d) {} }; \
         struct TInStream : public TStream, public istream { \
           TInStream(int d) : TStream(d), istream() {} \
         }; \
         struct TFileInStream : public TInStream { \
           TFileInStream(int d) : TInStream(d) {} \
         }; \
         int make() { \
           TFileInStream *p = new TFileInStream(5); \
           int r = p->get() + p->doc; \
           delete p; \
           return r; \
         } \
         int main(void){ return make() + 36; }",
        42,
    );
}

/// G48 (W6, RTL HEAP.C `#pragma startup _init_heap 2`): Borland's
/// INIT-record mechanism — `#pragma startup <fn> [prio]` runs `<fn>` before
/// main/WinMain, ascending priority (RTL reserves 0–63; C++ static ctors run
/// after). The recompiled RTL is built on it (heap 2, argv 3, handles 4,
/// streams 5, cvt 10, iostream 16); ignoring the pragma left `_init_heap`
/// unrun and railc.exe's first `malloc` (string global ctor) dereferencing
/// uninitialised heap variables — the WOW64 startup segfault. mdbcc now
/// splices the pragma through the pp, records it on the TU, emits a
/// `.mdbcc_ctor.$startup$NNN$<fn>` thunk (same-TU, so a `static` init fn
/// resolves), and mdlink calls startup thunks FIRST, ascending NNN, before
/// every plain ctor thunk. first(2): lg=3; second(5): lg=3*2+1=7; the C++
/// static ctor AFTER both: lg=70; 70-28 = 42 (diff vs bcc32, which owns the
/// same semantics).
#[test]
fn i386_pragma_startup_priority_order_before_ctors() {
    check_i386_cpp(
        "pragma_startup",
        "static int lg; \
         static void second(void) { lg = lg * 2 + 1; } \
         static void first(void) { lg = 3; }\n\
         #pragma startup second 5\n\
         #pragma startup first 2\n\
         struct G { int z; G(int k); }; \
         G::G(int k) { lg = lg * 10 + k; z = k; } \
         static G g(0); \
         int main(void) { return lg - 28; }",
        42,
    );
}

/// G50 (W6, RTL IOSTSTD.CPP `istream_withassign cin;`): an INIT-LESS record
/// global whose class has a 0-arg-callable ctor must DEFAULT-CONSTRUCT
/// (C++ default-initialization). mdbcc queued construction only for the
/// `G g(args);` form, so `cin`/`cout` never ran their ctors — the vbptr to
/// the `ios` VIRTUAL base stayed NULL, and `Iostream_init`'s `cin = &…`
/// faulted inside `ios::init` (railc startup crash, take 3). The inline-ctor
/// shape is the hard case: the parser lifts in-class methods to the END of
/// `tu.items`, so the gate pre-scans ctor arities instead of consulting
/// `sigs.funcs` mid-loop, and `compute_emitted` keeps the class live so the
/// inline ctor isn't pruned out from under the queued call. 4*10 + 2 = 42
/// (diff vs bcc32).
#[test]
fn i386_default_ctor_global_constructs() {
    check_i386_cpp(
        "defctor_global",
        "static int lg = 4; \
         struct G { G() { lg = lg * 10; } }; \
         static G g; \
         int main(void) { return lg + 2; }",
        42,
    );
}

/// B-11: an INIT-LESS file-scope array of class objects must default-construct
/// every element before `main`, in increasing subscript order. The scalar
/// `static G g;` path already worked; arrays used to stay all-zero because the
/// global ctor queue only recognized `Type::Record`, not `Type::Array<Record>`.
#[test]
fn i386_default_ctor_global_array_constructs_all_elements() {
    check_i386_cpp(
        "defctor_global_array",
        "static int lg = 0; \
         struct G { int v; G() { lg = lg + 1; v = lg; } }; \
         static G gs[3]; \
         int main(void) { return lg * 10 + gs[0].v + gs[1].v + gs[2].v + 6; }",
        42,
    );
}

/// G51 (W6, RTL IOSTSTD.CPP `new (&cin) istream_withassign`): Stage-3
/// shared-virtual-base setup existed only at LOCAL declaration sites (the
/// parser's `vbase_init_stmts` injection) — HEAP `new` and PLACEMENT new
/// constructed the object with a NULL vbptr and an unconstructed vbase, so
/// the first access through the vbptr faulted (`Iostream_init`'s
/// `cin = __stdin_streambuf` inside `ios::init` — railc startup crash,
/// take 4). `construct_in_place` (shared by both forms) now mirrors the
/// parser: store `obj+vbase.offset` into every vbptr field, then default-
/// construct each vbase, both BEFORE the most-derived ctor. Reading the
/// vbase member through the vbptr proves both: 7*4 + (7+1) + 6 = 42 (diff
/// vs bcc32).
#[test]
fn i386_vbase_setup_for_heap_and_placement_new() {
    check_i386_cpp(
        "vbase_new",
        "inline void *operator new(unsigned int, void *p) { return p; } \
         struct ios { int state; ios() { state = 7; } virtual ~ios() {} }; \
         struct istream : virtual ios { int pad; istream() { pad = 1; } }; \
         struct iwa : istream { iwa() {} }; \
         static char buf[64]; \
         int heap_case() { \
           istream *p = new istream(); \
           return p->state; \
         } \
         int placement_case() { \
           iwa *q = new (buf) iwa; \
           return q->state + q->pad; \
         } \
         int main(void) { return heap_case() * 4 + placement_case() + 6; }",
        42,
    );
}

/// G59 (W6 OWL `TInputDialog : TWindow(...), TDialog(...)`): a constructor
/// initializer may name a SHARED virtual base. It is not a data member and not
/// an extra direct base; lower it to a vbase ctor call and adjust `this` through
/// the vbptr. `V()` may run first via the construction-site setup, but the
/// explicit `V(k)` initializer must leave the shared vbase with `v == 40`.
#[test]
fn i386_ctor_initializer_names_virtual_base() {
    check_i386_cpp(
        "vbase_ctor_init",
        "struct V { int v; V(){ v = 1; } V(int k){ v = k; } virtual ~V() {} }; \
         struct B : virtual V { B(int k) : V(k) {} }; \
         struct D : B { D(int k) : V(k), B(5) {} }; \
         int main(void){ B b(40); D d(40); return b.v + d.v - 38; }",
        42,
    );
}

/// G61 (OWL OLEFRAME.CPP): unsupported multi-vbase classes are already
/// rejected at construction sites (`Record::mi_dropped`), but their constructor
/// function bodies still need to compile. If an initializer names a base that
/// was dropped from the layout graph, do not lower it as `this->Base = ...`.
#[test]
fn i386_mi_dropped_ctor_initializer_known_base_is_not_member() {
    let src = b"struct A { int a; A(int){} virtual ~A(){} }; \
                struct B : virtual A { B() : A(1) {} }; \
                struct C : virtual A { C() : A(2) {} }; \
                struct D : virtual B, C { D(); }; \
                D::D() : B(), C(), A(3) {} \
                struct E : D { E(); }; \
                E::E() : D(), A(4) {}";
    let resolver = DefaultResolver {
        base_dir: std::path::PathBuf::from("."),
    };
    compile_to_object_with_target(src, "main.cpp", &resolver, TargetKind::Win32)
        .expect("constructor body with dropped base initializer should compile");
}

/// G52 (W6, RTL TZSET.C `char * const _tzname[2] = {&_DfltZone[0], …}`): an
/// aggregate global whose pointer elements are ADDRESS CONSTANTS must fold
/// into the STATIC image with data relocations — Borland bakes such tables
/// at compile time. mdbcc's #32 fallback ran them as a plain dynamic-init
/// ctor thunk, which executes AFTER the `#pragma startup` chain — so
/// `tzset` (priority 30) strcpy'd through a still-NULL `_tzname[0]` (railc
/// startup crash, take 5). The startup-priority read below pins exactly
/// that ordering: 'E'(69) read at priority 5, minus 27 = 42 (diff vs
/// bcc32, whose image is statically relocated the same way).
#[test]
fn i386_static_pointer_table_readable_from_startup() {
    check_i386_cpp(
        "g52_ptr_table",
        "static char zoneA[4] = \"EST\"; \
         static char zoneB[4] = \"EDT\"; \
         char * const tznames[2] = { &zoneA[0], &zoneB[0] }; \
         static int seen; \
         static void early(void) { seen = tznames[0][0] + tznames[1][1]; }\n\
         #pragma startup early 5\n\
         int main(void) { return seen - 95; }",
        42,
    );
}

/// G51b (W6, OWL `ostrstream TDiagBase::Out(…)`): the QUEUED-GLOBAL ctor
/// thunk is the THIRD construction site needing Stage-3 shared-vbase setup
/// (locals: parser-injected; heap/placement new: G51). The thunk ran the
/// ctor chain over a NULL vbptr (`ios::init` fault — railc startup crash,
/// take 8). The queue now prepends the same vbptr-store + vbase-ctor
/// statements. 7 + 35 = 42 (diff vs bcc32).
#[test]
fn i386_global_with_vbase_constructs_via_thunk() {
    check_i386_cpp(
        "g51b_global_vbase",
        "struct ios { int state; ios() { state = 7; } virtual ~ios() {} }; \
         struct ostrstream : virtual ios { int pad; ostrstream(int k) { pad = k; } }; \
         static ostrstream Out(35); \
         int main(void) { return Out.state + Out.pad; }",
        42,
    );
}

/// G53 (W6, OWL APPLICAT.CPP `TApplication::TApplication`): an OUT-OF-LINE
/// ctor/dtor never received the class-typed-member ctor/dtor splice — the
/// per-class `inject_member_ctor_dtor_calls` pass runs at class-definition
/// END, before the out-of-line body exists. TApplication's `string CmdLine`
/// member stayed unconstructed (NULL TStringRef) and the ctor body's
/// `CmdLine = InitCmdLine` faulted inside `string::assign` (railc startup
/// crash, take 9). The splice now also runs on the out-of-line definition
/// itself. 7 + 35 = 42 (diff vs bcc32).
#[test]
fn i386_out_of_line_ctor_constructs_unnamed_members() {
    check_i386_cpp(
        "g53_ool_member",
        "struct S { int v; S(); }; \
         S::S() { v = 7; } \
         struct B { int z; B(int q); }; \
         B::B(int q) : z(q) {} \
         struct T : B { int a; S s; T(int k); }; \
         T::T(int k) : B(k), a(k * 5) { } \
         int main(void) { T t(7); return t.s.v + t.a; }",
        42,
    );
}

/// G41 (`*_Sig` closure symbols): OWL SIGNATUR.H's response-table signature
/// checkers are pointer-to-member IDENTITY templates (`inline void(T::*
/// v_U_SIZE_Sig(void(T::*pmf)(uint,TSize&)))(uint,TSize&) { return pmf; }`).
/// mdbcc skips PMF templates (S4.2f, unrepresentable declarator), so the use
/// site `(WPMF)v_U_SIZE_Sig(&W::EvSize)` fell out as a bare undefined extern
/// — unlinkable by design (bcc32 ALWAYS inlines these; Borland's OWL libs
/// contain no `_Sig` symbols). The skip now recognises the identity shape and
/// the call folds to its argument. Dispatch proves the folded value is the
/// real PMF: acc = 12 + 30 = 42 (diff vs bcc32, which compiles the template).
#[test]
fn i386_pmf_identity_template_call_folds_to_arg() {
    check_i386_cpp(
        "pmf_identity_fold",
        "typedef unsigned int uint; \
         struct TSize { int cx; int cy; }; \
         template <class T> \
         inline void(T::*v_U_SIZE_Sig(void(T::*pmf)(uint, TSize&)))(uint, TSize&) \
         { return pmf; } \
         struct W { \
           int acc; \
           void EvSize(uint code, TSize& s) { acc = (int)code + s.cx; } \
         }; \
         typedef void (W::*WPMF)(uint, TSize&); \
         int main(void){ \
           WPMF p = (WPMF)v_U_SIZE_Sig(&W::EvSize); \
           W w; w.acc = 0; \
           TSize sz; sz.cx = 30; sz.cy = 0; \
           (w.*p)(12u, sz); \
           return w.acc; }",
        42,
    );
}

/// OWL CHGICON.CPP: response-table macros use a class-scoped typedef
/// (`TMyClass`) and may name an inherited handler (`CmCancel` from TDialog).
/// `&TMyClass::CmCancel` must become a member-function pointer to the base
/// implementation, typed as a pointer to member of the derived response class.
#[test]
fn i386_pmf_typedef_qualifier_resolves_inherited_method() {
    check_i386_cpp(
        "pmf_typedef_inherited",
        "template <class T> inline void(T::*v_Sig(void(T::*pmf)()))() \
             { return pmf; } \
         struct B { int* out; void CmCancel(){ *out = 42; } }; \
         struct D : B { \
             typedef D TMyClass; \
             typedef void (D::*TMyPMF)(); \
             int fire(){ TMyPMF p = (TMyPMF)v_Sig(&TMyClass::CmCancel); \
                 (this->*p)(); return *out; } \
         }; \
         int main(void){ D d; int out = 0; d.out = &out; return d.fire(); }",
        42,
    );
}

/// G40 (`TMutex::operator=` closure symbol): a ctor-initializer naming a
/// REFERENCE member must BIND it (store the referent's address into the
/// slot), not assign through it. The old fallback lowered `: mo(m)` to
/// `this->mo = m`, which auto-derefs the UNINITIALIZED slot. Live-binding
/// proof: mutate the referent AFTER construction; the member must see the
/// new value. 30 + 12 = 42.
#[test]
fn i386_reference_member_ctor_init_binds() {
    check_i386_cpp(
        "ref_member_bind",
        "struct M { int v; }; \
         struct Holder { \
           const M& mo; \
           int k; \
           Holder(const M& m, int kk) : mo(m), k(kk) {} \
           int sum() const { return mo.v + k; } \
         }; \
         int main(void){ M m; m.v = 1; Holder h(m, 12); \
           m.v = 30; return h.sum(); }",
        42,
    );
}

/// G40b — the exact CLASSLIB THREAD.H `TMutex::Lock` shape: the referent
/// class DECLARES a private, never-DEFINED `operator=` (the noncopyable
/// idiom). The old Assign fallback rewrote the ctor-init to a call to that
/// operator= ⇒ undefined `TMutex::operator=` across the whole OWL link
/// (and a call through an uninitialized reference had it linked). Binding
/// references no operator= at all. Would fail to LINK before the fix.
#[test]
fn i386_reference_member_bind_skips_user_op_assign() {
    check_i386_cpp(
        "ref_member_noncopyable",
        "struct M { \
           int v; \
           M() { v = 40; } \
         private: \
           const M& operator=(const M&); \
         }; \
         struct Lock { \
           const M& mo; \
           Lock(const M& m, unsigned long) : mo(m) {} \
           int val() const { return mo.v; } \
         }; \
         int main(void){ M m; Lock l(m, 5000UL); return l.val() + 2; }",
        42,
    );
}

/// W4 OWL (`TAppMutex::NotWIN32s` closure symbol): a MULTI-level qualified
/// static data-member definition (`int TApplication::TAppMutex::NotWIN32s =
/// …;`, APPLICAT.CPP:225) must be keyed by the RESOLVED record's flat tag —
/// references resolve through the record tag (`TAppMutex::NotWIN32s`), but
/// the `=`-initialized global declarator path kept the verbatim three-level
/// name, so the def and its ~91 referencing TUs never met at link. The
/// member-FUNCTION path already normalized; this locks the data path.
/// Would fail to LINK before the fix. flag(41) + 1 = 42.
#[test]
fn i386_nested_static_member_def_links_to_flat_refs() {
    check_i386_cpp(
        "nested_static_def",
        "struct Outer { \
           struct Inner { static int flag; int get(); }; \
         }; \
         int Outer::Inner::flag = 41; \
         int Outer::Inner::get() { return flag + 1; } \
         int main(void){ Outer::Inner i; return i.get(); }",
        42,
    );
}

/// W2 streams (`filebuf::seekoff` closure symbol): an UNNAMED qualified-enum
/// parameter (`virtual streampos seekoff(streamoff, ios::seek_dir, int);`,
/// iostream.h:283) must type identically to the NAMED out-of-line definition
/// (`ios::seek_dir dir`). `qualify_nested`'s declarator_follows gate only
/// accepted Ident/`*`/`&` after the `::` chain, so the unnamed proto kept
/// param type Record{ios} (chain unconsumed, `seek_dir` swallowed as a bogus
/// declarator name) while the def resolved the enum to Int — sig mismatch ⇒
/// name_counts 2 ⇒ def emitted MANGLED while every vtable slot refs the BARE
/// name ⇒ unresolved at link. Now `,`/`)`/`=` commit the chain too (the
/// out-of-line-member case `string::outofrange::outofrange()` stays excluded
/// — `(` is not in the follow set; commit still requires the final component
/// to resolve as a type). Virtual dispatch: 3 + 1*10 + 1*100 = 113.
#[test]
fn i386_unnamed_qualified_enum_param_vtable_slot() {
    check_i386_cpp(
        "unnamed_qenum_param",
        "struct ios2 { enum seek_dir { beg, cur, end }; }; \
         struct sb { \
           virtual long seekoff(long, ios2::seek_dir, int); \
           virtual ~sb(); \
         }; \
         long sb::seekoff(long off, ios2::seek_dir dir, int mode) \
           { return off + (long)dir * 10 + (long)mode * 100; } \
         sb::~sb() {} \
         int main(void){ sb s; sb* p = &s; \
           return (int)p->seekoff(3, ios2::cur, 1); }",
        113,
    );
}

/// W2 RTL (`min` closure symbol): a function-template call nested in a METHOD-
/// call argument list must still instantiate. The monomorphiser's
/// `rewrite_expr` recursed into `Expr::Call` args but had no `Expr::MethodCall`
/// arm, so RTL string TUs (`p->splice(pos, min(n1, length()-pos), ...)` in
/// REPLACE/FIND1/OPRASGN1/STREMOVE.CPP) left a bare undefined `min` extern
/// (top-level `Decl`-init calls like STDTEMPL.H `min` worked — the gap was
/// only method-arg position). Would fail to LINK before the fix. 5 + 30 = 35.
#[test]
fn i386_template_call_in_method_arg_instantiates() {
    check_i386_cpp(
        "tmpl_method_arg",
        "template<class T> inline const T& min(const T& a, const T& b) \
           { return a < b ? a : b; } \
         struct S { \
           int take(unsigned v) { return (int)v; } \
           int go(unsigned a, unsigned b) { return take(min(a, b)); } \
         }; \
         int main(void){ S s; int r = s.go(7u, 5u); \
           if (r == 5) r += 30; return r; }",
        35,
    );
}

/// W2 RTL shim (`wrk_rtlshim/rtlshim.c`): the rand family. RAND.C is `#pragma
/// inline` (asm `_lrand`), so the shim reimplements it — bug-for-bug with the
/// SHIPPED asm whose 64-bit LCG multiplier is 0x000015A4_00004E35 (NOT the
/// 0x015A4E35 the C comment claims). This locks the 32-bit-only decomposition
/// (16-bit-half product + carry) under sh_ names (real names would clash with
/// bcc32's RTL here). Expectations cross-checked against the REAL Borland RTL
/// binary: srand(1) ⇒ _lrand()=5540 (=0x15A4, the multiplier's high dword —
/// neat), then 221838220; srand(12345) ⇒ rand()=15301 (one-off oracle run,
/// /tmp/randtest, 2026-06-09 — exact stdout parity incl. 0xDEADBEEF seed
/// interleavings; NB bcc32 evaluates call args right-to-left, so the oracle
/// driver assigns each value to a local before printing). 7+9+11 = 27.
#[test]
fn i386_rtl_shim_rand_lcg() {
    check_i386_cpp(
        "rtlshim_rand",
        "static unsigned se_lo = 1; static unsigned se_hi = 0; \
         void sh_srand(unsigned s){ se_lo = s; se_hi = 0; } \
         int sh_rand(void){ se_lo = 0x015A4E35u * se_lo + 1; \
           return (int)((se_lo >> 16) & 0x7FFF); } \
         long sh_lrand(void){ \
           unsigned lo = se_lo, hi = se_hi; \
           unsigned hipart = 0x15A4u * lo + 0x4E35u * hi; \
           unsigned l0 = lo & 0xFFFFu, l1 = lo >> 16; \
           unsigned m0 = l0 * 0x4E35u, m1 = l1 * 0x4E35u; \
           unsigned mid = (m0 >> 16) + (m1 & 0xFFFFu); \
           unsigned p_lo = (m0 & 0xFFFFu) | (mid << 16); \
           unsigned p_hi = (m1 >> 16) + (mid >> 16); \
           p_lo += 1u; if (p_lo == 0u) p_hi += 1u; \
           p_hi += hipart; se_lo = p_lo; se_hi = p_hi; \
           return (long)(p_hi & 0x7FFFFFFFu); } \
         int main(void){ int r = 0; \
           sh_srand(1u); \
           if (sh_lrand() == 5540L) r += 7; \
           if (sh_lrand() == 221838220L) r += 9; \
           sh_srand(12345u); \
           if (sh_rand() == 15301) r += 11; \
           return r; }",
        27,
    );
}

/// RailC Tier 2: Borland's inline `randomize()` is
/// `srand((unsigned)time(NULL))`. DOS headers also declare `struct time`, so
/// call typing must still treat `time(NULL)` as the function call before the
/// cdecl marshaller passes its scalar cast result.
#[test]
fn i386_cdecl_scalar_arg_cast_call_result_passes_value() {
    check_i386_cpp(
        "cdecl_cast_call_value_tag_collision",
        "#define NULL 0\n\
         #define _FAR\n\
         #define _RTLENTRY __cdecl\n\
         #define _EXPFUNC\n\
         struct time { int hour; }; \
         static unsigned seen; \
         extern \"C\" long _RTLENTRY _EXPFUNC time(long _FAR *); \
         extern \"C\" void _RTLENTRY _EXPFUNC seed(unsigned __seed); \
         inline void _RTLENTRY randomize_like(void) { seed((unsigned) time(NULL)); } \
         extern \"C\" long _RTLENTRY time(long *){ return 12345L; } \
         extern \"C\" void _RTLENTRY seed(unsigned v){ seen = v; } \
         int main(void){ randomize_like(); return seen == 12345u ? 42 : 1; }",
        42,
    );
}

/// #26b (forward-referenced class-scoped enum constant): an inline member body
/// may reference an enum constant declared LATER in the same class
/// ([class.mem]/7 complete-class context). OWL's `TCommandEnabler` does exactly
/// this — `GetHandled(){return Handled & WasHandled;}` / `SendsCommand()const
/// {return !(Handled & NonSender);}` with `enum {WasHandled=1, NonSender=2}`
/// declared AFTER the accessors (WINDOW.H). mdbcc parses inline bodies eagerly,
/// so `WasHandled` was mistaken for a member access ("no member named") and the
/// accessor was deferred + dropped. A class-body enum pre-scan now registers the
/// constants up front. RUN-verified the VALUES (diff vs bcc32): Handled=3 ⇒
/// GetHandled()=3&1=1; SendsCommand()=!(3&2)=0 ⇒ 0?0:10 = 10 ⇒ 1+10 = 11.
#[test]
fn i386_forward_ref_class_enum_constant() {
    check_i386_cpp(
        "fwd_enum_const",
        "struct C { int Handled; \
           int GetHandled() { return Handled & WasHandled; } \
           int SendsCommand() const { return !(Handled & NonSender); } \
           enum { WasHandled = 1, NonSender = 2 }; }; \
         int main(void){ C c; c.Handled = 3; \
           return c.GetHandled() + (c.SendsCommand()?0:10); }",
        11,
    );
}

/// #26c (deduce a function-template argument from a CALL result): a template
/// call whose argument is itself a function call must deduce from the callee's
/// return type. OWL's `TWindow::Register` does `ToBool(::GetClassInfo(...))` —
/// `T` is otherwise un-typeable, so the accessor deferred + dropped. The
/// monomorphizer's `type_of_expr` now types an `Expr::Call` via the TU's
/// function-return-type table. RUN-verified (diff vs bcc32): getval()=5 ⇒
/// ToBool<int>(5)=1 ⇒ 1*42 = 42 (would fail to LINK before — TWindow::Register
/// unresolved).
#[test]
fn i386_template_deduces_from_call_result() {
    check_i386_cpp(
        "tmpl_call_deduce",
        "int getval(void){ return 5; } \
         template<class T> int ToBool(const T& t){ return t ? 1 : 0; } \
         int main(void){ return ToBool(getval()) * 42; }",
        42,
    );
}

/// S2e (i386 float store): the float scalar-assignment store branch hardcoded a
/// 64-bit `mov rcx,rax` (the lhs-address move) instead of the width-aware `wreg`
/// form the integer branch already used — so any float STORE on i386 emitted a
/// `Mov [Gpr64,Gpr64]` the x86 encoder has no row for, and the whole function
/// was discarded (railc TSection/TPlatData::SetXScaleFactor: `Temp=X; X=N`).
/// This mirrors that pattern without a float *argument* call (a separate open
/// gap): local float stores (t,u) + a global float store (g). r=(int)(3+6)=9.
#[test]
fn i386_float_store_local_and_global() {
    check_i386(
        "float_store",
        "float g; int main(){ float t; float u; t = 3.0f; g = 6.0f; u = t + g; return (int)u; }",
        9,
    );
}

/// S5: `new T[n]` (array new) is now IMPLEMENTED on the i386 target (a 32-bit
/// parallel of the Win64 lowering — cdecl HeapAlloc, Gpr32, 4-byte cookie). It
/// previously emitted `mov r64, r64` — for which the x86 encoder has no row —
/// and was guarded by a clean error; now it compiles to a real object. This
/// locks that the cookie-less POD form produces a COFF object with no panic and
/// no encoder miss (the RUN behaviour is covered by `i386_array_new_*` above).
#[test]
fn i386_array_new_compiles_clean_on_i386() {
    let resolver = DefaultResolver {
        base_dir: std::path::PathBuf::from("."),
    };
    let src = b"struct T { int v; }; \
                int main(void){ T* p = new T[4]; return p[0].v; }";
    let obj = compile_to_object_with_target(src, "main.cpp", &resolver, TargetKind::Win32)
        .expect("i386 array-new must compile cleanly (no panic, no encoder miss)");
    assert_eq!(obj.machine, mdbcc::coff::Machine::I386, "i386 object");
}

/// S6: an explicit QUALIFIED conversion-operator call — `Base::operator int()`
/// (OCF/OCPART.H `return Base::operator int();`, the next shared gap for the
/// 12 OWL OCF/OLE files). The expression `::` parser now accepts an `operator`
/// component; it resolves to the class's `operator@<typecode>` method key and
/// dispatches statically on the `(Base*)this` subobject. D inherits B (v=42);
/// `B::operator int()` reads v through the base → 42 vs bcc32.
#[test]
fn i386_qualified_conversion_operator_call() {
    check_i386_cpp(
        "qual_conv_op",
        "struct B { int v; B(){ v = 42; } operator int() const { return v; } }; \
         struct D : B { int f() { return B::operator int(); } }; \
         int main(void){ D d; return d.f(); }",
        42,
    );
}

/// S6: a DEFAULT ARGUMENT in a function-POINTER TYPEDEF's parameter list —
/// `typedef int (*F)(int, unsigned id = 0);`. OCF/OCREG.H's
/// `typedef IUnknown* (*TComponentFactory)(IUnknown*, uint32, uint32 id = 0);`
/// (included by all 12 OWL OCF/OLE files) errored "expected ')'" at the `= 0`.
/// `param_type_list` now parses-and-discards the default (irrelevant to the
/// pointer's type). The typedef'd pointer is then callable; 40 + 2 = 42.
#[test]
fn i386_default_arg_in_function_pointer_typedef() {
    check_i386_cpp(
        "fnptr_typedef_default",
        "typedef int (*F)(int a, unsigned id = 0); \
         int add2(int a, unsigned b){ return a + (int)b; } \
         int main(void){ F f = (F)add2; return f(40, 2); }",
        42,
    );
}

/// S6 (#64): nested classes with a COLLIDING unqualified tag — `TBase` and
/// `TButton` each nest a `Streamer` (the DECLARE_STREAMER pattern across the
/// OWL streamable classes). The flat model merged them into one record,
/// collapsing member symbols + the `object` field type, so
/// `TButton::Streamer::Read`'s `GetObject()->IsDefPB` resolved against TBase's
/// GetObject (`TBase*`, no IsDefPB) → "no member named X" across ~14 OWL files.
/// Now a colliding nested DEFINITION mints a FRESH record with a unique tag
/// (`Streamer$<id>`); ctor/dtor are detected by the BARE name; qualified
/// `TButton::Streamer` (and out-of-line member defs) resolve via a scoped
/// `Outer::Inner` key. `s.Read()` reads the right object through the right
/// GetObject → 42 vs bcc32.
#[test]
fn i386_nested_class_tag_collision() {
    check_i386_cpp(
        "nested_tag_collision",
        "struct TBase { struct Streamer { TBase* object; \
             TBase* GetObject() const { return object; } }; }; \
         struct TButton : TBase { int IsDefPB; \
           struct Streamer { TButton* object; \
             TButton* GetObject() const { return object; } \
             int Read() { return GetObject()->IsDefPB; } }; }; \
         int main(void){ TButton b; b.IsDefPB = 42; \
             TButton::Streamer s; s.object = &b; return s.Read(); }",
        42,
    );
}

/// G13 (post-#64 streamer follow-on): a DEPENDENT nested type used inside a
/// function-template body — `T::Inner n(...)` where `T` is a template
/// parameter. CLASSLIB's `WriteBaseObject<Base>` / `ReadBaseObject<Base>`
/// (OBJSTRM.H) declare `Base::Streamer strmr(base); ... strmr.ClassVersion();`
/// — the streamer files (BUTTON/CHECKBOX/EDIT/GROUPBOX/FILTVAL) instantiate
/// them. The parser previously dropped the `Base` qualifier (`Base::Inner` →
/// `TemplateParam("Inner")`), so monomorphisation could not substitute the
/// nested type and codegen hit "method call on non-class". Now the qualifier
/// is kept (`TemplateParam("Base::Inner")`) and `subst_type` resolves the
/// concrete nested record via the scoped `Outer::Inner` key (#64). The
/// instantiation builds `Host::Inner n(42)` and calls `n.get()` → 42 vs bcc32.
#[test]
fn i386_dependent_nested_type_in_function_template() {
    check_i386_cpp(
        "dep_nested_tmpl",
        "struct Host { struct Inner { int v; Inner(int x) : v(x) {} \
             int get() { return v; } }; int data; }; \
         template<class T> int useNested(T* host) { \
             T::Inner n(host->data); return n.get(); } \
         int main(void){ Host h; h.data = 42; Host* p = &h; \
             return useNested(p); }",
        42,
    );
}

/// G60 (OWL OBJSTRM.H): dependent nested-type lookup must search inherited
/// nested classes too. `WriteBaseObject<TLayoutWindow>` spells
/// `TLayoutWindow::Streamer`, but `TLayoutWindow` inherits the `Streamer`
/// nested type from `TWindow`. Cover both the local direct-init form and the
/// functional temporary form used by `ReadBaseObject`.
#[test]
fn i386_dependent_nested_type_inherited_in_function_template() {
    check_i386_cpp(
        "dep_nested_inherited_tmpl",
        "struct Base { struct Inner { int v; Inner(int x) { v = x; } \
             int get() { return v; } }; }; \
         struct Derived : Base { int data; }; \
         template<class T> int useNested(T* host) { \
             T::Inner n(host->data); return n.get() + T::Inner(host->data).get() - 42; } \
         int main(void){ Derived d; d.data = 42; Derived* p = &d; return useNested(p); }",
        42,
    );
}

/// OWL CHGICON.CPP: many dialog classes declare a nested `TData`. A later
/// class member `TData& Data;` must bind to the current class's scoped nested
/// type (`Outer::TData`), not the first flat `TData` tag seen earlier. The
/// wrong binding still accepted `Data.Flags` but failed on `Data.MetaPict`.
#[test]
fn i386_unqualified_nested_type_prefers_current_class_scope() {
    check_i386_cpp(
        "nested_tdata_scope",
        "struct Earlier { struct TData { int Flags; }; TData& Data; \
             Earlier(TData& d) : Data(d) {} }; \
         struct Outer { struct TData { int Flags; int MetaPict; }; \
             Outer(TData& d) : Data(d) {} \
             int get(){ return Data.MetaPict; } \
             TData& Data; }; \
         int main(void){ Outer::TData d; d.MetaPict = 42; Outer o(d); \
             return o.get(); }",
        42,
    );
}

/// G15 (#25, cross-TU free-function mangling): a NON-overloaded FREE function
/// whose parameter is a record pointer (`Rec*`) must mangle its DEFINITION
/// symbol (`@take$qp3Rec`) — the same form the cross-TU REFERENCE side
/// (extern-proto `force_cpp`) and bcc32's EXTDEF already use. Before the fix
/// the definition emitted the raw name `take` while a caller in another TU
/// referenced `@take$qp3Rec`, leaving OWL's `SetCreationWindow` / instance
/// thunks / Gdi helpers unresolved across the all-mdbcc railc link. Same-TU
/// define+call must still resolve (now both via the mangled symbol): 41+1 = 42
/// vs bcc32.
#[test]
fn i386_free_function_record_param_mangled_definition() {
    check_i386_cpp(
        "free_rec_mangle",
        "struct Rec { int v; }; \
         int take(Rec* r){ return r->v + 1; } \
         int main(void){ Rec r; r.v = 41; return take(&r); }",
        42,
    );
}

/// G21 (S2, member-init copy of a trivially-copyable class): a ctor
/// member-init `: m(src)` where `m` is a class with only a default ctor (no
/// copy ctor) and `src` is the same type is COPY-INITIALISATION — a trivial
/// byte copy, NOT a call to a (nonexistent) 1-arg ctor. mdbcc reported "no
/// matching overload for call to 'M::M': expected 0..=0 args, got 1" (OWL
/// LAYOUTWI.CPP's `TChildMetrics::TChildMetrics(... TLayoutMetrics& metrics) :
/// Metrics(metrics)`). Now it lowers to a record assignment (memcpy):
/// src.a=41 copied into c.m, +c.x(1) = 42 vs bcc32.
#[test]
fn i386_member_init_copy_trivial_class() {
    check_i386_cpp(
        "minit_copy_trivial",
        "struct M { int a; M(){ a = 0; } }; \
         struct C { M m; int x; C(M& src) : m(src) { x = 1; } }; \
         int main(void){ M src; src.a = 41; C c(src); return c.m.a + c.x; }",
        42,
    );
}

/// G22 (unnamed by-value class catch): `catch (E)` (by value, NO parameter
/// name) observes no parameter, so the by-value copy is unobservable — it is a
/// pure type match, equivalent to `catch (E&)`. mdbcc deferred ALL by-value
/// class catches; OWL DIALOG.CPP's CATCH chain has `catch(Bad_cast)` /
/// `catch(Bad_typeid)` (both unnamed), which blocked the whole file (→ TDialog
/// ctor). Now an UNNAMED by-value class catch reuses the ByRef match (bind
/// nothing, run body); a NAMED one still defers. Throw E, caught by the unnamed
/// by-value handler → 42 vs bcc32.
#[test]
fn i386_unnamed_by_value_class_catch() {
    check_i386_cpp(
        "unnamed_byval_catch",
        "struct E { int v; E(){ v = 1; } }; \
         int main(void){ try { throw E(); } catch (E) { return 42; } \
             return 9; }",
        42,
    );
}

/// G30 (i386 non-trivial copy-ctor: Decl-init + new-expr). mdbcc had no working
/// i386 non-trivial record-copy path: the copy-ctor CALL sites were Win64-only
/// (REX.W reg64 + rcx/rdx) and `build_synth_copy_ctor` emitted an ENTIRELY Win64
/// body. Now the synth body is target-aware (i386: this/src at [ebp+8]/[ebp+12],
/// ecx/edx, cdecl inner calls, absolute vtable) and the Decl-init + new-expr
/// call sites route through emit_call on i386. Unblocks OWL EXCEPT.CPP
/// `new TXOwl(*this)` (TXOwl has a non-trivial `string` member). Here M's copy
/// ctor adds 100; the synth copy ctor of D (no user copy ctor) must invoke it
/// for both Decl-init and `new` → 5+100 twice → 210.
#[test]
fn i386_nontrivial_copy_ctor_declinit_and_new() {
    check_i386_cpp(
        "nontrivial_copy",
        "struct M { int n; M(){ n=0; } M(const M& o){ n = o.n + 100; } }; \
         struct D { M m; int v; D(const char*){ v=0; } ~D(){} }; \
         int main(void){ D a(\"x\"); a.m.n = 5; \
             D b = a;              /* Decl-init: synth copy ctor → b.m.n=105 */ \
             D* p = new D(a);      /* new-expr: synth copy ctor → p->m.n=105 */ \
             return b.m.n + p->m.n; }",
        210,
    );
}

/// G58 (W6, OWL TXWindow copy): a constructor initializer naming a base class
/// with no registered copy ctor still has to chain that base's primary base copy
/// ctor. This keeps `TXWindow(const TXWindow&) : TXOwl(src)` from byte-copying
/// `TXBase`/`xmsg` state while leaving `TXOwl`'s constructor overload set alone.
#[test]
fn i386_ctor_initializer_chains_primary_base_copy_ctor() {
    check_i386_cpp(
        "base_only_synth_copy",
        "struct Root { int v; Root(){ v = 1; } Root(const Root& o){ v = o.v + 10; } }; \
         struct Mid : Root { int m; Mid(){ m = 2; } }; \
         struct Derived : Mid { int d; Derived(){ d = 3; } \
             Derived(const Derived& o) : Mid(o) { d = o.d + 4; } }; \
         int main(void){ Derived a; a.v = 5; Derived b(a); return b.v + b.d; }",
        22,
    );
}

/// W6/TXOwl: throwing a class with no registered copy ctor must still
/// copy-construct any non-trivial primary base subobject before publishing the
/// EH buffer.
#[test]
fn i386_throw_chains_primary_base_copy_ctor_without_global_synth() {
    check_i386_cpp(
        "throw_base_only_synth_copy",
        "struct Root { int v; Root(){ v = 41; } Root(const Root&){ v = 42; } }; \
         struct Derived : Root { int tag; Derived(){ tag = 0; } }; \
         int main(void){ try { Derived d; throw d; } catch (Derived& e) { return e.v; } return 0; }",
        42,
    );
}

/// G28 (unary operator on a class returns by value; materialized as an lvalue
/// source): `-x` on a class dispatches to `x.operator-()` (returning by value).
/// gen_expr(Unary) had no record branch — it negated the record's raw bytes (a
/// silent segfault); and gen_addr couldn't address the operator- temporary for
/// a record copy. Now a record unary lowers to its operator method, and a
/// record-returning unary materializes (like Call/Binary) so an enclosing
/// assignment copies from it. OWL LAYOUTWI.CPP:857
/// `OrderedCombination[i] = -OrderedCombination[i]` (TFixed) hit both. Here
/// a(5) → a=-a (a.v=-5) → c=-a (c.v=5) → 42 vs bcc32.
#[test]
fn i386_unary_operator_on_class_returns_by_value() {
    check_i386_cpp(
        "unary_op_record",
        "struct T { int v; T(){ v=0; } T(int x){ v=x; } \
             T operator-(){ return T(-v); } }; \
         int main(void){ T a(5); a = -a; T c = -a; \
             return (a.v == -5 && c.v == 5) ? 42 : 0; }",
        42,
    );
}

/// G27 (chained assignment of a class type via the IMPLICIT operator=): for a
/// class with a converting ctor and the compiler-generated member-wise
/// `operator=`, `a = b = c = 1` must work — the inner assignment yields an
/// lvalue (the LHS) that the enclosing assignment copies from. mdbcc only
/// handled the EXPLICIT-`operator=` chain; the implicit/member-wise case fell
/// through `gen_addr` to "expression is not an lvalue". OWL LAYOUTWI.CPP:171
/// (`OrderedCombination[0]=OrderedCombination[1]=…=1`, a `TFixed[]`) hit this.
/// Each `=1` constructs via `T(int)` and member-wise-assigns; the chain leaves
/// all three = 1 → sum 3 vs bcc32.
#[test]
fn i386_chained_implicit_class_assignment() {
    check_i386_cpp(
        "chained_implicit_assign",
        "struct T { int v; T(){ v = 0; } T(int x){ v = x; } }; \
         int main(void){ T a[3]; a[0] = a[1] = a[2] = 1; \
             return a[0].v + a[1].v + a[2].v; }",
        3,
    );
}

/// G24 (char literal types as `char`, not `int`): a C++ char literal `':'`
/// has type `char`, so an overload set with char-family parameters resolves to
/// the exact `char` overload. mdbcc previously lowered char literals to
/// `Expr::Int` (type `int`), so `S(char)` vs `S(unsigned char)` BOTH needed an
/// int→1-byte conversion → ambiguous. This blocked OWL FRAMEWIN.CPP's
/// `title += ':'` (no `string::operator+=(char)`, so the char constructs a
/// `string` — `string(char)`/`string(signed char)`/`string(unsigned char)`
/// tied). Here the `char` overload sets v=1, the `unsigned char` overload v=2;
/// `S(':')` selecting v=1 proves the exact `char` match vs bcc32.
#[test]
fn i386_char_literal_selects_char_overload() {
    check_i386_cpp(
        "char_lit_overload",
        "struct S { int v; S(char){ v = 1; } S(unsigned char){ v = 2; } }; \
         int main(void){ S s(':'); return s.v; }",
        1,
    );
}

/// W6 RailC/RTL stream startup: an inline/vague forwarding overload must not
/// replace a later out-of-line body that provides the same final symbol. Under
/// mdbcc's current char/signed-char model, IOSTREAM.H's inline
/// `getline(signed char*)` wrapper collides with ISTGLINE.CPP's strong
/// `getline(char*)` body; keeping the wrapper makes the symbol recurse forever.
#[test]
fn i386_inline_signed_char_overload_does_not_replace_strong_char_body() {
    let src = "int depth = 0; \
         struct S { \
           int f(char*); \
           int f(signed char* p) { if (++depth > 1) return 7; return f((char*)p); } \
         }; \
         int S::f(char*) { return 42; } \
         int main(void){ char c; S s; return s.f(&c); }";
    let pe = mdbcc_i386_pe(src.as_bytes());
    let Some(exit) = run_pe(&pe, "inline_signed_char_strong_body") else {
        return;
    };
    assert_eq!(
        exit, 42,
        "[inline_signed_char_strong_body] strong body wins"
    );
}

#[test]
fn i386_inline_signed_char_wrapper_pruned_for_external_char_proto() {
    fn sym_name(obj: &coff::Object, sym: &coff::Symbol) -> String {
        match &sym.name {
            coff::SymName::Short(a) => {
                let end = a.iter().position(|&b| b == 0).unwrap_or(8);
                String::from_utf8_lossy(&a[..end]).into_owned()
            }
            coff::SymName::Long(off) => obj
                .strtab
                .get_str(*off)
                .map(str::to_string)
                .unwrap_or_default(),
        }
    }

    let caller_src = b"\
        struct S { \
          int f(char*); \
          int f(signed char* p) { return f((char*)p); } \
          int f(unsigned char* p) { return f((char*)p); } \
        }; \
        int main(void){ signed char c; S s; return s.f(&c); }";
    let def_src = b"\
        struct S { \
          int f(char*); \
          int f(signed char* p) { return f((char*)p); } \
          int f(unsigned char* p) { return f((char*)p); } \
        }; \
        int S::f(char*) { return 42; }";
    let resolver = DefaultResolver {
        base_dir: std::path::PathBuf::from("."),
    };
    let caller =
        compile_to_object_with_target(caller_src, "caller.cpp", &resolver, TargetKind::Win32)
            .expect("compile caller");
    let def = compile_to_object_with_target(def_src, "def.cpp", &resolver, TargetKind::Win32)
        .expect("compile def");

    let f_symbols: Vec<(String, coff::StorageClass, coff::SectionRef)> = caller
        .symbols
        .iter()
        .map(|s| (sym_name(&caller, s), s.storage, s.section))
        .filter(|(n, _, _)| n.contains("@S@f") || n == "S::f")
        .collect();
    assert!(
        f_symbols.iter().any(|(name, storage, section)| {
            name.contains("$qpc")
                && *storage == coff::StorageClass::External
                && matches!(section, coff::SectionRef::Undefined)
        }),
        "caller must reference the colliding S::f(char*) symbol as an undefined external; \
         symbols={f_symbols:?}"
    );
    assert!(
        !f_symbols.iter().any(|(name, storage, section)| {
            name.contains("$qpc")
                && *storage == coff::StorageClass::WeakExternal
                && matches!(section, coff::SectionRef::Section(_))
        }),
        "caller must not emit the colliding weak inline wrapper; symbols={f_symbols:?}"
    );
    assert!(
        f_symbols.iter().any(|(name, storage, section)| {
            name.contains("$qpuc")
                && *storage == coff::StorageClass::WeakExternal
                && matches!(section, coff::SectionRef::Section(_))
        }),
        "the distinct unsigned-char inline wrapper may still be emitted; symbols={f_symbols:?}"
    );
    assert!(
        f_symbols.iter().any(|(_, storage, section)| {
            *storage == coff::StorageClass::External
                && matches!(section, coff::SectionRef::Undefined)
        }),
        "caller must have an undefined S::f reference; symbols={f_symbols:?}"
    );

    let pe = link::link(
        &[Input::Object(&caller), Input::Object(&def)],
        &link_opts_i386(),
    )
    .expect("link caller + out-of-line char body");
    let Some(exit) = run_pe(&pe, "inline_signed_char_external_proto") else {
        return;
    };
    assert_eq!(
        exit, 42,
        "[inline_signed_char_external_proto] external body wins"
    );
}

/// W6 regression guard for the collision filter above: a matching external
/// member prototype plus an out-of-class inline `char*` body is the normal
/// BIDS/string pattern and must still emit the inline definition.
#[test]
fn i386_inline_char_pointer_body_survives_matching_external_proto() {
    let src = "struct S { int f(char*); }; \
         inline int S::f(char* p) { return p ? 42 : 0; } \
         int main(void){ char c = 0; S s; return s.f(&c); }";
    let pe = mdbcc_i386_pe(src.as_bytes());
    let Some(exit) = run_pe(&pe, "inline_char_matching_proto") else {
        return;
    };
    assert_eq!(
        exit, 42,
        "[inline_char_matching_proto] matching inline body must be emitted"
    );
}

/// W6 RailC/RTL archive closure: these Borland `cstring.h` wrappers are inline
/// definitions, but the public RTL archive must export them for other TUs.
#[test]
fn i386_borland_string_char_pointer_inline_wrappers_exported() {
    fn sym_name(obj: &coff::Object, sym: &coff::Symbol) -> String {
        match &sym.name {
            coff::SymName::Short(a) => {
                let end = a.iter().position(|&b| b == 0).unwrap_or(8);
                String::from_utf8_lossy(&a[..end]).into_owned()
            }
            coff::SymName::Long(off) => obj
                .strtab
                .get_str(*off)
                .map(str::to_string)
                .unwrap_or_default(),
        }
    }

    let src = b"\
        typedef unsigned int size_t; \
        unsigned int strlen(const char*); \
        class string { \
        public: \
          string& append(const char*, size_t, size_t); \
          string& prepend(const char*, size_t, size_t); \
          string& append(char*, size_t, size_t); \
          string& prepend(char*, size_t, size_t); \
          string& operator +=(const string&); \
          string& operator +=(const char*); \
          string& operator +=(char*); \
          string& prepend(const string&); \
          string& prepend(const char*); \
          string& prepend(char*); \
        }; \
        inline string& string::operator +=(const char* cp) \
          { return append(cp, 0, strlen(cp)); } \
        inline string& string::prepend(const char* cp) \
          { return prepend(cp, 0, strlen(cp)); } \
        int anchor(void) { return 0; }";
    let resolver = DefaultResolver {
        base_dir: std::path::PathBuf::from("."),
    };
    let obj =
        compile_to_object_with_target(src, "string_wrappers.cpp", &resolver, TargetKind::Win32)
            .expect("compile string wrapper fixture");

    let symbols: Vec<(String, coff::StorageClass, coff::SectionRef)> = obj
        .symbols
        .iter()
        .map(|s| (sym_name(&obj, s), s.storage, s.section))
        .collect();
    for expected in ["@string@$brplu$qpc", "@string@prepend$qpc"] {
        assert!(
            symbols.iter().any(|(name, storage, section)| {
                name == expected
                    && *storage == coff::StorageClass::WeakExternal
                    && matches!(section, coff::SectionRef::Section(_))
            }),
            "{expected} must be exported as a weak inline definition; symbols={symbols:?}"
        );
    }
}

/// G19 (local anonymous union member promotion): a declarator-less
/// `union { A a; B b; };` inside a function promotes its members (`a`, `b`)
/// into the function scope; a bare `a` rewrites to a member access on a hidden
/// local of the union. OWL DIB.CPP:429 declares
/// `union { BITMAPINFOHEADER infoHeader; BITMAPCOREHEADER coreHeader; };` and
/// then reads `infoHeader.biSize` — mdbcc reported "use of undeclared
/// identifier". Here `a.x = 42` then `b.y` aliases the same storage → 42 vs
/// bcc32 (proving both member promotion and union aliasing).
#[test]
fn i386_local_anonymous_union_member_promotion() {
    check_i386_cpp(
        "anon_union_local",
        "struct A { int x; }; struct B { int y; }; \
         int main(void){ union { A a; B b; }; a.x = 42; return b.y; }",
        42,
    );
}

/// G18 (#42b, multi-variable for-init): `for (int a = 0, b = 0; …; …)` parses
/// as a `Stmt::Block` of decls; the For codegen bound it via `gen_stmt(Block)`,
/// which pushed the Block's OWN scope and POPPED `a`/`b` before `cond` ran — so
/// a member-function `for(int entry=0,count=0; entry<N; …)` (OWL DIB.CPP:235)
/// reported "no member named 'entry'". The Block init's statements are now
/// inlined into the enclosing for-scope, so every init variable stays visible in
/// cond/step/body. Sum a=0..3 (b=a each step) → 0+1+2+3 = 6 vs bcc32.
#[test]
fn i386_multi_variable_for_init() {
    check_i386_cpp(
        "multi_for_init",
        "struct S { int N; \
           int f(){ int sum = 0; \
             for (int a = 0, b = 0; a < N; a++) { b = a; sum += b; } \
             return sum; } }; \
         int main(void){ S s; s.N = 4; return s.f(); }",
        6,
    );
}

/// G17 (#25b, default-arg overload keying): a class with a defaulted ctor
/// `C(const void* = 0)` AND a copy ctor `C(const C&)` — both name `C::C`, both
/// arity 1. `overload_defaults` was keyed by (name, arity), so the copy ctor
/// inherited the `=0` default and became spuriously viable for a 0-arg `C c;`,
/// yielding a false "ambiguous call to overloaded 'C::C'" (CLASSLIB's
/// TVoidPointer is exactly this shape; it blocked the BIDS TVectorImpBase
/// ctor/operator=/Resize family from `new(*this)T[sz]`). The record is now keyed
/// by param TYPES, so only the const-void ctor is viable for 0 args → `C c;`
/// default-constructs with p==0 → 42 vs bcc32.
#[test]
fn i386_default_arg_overload_keyed_by_param_types() {
    check_i386_cpp(
        "defarg_overload_key",
        "struct C { const void* p; C(const void* q = 0) : p(q) {} \
                    C(const C& r) : p(r.p) {} }; \
         int main(void){ C c; C d(c); return (c.p == 0 && d.p == 0) ? 42 : 9; }",
        42,
    );
}

/// G16 (placement array-new of a class WITH a constructor): `new(buf) T[n]`
/// where `T` has a ctor needs a per-element default-construction loop at the
/// caller-owned storage (no cookie). CLASSLIB's TVectorImpBase ctors build
/// their backing store with `Data( new(*this)T[sz] )` (the allocator form) and
/// were DEFERRED on this construct — 7 BIDS vector-base ctors in the railc link
/// closure. Here three `Counter`s are placement-array-constructed in a local
/// buffer; each ctor bumps a static, so the ids are 1,2,3 in order →
/// 1*100 + 2*10 + 3 = 123 vs bcc32 (proving all three ran, in index order).
#[test]
fn i386_placement_array_new_with_constructor() {
    check_i386_cpp(
        "placement_arr_ctor",
        "struct Counter { static int total; int id; Counter(){ id = ++total; } }; \
         int Counter::total = 0; \
         void* operator new[](unsigned, void* p){ return p; } \
         int main(void){ char buf[3 * sizeof(Counter)]; \
             Counter* c = new(buf) Counter[3]; \
             return c[0].id * 100 + c[1].id * 10 + c[2].id; }",
        123,
    );
}

/// G15b (#25 follow-on): a cxx-param free function used as a VALUE — passed by
/// BARE NAME as a callback (`apply(dbl, &r)`, OWL's `ForEach(shutDown)`). G15
/// routes such a function to a single-candidate `overloads` entry (mangled
/// symbol); the function-as-value paths (`expr_type` of a designator, `gen_addr`
/// of a designator) only consulted `sigs.funcs`, so the designator failed to
/// resolve ("undeclared identifier" / "no member named" — regressed 8 OWL files
/// incl. WINDOW.CPP). Now both consult the single-candidate overload. `dbl`
/// (cxx-param) passed by name and invoked through the pointer returns 21*2 = 42
/// vs bcc32.
#[test]
fn i386_cxx_param_free_function_as_callback_value() {
    check_i386_cpp(
        "free_fn_callback",
        "struct Rec { int v; }; \
         int dbl(Rec* r){ return r->v * 2; } \
         int apply(int (*fn)(Rec*), Rec* r){ return fn(r); } \
         int main(void){ Rec r; r.v = 21; return apply(dbl, &r); }",
        42,
    );
}

/// G14 (vtable-slot mangling): an OVERLOADED VIRTUAL method taking a
/// record-type parameter. The vtable slot symbol was mangled tagless
/// (a placeholder `R<id>` for the record arg) while the function definition
/// and every call site used the real class tag (`3Rec`) — a SPLIT symbol that
/// left the slot's target unresolved across an all-mdbcc link (OWL's
/// `TDC::SelectObject(TPen&)` / `ExtTextOutA(TRect&)` families: 12 of railc's
/// 51 link-closure unresolveds). The slot now mangles with the record table,
/// so slot, definition and dispatch agree. Dispatch through a `Base*` to the
/// record-arg overload returns 42 vs bcc32 (and the i386 PE link resolves the
/// slot's target — which it could not before the fix).
#[test]
fn i386_overloaded_virtual_record_param_vtable_slot() {
    check_i386_cpp(
        "vt_ovl_rec",
        "struct Rec { int v; }; \
         struct Base { virtual int sel(Rec r) { return r.v; } \
                       virtual int sel(int x) { return x + 1; } }; \
         int main(void){ Rec r; r.v = 42; Base b; Base* p = &b; \
             return p->sel(r); }",
        42,
    );
}

/// RailC Tier 2: virtual cdecl calls must apply record-to-scalar conversion
/// operators before falling back to by-value record marshalling. Arrivals and
/// Departures declare virtual `UpdateDisplay(HDC, BOOL)` and call it as
/// `UpdateDisplay(TDC&, TRUE)` from `Paint`; pushing the whole `TDC` object
/// made GDI see an invalid HDC.
#[test]
fn i386_virtual_call_record_to_scalar_conv_op_arg() {
    check_i386_cpp(
        "vt_conv_arg",
        "struct TDC { int pad; int h; operator int(){ return h; } }; \
         struct Base { virtual int draw(int h, int redraw) { return h + redraw; } }; \
         struct Win : Base { \
             int draw(int h, int redraw) { return h + redraw + 1; } \
             int paint(TDC& dc) { return draw(dc, 1); } \
         }; \
         int main(){ TDC dc; dc.pad = 5; dc.h = 40; Win w; return w.paint(dc); }",
        42,
    );
}

/// W6 railc runtime: a base virtual method calling another base virtual must
/// dispatch to the inherited slot, not the following derived override. RailC's
/// `TStartup` overrides `SetupWindow` but inherits `GetClassName`; mdbcc called
/// the `SetupWindow` slot when `TWindow::GetWindowClass` asked for
/// `GetClassName`, leaving `WNDCLASS.lpszClassName == NULL`.
#[test]
fn i386_virtual_call_to_inherited_middle_slot() {
    check_i386_cpp(
        "vt_inherited_mid_slot",
        "struct Base { \
             virtual int before() { return 11; } \
             int name(int*, int) const { return 9; } \
             virtual int name() { return 42; } \
             virtual int setup() { return 3; } \
             int register_like() { return name(); } \
         }; \
         struct Derived : Base { int setup() { return 7; } }; \
         int main(){ Derived d; Base* p = &d; return p->register_like(); }",
        42,
    );
}

/// W6 railc/OWL runtime: BC++ 4.52's Win32 world has no native C++ `bool`;
/// CLASSLIB provides `typedef int bool`, and Windows provides `typedef int
/// BOOL`. Header-free Win32 parsing must therefore make `bool` ABI-compatible
/// with `BOOL` before the library typedef is replayed. RailC's toolbar classes
/// use exactly this shape for `Paint(TDC&, BOOL, TRect&)` overriding OWL's
/// `Paint(TDC&, bool, TRect&)`; if the override is missed, the vtable slot keeps
/// `TWindow::Paint` and toolbar/client repaint does nothing.
#[test]
fn i386_predefined_borland_bool_matches_bool_alias_virtual_override() {
    let src = "typedef int BOOL; \
         struct TDC; \
         struct TRect; \
         struct TWindow { virtual int Paint(TDC& dc, bool erase, TRect& rect) { return 1; } }; \
         struct TDC { int h; }; \
         struct TRect { int l; }; \
         struct TToolbutton : TWindow { int Paint(TDC& dc, BOOL erase, TRect& rect) { return dc.h + rect.l + (erase ? 30 : 0); } }; \
         int main(){ TDC dc; dc.h = 5; TRect r; r.l = 7; TToolbutton d; TWindow* p = &d; return p->Paint(dc, 1, r); }";
    let pe = mdbcc_i386_pe(src.as_bytes());
    let Some(exit) = run_pe(&pe, "vt_bool_bool_alias") else {
        return;
    };
    assert_eq!(exit, 42, "[vt_bool_bool_alias] virtual bool/BOOL override");
}

/// W6 railc/OWL runtime: vtable slot order is a cross-TU ABI. A TU that
/// defines both a virtual method and a same-name non-virtual overload must not
/// duplicate the virtual's vtable slot; otherwise its compiled self-call uses a
/// slot index one past the derived vtable emitted by another TU. This is the
/// `TWindow::GetClassName()`/`GetClassName(char*,int) const` shape that shifted
/// `TWindow::EvCreate` from `SetupWindow` to `CleanupWindow`.
#[test]
fn i386_virtual_slot_abi_dedups_defined_and_declared_virtual_overload() {
    let header = "struct Base { \
                    virtual int name(); \
                    int name(int*, int) const; \
                    virtual int setup(); \
                    virtual int cleanup(); \
                    int register_like(); \
                  }; \
                  struct Derived : Base { int setup(); };";
    let base_tu = format!(
        "{header} \
         int Base::name() {{ return 1; }} \
         int Base::name(int*, int) const {{ return 9; }} \
         int Base::setup() {{ return 3; }} \
         int Base::cleanup() {{ return 5; }} \
         int Base::register_like() {{ return setup(); }}"
    );
    let derived_tu = format!(
        "{header} int Derived::setup() {{ return 42; }} int main() {{ Derived d; return d.register_like(); }}"
    );
    let resolver = DefaultResolver {
        base_dir: std::path::PathBuf::from("."),
    };
    let o_base = compile_to_object_with_target(
        base_tu.as_bytes(),
        "vt_slot_abi_base.cpp",
        &resolver,
        TargetKind::Win32,
    )
    .expect("base TU");
    let o_derived = compile_to_object_with_target(
        derived_tu.as_bytes(),
        "vt_slot_abi_derived.cpp",
        &resolver,
        TargetKind::Win32,
    )
    .expect("derived TU");
    let pe = link::link(
        &[Input::Object(&o_derived), Input::Object(&o_base)],
        &link_opts_i386(),
    )
    .expect("link i386 PE32 (virtual slot ABI)");
    let Some(exit) = run_pe(&pe, "vt_slot_abi") else {
        return;
    };
    assert_eq!(exit, 42, "[vt_slot_abi] cross-TU virtual slot ABI");
}

/// W6 railc/OWL runtime: a derived non-virtual overload with the same source
/// name as an inherited virtual does not override that virtual. OWL control
/// classes inherit `TWindow::GetClassName()` while also exposing helper
/// overloads such as `GetClassName(char*, int) const`; the helper must not
/// replace the inherited vtable slot.
#[test]
fn i386_derived_nonvirtual_overload_does_not_override_virtual() {
    check_i386_cpp(
        "vt_derived_nonvirtual_overload",
        "struct Base { virtual int name() { return 42; } }; \
         struct Derived : Base { int name(int*) const { return 9; } }; \
         int main(){ Derived d; Base* p = &d; return p->name(); }",
        42,
    );
}

/// W6 railc/OWL link closure: when a derived class overrides one overloaded
/// base virtual but the derived method itself is not overloaded, mdbcc emits
/// the derived body under the bare source symbol. The inherited expanded slot
/// must therefore target that bare symbol, not a newly invented
/// `@Derived@name$q...` symbol.
#[test]
fn i386_derived_single_override_of_overloaded_base_uses_emitted_symbol() {
    check_i386_cpp(
        "vt_derived_single_override_overloaded_base",
        "struct Base { \
             int name(int*) const { return 9; } \
             virtual int name() { return 1; } \
         }; \
         struct Derived : Base { int name() { return 42; } }; \
         int main(){ Derived d; Base* p = &d; return p->name(); }",
        42,
    );
}

/// OWL `TWindow::WindowProc` calls virtual `Find(eventInfo)` and relies on the
/// defaulted second parameter (`TEqualOperator = 0`). Virtual dispatch must
/// append defaults for non-overloaded member functions before marshalling.
#[test]
fn i386_virtual_call_uses_default_argument() {
    check_i386_cpp(
        "vt_default_arg",
        "struct Base { virtual int f(int x = 42) { return x; } }; \
         struct Derived : Base {}; \
         int main(){ Derived d; Base* p = &d; return p->f(); }",
        42,
    );
}

/// S5 (#62): the Borland `_EAX` register pseudo-variable. OWL's StdWndProc
/// (WINDOW.CPP:900) recovers `this` from the entry register with
/// `((TWindow*)_EAX)->ReceiveMessage(...)` — the window-class thunk loads EAX
/// with the object pointer before transferring control. mdbcc must spill the
/// entry-EAX in the prologue (before the param-spill clobbers it) and read that
/// slot for `_EAX`. Here `f()` leaves 42 in EAX; `g()` is entered with EAX=42
/// still live and returns `_EAX`; both mdbcc and bcc32 must yield 42.
#[test]
fn i386_eax_register_pseudovariable() {
    check_i386_cpp(
        "eax_pseudovar",
        "int f(){ return 42; } int g(){ return _EAX; } int main(){ f(); return g(); }",
        42,
    );
}

/// B-24: Borland register pseudo-variables are also writable. RTL
/// EXCEPT.C seeds EAX/EDX immediately before calling ___doGlobalUnwind, whose
/// assembly reads those registers as implicit inputs. mdbcc must preserve the
/// assigned pseudo-register values across any temporary clobbering until the
/// following call observes them.
#[test]
fn i386_eax_edx_pseudoregister_writes_materialize_before_call() {
    check_i386_cpp(
        "eax_edx_pseudoreg_writes",
        "int seen_eax; int seen_edx; \
         void capture(){ seen_eax = _EAX; seen_edx = _EDX; } \
         int main(){ _EAX = 17; _EDX = 25; capture(); return seen_eax + seen_edx; }",
        42,
    );
}

/// S5: cast to a FUNCTION-POINTER type — `(int (*)(void *))add3`. The RTL
/// scanf family (FSCANF/SSCANF/SCANF/VFSCANF/VSCANF/CSCANF) and the strto*
/// family pass `fgetc`/`ungetc` to `_scanner`/`_scantod` through exactly this
/// cast shape; mdbcc's cast gate previously rejected the grouped abstract
/// declarator (`expected an expression`). The call goes THROUGH the cast
/// pointer at a different signature (same cdecl), exit 39+3 = 42 vs bcc32.
#[test]
fn i386_cast_to_function_pointer_type() {
    check_i386_cpp(
        "fnptr_cast",
        "int add3(int x){ return x + 3; } \
         int call(int (*g)(void *), void * a){ return g(a); } \
         int main(void){ return call((int (*)(void *))add3, (void *)39); }",
        42,
    );
}

/// S5: a PARENTHESIZED conv-led function declarator —
/// `int (__cdecl add2)(int x) { … }`. The RTL ctype family (LOCALE/IS.C) defines
/// every `is*` function this way (`int (_RTLENTRY _EXPFUNC isalnum)(int c)`) so
/// the parens suppress the same-named ctype.h macro. Previously misparsed as a
/// prototype ("expected ';'" at the `{`). Exit 40+2 = 42, matched vs bcc32.
#[test]
fn i386_parenthesized_conv_function_definition() {
    check_i386_cpp(
        "paren_fn_def",
        "int (__cdecl add2)(int x) { return x + 2; } \
         int main(void){ return add2(40); }",
        42,
    );
}

/// S5: address-of a width-CHANGING cast chain over an lvalue —
/// `&((unsigned char)(unsigned int) buf[2])`, the Borland cast-as-lvalue
/// extension in ADDRESS-OF position. RTL LOCALE.C/LSETLOCL.C compute their
/// tolower/toupper table addresses exactly this way. No store occurs, so any
/// widths are safe: the address is the innermost lvalue's. 39+3 = 42 vs bcc32.
#[test]
fn i386_addr_of_cast_chain_lvalue() {
    check_i386_cpp(
        "addr_cast_chain",
        "unsigned char buf[4]; \
         int main(void){ \
             buf[2] = 39; \
             unsigned char * p = (unsigned char *)( &( (unsigned char)(unsigned int) buf[2] ) ); \
             return *p + 3; }",
        42,
    );
}

/// S5: pointer-to-global / pointer-to-string GLOBAL INITIALIZERS on i386 —
/// `int *p = &target;` (RTL FMODEPTR.C `int *_fmodeptr = &_fmode;`) and
/// `char *s = "…";`. The COFF converter hardcoded `Addr64` for both .data
/// relocs and PANICKED at write time on i386 (`RelocKindUnsupported(Addr64,
/// I386)` — also hit by OWL CLIPBOAR.CPP); now Addr32. The run proves the
/// 4-byte absolute relocs RESOLVE (read 39 through p, 'x'=120 via s[0]):
/// 39 + 3 = 42 and the s[0] check folds to 0. Matched vs bcc32.
#[test]
fn i386_ptr_global_and_ptr_str_initializers() {
    check_i386_cpp(
        "ptr_global_init",
        "int target = 39; \
         int *p = &target; \
         char *s = \"x\"; \
         int main(void){ return *p + 3 + (s[0] == 'x' ? 0 : 100); }",
        42,
    );
}

/// S6 (G1 Stage-1): plain multiple inheritance — POD bases, flat member
/// access through the derived object AND through an UPCAST pointer to the
/// extra (second) base, which must be adjusted by the B-subobject offset
/// (`B* pb = &c` ⇒ pb = &c + off(B)). 30 + 12 = 42 vs bcc32.
#[test]
fn i386_mi_two_pod_bases_member_access() {
    check_i386_cpp(
        "mi_pod",
        "struct A { int a; }; struct B { int b; }; struct C : A, B { }; \
         int main(void){ C c; c.a = 30; c.b = 12; B* pb = &c; \
                         return c.a + pb->b; }",
        42,
    );
}

/// S6 (G1 Stage-1): the G1 minimal repro — a ctor mem-init list naming BOTH
/// direct bases (`C() : A(), B()`), previously "no member named 'B'". Each
/// base ctor runs on its own subobject (B's on `this+off`). 1*10 + 2*16 = 42.
#[test]
fn i386_mi_ctor_init_names_both_bases() {
    check_i386_cpp(
        "mi_ctor_both",
        "struct A { int a; A(){ a = 1; } }; \
         struct B { int b; B(){ b = 2; } }; \
         struct C : A, B { C() : A(), B() {} }; \
         int main(void){ C c; return c.a * 10 + c.b * 16; }",
        42,
    );
}

/// S6 (G1 Stage-1): the sweep's CORRECTNESS LANDMINE — a user ctor that does
/// NOT name the second base must still construct it (C++ [class.base.init]:
/// unnamed bases are default-constructed). Previously B was silently never
/// constructed. Also covers the fully-implicit case (C declares no ctor; the
/// synthesized one chains both). 1*10 + 2*16 = 42 both shapes.
#[test]
fn i386_mi_unnamed_extra_base_is_constructed() {
    check_i386_cpp(
        "mi_implicit_b",
        "struct A { int a; A(){ a = 1; } }; \
         struct B { int b; B(){ b = 2; } }; \
         struct C : A, B { C() : A() {} }; \
         struct D : A, B { }; \
         int main(void){ C c; D d; \
             return (c.a * 10 + c.b * 16) == 42 && (d.a * 10 + d.b * 16) == 42 \
                 ? 42 : 0; }",
        42,
    );
}

/// S6 (G1 Stage-1): a METHOD of the extra base called on the derived object —
/// `this` must be adjusted to the B subobject (method_target's walk reaches
/// B with the accumulated extra-base offset). 40 + 2 = 42 vs bcc32.
#[test]
fn i386_mi_extra_base_method_this_adjust() {
    check_i386_cpp(
        "mi_b_method",
        "struct A { int a; A(){ a = 40; } }; \
         struct B { int b; B(){ b = 2; } int get_b(){ return b; } }; \
         struct C : A, B { }; \
         int main(void){ C c; return c.a + c.get_b(); }",
        42,
    );
}

/// S6 (G1 Stage-1): destruction order across MI — body, then bases in REVERSE
/// declaration order (B before A). The log digit-encodes the sequence:
/// ~B then ~A ⇒ log = 0*10+2, then *10+1 = 21; +21 = 42 vs bcc32.
#[test]
fn i386_mi_dtor_reverse_declaration_order() {
    check_i386_cpp(
        "mi_dtor_order",
        "int lg = 0; \
         struct A { int a; A(){ a = 1; } ~A(){ lg = lg * 10 + 1; } }; \
         struct B { int b; B(){ b = 2; } ~B(){ lg = lg * 10 + 2; } }; \
         struct C : A, B { }; \
         int main(void){ { C c; } return lg + 21; }",
        42,
    );
}

/// S6 (G2): free/friend operator candidates must be considered when the LHS
/// class declares 2+ MEMBER overloads of the same operator and none is viable
/// (C++ [over.match.oper] — member and non-member candidates together). The
/// RTL trigger: `is >> setw(4)` (istream has many member `operator>>`s; only
/// IOMANIP.H's friend matches) — previously a hard "no matching overload for
/// 'istream::operator>>'" (STRINGIO/DATEIO/TIMEIO). Here `s << m` (M matches
/// no member; only the friend) sits CHAINED between member-resolved calls, so
/// expr_type's member-fail→free fallback is exercised too. 5+30+7 = 42.
#[test]
fn i386_free_operator_fallback_with_two_member_overloads() {
    check_i386_cpp(
        "free_op_fallback",
        "struct M { int v; M(int x){ v = x; } }; \
         struct S { int acc; S(){ acc = 0; } \
                    S& operator<<(int x){ acc += x; return *this; } \
                    S& operator<<(short c){ acc += c * 100; return *this; } }; \
         S& operator<<(S& s, const M& m){ s.acc += m.v; return s; } \
         int main(void){ S s; M m(30); s << 5 << m << 7; return s.acc; }",
        42,
    );
}

/// S6 (G3): C++ name hiding — a derived-class DATA MEMBER shadows a
/// same-named inherited one. The flat field model resolved `d.Attr` to the
/// BASE's field (first match in [base | own] order) — OWL's TDialog::Attr
/// shadows TWindow::Attr (DIALOG.CPP), and the misresolution was a SILENT
/// MISCOMPILE (both writes landed on B::Attr: mdbcc 80 vs bcc32 42).
/// Own-slice-first lookup: d.Attr = D's (40), pb->Attr = B's (2) → 42.
#[test]
fn i386_derived_member_shadows_base_member() {
    check_i386_cpp(
        "member_shadow",
        "struct B { int Attr; }; \
         struct D : B { int Attr; }; \
         int main(void){ D d; B* pb = &d; pb->Attr = 2; d.Attr = 40; \
                         return d.Attr + pb->Attr; }",
        42,
    );
}

/// S6 (G4): derived-to-base overload ranking by inheritance DISTANCE
/// (C++ [over.ics.rank]/4 — the conversion to the CLOSER base wins). A flat
/// rank tied OWL's `GetApplication()->SuspendThrow(x)` (x: TXOwl&, candidates
/// `TXBase&` at 1 hop and `xmsg&` at 2 hops — WINDOW.CPP:927) into a spurious
/// "ambiguous call". Here `f(C&)` must pick `f(B&)` (1 hop) over `f(A&)`
/// (2 hops): r==2 → 42, matched vs bcc32.
#[test]
fn i386_overload_prefers_closer_base() {
    check_i386_cpp(
        "closer_base",
        "struct A { int pad; }; \
         struct B : A { int pad2; }; \
         struct C : B { int pad3; }; \
         struct S { int r; \
                    void f(A& a){ r = 1; } \
                    void f(B& b){ r = 2; } }; \
         int main(void){ S s; s.r = 0; C c; s.f(c); return s.r == 2 ? 42 : s.r; }",
        42,
    );
}

/// S6 (G5): TWO SEQUENTIAL `try` blocks in one function — the multi-try
/// fs:[0] machinery (20-byte table-driven record + frame trylevel + the
/// module multi handler). f(0)=3 (no throw), f(1)=12 (first try throws,
/// second still runs), f(2)=41 (second throws after first completed) —
/// 3 + 12 − 41 + 56 = 30, matched vs bcc32 4.52. The exact shape of OWL's
/// TApplication::Run / TWindow::ReceiveMessage (4 and 6 sequential trys).
#[test]
fn i386_two_sequential_try_blocks() {
    check_i386_cpp(
        "multi_try_seq",
        "int f(int k){ \
           int r = 0; \
           try { if (k == 1) throw 10; r += 1; } catch (int e) { r += e; } \
           try { if (k == 2) throw 20; r += 2; } catch (int e) { r += e * 2; } \
           return r; } \
         int main(void){ return f(0) + f(1) - f(2) + 56; }",
        30,
    );
}

/// S6 (G5): ONE `try` with TWO catch clauses of different kinds (int + class
/// by-ref) — also needs the scope table (the legacy record holds a single
/// pad). The handler matches the row by exception code/type: g(0) throws an
/// int (12), g(1) a class (v=30). 12 + 30 = 42 vs bcc32.
#[test]
fn i386_one_try_mixed_catch_clauses() {
    check_i386_cpp(
        "multi_clause",
        "struct X { int v; }; \
         int g(int k){ \
           try { if (k) { X x; x.v = 30; throw x; } else throw 12; } \
           catch (int e) { return e; } \
           catch (X& x) { return x.v; } \
           return 0; } \
         int main(void){ return g(0) + g(1); }",
        42,
    );
}

/// S6 (G5): a throw INSIDE a multi-try function's catch body must propagate
/// OUT of the frame (the handler disarms trylevel to -1 before delivering,
/// so the frame's own table never re-matches) and reach the CALLER's catch.
/// inner: try1 completes (r=1), try2 throws 5, its catch re-throws 35 → out
/// to main's catch → 35 + 7 = 42 vs bcc32.
#[test]
fn i386_throw_from_multi_try_catch_propagates_out() {
    check_i386_cpp(
        "multi_try_rethrow_out",
        "int inner(void){ \
           int r = 0; \
           try { r += 1; } catch (int e) { r = 100; } \
           try { throw 5; } catch (int e) { throw e + 30; } \
           return r; } \
         int main(void){ try { return inner(); } catch (int e) { return e + 7; } }",
        42,
    );
}

/// B-10: a nested i386 `try` must restore the enclosing trylevel after the
/// inner try body completes normally, so a later throw in the same outer try
/// is caught by the outer handler.
#[test]
fn i386_nested_try_fallthrough_restores_outer_level() {
    check_i386_cpp(
        "nested_try_fallthrough_outer",
        "int main(void){ \
           int r = 0; \
           try { \
             try { r = 10; } catch (int e) { return 1; } \
             throw r + 32; \
           } catch (int e) { return e; } \
           return 0; }",
        42,
    );
}

/// B-10: a throw from an inner catch body is outside that inner try, but still
/// inside the enclosing try statement. The catch landing pad must restore the
/// parent trylevel before it emits the user handler body.
#[test]
fn i386_nested_try_inner_catch_throw_reaches_outer() {
    check_i386_cpp(
        "nested_try_catch_throw_outer",
        "int main(void){ \
           try { \
             try { throw 7; } catch (int e) { throw e + 34; } \
           } catch (int e) { return e + 1; } \
           return 0; }",
        42,
    );
}

/// B-10: if the innermost active try has no matching handler, the same i386
/// frame must continue the search at the enclosing try level before letting the
/// exception propagate to caller frames.
#[test]
fn i386_nested_try_outer_catches_inner_nonmatch() {
    check_i386_cpp(
        "nested_try_outer_nonmatch",
        "struct X { int v; }; \
         int main(void){ \
           try { \
             try { throw 39; } catch (X& x) { return 1; } \
           } catch (int e) { return e + 3; } \
           return 0; }",
        42,
    );
}

/// S6 (G8): i386 member-function-pointer VALUES and CALLS — the `.*`/`->*`
/// dispatch OWL's response tables run on (`(eventInfo.Object->*pmf)(…)`,
/// WINDOW.CPP EvWin32CtlColor). The Win64-shaped path emitted REX bytes /
/// bit-63 imm64 (encoder error `CallReg [Gpr64]`). i386: a non-virtual MFP
/// is the function address (B8 + DIR32); a virtual MFP is bit 31 | slot*4,
/// dispatched through `[[this]+off]` — here through a BASE pointer with a
/// derived OVERRIDE (the virtual tag must dispatch dynamically).
/// (w.*direct)(10) = 12; (p->*vfn)(10) → W2::vfn = 21; 12+21+9 = 42 vs bcc32.
#[test]
fn i386_member_function_pointer_calls() {
    check_i386_cpp(
        "mfp_calls",
        "struct W { int base; W(){ base = 2; } \
                    int direct(int x){ return base + x; } \
                    virtual int vfn(int x){ return base * x; } }; \
         struct W2 : W { int vfn(int x){ return base * x + 1; } }; \
         typedef int (W::*PMF)(int); \
         int main(void){ \
           W2 w; \
           PMF d = &W::direct; \
           PMF v = &W::vfn; \
           int a = (w.*d)(10); \
           W* p = &w; \
           int b = (p->*v)(10); \
           return a + b + 9; }",
        42,
    );
}

/// S6 (G4 slice 2): conversion quality dominates default-arg usage
/// LEXICOGRAPHICALLY ([over.match.best]) — an EXACT-match candidate that
/// omits a trailing defaulted param must beat a pointer-CONVERSION candidate
/// with exact arity. The additive score mixing tied them — OWL's
/// `TMenu popupMenu(hPopupMenu)` (exact `TMenu(HMENU,TAutoDelete=)` vs
/// `TMenu(const void*)`, WINDOW.CPP:2417) errored "ambiguous"; bcc32 picks
/// the exact match. r=30 here ⇒ 30+12 = 42 vs bcc32.
#[test]
fn i386_exact_with_default_beats_conversion() {
    check_i386_cpp(
        "exact_default_vs_conv",
        "struct H__ { int u; }; typedef H__* H; \
         struct M { int r; \
                    M(H h, int d = 7){ r = 30; } \
                    M(const void* p){ r = 1; } }; \
         int main(void){ H h = 0; M m(h); return m.r + 12; }",
        42,
    );
}

/// S6 (G11): a VIRTUAL method returning a record BY VALUE on i386 — the
/// hidden result-buffer pointer (sret) is pushed as the FIRST stack arg
/// ([ebp+8], before `this` at [ebp+12] — the direct-call/callee ABI), through
/// the vtable dispatch. OWL's TGauge/TSlider PosToPoint shape (sweep G11,
/// 7 files). Dynamic dispatch via a base pointer reaches the override:
/// D::get → {30,12} ⇒ 42 vs bcc32.
#[test]
fn i386_virtual_record_return_by_value() {
    check_i386_cpp(
        "virtual_sret",
        "struct P { int x; int y; }; \
         struct B { virtual P get(){ P p; p.x = 1; p.y = 2; return p; } }; \
         struct D : B { P get(){ P p; p.x = 30; p.y = 12; return p; } }; \
         int main(void){ B* b = new D(); P p = b->get(); return p.x + p.y; }",
        42,
    );
}

/// S6 (G1 Stage-2): MI with a POLYMORPHIC second base — the secondary vtable
/// plus this-adjusting thunk machinery. `D : B1, B2` (both polymorphic, D
/// overrides both). The B2 subobject's vptr is installed (by D's SetVptr,
/// after B2::B2 set its own) to the SYNTHETIC secondary vtable whose `g` slot
/// is the thunk `sub [esp+4], off(B2); jmp D::g` — so `p2->g()` through the
/// upcast-adjusted B2* dispatches D::g with a correctly-restored `this`
/// (reads `b` at the right offset). 15 + 26 + 7 minus 6 = 42 vs bcc32 4.52.
#[test]
fn i386_mi_polymorphic_second_base_virtual_dispatch() {
    check_i386_cpp(
        "mi_stage2_thunk",
        "struct B1 { int a; B1(){ a = 5; } virtual int f(){ return 1; } }; \
         struct B2 { int b; B2(){ b = 6; } virtual int g(){ return 2; } }; \
         struct D : B1, B2 { \
           int c; \
           D(){ c = 7; } \
           int f(){ return a + 10; } \
           int g(){ return b + 20; } }; \
         int main(void){ \
           D d; \
           B2* p2 = &d; \
           B1* p1 = &d; \
           return p1->f() + p2->g() + d.c - 6; }",
        42,
    );
}

/// S6 (G9): a `template<>`-less SPECIALIZATION MEMBER definition —
/// `inline void TAuto<short>::Value(short&) {…}` (pre-standard Borland
/// syntax; OCF/AUTODEFS.H defines TAutoEnumerator's members this way). The
/// declarator's template-id qualifier now INSTANTIATES on cache-miss
/// (rewind to the tag + the base-clause machinery) instead of failing
/// "no class named". Value(s) stores Current → 42 vs bcc32.
#[test]
fn i386_template_id_qualified_member_definition() {
    check_i386_cpp(
        "tmpl_id_member_def",
        "template <class T> class TAuto { \
           public: \
             T Current; \
             void Value(T& v); \
             TAuto(){ } \
         }; \
         inline void TAuto<short>::Value(short& v) { v = Current; } \
         int main(void){ TAuto<short> a; a.Current = 42; short s = 0; \
                         a.Value(s); return s; }",
        42,
    );
}

/// S6: Borland's `template<>`-less FULL class specialization syntax —
/// `class Ptr<char> : public PtrBase<char> { ... }`, matching
/// OSL/GEOMETRY.H's `TPointer<char>`. The specialization is a real concrete
/// record (not the primary template): it derives from a template-id base,
/// constructs that base, refers to `Ptr<char>` inside its own `operator=`, and
/// exposes the specialization-only `operator[]`. 10 + 32 = 42 vs bcc32.
#[test]
fn i386_class_template_full_specialization_body() {
    check_i386_cpp(
        "class_tmpl_full_spec",
        "template<class T> class PtrBase { \
           public: operator T*() { return P; } \
           protected: PtrBase(T* p) : P(p) {} PtrBase() : P(0) {} T* P; \
         }; \
         template<class T> class Ptr : public PtrBase<T> { \
           public: \
             Ptr() : PtrBase<T>() {} \
             Ptr(T* p) : PtrBase<T>(p) {} \
             T* operator=(T* src) { delete P; return P = src; } \
             T* operator=(const Ptr<T>& src) { delete P; return P = src.P; } \
             T* operator->() { return P; } \
         }; \
         class Ptr<char> : public PtrBase<char> { \
           public: \
             Ptr() : PtrBase<char>() {} \
             Ptr(char* p) : PtrBase<char>(p) {} \
             char* operator=(char* src) { delete P; return P = src; } \
             char* operator=(const Ptr<char>& src) { delete P; return P = src.P; } \
             char& operator[](int i) { return P[i]; } \
         }; \
         int main(void){ \
           char data[2]; data[0] = 10; data[1] = 20; \
           Ptr<char> p; p = data; \
           Ptr<char> q; q = p; \
           q[1] = 32; \
           char* raw = (char*)q; \
           return raw[0] + raw[1]; }",
        42,
    );
}

/// S6 (RailC W6 `OLEDLG.CPP`): copy-initialisation of a class specialization
/// from a scalar/pointer expression constructs via the converting ctor. This is
/// not a whole-record copy, so the initializer has no lvalue address to copy
/// from. Mirrors `TPointer<char> pstr = new char[BuffLen];`.
#[test]
fn i386_record_copy_init_from_scalar_uses_converting_ctor() {
    check_i386_cpp(
        "record_copy_init_scalar_ctor",
        "template<class T> class PtrBase { \
           public: operator T*() { return P; } \
           protected: PtrBase(T* p) : P(p) {} PtrBase() : P(0) {} T* P; \
         }; \
         template<class T> class Ptr : public PtrBase<T> { \
           public: Ptr(T* p) : PtrBase<T>(p) {} \
         }; \
         class Ptr<char> : public PtrBase<char> { \
           public: \
             Ptr(char* p) : PtrBase<char>(p) {} \
             char& operator[](int i) { return P[i]; } \
         }; \
         int main(void){ \
           Ptr<char> p = new char[2]; \
           p[0] = 10; p[1] = 32; \
           char* raw = (char*)p; \
           return raw[0] + raw[1]; }",
        42,
    );
}

/// S6 (G1 Stage-3 slice): STATELESS virtual mixins — `W : virtual M1,
/// virtual M2` where both bases are dataless interface classes (OWL's
/// `TWindow : virtual TEventHandler, virtual TStreamableBase` shape). Laid
/// out as plain bases (duplicate dataless subobjects on re-inheritance are
/// behaviorally sound — no state to split); the polymorphic extras ride the
/// Stage-2 secondary-vtable machinery, so dispatch through BOTH upcast mixin
/// pointers reaches W's overrides with adjusted `this`:
/// 31 + 10 + 1 = 42 vs bcc32 4.52. Data-bearing virtual bases (ios, TWindow
/// itself) still defer to full Stage-3.
#[test]
fn i386_stateless_virtual_mixins() {
    check_i386_cpp(
        "vmixin_stateless",
        "struct M1 { virtual int f(){ return 1; } }; \
         struct M2 { virtual int g(){ return 2; } }; \
         struct W : virtual M1, virtual M2 { \
           int data; \
           W(){ data = 30; } \
           int f(){ return data + 1; } \
           int g(){ return data - 20; } }; \
         int main(void){ \
           W w; \
           M1* m1 = &w; \
           M2* m2 = &w; \
           return m1->f() + m2->g() + 1; }",
        42,
    );
}

/// S6 (G1 Stage-3): LAYOUT of a DATA-BEARING shared virtual-base diamond
/// (the `ios` shape). `Base` is the single shared vbase; `Left`/`Right` each
/// `virtual public Base`; `Diamond : Left, Right`. The shared `Base` is
/// appended ONCE at the object tail and reached via a vbptr — so
/// `sizeof(Diamond)` is `[Left-nv 12][Right-nv 12][d 4][Base 8] = 36`,
/// byte-identical to bcc32 4.52 (verified: 36). This checks the layout half
/// of Stage-3 independently of construction.
#[test]
fn i386_vbase_diamond_sizeof() {
    check_i386_cpp(
        "vbase_diamond_sizeof",
        "struct Base { int s; virtual ~Base(){} }; \
         struct Left : virtual public Base { int l; virtual ~Left(){} }; \
         struct Right : virtual public Base { int r; virtual ~Right(){} }; \
         struct Diamond : public Left, public Right { int d; virtual ~Diamond(){} }; \
         int main(void){ return sizeof(Diamond); }",
        36,
    );
}

/// S6 (G1 Stage-3): a DATA-BEARING shared virtual base (the iostream `ios`
/// diamond, minimal form). `Base` (data `s`, polymorphic) is virtually derived
/// by `Left` and `Right`; `Diamond : Left, Right` shares ONE `Base`. The
/// construction site default-constructs the shared `Base` once and sets every
/// subobject's vbptr; member access + `Left*`/`Right*`→`Base*` upcasts indirect
/// through the vbptr. All four checks (own data + the shared `s` seen through
/// both base paths == 11) ⇒ 42 vs bcc32 4.52.
#[test]
fn i386_data_bearing_virtual_diamond_shared_base() {
    check_i386_cpp(
        "vbase_diamond_shared",
        "struct Base { int s; Base(){ s=11; } virtual ~Base(){} }; \
         struct Left : virtual public Base { int l; Left(){ l=22; } virtual ~Left(){} }; \
         struct Right : virtual public Base { int r; Right(){ r=33; } virtual ~Right(){} }; \
         struct Diamond : public Left, public Right { int d; Diamond(){ d=44; } virtual ~Diamond(){} }; \
         int main(void){ \
           Diamond x; \
           Left* lp = &x; Right* rp = &x; \
           return (x.s==11 && x.l==22 && x.r==33 && x.d==44 && \
                   ((Base*)lp)->s==11 && ((Base*)rp)->s==11) ? 42 : 0; }",
        42,
    );
}

/// S6 (G1 Stage-3): a METHOD inherited from a SHARED virtual base, called on a
/// derived object — `this` must be adjusted to the shared base subobject by
/// LOADING the vbptr (not a static offset), since the vbase floats to the
/// most-derived tail. `Base::set`/`Base::val` reached through `Diamond` and
/// through an upcast `Left*` both hit the ONE shared `Base`. (This is exactly
/// how `infile.eof()`/`clear()`/`setstate()` resolve to `ios::*` for fstream.)
/// 5 (set) seen via both paths + 22 + 15 → 42 vs bcc32 4.52.
#[test]
fn i386_vbase_method_through_shared_base() {
    check_i386_cpp(
        "vbase_method_shared",
        "struct Base { int s; Base(){ s=1; } int val(){ return s; } \
                       void set(int x){ s=x; } virtual ~Base(){} }; \
         struct Left : virtual public Base { int l; Left(){ l=22; } virtual ~Left(){} }; \
         struct Right : virtual public Base { int r; Right(){ r=33; } virtual ~Right(){} }; \
         struct Diamond : public Left, public Right { int d; Diamond(){ d=44; } virtual ~Diamond(){} }; \
         int main(void){ \
           Diamond x; \
           x.set(5); \
           Left* lp = &x; \
           return (x.val()==5 && lp->val()==5 && x.l==22 && x.r==33) ? 42 : 0; }",
        42,
    );
}

/// S6 (G8b): a Win32 API from the GDI32/USER32 surface OWL calls — now
/// recognised by codegen via `is_win32_import` and emitted as an IAT import
/// (instead of a C++-mangled call that the linker can't resolve). Collapsed
/// ~140 unresolved from the railc closure. `GetMenuItemCount(NULL)` returns
/// -1 (invalid menu) on any system, deterministically; both mdbcc and bcc32
/// dispatch the same USER32 export → 42.
#[test]
fn i386_win32_user_gdi_api_import() {
    check_i386_cpp(
        "win32_api_import",
        "extern \"C\" long __stdcall GetMenuItemCount(void*); \
         int main(void){ return GetMenuItemCount(0) == -1 ? 42 : 0; }",
        42,
    );
}

/// S6: file-scope DIRECT-INIT whose FIRST argument is a qualified
/// enum-constant (`Type::value`) — `static B obj(Q::Hatch, 12)`. The
/// one-token disambiguation peek saw the leading type-name `Q` and assumed a
/// function declaration `B obj(Q::…, …)`, then tried to parse the next arg as
/// a parameter type ("expected a type, found '::'"). OWL BUTTONGA.CPP:
/// `static THatch8x8Brush ditherBrush(THatch8x8Brush::Hatch11F1,
/// ::GetSysColor(...), …)`. Now `Type::value` (tail not a type) ⇒ direct-init.
/// obj.v = 30 + 12 = 42 vs bcc32.
#[test]
fn i386_direct_init_qualified_enum_first_arg() {
    check_i386_cpp(
        "direct_init_qual_enum",
        "struct Q { enum E { Hatch = 30 }; }; \
         struct B { int v; B(int a, int b){ v = a + b; } }; \
         static B obj(Q::Hatch, 12); \
         int main(void){ return obj.v; }",
        42,
    );
}

/// S6 (#64-adjacent): a block-scope `const int` used as an ARRAY BOUND —
/// `const int N = 10; int a[N];`. The const-folder only substituted
/// file-scope const-ints, so a local one errored "expected a constant
/// expression" (OWL DOCMANAG.CPP `const int MaxViewCount = 25;
/// TDocTemplate* tplList[MaxViewCount];` — a ubiquitous C++ idiom). Now
/// local const-ints fold too (gated by fn_locals). a[0]=42, a[9]=1 ⇒ 42.
#[test]
fn i386_local_const_int_array_bound() {
    check_i386_cpp(
        "local_const_bound",
        "int main(void){ const int N = 10; int a[N]; \
                         a[0] = 42; a[N-1] = 1; return a[0]; }",
        42,
    );
}

/// G54 (W6, OWL TApplication::Run's `catch (TXOwl&)`): CROSS-TU class
/// exception matching. EH class identity is the vtable RVA (or the typeinfo
/// RVA for a non-poly class) — and both were per-TU `.Lvtbl/.Lxt` STATICS,
/// so a class thrown in one TU NEVER matched a `catch` of the same class in
/// another (the exception fail-fasted with 0xE0000002 — railc's TWindow::
/// Create throw sailed past Run's handlers). Two fixes under test: (1) a
/// TAGGED class's vtable/typeinfo emit under the link-CANONICAL bcc32 names
/// (`@Tag@3` / `@$xt$…`) as WeakExternal; (2) mdlink's COMDAT fold now
/// REDIRECTS losing WeakExternal copies' own resolution to the winner, so
/// intra-TU relocs also land on the single canonical RVA. Derived-thrown,
/// caught-as-base CROSS-TU still needs the thrower's chain (parked: G55).
#[test]
fn i386_class_exception_caught_across_tu() {
    let header = "struct TXOwl { int code; TXOwl(int c) : code(c) {} virtual ~TXOwl() {} };";
    let thrower = format!("{header} void boom(int c) {{ throw TXOwl(c); }}");
    let catcher = format!(
        "{header} void boom(int c); \
         int main() {{ \
           try {{ boom(40); }} \
           catch (TXOwl& x) {{ return x.code + 2; }} \
           return 7; }}"
    );
    let resolver = DefaultResolver {
        base_dir: std::path::PathBuf::from("."),
    };
    let o_throw = compile_to_object_with_target(
        thrower.as_bytes(),
        "thrower.cpp",
        &resolver,
        TargetKind::Win32,
    )
    .expect("thrower TU");
    let o_catch = compile_to_object_with_target(
        catcher.as_bytes(),
        "catcher.cpp",
        &resolver,
        TargetKind::Win32,
    )
    .expect("catcher TU");
    let pe = link::link(
        &[Input::Object(&o_catch), Input::Object(&o_throw)],
        &link_opts_i386(),
    )
    .expect("link i386 PE32 (cross-TU EH)");
    let Some(exit) = run_pe(&pe, "eh_cross_tu") else {
        return;
    };
    assert_eq!(exit, 42, "[eh_cross_tu] cross-TU class catch must match");
}

/// G55 (W6): a DERIVED class thrown, caught as its BASE — the i386 SEH3
/// handlers' class match was EXACT-only (the hierarchy walk existed only in
/// the x64 personality), so OWL's `catch (TXOwl&)` missed every thrown
/// TXWindow-derived exception even in one TU. The throw now marks a
/// polymorphic tag (args[2] bit 0) and the handlers walk the RTTI/EH
/// descriptor word at `[vtable-4]` (the base class's vtable, emitted for
/// every i386 EH module — previously dynamic_cast-gated) up the chain,
/// 32-step capped. 40 + 2 = 42 (diff vs bcc32).
#[test]
fn i386_derived_thrown_caught_as_base() {
    check_i386_cpp(
        "eh_derived_base",
        "struct TXOwl { int code; TXOwl(int c) : code(c) {} virtual ~TXOwl() {} }; \
         struct TXWin : TXOwl { int w; TXWin(int c) : TXOwl(c), w(1) {} }; \
         int main() { \
           try { throw TXWin(40); } \
           catch (TXOwl& x) { return x.code + 2; } \
           return 7; }",
        42,
    );
}

/// G55 (cross-TU composition with G54): derived thrown in ONE TU, caught as
/// base in ANOTHER — the OWL TWindow::Create → TApplication::Run shape.
/// Needs BOTH the canonical folded `@Tag@3` tags (G54) and the descriptor-
/// chain walk (G55): the thrown TXWin tag folds to the canonical copy,
/// whose `[tag-4]` descriptor points at the canonical TXOwl vtable, which
/// equals the catcher's row tag.
#[test]
fn i386_derived_class_exception_caught_across_tu() {
    let header = "struct TXOwl { int code; TXOwl(int c) : code(c) {} virtual ~TXOwl() {} } ; \
                  struct TXWin : TXOwl { int w; TXWin(int c) : TXOwl(c), w(1) {} };";
    let thrower = format!("{header} void boom(int c) {{ throw TXWin(c); }}");
    let catcher = format!(
        "{header} void boom(int c); \
         int main() {{ \
           try {{ boom(40); }} \
           catch (TXOwl& x) {{ return x.code + 2; }} \
           return 7; }}"
    );
    let resolver = DefaultResolver {
        base_dir: std::path::PathBuf::from("."),
    };
    let o_throw = compile_to_object_with_target(
        thrower.as_bytes(),
        "thrower2.cpp",
        &resolver,
        TargetKind::Win32,
    )
    .expect("thrower TU");
    let o_catch = compile_to_object_with_target(
        catcher.as_bytes(),
        "catcher2.cpp",
        &resolver,
        TargetKind::Win32,
    )
    .expect("catcher TU");
    let pe = link::link(
        &[Input::Object(&o_catch), Input::Object(&o_throw)],
        &link_opts_i386(),
    )
    .expect("link i386 PE32 (cross-TU derived EH)");
    let Some(exit) = run_pe(&pe, "eh_x_tu_derived") else {
        return;
    };
    assert_eq!(exit, 42, "[eh_x_tu_derived] derived-as-base cross-TU catch");
}

/// G57 (W6, OWL `TXOwl::Unhandled → TModule::Error(xmsg&,…)`): binding a
/// DERIVED lvalue to a BASE& parameter is an implicit upcast of the bound
/// ADDRESS. A polymorphic class over a data-bearing NON-poly base shifts
/// the base subobject past the vptr (base_offset = 4, the Microsoft
/// model), and the i386 ref-marshal passed `&derived` unadjusted — OWL's
/// HandleGlobalException read TXOwl's VPTR as `xmsg::str` and faulted in
/// `string::length`. The ref-bind now routes through `convert`'s
/// Ptr-upcast arms (static base_offset + Stage-3 vbase load). 40 + 2 = 42
/// (diff vs bcc32).
#[test]
fn i386_derived_ref_binds_base_param_with_offset() {
    check_i386_cpp(
        "ref_base_adjust",
        "struct M { int v; M(int k) : v(k) {} }; \
         struct D : M { D() : M(40) {} virtual int f() { return 1; } }; \
         int take(M& m) { return m.v + 2; } \
         int main() { D d; return take(d); }",
        42,
    );
}

/// G58b (W6, OWL `TXOwl::Unhandled`): the same ref-arg base adjustment must
/// apply when the derived lvalue is spelled `*this`. `TXOwl::Unhandled` passes
/// `*this` to `TModule::Error(xmsg&, ...)`; without the upcast,
/// HandleGlobalException reads the derived vptr as `xmsg::str`.
#[test]
fn i386_this_deref_ref_arg_binds_base_param_with_offset() {
    check_i386_cpp(
        "ref_base_adjust_this_deref",
        "struct M { int v; M(int k) : v(k) {} }; \
         int take(M& m) { return m.v + 2; } \
         struct D : M { D() : M(40) {} virtual int f() { return take(*this); } }; \
         int main() { D d; return d.f(); }",
        42,
    );
}

/// G58c: the i386 virtual-call marshaller has its own cdecl path. It must apply
/// the same derived-address to base-reference conversion as direct calls before
/// pushing a `Base&` argument.
#[test]
fn i386_virtual_ref_arg_binds_base_param_with_offset() {
    check_i386_cpp(
        "virtual_ref_base_adjust",
        "struct M { int v; M(int k) : v(k) {} }; \
         struct App { virtual int take(M& m) { return m.v + 2; } }; \
         struct D : M { D() : M(40) {} virtual int f(App* app) { return app->take(*this); } }; \
         int main() { App app; D d; return d.f(&app); }",
        42,
    );
}

/// G58 (W6): a non-overloaded extern prototype with a C++ reference parameter
/// emits a Borland-mangled call symbol, but argument marshalling must still use
/// the SOURCE-name signature. Without that source-signature handoff, i386
/// treats `B&` as an unknown by-value record and pushes `b.v` instead of `&b`.
#[test]
fn i386_extern_proto_ref_param_uses_source_signature_for_mangled_call() {
    let decl = "struct B { int v; B(int k) : v(k) {} }; int forward(B& b);";
    let caller = format!("{decl} int main() {{ B b(40); return forward(b); }}");
    let callee = "struct B { int v; B(int k) : v(k) {} }; \
                  int forward(B& b) { return b.v + 2; }";
    let resolver = DefaultResolver {
        base_dir: std::path::PathBuf::from("."),
    };
    let o_call = compile_to_object_with_target(
        caller.as_bytes(),
        "extern_ref_call.cpp",
        &resolver,
        TargetKind::Win32,
    )
    .expect("caller TU");
    let o_def = compile_to_object_with_target(
        callee.as_bytes(),
        "extern_ref_def.cpp",
        &resolver,
        TargetKind::Win32,
    )
    .expect("callee TU");
    let pe = link::link(
        &[Input::Object(&o_call), Input::Object(&o_def)],
        &link_opts_i386(),
    )
    .expect("link i386 PE32 (extern ref param)");
    let Some(exit) = run_pe(&pe, "extern_ref_param") else {
        return;
    };
    assert_eq!(exit, 42, "[extern_ref_param] extern ref arg must pass &b");
}

/// G59 (W6): an extern-only C++ prototype is emitted as a Borland-mangled call
/// symbol, but its default arguments are recorded under the source name. The
/// call must append those defaults before marshalling, otherwise a call like
/// OWL's `GetWindowPtr(hDlg)` pushes too few args and the callee reads stack
/// garbage for the defaulted parameter.
#[test]
fn i386_extern_proto_default_arg_uses_source_defaults_for_mangled_call() {
    let caller = "int ext(int a, int b = 40); int main() { return ext(2); }";
    let callee = "int ext(int a, int b) { return a + b; }";
    let resolver = DefaultResolver {
        base_dir: std::path::PathBuf::from("."),
    };
    let o_call = compile_to_object_with_target(
        caller.as_bytes(),
        "extern_default_call.cpp",
        &resolver,
        TargetKind::Win32,
    )
    .expect("caller TU");
    let o_def = compile_to_object_with_target(
        callee.as_bytes(),
        "extern_default_def.cpp",
        &resolver,
        TargetKind::Win32,
    )
    .expect("callee TU");
    let pe = link::link(
        &[Input::Object(&o_call), Input::Object(&o_def)],
        &link_opts_i386(),
    )
    .expect("link i386 PE32 (extern default arg)");
    let Some(exit) = run_pe(&pe, "extern_default_arg") else {
        return;
    };
    assert_eq!(exit, 42, "[extern_default_arg] default arg must be pushed");
}

/// G57b (W6): the OTHER two ref-binding sites — `Base& r = derived;`
/// (decl-init) and `Base& f() { return derived; }` (return) — had the same
/// missing-upcast bug as the argument site (G57): the stored/returned
/// address must add `base_offset` past the derived vptr (and load the
/// vbptr for a virtual base). Both routed through `convert`'s Ptr-upcast
/// arms now. 40 + 40 - 38 = 42 (diff vs bcc32).
#[test]
fn i386_ref_decl_and_return_upcast_adjust() {
    check_i386_cpp(
        "ref_sites_adjust",
        "struct M { int v; M(int k) : v(k) {} }; \
         struct D : M { D() : M(40) {} virtual int f() { return 1; } }; \
         D g; \
         M& pick() { return g; } \
         int main() { \
           M& r = g; \
           return r.v + pick().v - 38; }",
        42,
    );
}

/// S5: `_DestructorCount` — the Borland compiler-magic global. bcc32 4.52
/// implicitly declares it (`unsigned long`, external linkage; verified: bcc32
/// compiles the bare use with rc 0); the RTL defines it once in
/// EXCEPT/DTRCOUNT.C, and the vector-new/delete helpers (VNEW/VNEWV/VDELX.CPP)
/// read/write it with no declaration in scope. mdbcc registers an implicit
/// extern global when (and only when) a TU references it. Two-TU link here:
/// the user TU (bare use) + the DTRCOUNT-equivalent definition; exit 37. The
/// bcc32 oracle resolves the same source against its own RTL's DTRCOUNT.OBJ.
#[test]
fn i386_destructor_count_implicit_extern_links_and_runs() {
    let user_src = "int main(void){ _DestructorCount = 37; return (int)_DestructorCount; }";
    let resolver = DefaultResolver {
        base_dir: std::path::PathBuf::from("."),
    };
    let o_use =
        compile_to_object_with_target(user_src.as_bytes(), "use.cpp", &resolver, TargetKind::Win32)
            .expect("bare _DestructorCount use must compile (implicit extern)");
    let o_def = compile_to_object_with_target(
        b"unsigned long _DestructorCount;", // the RTL DTRCOUNT.C definition
        "dtrcount.c",
        &resolver,
        TargetKind::Win32,
    )
    .expect("DTRCOUNT definition TU");
    let pe = link::link(
        &[Input::Object(&o_use), Input::Object(&o_def)],
        &link_opts_i386(),
    )
    .expect("link i386 PE32 (extern _DestructorCount resolves to DTRCOUNT)");
    let Some(exit) = run_pe(&pe, "dtor_count") else {
        return;
    };
    assert_eq!(exit, 37, "[dtor_count] mdbcc i386 exit");
    if let Some(oracle) = BccOracle::discover() {
        let opts = BuildOpts {
            lang: support::bcc_oracle::Lang::Cpp,
            ..BuildOpts::default()
        };
        let r = oracle.build(user_src, &opts);
        let bcc_exe = r.exe.unwrap_or_else(|| {
            panic!(
                "[dtor_count] bcc32 build failed: exit={:?}\nstderr={}",
                r.output.exit,
                String::from_utf8_lossy(&r.output.stderr)
            )
        });
        let bcc_run = oracle.run(&bcc_exe, &[]);
        assert_eq!(
            bcc_run.output.exit,
            Some(exit),
            "[dtor_count] mdbcc i386 exit ({exit}) must match bcc32 reference"
        );
    } else {
        eprintln!("NOTE (dtor_count): BCC 4.52 oracle absent — skipped bcc32 diff");
    }
}

/// S5 (i386): `new T[n]` of a class with a ctor AND dtor — the cookie path.
/// The ctor runs on each of the 3 elements (x=7), so the element sum is 21 and
/// `cc==3`; `delete[]` reads the 4-byte count cookie at `p-4` and runs the dtor
/// in reverse 3 times (`dc==3`). 21+3+3 = 27, matched against bcc32 4.52.
#[test]
fn i386_array_new_class_ctor_dtor_cookie() {
    check_i386_cpp(
        "anew_cookie",
        "int cc = 0; int dc = 0; \
         struct T { int x; T(){ x = 7; cc++; } ~T(){ dc++; } }; \
         int main(){ T* p = new T[3]; \
                     int s = p[0].x + p[1].x + p[2].x; \
                     delete[] p; return s + cc + dc; }",
        27,
    );
}

/// S5 (i386): `new P[n]` of a POD (no ctor, no dtor) — the COOKIE-LESS path.
/// `new` is a raw `HeapAlloc(n*sizeof(P))` and `delete[]` a raw `HeapFree`; the
/// elements are written/read directly. Sum 5+6+7+8 = 26, matched vs bcc32.
#[test]
fn i386_array_new_pod_cookieless() {
    check_i386_cpp(
        "anew_pod",
        "struct P { int a; int b; }; \
         int main(){ P* p = new P[2]; \
                     p[0].a = 5; p[0].b = 6; p[1].a = 7; p[1].b = 8; \
                     int s = p[0].a + p[0].b + p[1].a + p[1].b; \
                     delete[] p; return s; }",
        26,
    );
}

/// S5 (i386): `new T[n]` / `delete[]` where T has a VIRTUAL destructor — the
/// cookie path with vptr-dispatched dtor. The ctor sets each element's vptr and
/// x=3; `delete[]` walks the cookie count and dispatches `~T` through the vtable
/// slot 4 times (`dc==4`). (p[0].x + p[3].x) + dc = 6 + 4 = 10, matched vs bcc32.
#[test]
fn i386_array_new_virtual_dtor_cookie() {
    check_i386_cpp(
        "anew_vdtor",
        "int dc = 0; \
         struct T { int x; T(){ x = 3; } virtual ~T(){ dc++; } }; \
         int main(){ T* p = new T[4]; \
                     int s = p[0].x + p[3].x; \
                     delete[] p; return s + dc; }",
        10,
    );
}

/// General encoder-miss safety net (sticky `encode_miss`): any (op, operand-
/// kinds) shape with no x86 table row must surface as a clean CodegenError that
/// names the instruction, never panic in `encode`. Unlike array-new (which has a
/// dedicated up-front guard), `(long long)d` reaches the encoder and asks for
/// `cvttsd2si r64, xmm` — a 64-bit form absent on i386 — exercising the catch-
/// all path. Several RTL STRING files (INSERT1/2, REPLACE, STREMOVE, STRINGS)
/// emit `mov r64, r64` and previously panicked here on -m32; they now degrade
/// gracefully (the i386 64-bit-register codegen itself remains a separate gap).
#[test]
fn i386_unsupported_encoding_is_clean_error_not_panic() {
    let resolver = DefaultResolver {
        base_dir: std::path::PathBuf::from("."),
    };
    let src = b"long long f(double d){ return (long long)d; } \
                int main(void){ return (int)f(3.5); }";
    let err = compile_to_object_with_target(src, "main.cpp", &resolver, TargetKind::Win32)
        .expect_err("i386 unsupported encoding must be a clean error, not a panic");
    let msg = err.to_string();
    assert!(
        msg.contains("no encoder pattern"),
        "expected a clean encoder-miss error; got: {msg}"
    );
}
