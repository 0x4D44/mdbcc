//! Tick 64 / J-13 v1: variadic user functions.
//!
//! Scope (this tick):
//! - Parsing `int f(int n, ...) { ... }` (recognising the trailing `...`).
//! - Callee-side `<stdarg.h>` intrinsic: `va_list` is a `typedef char*`;
//!   `va_start`, `va_arg`, and `va_end` are codegen intrinsics (recognised
//!   in the parser; not preprocessor macros). The prologue spills the four
//!   positional GPRs (RCX/RDX/R8/R9) into the caller-allocated home space
//!   at `[rbp+16..+40]` so `va_start(ap, last)` lands a `char*` walking
//!   pointer into the contiguous slot array.
//! - Caller-side Win64 variadic ABI: an FP argument at positional slot
//!   0..3 of a variadic-callee call site is emitted into BOTH the
//!   positional XMM and the corresponding GPR, so the callee's home-space
//!   spill recovers the IEEE-754 image regardless of which type
//!   `va_arg` requests.
//!
//! Out of scope (filed for J-13b / later):
//! - Variadic functions returning a >8-byte struct by value — the
//!   hidden-result-pointer ABI would collide with the home-space layout.
//!   Rejected at codegen-time.
//! - `va_arg` with a struct/union type.
//! - Forwarding a `va_list` to another function (`vprintf`-shape APIs).
//!
//! Tick 72 (J-13b) extends the v1 set: variadic *member* functions are
//! now supported — see `j13b_*` tests below.
//! B-12 extends the same machinery to variadic constructors.

#![cfg(windows)]

mod support;

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use mdbcc::compile_to_pe;
use support::{Lang, msvc_ref, normalize_newlines, o2_active};

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct TempExe(PathBuf);
impl Drop for TempExe {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn build(src: &str) -> TempExe {
    let exe = compile_to_pe(src.as_bytes()).expect("mdbcc compile ok");
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("mdbcc_variadic_{}_{}.exe", std::process::id(), n));
    let t = TempExe(p);
    std::fs::write(&t.0, &exe).expect("write exe");
    t
}

fn code(src: &str) -> i32 {
    let t = build(src);
    Command::new(&t.0)
        .status()
        .expect("launch")
        .code()
        .expect("exit code")
}

/// stdout of `src` after compile-and-run.
fn out(src: &str) -> String {
    let t = build(src);
    let o = Command::new(&t.0).output().expect("launch");
    String::from_utf8_lossy(&o.stdout).into_owned()
}

// ===========================================================================
// 1. The canonical example from the brief: three ints summed via va_arg.
// ===========================================================================

#[test]
fn j13_basic_int_variadic() {
    let src = r#"
#include <stdarg.h>
int sum_three_ints(int a, ...) {
  va_list ap;
  va_start(ap, a);
  int b = va_arg(ap, int);
  int c = va_arg(ap, int);
  va_end(ap);
  return a + b + c;
}
int main(void) { return sum_three_ints(1, 2, 3); } // 1+2+3 = 6
"#;
    assert_eq!(code(src), 6);
}

// ===========================================================================
// 2. Variadic with zero extra args (just the named param).
// ===========================================================================

#[test]
fn j13_variadic_zero_extra_args() {
    let src = r#"
#include <stdarg.h>
int just_named(int a, ...) {
  va_list ap;
  va_start(ap, a);
  // Don't call va_arg — the list is empty.
  va_end(ap);
  return a;
}
int main(void) { return just_named(42); }
"#;
    assert_eq!(code(src), 42);
}

// ===========================================================================
// 3. Mixed int + pointer-shaped (string) extras.
// ===========================================================================

#[test]
fn j13_variadic_mixed_int_and_pointer() {
    let src = r#"
#include <stdarg.h>
int sum_int_and_strlen(int n, ...) {
  va_list ap;
  va_start(ap, n);
  int x = va_arg(ap, int);
  char *s = va_arg(ap, char *);
  // Walk s manually so we don't depend on any libc intrinsic shape.
  int len = 0;
  while (s[len] != 0) len = len + 1;
  va_end(ap);
  return n + x + len;
}
int main(void) {
  // 10 + 5 + length("hello") = 10 + 5 + 5 = 20
  return sum_int_and_strlen(10, 5, "hello");
}
"#;
    assert_eq!(code(src), 20);
}

// ===========================================================================
// 4. ≥ 6 ints — exercises positions 4 and 5 (off the shadow space, into
//    the caller's outgoing stack-arg area).
// ===========================================================================

#[test]
fn j13_variadic_5_or_more_args_stack() {
    let src = r#"
#include <stdarg.h>
int sum_six(int n, ...) {
  va_list ap;
  va_start(ap, n);
  int total = 0;
  int i = 0;
  while (i < 5) {
    total = total + va_arg(ap, int);
    i = i + 1;
  }
  va_end(ap);
  return n + total;
}
int main(void) {
  // 1 + 2 + 3 + 4 + 5 + 6 = 21 ; named=1, varargs=2..6.
  return sum_six(1, 2, 3, 4, 5, 6);
}
"#;
    assert_eq!(code(src), 21);
}

// ===========================================================================
// 5. FP arg passed variadically — verifies the caller-side XMM-AND-GPR
//    copy and the callee's va_arg-as-double path.
// ===========================================================================

#[test]
fn j13_variadic_float_promoted_in_xmm_and_gpr() {
    let src = r#"
#include <stdarg.h>
int round_then_add(int n, ...) {
  va_list ap;
  va_start(ap, n);
  // Truncate the variadic double to int and sum.
  double d = va_arg(ap, double);
  va_end(ap);
  return n + (int)d;
}
int main(void) {
  // 10 + (int)2.75 = 10 + 2 = 12 ; the double traverses xmm1 AND rdx
  // (variadic ABI), the callee spills rdx into [rbp+24] and va_arg
  // reads the IEEE-754 image back through that shadow slot.
  return round_then_add(10, 2.75);
}
"#;
    assert_eq!(code(src), 12);
}

// ===========================================================================
// 6. va_start on a non-parameter name is a clean compile error (not a
//    silent miscompile).
// ===========================================================================

#[test]
fn j13_va_start_unknown_anchor_rejected() {
    let src = r#"
#include <stdarg.h>
int f(int a, ...) {
  va_list ap;
  int local = 7;
  va_start(ap, local);   // 'local' is not a parameter
  va_end(ap);
  return a;
}
int main(void) { return f(1, 2); }
"#;
    let err = compile_to_pe(src.as_bytes()).expect_err("must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("not a parameter name"),
        "diagnostic should explain why the anchor is rejected: {msg}"
    );
}

// ===========================================================================
// 7. Using `va_arg` outside a variadic function is rejected loudly.
// ===========================================================================

#[test]
fn j13_va_arg_outside_variadic_rejected() {
    let src = r#"
#include <stdarg.h>
int f(int a) {
  va_list ap;
  // No `...` ⇒ va_start has no meaning here.
  va_start(ap, a);
  return va_arg(ap, int);
}
int main(void) { return f(1); }
"#;
    let err = compile_to_pe(src.as_bytes()).expect_err("must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("outside a variadic function"),
        "diagnostic should mention 'outside a variadic function': {msg}"
    );
}

// ===========================================================================
// 8. Variadic prototype + non-variadic-looking definition (the parser
//    folds the variadic bit from the prototype onto the definition, so
//    callers do the correct ABI). This exercises the prototype-fold
//    path in `Parser::parse`.
// ===========================================================================

#[test]
fn j13_variadic_prototype_then_definition() {
    let src = r#"
#include <stdarg.h>
int sum2(int a, ...);   // prototype declares variadic
int sum2(int a, ...) {  // definition matches
  va_list ap;
  va_start(ap, a);
  int b = va_arg(ap, int);
  va_end(ap);
  return a + b;
}
int main(void) { return sum2(20, 22); } // 42
"#;
    assert_eq!(code(src), 42);
}

// ===========================================================================
// 10. Sanity check: a NON-variadic function with the same body should
//     produce the same numerical result as before this tick (no regression
//     on the non-variadic path).
// ===========================================================================

#[test]
fn j13_non_variadic_unchanged() {
    let src = r#"
int add3(int a, int b, int c) { return a + b + c; }
int main(void) { return add3(1, 2, 3); }
"#;
    assert_eq!(code(src), 6);
}

// ===========================================================================
// 11. Differential against `cl /MT`: the canonical sum_three_ints sample
//     must agree byte-for-byte with MSVC's <stdarg.h>. Silent skip if cl
//     is not on PATH (matches every other suite's differential pattern).
// ===========================================================================

#[test]
fn j13_differential_cl_sum_three_ints() {
    let src = r#"
#include <stdarg.h>
int sum_three_ints(int a, ...) {
  va_list ap;
  va_start(ap, a);
  int b = va_arg(ap, int);
  int c = va_arg(ap, int);
  va_end(ap);
  return a + b + c;
}
int main(void) { return sum_three_ints(1, 2, 3); }
"#;
    let mdbcc_exit = code(src);
    if !o2_active() {
        return;
    }
    let r = msvc_ref(src, Lang::C);
    if !r.launched {
        return;
    }
    let _ = normalize_newlines(&r.stdout); // no stdout expected
    assert_eq!(
        r.exit,
        Some(mdbcc_exit),
        "cl differential FAIL: cl={:?} mdbcc={}",
        r.exit,
        mdbcc_exit
    );
}

// ===========================================================================
// 12. Differential against `cl /MT`: a variadic double also matches MSVC.
// ===========================================================================

#[test]
fn j13_differential_cl_variadic_double() {
    let src = r#"
#include <stdarg.h>
int sum_int_and_truncated_double(int n, ...) {
  va_list ap;
  va_start(ap, n);
  double d = va_arg(ap, double);
  va_end(ap);
  return n + (int)d;
}
int main(void) { return sum_int_and_truncated_double(10, 3.7); }
"#;
    let mdbcc_exit = code(src);
    if !o2_active() {
        return;
    }
    let r = msvc_ref(src, Lang::C);
    if !r.launched {
        return;
    }
    assert_eq!(
        r.exit,
        Some(mdbcc_exit),
        "cl differential FAIL: cl={:?} mdbcc={}",
        r.exit,
        mdbcc_exit
    );
}

// ===========================================================================
// Tick 72 (J-13b): variadic *member* functions.
//
// For a member fn `void Tag::log(int n, ...)`, `this` occupies positional
// slot 0 (RCX) — explicit named arg `n` ends up at slot 1 (RDX), and the
// first variadic arg lands at slot 2 (R8) ⇒ shadow offset 32. The
// `va_start` math (offset = 16 + 8 * (last_index + 1)) uses `last_index`
// indexed against `f.params`, which INCLUDES the implicit `this` ⇒ the
// `this`-induced shift in the shadow layout cancels exactly with the
// `+1` from `this`'s presence in `variadic_named`.
// ===========================================================================

#[test]
fn j13b_variadic_member_fn_basic() {
    // The canonical brief example: a member `log(int n, ...)` reads one
    // variadic int via va_arg and prints the result with printf.
    let src = r#"
#include <stdarg.h>
#include <stdio.h>
class Logger {
public:
  void log(int n, ...) {
    va_list ap;
    va_start(ap, n);
    int v = va_arg(ap, int);
    printf("n=%d v=%d\n", n, v);
    va_end(ap);
  }
};
int main(void) {
  Logger l;
  l.log(1, 42);
  return 0;
}
"#;
    assert_eq!(normalize_newlines(out(src).as_bytes()), b"n=1 v=42\n");
}

#[test]
fn j13b_variadic_member_fn_with_fp_arg() {
    // A variadic FP arg at positional slot 2 (R8 + XMM2) — the caller's
    // XMM-AND-GPR emit fires; the callee spills R8 into [rbp+32] and
    // va_arg(ap, double) reads the IEEE-754 image back through that
    // shadow slot. `n` (slot 1) lands in RDX as usual.
    let src = r#"
#include <stdarg.h>
#include <stdio.h>
class Calc {
public:
  int add_n_and_double(int n, ...) {
    va_list ap;
    va_start(ap, n);
    double d = va_arg(ap, double);
    va_end(ap);
    return n + (int)d;
  }
};
int main(void) {
  Calc c;
  // 10 + (int)2.75 = 12
  return c.add_n_and_double(10, 2.75);
}
"#;
    assert_eq!(code(src), 12);
}

#[test]
fn j13b_variadic_method_returns_value() {
    // A variadic *method returning a non-void scalar* — verifies the
    // return path doesn't interact badly with the variadic ABI. The
    // method sums `n` and one va_arg int, returns the sum.
    let src = r#"
#include <stdarg.h>
class Adder {
public:
  int add(int n, ...) {
    va_list ap;
    va_start(ap, n);
    int b = va_arg(ap, int);
    va_end(ap);
    return n + b;
  }
};
int main(void) {
  Adder a;
  return a.add(20, 22); // 42
}
"#;
    assert_eq!(code(src), 42);
}

#[test]
fn j13b_variadic_method_call_through_pointer() {
    // Defensive: invoking a (non-virtual) variadic method through a
    // class-typed pointer — the receiver-loading path is shared with
    // value-receiver dispatch, so this just confirms the variadic
    // marshalling fires identically when `this` arrives via `->`.
    let src = r#"
#include <stdarg.h>
class Tally {
public:
  int sum2(int a, ...) {
    va_list ap;
    va_start(ap, a);
    int b = va_arg(ap, int);
    va_end(ap);
    return a + b;
  }
};
int main(void) {
  Tally t;
  Tally* p = &t;
  return p->sum2(7, 35); // 42
}
"#;
    assert_eq!(code(src), 42);
}

#[test]
fn b12_inline_variadic_constructor_reads_int_args() {
    let src = r#"
#include <stdarg.h>
class Pack {
public:
  int total;
  Pack(int a, ...) {
    va_list ap;
    va_start(ap, a);
    int b = va_arg(ap, int);
    int c = va_arg(ap, int);
    va_end(ap);
    total = a + b + c;
  }
};
int main(void) {
  Pack p(10, 20, 12);
  return p.total;
}
"#;
    assert_eq!(code(src), 42);
}

#[test]
fn b12_out_of_line_variadic_constructor_reads_fp_arg() {
    let src = r#"
#include <stdarg.h>
class Pack {
public:
  int total;
  Pack(int a, ...);
};
Pack::Pack(int a, ...) {
  va_list ap;
  va_start(ap, a);
  double d = va_arg(ap, double);
  va_end(ap);
  total = a + (int)d;
}
int main(void) {
  Pack p(40, 2.75);
  return p.total;
}
"#;
    assert_eq!(code(src), 42);
}
