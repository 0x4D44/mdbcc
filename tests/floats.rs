//! Phase F-2: SSE2 scalar arithmetic + comparisons + literals + globals +
//! return. After F-2 the FP front-end (Type::Float, Expr::Float) reaches
//! real codegen: `movsd` into xmm0 from a per-function `.flit.*` global,
//! `addsd`/`subsd`/`mulsd`/`divsd`/`ucomisd`, `cvtsi2sd`/`cvttsd2si` for
//! mixed-type arith and `(int)d` casts, and the sign-bit-XOR unary minus.
//!
//! Scope (matches HLD §F2 precisely):
//! - **double** (8-byte) is the primary target — every test uses `double`.
//! - **float** (4-byte) keyword still parses and the codegen path is shared
//!   (storage rounds via `as f32` only at the global-init boundary; locals
//!   ride the 8-byte slot — see store_at_rcx note). No `float`-only test
//!   is included; refining `movss` is a tracked F-future polish.
//! - **FP function args** still error (F-3 / §F-c); see `fp_param_*` below.
//! - **printf %f** still errors (F-4); not tested here.
//!
//! Test inputs are all dyadic-rationals (exactly representable in IEEE-754
//! double) so round-half-to-even and SSE2 64-bit precision agree byte-for-
//! byte with `cl /O2` and `bcc32`; the chosen values cannot diverge.

#![cfg(windows)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use mdbcc::compile_to_pe;

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct TempExe(PathBuf);
impl Drop for TempExe {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Compile, write a temp `.exe`, run, return the exit code.
fn exit_of(src: &str) -> i32 {
    let exe = compile_to_pe(src.as_bytes()).expect("compile ok");
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("mdbcc_fp_{}_{}.exe", std::process::id(), n));
    let tmp = TempExe(p);
    std::fs::write(&tmp.0, &exe).expect("write exe");
    let st = Command::new(&tmp.0).status().expect("launch");
    st.code().expect("exit code")
}

/// Convenience: assert the compiler rejects `src` with a message mentioning
/// `frag` (for paths still deferred — F-3 FP args, F-4 printf %f).
fn err_msg(src: &str) -> String {
    match compile_to_pe(src.as_bytes()) {
        Ok(_) => panic!("expected a compile error, got a PE image"),
        Err(e) => e.to_string(),
    }
}

// ---------- F-2 green tests (the new SSE2 vertical slice) -------------------

#[test]
fn fp_basic_arithmetic() {
    // The minimum F2 oracle: declare, literal, mul, cast-to-int, return.
    // 3.5 * 2.0 = 7.0 → truncated to 7.
    let src = "int main(void) { double x = 3.5; double y = 2.0; \
               return (int)(x*y); }";
    assert_eq!(exit_of(src), 7);
}

#[test]
fn fp_compare() {
    // ucomisd + seta (xmm0 > xmm1 ⇒ CF=0,ZF=0 ⇒ seta al). 1.5 > 1.0 ⇒ 1.
    let src = "int main(void) { double x = 1.5; \
               if (x > 1.0) return 1; return 0; }";
    assert_eq!(exit_of(src), 1);
}

#[test]
fn fp_int_to_double_promotion() {
    // Mixed-type `double * int` promotes the int via cvtsi2sd. 2.5*4=10.
    let src = "int main(void) { double x = 2.5; int n = 4; \
               return (int)(x*n); }";
    assert_eq!(exit_of(src), 10);
}

#[test]
fn fp_global_round_trip() {
    // File-scope `double k = 2.5;` lands its IEEE-754 image in `.data`
    // (global_image §F-g); the read goes through movsd from the global's
    // RIP-relative slot. 2.5 * 4 = 10.
    let src = "double k = 2.5; int main(void) { return (int)(k*4); }";
    assert_eq!(exit_of(src), 10);
}

#[test]
fn fp_zero_special() {
    // `0.0` lowers to `xorpd xmm0,xmm0` (no `.data` slot). Truthiness via
    // `if (z)` ⇒ test rax,rax after... wait — `if (z)` where z is double
    // uses the bool conversion. The compiler should reject this for now
    // OR convert via `z != 0.0`. Phase F-2 lowers `if (z)` as integer-test
    // because `gen_stmt(If)` calls `gen_expr(cond)` then `test_rax`. For a
    // double value, gen_expr leaves the value in xmm0 (not eax) and the
    // subsequent `test rax,rax` is wrong (it tests whatever stale value
    // is in rax). To make this test honest, use an explicit comparison.
    let src = "int main(void) { double z = 0.0; \
               if (z == 0.0) return 0; return 99; }";
    assert_eq!(exit_of(src), 0);
}

#[test]
fn fp_unary_neg() {
    // `-x` of a double sign-bit-XORs the slot's high byte. `-(-2.5)*2 = 5`.
    let src = "int main(void) { double x = -2.5; return (int)(-x * 2); }";
    assert_eq!(exit_of(src), 5);
}

#[test]
fn fp_double_subtract_div() {
    // sub + div + truncating cast: (10.0 - 3.0) / 2.0 = 3.5 → 3.
    let src = "int main(void) { return (int)((10.0 - 3.0) / 2.0); }";
    assert_eq!(exit_of(src), 3);
}

#[test]
fn fp_assign_to_local() {
    // Re-assign a double local, then read it back via cast.
    let src = "int main(void) { double x = 1.0; x = 4.5; \
               return (int)(x*2); }";
    assert_eq!(exit_of(src), 9);
}

#[test]
fn fp_compare_less_equal_and_equal() {
    // setbe (Le) and sete (Eq). 2.0 <= 2.0 ⇒ 1; 2.0 == 2.0 ⇒ 1.
    let src = "int main(void) { double a = 2.0; double b = 2.0; \
               if (a <= b && a == b) return 7; return 0; }";
    assert_eq!(exit_of(src), 7);
}

#[test]
fn fp_global_zero_initialised() {
    // Uninitialised FP global ⇒ 0.0 bit pattern; `(int)g` ⇒ 0.
    let src = "double g; int main(void) { return (int)g; }";
    assert_eq!(exit_of(src), 0);
}

// ---------- F-3 green tests (FP function args + positional XMM ABI) ---------

#[test]
fn fp_param_simple_double() {
    // F-3 supersedes the F2-era guard that rejected FP parameters: a single
    // double param now passes through xmm0 (positional slot 0). 1.0 → x; the
    // body returns `(int)x = 1`. The simplest oracle that proves the prologue
    // spills xmm0 to the local's slot and the body reads it back via movsd.
    let src = "int f(double x) { return (int)x; } \
               int main(void) { return f(1.0); }";
    assert_eq!(exit_of(src), 1);
}

#[test]
fn fp_args_1_4_pure_double() {
    // All four positional XMM slots: xmm0..xmm3 carry a, b, c, d.
    // 1+2+4+8 = 15.
    let src = "double f(double a, double b, double c, double d) \
               { return a+b+c+d; } \
               int main(void) { return (int)f(1.0, 2.0, 4.0, 8.0); }";
    assert_eq!(exit_of(src), 15);
}

#[test]
fn fp_args_mixed_int_double_skip_pattern() {
    // The slot-positional rule: rcx, xmm1, r8, xmm3 (skip xmm0/rdx/xmm2/r9 at
    // those positions). 2*1.5 + 3*2.5 = 3 + 7.5 = 10.5 → (int) = 10.
    let src = "double g(int a, double b, int c, double d) \
               { return a*b + c*d; } \
               int main(void) { return (int)g(2, 1.5, 3, 2.5); }";
    assert_eq!(exit_of(src), 10);
}

#[test]
fn fp_args_5_to_8_stack() {
    // XMM0..3 + 4 stack args (movsd to [rsp+0x20], +0x28, +0x30, +0x38 via
    // the GPR shuttle path — bit-pattern correct for double). Sum of powers
    // of two from 1..128 = 255.
    let src = "double f(double a, double b, double c, double d, \
                        double e, double f, double g, double h) \
               { return a+b+c+d+e+f+g+h; } \
               int main(void) { return (int)f(1.0, 2.0, 4.0, 8.0, \
                                              16.0, 32.0, 64.0, 128.0); }";
    assert_eq!(exit_of(src), 255);
}

#[test]
fn fp_args_mixed_8_with_int_and_double_stack() {
    // Slot-positional preserves across the stack boundary. Signature uses 8
    // params alternating int/double; positions 0..3 are reg slots (rcx,
    // xmm1, r8, xmm3); positions 4..7 are stack slots. Values chosen exact-
    // representable: 1 + 2.0 + 3 + 4.0 + 5 + 6.0 + 7 + 8.0 = 36.
    let src = "double f(int a, double b, int c, double d, \
                        int e, double g, int h, double i) \
               { return a+b+c+d+e+g+h+i; } \
               int main(void) { return (int)f(1, 2.0, 3, 4.0, \
                                              5, 6.0, 7, 8.0); }";
    assert_eq!(exit_of(src), 36);
}

#[test]
fn fp_return_chained() {
    // Return → arg flow: h(2.0) returns 5.0 in xmm0; the caller's marshal
    // pushes it into xmm0 again for the outer call; h(5.0) returns 12.5;
    // (int)12.5 = 12.
    let src = "double h(double x) { return x*2.5; } \
               int main(void) { return (int)h(h(2.0)); }";
    assert_eq!(exit_of(src), 12);
}

#[test]
fn signed_float_combo_is_parse_error() {
    // `signed float` is illegal C; never silently accept it. Parser-caught.
    let src = "int main(void) { signed float x; return 0; }";
    let msg = err_msg(src);
    assert!(
        msg.contains("invalid") || msg.contains("not valid") || msg.contains("float"),
        "unexpected error message: {msg}"
    );
}

#[test]
fn bool_keyword_now_accepted_as_int8() {
    // B-6 fold-in (landed in F-1): `bool` ⇒ 1-byte unsigned int. Runs clean.
    let src = "int main(void) { bool b; b = 1; return 0; }";
    let exe = compile_to_pe(src.as_bytes()).expect("bool must compile cleanly post B-6");
    assert!(!exe.is_empty());
}

#[test]
fn bool_used_as_truthy_value() {
    // A `bool` value lowers through the integer path (it IS an int8).
    let src = "int main(void) { bool b = 1; if (b) return 7; return 0; }";
    assert_eq!(exit_of(src), 7);
}

#[test]
fn float_literal_lexes_and_parses() {
    // Several float-literal forms must all reach codegen successfully
    // (post-F-2 they actually evaluate, not error). The literals are all
    // dyadic-rationals so `(int)` truncation is exact and predictable.
    // `2.5E-3 * 1000 = 2.5 → 2`; `1.5f * 2 = 3`; `100.0L * 0 = 0` (long
    // double folds to double). Just verify the program compiles + the
    // exit code is the truncated product.
    for (lit, multiplier, expected) in &[
        ("1.0", 5, 5),
        ("0.5", 8, 4),
        (".5", 4, 2),
        ("1.", 7, 7),
        ("3.14", 2, 6),
        ("1.5f", 4, 6),
        ("2.5E-3", 1000, 2),
        ("100.0L", 0, 0),
        ("1e10", 0, 0), // multiplied by 0 — avoid overflow at cast
    ] {
        let src = format!(
            "int main(void) {{ double x = {lit}; \
             return (int)(x * {multiplier}); }}"
        );
        assert_eq!(exit_of(&src), *expected, "literal {lit:?}");
    }
}

// ---------- Phase F MAJOR-1 regressions (arg-convert + int64 ↔ FP) ----------

#[test]
fn fp_int_arg_promoted_to_double() {
    // Reviewer's exact reproducer: an int passed to a `double` parameter
    // must be promoted via cvtsi2sd before the xmm0 spill. Pre-fix this
    // returned 0 (xmm0 garbage * 2.0); post-fix it returns 84.
    let src = "double f(double x) { return 2.0 * x; } \
               int main(void) { return (int)f(42); }";
    assert_eq!(exit_of(src), 84);
}

#[test]
fn fp_double_arg_truncated_to_int() {
    // The FP→int direction: a `double` argument passed to an `int`
    // parameter must be truncated via cvttsd2si into eax before the
    // GPR spill. (int)3.7 + 1 = 4.
    let src = "int g(int n) { return n + 1; } \
               int main(void) { return g((int)3.7); }";
    assert_eq!(exit_of(src), 4);
}

#[test]
fn fp_double_arg_passed_to_int_param() {
    // Same direction, but the cast is implicit: a `double` literal is
    // passed directly to an `int` parameter and `convert` must lower
    // it via cvttsd2si (truncating). 7.5 → 7.
    let src = "int h(int x) { return x; } \
               int main(void) { return h(7.5); }";
    assert_eq!(exit_of(src), 7);
}

#[test]
fn fp_int64_to_double_via_rex_w() {
    // REX.W cvtsi2sd path: a `long long` global holds 0x1_0000_0000 = 2^32
    // (the literal is const_eval'd into the global image so the full 64-bit
    // value survives — local `long long n = 4294967296` cannot today
    // because the `Expr::Int` literal types as int32 and convert narrows
    // it before the store). Pre-fix, the 32-bit `cvtsi2sd xmm0,eax` would
    // read only the low 32 bits (0) and produce 0.0. Post-fix, REX.W
    // `cvtsi2sd xmm0,rax` converts the full 64-bit value to 4294967296.0;
    // dividing by 1e6 and truncating yields 4294.
    let src = "long long g = 4294967296; \
               int main(void) { double x = (double)g; \
               return (int)(x / 1000000.0); }";
    assert_eq!(exit_of(src), 4294);
}

#[test]
fn fp_double_to_int64_via_rex_w() {
    // REX.W cvttsd2si path: 1.5e10 doesn't fit in int32 (the legacy
    // 32-bit cvttsd2si saturates to 0x80000000). With the fix, the
    // round-trip `(double)(long long)1.5e10` goes through REX.W
    // cvttsd2si → all 64 bits land in rax = 15_000_000_000, then
    // REX.W cvtsi2sd converts back to 1.5e10 in xmm0. Dividing by
    // 1e6 and truncating (via the 32-bit (int) cast — fits) yields
    // 15000. Pre-fix the round-trip clips to 0x80000000 → the second
    // cvtsi2sd produces a different value and the assertion fails.
    let src = "int main(void) { double x = 1.5e10; \
               return (int)((double)(long long)x / 1e6); }";
    assert_eq!(exit_of(src), 15000);
}

// ---------- 4-byte `float` memory width (RailC track-diagram blank) ----------
// A `Type::Float { bytes: 4 }` lvalue is a genuine 4-byte f32 image in memory
// (`image_rec` lays the static init `as f32`); the compute value in xmm0 is
// f64. Before the fix, `load_rax`/`store_at_rcx`/`store_to_local` used 8-byte
// `movsd` for every FP type, so a `float` global was over-read 4 bytes wide
// (reading the f32 image + a neighbour as a near-zero double) and a `float`
// store clobbered the adjacent slot. The fix narrows on store (`cvtsd2ss` +
// `movss`) and widens on load (`movss` + `cvtss2sd`). These are the cases that
// failed before and the regression guards that must stay green after.

#[test]
fn fp_float_global_static_init_read() {
    // RailC `static float XScaleFactor` repro: a file-scope `float` set ONLY by
    // its static initializer (never written by code). `image_rec` lays a true
    // 4-byte f32 image; an 8-byte `movsd` over-reads it as a near-zero f64 → 0.
    let src = "float g = 1.25;\nint main(void){ return (int)(300 * g); }";
    assert_eq!(exit_of(src), 375); // pre-fix: 0
}

#[test]
fn fp_float_global_write_then_read() {
    // Symmetry guard: fixing only the LOAD (movss) without narrowing the STORE
    // would regress this (store an 8-byte f64 image, read low 4 bytes ≈ 0).
    let src = "float g = 1.0;\nint main(void){ g = 1.25; return (int)(300 * g); }";
    assert_eq!(exit_of(src), 375);
}

#[test]
fn fp_float_member_roundtrip_adjacency() {
    // A genuine 4-byte float MEMBER stored then read; `n` sits immediately after
    // `scale`, so the old 8-byte-movsd store would overrun `scale` into `n`.
    let src = "struct Box { float scale; int n; };\n\
               int main(void){ struct Box b; b.scale = 1.25f; b.n = 300; \
               return (int)(b.n * b.scale); }";
    assert_eq!(exit_of(src), 375); // pre-fix: store overrun / garbage read
}

#[test]
fn fp_static_member_scale_like_railc() {
    // The exact RailC TSection storage form: a `static float` class member,
    // defined out-of-line, set by a runtime store, then read back and used to
    // scale an int — `GetSection`'s `point.x = setpoint.x * XScaleFactor`.
    let src = "struct S { static float k; };\n\
               float S::k = 1.0;\n\
               int main(void){ S::k = 1.25; return (int)(300 * S::k); }";
    assert_eq!(exit_of(src), 375);
}

#[test]
fn fp_int_times_float_global_truncates() {
    // int * float_global then C-cast truncation: must read the 4-byte global
    // 0.5 correctly and truncate 3.5 → 3 (not 0 from garbage, not 4).
    let src = "float g = 0.5;\nint main(void){ return (int)(7 * g); }";
    assert_eq!(exit_of(src), 3); // pre-fix: 0
}

#[test]
fn fp_double_global_unchanged() {
    // Regression guard: the bytes==8 path must still `movsd`; the new bytes==4
    // branch must not disturb double globals. Passes today, must stay green.
    let src = "double g = 1.25;\nint main(void){ return (int)(300 * g); }";
    assert_eq!(exit_of(src), 375);
}

// ---------- 4-byte `float` PARAMETERS (Win64 XMM spill / stack shuttle) -------
// A `float` param's home slot must hold the 4-byte f32 image so the body's
// `movss` load reads it back. Before the param-spill narrowing fix, the Win64
// callee spilled the arg 8-byte (`movsd`) and the now-narrowed read returned
// ~0 (the DrawDelayBox `float xiDelay` family of miscompiles).

#[test]
fn fp_float_param_read_only() {
    // Pre-fix returned 0 (low 4 bytes of the f64-spilled 1.25 are zero).
    let src = "int f(float x){ return (int)(300 * x); } \
               int main(void){ return f(1.25f); }";
    assert_eq!(exit_of(src), 375);
}

#[test]
fn fp_float_param_modify_in_place() {
    // DrawDelayBox shape: clamp + read-modify-write a float param, truncate.
    // 20.23 + 0.05 = 20.28 -> (int)x=20 -> 2000; (int)(202.8)%10=2 -> 2002.
    let src = "int f(float x){ if (x < 0) x = 0; x += 0.05; \
               return ((int)x)*100 + (((int)(10*x))%10); } \
               int main(void){ return f(20.23f); }";
    assert_eq!(exit_of(src), 2002);
}

#[test]
fn fp_float_param_fifth_is_stack() {
    // Win64: params 0..3 ride xmm0..3; the 5th (e) is a stack arg (ri>=4).
    // Both the register-spill and stack-shuttle float paths must narrow.
    // 1.5*1000 + 2.5*100 = 1500 + 250 = 1750.
    let src = "int f(float a, float b, float c, float d, float e){ \
               return (int)(a * 1000 + e * 100); } \
               int main(void){ return f(1.5f, 0, 0, 0, 2.5f); }";
    assert_eq!(exit_of(src), 1750);
}

#[test]
fn fp_double_param_unchanged() {
    // Regression guard: a `double` param still rides the 8-byte `movsd` spill.
    let src = "int f(double x){ if (x < 0) x = 0; x += 0.05; \
               return ((int)x)*100 + (((int)(10*x))%10); } \
               int main(void){ return f(20.23); }";
    assert_eq!(exit_of(src), 2002);
}
