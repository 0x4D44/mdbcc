//! O1-style hand-expected oracle for printf format specifiers (fast,
//! in-process; no external toolchain). Broad three-way coverage lives in
//! the differential corpus (`tests/corpus/portable/printf_*.c`); this file
//! is the tight TDD loop with hand-computed C-standard expectations.
//!
//! Scope (mdbcc v1): width, `-`, `0`, `+`, space, `#`, string precision,
//! length-modifier skipping. Integer precision / `*` are deferred and
//! rejected with a clear compile error (asserted by
//! `deferred_features_error`).

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

fn out(src: &str) -> String {
    let exe = compile_to_pe(src.as_bytes()).expect("compile ok");
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("mdbcc_pf_{}_{}.exe", std::process::id(), n));
    let tmp = TempExe(p);
    std::fs::write(&tmp.0, &exe).expect("write exe");
    let o = Command::new(&tmp.0).output().expect("launch");
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn pf(call: &str) -> String {
    out(&format!(
        "#include <stdio.h>\nint main(void){{ {call} return 0; }}\n"
    ))
}

#[test]
fn width_and_left_justify() {
    assert_eq!(pf(r#"printf("[%5d]", 42);"#), "[   42]");
    assert_eq!(pf(r#"printf("[%-5d]", 42);"#), "[42   ]");
    assert_eq!(pf(r#"printf("[%5d]", -42);"#), "[  -42]");
    assert_eq!(pf(r#"printf("[%5u]", 7u);"#), "[    7]");
    assert_eq!(pf(r#"printf("[%6x]", 171u);"#), "[    ab]");
    assert_eq!(pf(r#"printf("[%-6x]", 171u);"#), "[ab    ]");
    assert_eq!(pf(r#"printf("[%8s]", "hi");"#), "[      hi]");
    assert_eq!(pf(r#"printf("[%-8s]", "hi");"#), "[hi      ]");
    assert_eq!(pf(r#"printf("[%3c]", 'Q');"#), "[  Q]");
    assert_eq!(pf(r#"printf("[%-3c]", 'Q');"#), "[Q  ]");
    assert_eq!(pf(r#"printf("[%2d]", 12345);"#), "[12345]");
}

#[test]
fn zero_flag_and_sign_placement() {
    assert_eq!(pf(r#"printf("[%05d]", 42);"#), "[00042]");
    assert_eq!(pf(r#"printf("[%05d]", -42);"#), "[-0042]");
    assert_eq!(pf(r#"printf("[%08x]", 3735928559u);"#), "[deadbeef]");
    assert_eq!(pf(r#"printf("[%04X]", 42u);"#), "[002A]");
    assert_eq!(pf(r#"printf("[%06u]", 1234u);"#), "[001234]");
    // '-' overrides '0' -> left-justify with spaces (C semantics).
    assert_eq!(pf(r#"printf("[%-08d]", 42);"#), "[42      ]");
}

#[test]
fn sign_flags_and_alternate_forms() {
    assert_eq!(
        pf(r#"printf("[%+d][%+d][% d][% d]", 5, -5, 5, -5);"#),
        "[+5][-5][ 5][-5]"
    );
    assert_eq!(pf(r#"printf("[%+05d]", 42);"#), "[+0042]");
    assert_eq!(pf(r#"printf("[% 05d]", 42);"#), "[ 0042]");
    // '+' takes precedence over the space flag.
    assert_eq!(pf(r#"printf("[%+ d]", 7);"#), "[+7]");

    assert_eq!(
        pf(r#"printf("[%#x][%#X][%#o]", 171u, 171u, 10u);"#),
        "[0xab][0XAB][012]"
    );
    assert_eq!(pf(r#"printf("[%#08x]", 42u);"#), "[0x00002a]");
    assert_eq!(pf(r#"printf("[%#x][%#o]", 0u, 0u);"#), "[0][0]");
    assert_eq!(pf(r#"printf("[%#.0f]", 7.0);"#), "[7.]");
}

#[test]
fn string_precision() {
    assert_eq!(pf(r#"printf("[%.3s]", "hello");"#), "[hel]");
    assert_eq!(pf(r#"printf("[%8.3s]", "hello");"#), "[     hel]");
    assert_eq!(pf(r#"printf("[%-8.3s]", "hello");"#), "[hel     ]");
    assert_eq!(pf(r#"printf("[%.10s]", "abc");"#), "[abc]");
    assert_eq!(pf(r#"printf("[%.0s]", "abc");"#), "[]");
}

#[test]
fn length_modifiers_ignored() {
    assert_eq!(
        pf("long a; a = -123456; printf(\"[%ld]\", a);"),
        "[-123456]"
    );
    assert_eq!(
        pf("unsigned long b; b = 4000000000UL; printf(\"[%lu]\", b);"),
        "[4000000000]"
    );
    assert_eq!(
        pf("long a; a = -123456; printf(\"[%08ld]\", a);"),
        "[-0123456]"
    );
    assert_eq!(
        pf("long a; a = -123456; printf(\"[%8ld]\", a);"),
        "[ -123456]"
    );
}

#[test]
fn deferred_features_are_explicit_errors() {
    // Never silently wrong: each must fail to compile (not misformat).
    for call in [
        r#"printf("[%.5d]", 42);"#,
        r#"printf("[%*d]", 5, 42);"#,
        // Phase F-5 deferred conversions.
        r#"printf("[%g]", 1.0);"#,
        r#"printf("[%e]", 1.0);"#,
        r#"printf("[%G]", 1.0);"#,
        r#"printf("[%E]", 1.0);"#,
        // Phase F-4 v1: %f requires an FP argument; an int arg is a clear error
        // (avoids reinterpreting int bits as a double).
        r#"printf("[%f]", 1);"#,
    ] {
        let src = format!("#include <stdio.h>\nint main(void){{ {call} return 0; }}\n");
        assert!(
            compile_to_pe(src.as_bytes()).is_err(),
            "expected a clear compile error for deferred spec: {call}"
        );
    }
}

// ---------- Phase F-4 — printf %f (hand-emitted dtoa) ----------------------
//
// Every test input is a dyadic-rational (powers of 2 or finite sums thereof),
// or a value (like 3.14) that the chosen precision round-trips exactly across
// cl /O2 and bcc32 5.5.1 and mdbcc's simple round-half-up dtoa. No 0.55 /
// 2.675 / etc. — those land on a half-step where banker's rounding diverges
// from round-half-up.

#[test]
fn printf_f_basic() {
    // Default precision is 6 (C standard).
    assert_eq!(pf(r#"printf("%f", 3.14);"#), "3.140000");
    assert_eq!(pf(r#"printf("%f", 0.5);"#), "0.500000");
    assert_eq!(pf(r#"printf("%f", 1.5);"#), "1.500000");
    assert_eq!(pf(r#"printf("%f", 2.0);"#), "2.000000");
}

#[test]
fn printf_f_precision_0_to_10() {
    // %.0f: no decimal point, no fractional digits (whole-number inputs avoid
    // the half-rounding-mode divergence between round-half-up and banker's).
    assert_eq!(pf(r#"printf("%.0f", 7.0);"#), "7");
    assert_eq!(pf(r#"printf("%.0f", 0.0);"#), "0");
    // %.3f: three digits after the decimal.
    assert_eq!(pf(r#"printf("%.3f", 3.14);"#), "3.140");
    assert_eq!(pf(r#"printf("%.3f", 0.125);"#), "0.125");
    // %.10f: ten digits — exact for dyadic-rational inputs.
    assert_eq!(pf(r#"printf("%.10f", 0.5);"#), "0.5000000000");
    assert_eq!(pf(r#"printf("%.10f", 0.25);"#), "0.2500000000");
    // %.1f, %.2f mid-range.
    assert_eq!(pf(r#"printf("%.1f", 3.5);"#), "3.5");
    assert_eq!(pf(r#"printf("%.2f", 0.25);"#), "0.25");
}

#[test]
fn printf_f_precision_above_15() {
    assert_eq!(pf(r#"printf("%.16f", 0.5);"#), "0.5000000000000000");
    assert_eq!(pf(r#"printf("%.20f", 0.25);"#), "0.25000000000000000000");
}

#[test]
fn printf_f_negative() {
    assert_eq!(pf(r#"printf("%f", -3.5);"#), "-3.500000");
    assert_eq!(pf(r#"printf("%.2f", -0.25);"#), "-0.25");
    assert_eq!(pf(r#"printf("%.0f", -7.0);"#), "-7");
}

#[test]
fn printf_f_zero() {
    // +0.0 → "0.000000" (the xorpd-zero literal path).
    assert_eq!(pf(r#"printf("%f", 0.0);"#), "0.000000");
    assert_eq!(pf(r#"printf("%.3f", 0.0);"#), "0.000");
    assert_eq!(pf(r#"printf("%.0f", 0.0);"#), "0");
}

#[test]
fn printf_f_inf_nan() {
    // Runtime-produced specials via SSE2 default IEEE-754 results: 1.0/0.0 →
    // +inf, -1.0/0.0 → -inf, 0.0/0.0 → NaN. (Literal `1.0/0.0` won't parse
    // as `inf` — F-2's literal path rejects over-range inputs. The runtime
    // divsd produces the IEEE special exactly.)
    let src_pinf = "#include <stdio.h>\n\
                    int main(void){ double a = 1.0; double b = 0.0; \
                                    printf(\"%f\", a/b); return 0; }\n";
    assert_eq!(out(src_pinf), "inf");

    let src_ninf = "#include <stdio.h>\n\
                    int main(void){ double a = -1.0; double b = 0.0; \
                                    printf(\"%f\", a/b); return 0; }\n";
    assert_eq!(out(src_ninf), "-inf");

    let src_nan = "#include <stdio.h>\n\
                   int main(void){ double a = 0.0; double b = 0.0; \
                                   printf(\"%f\", a/b); return 0; }\n";
    assert_eq!(out(src_nan), "nan");
}

#[test]
fn printf_f_width_padding() {
    // Right-justified default (spaces on the left).
    assert_eq!(pf(r#"printf("[%10.2f]", 1.5);"#), "[      1.50]");
    assert_eq!(pf(r#"printf("[%10.2f]", -1.5);"#), "[     -1.50]");
    // Left-justify with '-' (spaces on the right).
    assert_eq!(pf(r#"printf("[%-10.2f]", 1.5);"#), "[1.50      ]");
    assert_eq!(pf(r#"printf("[%-10.2f]", -1.5);"#), "[-1.50     ]");
    // Zero-pad: zeros appear after the sign (or before the int part if no sign).
    assert_eq!(pf(r#"printf("[%010.2f]", 1.5);"#), "[0000001.50]");
    assert_eq!(pf(r#"printf("[%010.2f]", -1.5);"#), "[-000001.50]");
    // Width smaller than the rendered text: no truncation, no padding.
    assert_eq!(pf(r#"printf("[%2.2f]", 12.5);"#), "[12.50]");
}

#[test]
fn printf_f_combined() {
    // Several spec combinations in one call (validates accumulated byte
    // total + sequential format-spec dispatch).
    let src = "#include <stdio.h>\n\
               int main(void){ \
                 printf(\"%.2f %f %.0f\\n\", 0.5, 1.5, 3.0); \
                 return 0; }\n";
    assert_eq!(out(src), "0.50 1.500000 3\n");

    let src2 = "#include <stdio.h>\n\
                int main(void){ \
                  printf(\"[%-8.2f|%08.2f]\\n\", 1.5, 1.5); \
                  return 0; }\n";
    assert_eq!(out(src2), "[1.50    |00001.50]\n");
}
