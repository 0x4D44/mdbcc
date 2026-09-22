//! Win64 64-bit integer arithmetic oracle.
//!
//! Historically the integer path emitted hardcoded 32-bit opcodes for ALL
//! widths and `expr_type` typed every integer literal as `int`, so a
//! `long long` (8-byte) operation silently miscompiled on Win64:
//!   * a shift count >= 32 wrapped mod 32 (x86 uses only CL's low 5 bits),
//!     so `x >> 32` returned the value unchanged ("lo == hi");
//!   * 64-bit divide used `cdq` (32-bit sign-extend) instead of `cqo`,
//!     yielding wrong quotients or a #DE crash;
//!   * add/sub/mul lost carry/borrow across the 32-bit boundary.
//!
//! The fix is three-part: `gen_intop64` (REX.W instruction forms),
//! `op64`/`extend_rax_to_64` operand setup in `gen_binary`, and 64-bit
//! literal typing (magnitude rule in `expr_type` + a Cast wrap for small
//! `LL`-suffixed literals in the parser).
//!
//! Each case is constructed so the CORRECT 64-bit result and the BUGGY
//! 32-bit result differ unambiguously, and so it sidesteps the
//! `0x8000_0000..=0xFFFF_FFFF` range (which mdbcc models as signed `int`,
//! an orthogonal pre-existing choice): every operand is either a `long
//! long` variable (small positive init) or a literal clearly past 2^32.
//! RailC avoids u64 in its hot paths, so these guard the gap RailC's
//! single shape can't expose.

#![cfg(windows)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use mdbcc::compile_to_pe;

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct TempExe(PathBuf);

impl TempExe {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!("mdbcc_i64_{}_{}.exe", std::process::id(), n));
        TempExe(p)
    }
}

impl Drop for TempExe {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn run_return(expr: &str) -> i32 {
    run_body(&format!("return {expr};"))
}

fn run_body(body: &str) -> i32 {
    let src = format!("int main(void) {{ {body} }}");
    let exe = compile_to_pe(src.as_bytes()).expect("compile ok");
    let tmp = TempExe::new();
    std::fs::write(&tmp.0, &exe).expect("write exe");
    let status = Command::new(&tmp.0)
        .status()
        .unwrap_or_else(|e| panic!("failed to launch generated exe: {e}"));
    status.code().expect("process returned an exit code")
}

// ---- shifts -------------------------------------------------------------

#[test]
fn u64_shift_right_takes_high_bits() {
    // 0xAABBCCDD11223344 >> 40 == 0xAABBCC. Buggy path shifts the low dword
    // (0x11223344) by 40&31==8 -> 0x00112233.
    assert_eq!(
        run_return("(0xAABBCCDD11223344ULL >> 40) == 0xAABBCCULL ? 7 : 0"),
        7
    );
}

#[test]
fn u64_shift_left_clears_low_bits() {
    // 1 << 40 == 0x10000000000. Buggy path: 1 << (40&31==8) == 256.
    assert_eq!(run_return("(1ULL << 40) == 0x10000000000ULL ? 7 : 0"), 7);
}

#[test]
fn i64_signed_shift_right_positive() {
    // 0x1122334455667788 >> 40 == 0x112233 (sar, value positive).
    assert_eq!(
        run_return("(0x1122334455667788LL >> 40) == 0x112233LL ? 7 : 0"),
        7
    );
}

#[test]
fn i64_negative_arithmetic_shift_right() {
    // -1 >> 40 == -1 (sar keeps the sign). Must be 64-bit `sar rax,cl`.
    assert_eq!(
        run_body("long long n = -1; return (n >> 40) == -1 ? 7 : 0;"),
        7
    );
}

#[test]
fn i64_negative_value_arithmetic_shift() {
    // A negative 64-bit value built by subtraction, then arithmetic-shifted:
    // (0x100000000 - 0x300000000) = -0x200000000 = 0xFFFFFFFE00000000;
    // >> 33 (signed) == -1. Buggy 32-bit sub+shift gives 0.
    assert_eq!(
        run_body(
            "long long lo = 0x100000000LL; long long hi = 0x300000000LL; \
             return ((lo - hi) >> 33) == -1 ? 7 : 0;"
        ),
        7
    );
}

// ---- add / sub / mul carry across the 32-bit boundary -------------------

#[test]
fn u64_add_carries_past_32_bits() {
    // 4 * 0x40000000 (=2^30) == 0x100000000 (=2^32) via repeated 64-bit add.
    // Buggy 32-bit add never carries into the high dword.
    assert_eq!(
        run_body("long long a = 0x40000000LL; return (a + a + a + a) == 0x100000000LL ? 7 : 0;"),
        7
    );
}

#[test]
fn u64_subtract_borrows_from_high_dword() {
    // 0x500000000 - 0x100000000 == 0x400000000. Buggy 32-bit sub on the (zero)
    // low dwords gives 0, never borrowing across the boundary.
    assert_eq!(
        run_return("(0x500000000ULL - 0x100000000ULL) == 0x400000000ULL ? 7 : 0"),
        7
    );
}

#[test]
fn u64_multiply_keeps_high_product() {
    // 0x100000001 * 3 == 0x300000003. Buggy `imul eax,ecx` gives 3.
    assert_eq!(
        run_return("(0x100000001ULL * 3ULL) == 0x300000003ULL ? 7 : 0"),
        7
    );
}

// ---- divide / modulo (cqo/cqo-free vs cdq) ------------------------------

#[test]
fn u64_divide_uses_full_dividend() {
    // 0x123456789A / 2 == 0x91A2B3C4D. Buggy 32-bit divide works on the low
    // dword only (0x3456789A / 2 == 0x1A2B3C4D).
    assert_eq!(
        run_return("(0x123456789AULL / 2ULL) == 0x91A2B3C4DULL ? 7 : 0"),
        7
    );
}

#[test]
fn u64_modulo_uses_full_dividend() {
    // 0x123456789A % 7 == 6. Buggy 32-bit modulo on the low dword gives 4.
    assert_eq!(run_return("(0x123456789AULL % 7ULL) == 6ULL ? 7 : 0"), 7);
}

#[test]
fn i64_signed_divide_high_dividend() {
    // 0x200000000 / 2 == 0x100000000. Requires `cqo; idiv rcx` — a 32-bit
    // `cdq; idiv ecx` divides the (zero) low dword and yields 0.
    assert_eq!(
        run_body("long long n = 0x200000000LL; return (n / 2) == 0x100000000LL ? 7 : 0;"),
        7
    );
}

// ---- mixed-width promotion ----------------------------------------------

#[test]
fn i64_plus_positive_int() {
    // long long + (positive) int. 0x100000000 + 5 == 0x100000005.
    assert_eq!(
        run_body(
            "int i = 5; long long x = 0x100000000LL; return (x + i) == 0x100000005LL ? 7 : 0;"
        ),
        7
    );
}

#[test]
fn i64_plus_negative_int_sign_extends() {
    // long long + (signed) int: the int operand must be sign-extended to 64
    // bits before the add. 0x200000000 + (-1) == 0x1FFFFFFFF.
    assert_eq!(
        run_body(
            "int j = -1; long long y = 0x200000000LL; return (y + j) == 0x1FFFFFFFFLL ? 7 : 0;"
        ),
        7
    );
}

// ---- bitwise / comparison of full 64-bit operands -----------------------

#[test]
fn u64_bitand_keeps_high_half() {
    // 0xFF00FF00FF00FF00 & 0x00FFFF0000FFFF00 == 0x0000FF000000FF00.
    assert_eq!(
        run_return(
            "(0xFF00FF00FF00FF00ULL & 0x00FFFF0000FFFF00ULL) == 0x0000FF000000FF00ULL ? 7 : 0"
        ),
        7
    );
}

#[test]
fn u64_compare_uses_full_width() {
    // Two values equal in their low 32 bits but different in the high half
    // must compare NOT-equal. Buggy 32-bit `cmp eax,ecx` would call them equal.
    assert_eq!(run_return("(0x100000001ULL == 0x200000001ULL) ? 0 : 7"), 7);
}

#[test]
fn ull_suffix_u32_max_literal_is_64bit() {
    // B-02: the ULL suffix is load-bearing even when the magnitude still fits
    // an unsigned 32-bit value. Buggy typing treats 0xFFFFFFFFULL as a signed
    // 32-bit int, then the 64-bit add sign-extends it to -1 and yields 0.
    assert_eq!(
        run_return("(0xFFFFFFFFULL + 1ULL) == 0x100000000ULL ? 7 : 0"),
        7
    );
}

#[test]
fn ll_suffix_high_u32_literal_is_positive_i64() {
    // The signed LL spelling has the same boundary hole: 0x80000000LL fits
    // signed 64-bit and must not become a sign-extended 32-bit -2147483648.
    assert_eq!(run_return("(0x80000000LL >> 31) == 1LL ? 7 : 0"), 7);
}

#[test]
fn const_eval_unsigned_u64_shift_is_logical() {
    // B-03: constant folding must use unsigned semantics for an unsigned
    // 64-bit right shift. Buggy const_eval folds the shift arithmetically to
    // -1, selects the -1 array bound, and rejects the program.
    assert_eq!(
        run_body(
            "char a[(0x8000000000000000ULL >> 63) == 1ULL ? 42 : -1]; \
             return (int)sizeof(a);"
        ),
        42
    );
}

#[test]
fn const_eval_unsigned_32bit_shift_uses_32bit_width() {
    // Review edge for B-03: fixing unsigned shifts with a blanket u64 logical
    // shift would make ((unsigned)-1) >> 31 fold to 0x1FFFFFFFF instead of 1.
    assert_eq!(
        run_body("char a[(((unsigned)-1) >> 31) == 1 ? 9 : -1]; return (int)sizeof(a);"),
        9
    );
}

#[test]
fn const_eval_unsigned_shift_uses_widest_operand() {
    // Mixed unsigned widths should fold with the wider integer conversion.
    // A first-unsigned-operand shortcut would treat this as 32-bit and fold to 0.
    assert_eq!(
        run_body(
            "char a[((((unsigned)1 + 0x8000000000000000ULL) >> 63) == 1ULL) \
             ? 11 : -1]; return (int)sizeof(a);"
        ),
        11
    );
}

// ---- unary negate / bitwise-not over the full width ---------------------

#[test]
fn i64_unary_negate_full_width() {
    // -(0x300000000) == 0xFFFFFFFD00000000; (>> 33 arithmetic) == -2. A buggy
    // `neg eax` negates only the low dword and leaves the value positive.
    assert_eq!(
        run_body("long long x = 0x300000000LL; return ((-x) >> 33) == -2 ? 7 : 0;"),
        7
    );
}

#[test]
fn i64_bitnot_full_width() {
    // ~0 == -1 (all 64 bits set). A buggy `not eax` sets only the low dword,
    // leaving the high half zero (0x00000000FFFFFFFF != -1).
    assert_eq!(run_body("long long x = 0; return (~x == -1) ? 7 : 0;"), 7);
}
