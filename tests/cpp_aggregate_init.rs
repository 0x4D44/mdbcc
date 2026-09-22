//! J-9: aggregate (brace) initializers `{...}` for arrays and structs.
//!
//! Scope (Tick 57):
//! - Array of scalar values with given size: `int a[5] = {1,2,3,4,5};`
//! - Array with deduced size: `int a[] = {1,2,3};`
//! - Partial array init, rest zero: `int a[10] = {1,2,3};`
//! - Struct init by declaration order: `Point p = {3, 4};`
//! - Struct partial init, rest zero: `Point p = {3};`
//! - Nested aggregates: `struct Line { Point a, b; }; Line l = {{1,2},{3,4}};`
//! - Array of struct: `Point p[2] = {{1,2},{3,4}};`
//! - Trailing comma tolerated: `{1,2,3,}`.
//!
//! Out of scope (filed for J-9-future):
//! - Designated initializers `{.x = 3}` (C99/C++20).
//! - Empty `{}` brace-init (T x = {};).
//! - C++11 ctor brace-init `Point p{3,4};`.
//! - File-scope globals with brace-init — block-scope only in tick 57; the
//!   global path is explicitly rejected with a Grep-able phrase.

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
    p.push(format!("mdbcc_agginit_{}_{}.exe", std::process::id(), n));
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

fn differential_against_cl(src: &str, mdbcc_exit: i32) -> bool {
    if !o2_active() {
        return false;
    }
    let r = msvc_ref(src, Lang::Cpp);
    if !r.launched {
        return false;
    }
    let cl_stdout = String::from_utf8_lossy(&normalize_newlines(&r.stdout)).into_owned();
    // Pure exit-code differential for now (no I/O in these fixtures).
    assert!(
        cl_stdout.is_empty(),
        "cl produced unexpected stdout for an init-only test: {cl_stdout:?}"
    );
    assert_eq!(
        r.exit,
        Some(mdbcc_exit),
        "cl differential FAIL (exit): cl={:?} mdbcc={mdbcc_exit}",
        r.exit
    );
    true
}

// ===========================================================================
// 1. Array of scalars, full size given.
// ===========================================================================

#[test]
fn array_init_full_size_5_ints() {
    // Sum of {1,2,3,4,5} = 15.
    let src = "\
        int main(void) {\n\
          int a[5] = {1, 2, 3, 4, 5};\n\
          int s = 0; int i = 0;\n\
          while (i < 5) { s = s + a[i]; i = i + 1; }\n\
          return s;\n\
        }\n";
    assert_eq!(code(src), 15);
}

// ===========================================================================
// 2. Array with deduced size.
// ===========================================================================

#[test]
fn array_init_deduced_size() {
    // `int a[]` ⇒ size from list length ⇒ 3 ⇒ sizeof(a)/sizeof(*a) == 3.
    // Sum of {7,8,9} = 24.
    let src = "\
        int main(void) {\n\
          int a[] = {7, 8, 9};\n\
          int n = (int)(sizeof(a) / sizeof(a[0]));\n\
          int s = 0; int i = 0;\n\
          while (i < n) { s = s + a[i]; i = i + 1; }\n\
          /* exit code = sum + n so we lock both. 24 + 3 = 27. */\n\
          return s + n;\n\
        }\n";
    assert_eq!(code(src), 27);
}

// ===========================================================================
// 3. Partial array init: elements beyond list are zero-initialized.
// ===========================================================================

#[test]
fn array_init_partial_rest_zero() {
    // a[0..2] = {1,2,3}; a[3..9] = 0. Sum across all 10 == 6.
    let src = "\
        int main(void) {\n\
          int a[10] = {1, 2, 3};\n\
          int s = 0; int i = 0;\n\
          while (i < 10) { s = s + a[i]; i = i + 1; }\n\
          return s;\n\
        }\n";
    let exit = code(src);
    assert_eq!(exit, 6);
    let _ = differential_against_cl(src, exit);
}

// ===========================================================================
// 4. Trailing comma allowed.
// ===========================================================================

#[test]
fn array_init_trailing_comma() {
    let src = "\
        int main(void) {\n\
          int a[3] = {1, 2, 3,};\n\
          return a[0] + a[1] + a[2];\n\
        }\n";
    assert_eq!(code(src), 6);
}

// ===========================================================================
// 5. Struct init by declaration order.
// ===========================================================================

#[test]
fn struct_init_by_order() {
    // p.x = 3, p.y = 4 ⇒ return 7.
    let src = "\
        struct Point { int x; int y; };\n\
        int main(void) {\n\
          struct Point p = {3, 4};\n\
          return p.x + p.y;\n\
        }\n";
    let exit = code(src);
    assert_eq!(exit, 7);
    let _ = differential_against_cl(src, exit);
}

// ===========================================================================
// 6. Struct partial init: trailing fields zero.
// ===========================================================================

#[test]
fn struct_init_partial_rest_zero() {
    // p.x = 3, p.y untouched ⇒ p.y == 0 ⇒ return 3.
    let src = "\
        struct Point { int x; int y; };\n\
        int main(void) {\n\
          struct Point p = {3};\n\
          /* lock both fields so any leakage breaks the test */\n\
          return p.x * 10 + p.y;\n\
        }\n";
    assert_eq!(code(src), 30);
}

// ===========================================================================
// 7. Nested struct of struct.
// ===========================================================================

#[test]
fn nested_struct_init() {
    // l.a = {1,2}, l.b = {3,4} ⇒ l.a.x + l.b.y = 1 + 4 = 5.
    let src = "\
        struct Point { int x; int y; };\n\
        struct Line { struct Point a; struct Point b; };\n\
        int main(void) {\n\
          struct Line l = {{1, 2}, {3, 4}};\n\
          return l.a.x + l.b.y;\n\
        }\n";
    let exit = code(src);
    assert_eq!(exit, 5);
    let _ = differential_against_cl(src, exit);
}

// ===========================================================================
// 8. Array of struct.
// ===========================================================================

#[test]
fn array_of_struct_init() {
    // p[0]={1,2}, p[1]={3,4} ⇒ p[1].x = 3.
    let src = "\
        struct Point { int x; int y; };\n\
        int main(void) {\n\
          struct Point p[2] = {{1, 2}, {3, 4}};\n\
          return p[1].x * 10 + p[0].y;\n\
        }\n";
    let exit = code(src);
    assert_eq!(exit, 32);
    let _ = differential_against_cl(src, exit);
}

// ===========================================================================
// 9. Char array initialised with brace-init (vs the existing string form).
// ===========================================================================

#[test]
fn char_array_brace_init() {
    // {'h','i',0} ⇒ same as "hi" — separately exercised so the new
    // InitList path covers char arrays as well as int arrays.
    let src = "\
        int main(void) {\n\
          char a[3] = {'h', 'i', 0};\n\
          return (int)a[0] + (int)a[1];\n\
        }\n";
    // 'h'=104, 'i'=105 ⇒ 209.
    assert_eq!(code(src), 209);
}

// ===========================================================================
// 10. File-scope (global) brace init: const-evaluated byte image (S4.2ac).
// ===========================================================================

#[test]
fn global_brace_init_runs() {
    // S4.2ac: file-scope aggregate-init globals now const-evaluate into the
    // global's `.data` byte image (formerly the J-9b explicit rejection).
    // `fill_aggregate` dispatches by container and recurses through
    // `global_image`, so all three forms + nesting work. Diff-confirmed vs
    // bcc32 4.52 (the array+struct combo returns 102 there too).
    // Array: {10,20,30} -> 60.
    assert_eq!(
        code("int g[3] = {10,20,30};\nint main(void){ return g[0]+g[1]+g[2]; }\n"),
        60
    );
    // Struct: {7,35} -> 42.
    assert_eq!(
        code(
            "struct P{int x;int y;}; P p = {7,35};\n\
              int main(void){ return p.x+p.y; }\n"
        ),
        42
    );
    // Nested: array of structs {{1,2},{3,4}} -> 1+2+3+4 = 10.
    assert_eq!(
        code(
            "struct P{int x;int y;}; P a[2] = {{1,2},{3,4}};\n\
              int main(void){ return a[0].x+a[0].y+a[1].x+a[1].y; }\n"
        ),
        10
    );
}
