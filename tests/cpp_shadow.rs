//! Phase H H8: block-scope shadowing.
//!
//! Per the Phase H HLD §H8 (`wrk_docs/2026.05.18 - HLD - Phase H
//! (C++ maturation).md`): `collect_decls` used to flatten **all** nested
//! blocks into a single `locals: HashMap<String, …>` so
//! `{ int x; { int x = 2; } }` collapsed to ONE slot — a silent
//! miscompile observable today. H8 replaces the flat HashMap with a
//! per-declaration slot table and a scope-stack name resolver, so each
//! nested `int x` gets its own slot and lookups walk innermost-out.
//!
//! **Byte-identity contract (gate of the regression risk)**: the post-H8
//! layout walk is equivalent to the pre-H8 one for any function where
//! every name appears at most once — same DFS order, same `next` offset
//! cursor, same slots. The 88 `end_to_end.rs` fixtures all satisfy that
//! invariant, so the H8 change is byte-identical on the O1 suite.
//!
//! Differential against `cl /MT` (per HLD §H8: "Viable" — block-scope
//! shadowing is standard C++ with no ABI seam): two tests run cl
//! side-by-side and assert matching exit code + stdout.

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
    p.push(format!("mdbcc_cppshadow_{}_{}.exe", std::process::id(), n));
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

fn out(src: &str) -> (i32, String) {
    let t = build(src);
    let o = Command::new(&t.0).output().expect("launch");
    (
        o.status.code().expect("exit code"),
        String::from_utf8_lossy(&o.stdout).into_owned(),
    )
}

/// FNV-1a 64-bit hash — small, deterministic, no extra dep. A single bit
/// flip in the PE image perturbs many output bytes, so collisions in
/// byte-identity contexts are not a practical concern.
fn fnv64(b: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &x in b {
        h = h.wrapping_mul(0x100000001b3) ^ x as u64;
    }
    h
}

fn pe_hash(src: &str) -> (usize, u64) {
    let pe = compile_to_pe(src.as_bytes()).expect("compile");
    (pe.len(), fnv64(&pe))
}

fn differential_against_cl(src: &str, mdbcc_stdout: &str, mdbcc_exit: i32) -> bool {
    if !o2_active() {
        return false;
    }
    let r = msvc_ref(src, Lang::Cpp);
    if !r.launched {
        return false;
    }
    let cl_out = String::from_utf8_lossy(&normalize_newlines(&r.stdout)).into_owned();
    assert_eq!(cl_out, mdbcc_stdout, "cl differential: stdout mismatch");
    assert_eq!(
        r.exit.expect("cl produced an exit code"),
        mdbcc_exit,
        "cl differential: exit code mismatch"
    );
    true
}

// ===========================================================================
// 1. Basic shadow: outer x=5; inner block int x=10; outer survives.
// ===========================================================================

#[test]
fn basic_shadow_inner_does_not_leak() {
    // Pre-H8 returned 10 (silent collapse to one slot). Post-H8 the
    // inner `int x = 10` gets its own slot ⇒ outer x stays 5 after the
    // block exits ⇒ exit 5. **This is the canonical H8 fix-vs-bug
    // assertion.**
    let src = "\
        int main(void) {\n\
          int x; x = 5;\n\
          { int x; x = 10; }\n\
          return x;\n\
        }\n";
    assert_eq!(code(src), 5);
}

// ===========================================================================
// 2. Triple-nested shadow: each level sees its own x.
// ===========================================================================

#[test]
fn triple_nested_shadow_each_level_visible() {
    let src = "\
        int printf(const char *fmt, ...);\n\
        int main(void) {\n\
          int x; x = 5;\n\
          {\n\
            int x; x = 10;\n\
            {\n\
              int x; x = 15;\n\
              printf(\"inner=%d \", x);\n\
            }\n\
            printf(\"middle=%d \", x);\n\
          }\n\
          printf(\"outer=%d\\n\", x);\n\
          return 0;\n\
        }\n";
    let (ec, so) = out(src);
    assert_eq!(ec, 0);
    assert_eq!(so, "inner=15 middle=10 outer=5\n");
    differential_against_cl(src, &so, ec);
}

// ===========================================================================
// 3. Byte-identity guard: deterministic re-compile.
//    Same source twice must produce identical bytes — the property the
//    O1 88 byte-identity claim relies on. Three representative
//    non-shadowing fixtures from `end_to_end.rs`.
// ===========================================================================

#[test]
fn byte_identity_deterministic_recompile() {
    let srcs = [
        "int main(void){return (2+3)*8-10;}",
        "int main(void){int x; x = 7; 0 && (1/0); return x;}",
        "int add(int a, int b) { return a + b; } \
         int main(void){ return add(3,4); }",
    ];
    for s in srcs {
        let (l1, h1) = pe_hash(s);
        let (l2, h2) = pe_hash(s);
        assert_eq!(l1, l2, "PE length must be deterministic for: {s}");
        assert_eq!(h1, h2, "PE bytes must be deterministic for: {s}");
    }
}

// ===========================================================================
// 4. For-loop init variable shadows outer name.
// ===========================================================================

#[test]
fn for_loop_init_redeclares_outer_is_an_error_borland() {
    // bcc32 4.52 is PRE-STANDARD: a `for (int i = …; …)` init variable scopes to
    // the ENCLOSING block — it does NOT open a new scope (see #42 / the leak
    // test `for_init_variable_scopes_to_enclosing_block` in end_to_end). So
    // `int i; for (int i = …)` is a REDECLARATION of `i` in the same block:
    // bcc32 rejects it ("Multiple declaration for 'i'"), so mdbcc must too —
    // matching the bcc32 reference, NOT modern C++'s for-scope shadowing. (This
    // test previously asserted the standard shadow → 102, which bcc32 refuses.)
    let src = "\
        int main(void) {\n\
          int i; i = 99;\n\
          for (int i = 0; i < 3; i = i + 1) { (void)i; }\n\
          return i;\n\
        }\n";
    assert!(
        compile_to_pe(src.as_bytes()).is_err(),
        "a for-init redeclaring an outer same-block variable must error \
         (bcc32 leaks the for-init to the enclosing scope)"
    );
}

// ===========================================================================
// 5. Shadow inside if-branch — outer survives after branch.
// ===========================================================================

#[test]
fn if_branch_shadow_does_not_leak() {
    let src = "\
        int main(void) {\n\
          int x; x = 1;\n\
          if (x == 1) {\n\
            int x; x = 77;\n\
            x = x + 1;\n\
          }\n\
          return x;\n\
        }\n";
    assert_eq!(code(src), 1);
}

// ===========================================================================
// 6. Block shadows function parameter; param survives after block.
// ===========================================================================

#[test]
fn block_shadows_parameter() {
    // f(7) — inside the block `int n = 100` shadows the param `n`.
    // After the block `n` (the param) is still 7. doubled = 100+100 = 200,
    // so the function returns 7 + 200 = 207.
    let src = "\
        int f(int n) {\n\
          int doubled;\n\
          { int n; n = 100; doubled = n + n; }\n\
          return n + doubled;\n\
        }\n\
        int main(void) { return f(7); }\n";
    assert_eq!(code(src), 207);
}

// ===========================================================================
// 7. Sibling scopes: each has its own x; no cross-contamination.
// ===========================================================================

#[test]
fn sibling_scopes_each_have_own_x() {
    let src = "\
        int printf(const char *fmt, ...);\n\
        int main(void) {\n\
          int sum; sum = 0;\n\
          { int x; x = 11; sum = sum + x; }\n\
          { int x; x = 22; sum = sum + x; }\n\
          printf(\"sum=%d\\n\", sum);\n\
          return sum;\n\
        }\n";
    let (ec, so) = out(src);
    assert_eq!(ec, 33);
    assert_eq!(so, "sum=33\n");
}

// ===========================================================================
// 8. Shadow with class types: scope-correct dtor counts.
// ===========================================================================

#[test]
fn class_shadow_constructs_and_destructs_per_scope() {
    // Outer `Counter c` (ctor=1). Inner-block `Counter c` (ctor=2;
    // shadows outer). Inner block exits ⇒ inner dtor (dtor=1). Return
    // expression reads counts BEFORE the function-scope outer dtor runs,
    // so we observe ctor=2, dtor=1 ⇒ 21.
    let src = "\
        int ctor_count;\n\
        int dtor_count;\n\
        class Counter { public:\n\
          int v;\n\
          Counter() { v = 1; ctor_count = ctor_count + 1; }\n\
          ~Counter() { dtor_count = dtor_count + 1; }\n\
        };\n\
        int main(void) {\n\
          ctor_count = 0; dtor_count = 0;\n\
          Counter c;\n\
          { Counter c; }\n\
          return ctor_count * 10 + dtor_count;\n\
        }\n";
    assert_eq!(code(src), 21);
}

// ===========================================================================
// 9. Four-level shadow with prints — each level visible inside.
// ===========================================================================

#[test]
fn four_level_shadow_each_visible_inside() {
    let src = "\
        int printf(const char *fmt, ...);\n\
        int main(void) {\n\
          int n; n = 1;\n\
          printf(\"%d \", n);\n\
          {\n\
            int n; n = 2;\n\
            printf(\"%d \", n);\n\
            {\n\
              int n; n = 3;\n\
              printf(\"%d \", n);\n\
              {\n\
                int n; n = 4;\n\
                printf(\"%d\\n\", n);\n\
              }\n\
            }\n\
          }\n\
          return n;\n\
        }\n";
    let (ec, so) = out(src);
    assert_eq!(ec, 1);
    assert_eq!(so, "1 2 3 4\n");
    differential_against_cl(src, &so, ec);
}

// ===========================================================================
// 10. Same-scope redeclaration is a CLEAN ERROR (no silent collapse).
// ===========================================================================

#[test]
fn same_scope_redeclaration_errors() {
    let src = "int main(void) { int x; int x; return 0; }";
    let r = compile_to_pe(src.as_bytes());
    assert!(r.is_err(), "expected redeclaration error, got Ok");
    let msg = r.unwrap_err().to_string();
    assert!(
        msg.contains("redeclaration") || msg.contains("'x'"),
        "expected redeclaration / x diagnostic, got: {msg}"
    );
}

// ===========================================================================
// 11. For-loop shadow with a working iteration count.
//     Outer i drives loop; inner shadow contributes to a sum.
// ===========================================================================

#[test]
fn for_loop_body_shadows_index_into_sum() {
    // Outer i counts 0..3 via the for-step. Inside the body, a SHADOW
    // `int i = 100` contributes to sum each iteration (3 × 100 = 300).
    // Outer i is unchanged by the body (the shadow hides it), but the
    // for-step still increments outer i because the step expression
    // `i = i + 1` lives in the for's scope (not the body's), where the
    // shadow is not visible.
    let src = "\
        int main(void) {\n\
          int total; total = 0;\n\
          int i;\n\
          for (i = 0; i < 3; i = i + 1) {\n\
            int i; i = 100;\n\
            total = total + i;\n\
          }\n\
          return total;\n\
        }\n";
    assert_eq!(code(src), 300);
}

// ===========================================================================
// 12. Address identity: outer x and inner x have DIFFERENT addresses
//     (proves each Decl gets its own slot — the core H8 invariant).
// ===========================================================================

#[test]
fn outer_and_inner_have_distinct_addresses() {
    let src = "\
        int main(void) {\n\
          int x; x = 1;\n\
          int *po; po = &x;\n\
          int *pi;\n\
          { int x; x = 2; pi = &x; }\n\
          return (po == pi) ? 1 : 0;\n\
        }\n";
    assert_eq!(code(src), 0);
}
