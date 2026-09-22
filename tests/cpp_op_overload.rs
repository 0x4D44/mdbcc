//! Phase H H7: call-site lowering for the three special operator
//! overloads — `operator[]`, `operator()`, and `operator=`.
//!
//! Per the Phase H HLD §H7 (`wrk_docs/2026.05.18 - HLD - Phase H
//! (C++ maturation).md`): the binary-operator lowering for
//! `a @ b → a.operator@(b)` already exists (`src/codegen.rs:3342-3349`)
//! and the parser accepts `operator[]`/`operator()` syntactically
//! (`src/parser.rs:985-998`). H7 wires up the three call-site
//! rewrites at the matching AST nodes — and only when the class
//! declares the corresponding operator:
//!
//! - `Expr::Index { base: <class>, idx }` => `base.operator[](idx)`
//! - `Expr::CallPtr { target: <class>, args }` => `target.operator()(args)`
//! - `Expr::Assign { lhs: <class>, rhs }` => `lhs.operator=(rhs)`
//!
//! **Byte-identity contract (H7 must not break it)**: a class without
//! a user-defined `operator[X]` keeps the existing builtin code path
//! byte-for-byte (`int arr[3]; arr[0] = 5;` and `struct S s,t; s = t;`
//! both lower exactly as they did pre-H7). The `end_to_end.rs` 88
//! fixtures contain neither user-defined operator overloads of these
//! three kinds nor any class with the missing-operator-could-be-applied
//! pattern, so the entire pre-H7 byte image is preserved (gates the O1
//! regression).
//!
//! Differential against `cl /MT` (per HLD §H7: "behavioural only" —
//! cl's symbol-name encoding differs but observable behaviour matches):
//! for at least two representative tests we run cl side-by-side and
//! assert matching exit code + stdout (the standard `\r\n`→`\n`
//! normalisation).

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
    p.push(format!("mdbcc_cppop_{}_{}.exe", std::process::id(), n));
    let t = TempExe(p);
    std::fs::write(&t.0, &exe).expect("write exe");
    t
}

/// Exit code of `int main(){...}` in `src`.
fn code(src: &str) -> i32 {
    let t = build(src);
    Command::new(&t.0)
        .status()
        .expect("launch")
        .code()
        .expect("exit code")
}

/// stdout of `src`.
fn out(src: &str) -> String {
    let t = build(src);
    let o = Command::new(&t.0).output().expect("launch");
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// Behavioural differential against `cl /MT`: compile the same source
/// with MSVC, run it, assert mdbcc's stdout (after newline normalisation)
/// and exit code match. cl absent ⇒ silent skip — the caller's mdbcc-
/// side assertion still ran. Returns whether the comparison happened.
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
// operator[] — five variants
// ===========================================================================

// ---- 1: operator[] returning by value, used as rvalue ---------------------

#[test]
fn op_index_by_value_rvalue() {
    // `v[i]` rewrites to `v.operator[](i)`; by-value return surfaces in
    // RAX directly. data[2] = 30 ⇒ exit 30.
    let src = "\
        class Vec { public:\n\
          int data[5];\n\
          Vec() { data[0]=10; data[1]=20; data[2]=30; data[3]=40; data[4]=50; }\n\
          int operator[](int i) { return data[i]; }\n\
        };\n\
        int main(void) { Vec v; return v[2]; }\n";
    assert_eq!(code(src), 30);
}

// ---- 2: operator[] returning by reference, lvalue + rvalue ----------------

#[test]
fn op_index_by_reference_lvalue_and_rvalue() {
    // `T& operator[](int)` lets `v[i] = 42` and `return v[i]` both
    // work. The lvalue path needs the reference's address (which the
    // method puts in RAX); the rvalue path then loads through it.
    let src = "\
        class Vec { public:\n\
          int data[5];\n\
          Vec() { data[0]=0; data[1]=0; data[2]=0; data[3]=0; data[4]=0; }\n\
          int& operator[](int i) { return data[i]; }\n\
        };\n\
        int main(void) {\n\
          Vec v;\n\
          v[1] = 7;\n\
          v[3] = 13;\n\
          return v[1] + v[3] + v[0];\n\
        }\n";
    // 7 + 13 + 0 = 20.
    assert_eq!(code(src), 20);
}

// ---- 3: mixed read + read in one expression -------------------------------

#[test]
fn op_index_mixed_reads() {
    // `v[0] + v[1] + v[2]`: three method calls, three returns, summed.
    let src = "\
        class Vec { public:\n\
          int data[3];\n\
          Vec() { data[0]=5; data[1]=11; data[2]=23; }\n\
          int operator[](int i) { return data[i]; }\n\
        };\n\
        int main(void) {\n\
          Vec v;\n\
          int x; x = v[0] + v[1] + v[2];\n\
          return x;\n\
        }\n";
    assert_eq!(code(src), 39);
}

// ---- 4: operator[] with non-trivial computation ---------------------------

#[test]
fn op_index_with_computation() {
    // operator[] body does arithmetic on the index (sentinel: 100 + i).
    // Exercises that `i` arrives correctly as the method arg (not the
    // pointer-arithmetic scaled value the pre-H7 builtin would compute).
    let src = "\
        class Times100 { public:\n\
          int operator[](int i) { return 100 + i; }\n\
        };\n\
        int main(void) {\n\
          Times100 t;\n\
          return t[5];\n\
        }\n";
    assert_eq!(code(src), 105);
}

// ---- 5: operator[] returning a struct (by value) --------------------------

#[test]
fn op_index_class_type_return() {
    // operator[] returning a small struct (Point) by value. Exercises
    // H2's struct-return ABI path via the MethodCall rewrite — the
    // returned record is consumed by Member access (`.x`).
    let src = "\
        class Point { public:\n\
          int x;\n\
          int y;\n\
        };\n\
        class Grid { public:\n\
          int base;\n\
          Point operator[](int i) {\n\
            Point p;\n\
            p.x = base + i;\n\
            p.y = base + i * 2;\n\
            return p;\n\
          }\n\
        };\n\
        int main(void) {\n\
          Grid g;\n\
          g.base = 10;\n\
          return g[3].x + g[3].y;\n\
        }\n";
    // g[3].x = 13; g[3].y = 16; sum = 29.
    assert_eq!(code(src), 29);
}

// ---- 6: differential vs cl /MT - operator[] returning int& ---------------

#[test]
fn differential_cl_op_index_reference() {
    let src = "\
        #include <stdio.h>\n\
        class Arr { public:\n\
          int data[4];\n\
          Arr() { data[0]=0; data[1]=0; data[2]=0; data[3]=0; }\n\
          int& operator[](int i) { return data[i]; }\n\
        };\n\
        int main(void) {\n\
          Arr a;\n\
          a[0] = 11; a[1] = 22; a[2] = 33; a[3] = 44;\n\
          printf(\"%d %d %d %d\\n\", a[0], a[1], a[2], a[3]);\n\
          return a[2];\n\
        }\n";
    let mdbcc_out = out(src);
    let mdbcc_exit = code(src);
    assert_eq!(mdbcc_out, "11 22 33 44\n");
    assert_eq!(mdbcc_exit, 33);
    differential_against_cl(src, &mdbcc_out, mdbcc_exit);
}

// ===========================================================================
// operator() — four variants
// ===========================================================================

// ---- 7: Adder functor with one arg ---------------------------------------

#[test]
fn op_call_unary_functor() {
    // `Adder a(10); a(5)` ⇒ `a.operator()(5)` ⇒ 15.
    let src = "\
        class Adder { public:\n\
          int base;\n\
          Adder(int b) { base = b; }\n\
          int operator()(int x) { return base + x; }\n\
        };\n\
        int main(void) {\n\
          Adder a(10);\n\
          return a(5);\n\
        }\n";
    assert_eq!(code(src), 15);
}

// ---- 8: operator() with zero args ----------------------------------------

#[test]
fn op_call_zero_arity() {
    // `f()` where `f` is a functor with `int operator()()`.
    let src = "\
        class Const42 { public:\n\
          int operator()() { return 42; }\n\
        };\n\
        int main(void) {\n\
          Const42 c;\n\
          return c();\n\
        }\n";
    assert_eq!(code(src), 42);
}

// ---- 9: operator() with multiple args ------------------------------------

#[test]
fn op_call_multi_arity() {
    // operator()(a,b,c) ⇒ method with three params (plus implicit this).
    let src = "\
        class Sum3 { public:\n\
          int operator()(int a, int b, int c) { return a + b + c; }\n\
        };\n\
        int main(void) {\n\
          Sum3 s;\n\
          return s(7, 11, 13);\n\
        }\n";
    assert_eq!(code(src), 31);
}

// ---- 10: operator() overloaded by arity (uses H5 overload resolution) ----

#[test]
fn op_call_overloaded_by_arity() {
    // Two `operator()` overloads, arity 1 and arity 2. H5's
    // resolve_overload picks the right one based on call-site arity.
    let src = "\
        class F { public:\n\
          int operator()(int x) { return x + 1; }\n\
          int operator()(int x, int y) { return x * y; }\n\
        };\n\
        int main(void) {\n\
          F f;\n\
          return f(9) + f(3, 4);\n\
        }\n";
    // 10 + 12 = 22.
    assert_eq!(code(src), 22);
}

// ===========================================================================
// operator= — four variants
// ===========================================================================

// ---- 11: operator= with side-effect (copy counter) -----------------------

#[test]
fn op_assign_runs_user_defined() {
    // A user-defined `operator=` MUST run on `a = b` (per C++ rules).
    // The counter increments only when the overload runs — proves
    // builtin memcpy was NOT taken.
    let src = "\
        int g_copies = 0;\n\
        class Counted { public:\n\
          int v;\n\
          Counted() { v = 0; }\n\
          int operator=(Counted& other) { g_copies = g_copies + 1; v = other.v; return v; }\n\
        };\n\
        int main(void) {\n\
          Counted a, b;\n\
          b.v = 7;\n\
          a = b;\n\
          return g_copies + a.v;\n\
        }\n";
    // 1 (copy ran) + 7 (a.v = b.v) = 8.
    assert_eq!(code(src), 8);
}

// ---- 12: class WITHOUT user-defined operator= - default behavior ---------

#[test]
fn op_assign_default_unchanged_without_overload() {
    // A class with no user-defined `operator=` falls through to the
    // existing builtin (memcpy) path. This is the byte-identity check:
    // pre-H7 behaviour for trivial classes is preserved.
    let src = "\
        class Plain { public:\n\
          int a;\n\
          int b;\n\
          int c;\n\
        };\n\
        int main(void) {\n\
          Plain p;\n\
          p.a = 1; p.b = 2; p.c = 3;\n\
          Plain q;\n\
          q.a = 100; q.b = 100; q.c = 100;\n\
          q = p;\n\
          return q.a + q.b + q.c;\n\
        }\n";
    // After q = p: q is byte-copy of p ⇒ 1 + 2 + 3 = 6.
    assert_eq!(code(src), 6);
}

// ---- 13: outer class with operator= does NOT propagate to fields ---------

#[test]
fn op_assign_outer_overrides_inner() {
    // Outer class defines `operator=` that does NOT propagate into
    // fields; only the outer override runs. Counter proves it: one
    // increment per outer assignment, and the field's value is NOT
    // touched (q.f.v stays at the value set by the explicit init,
    // proving the outer operator= did NOT recursively call the
    // field's assign / memcpy machinery).
    let src = "\
        int g_outer = 0;\n\
        class Outer { public:\n\
          int f_v;\n\
          int operator=(Outer& other) {\n\
            g_outer = g_outer + 1;\n\
            return 1;\n\
          }\n\
        };\n\
        int main(void) {\n\
          Outer x, y;\n\
          x.f_v = 42;\n\
          y.f_v = 99;\n\
          x = y;\n\
          return g_outer + x.f_v;\n\
        }\n";
    // 1 (outer ran) + 42 (x.f_v UNCHANGED, since outer operator= didn't
    // assign the field) = 43.
    assert_eq!(code(src), 43);
}

// ---- 14a: chained `a = b = c` calls operator= twice -----------------------

#[test]
fn op_assign_chained() {
    // `a = b = c` parses right-associative: first `b = c`
    // (operator= runs, counter +1, returns V&), then the result
    // is the rhs of `a = …` (operator= runs again, counter +1).
    // Both x and y should end up with the value from z. The V&
    // return convention (with H7's Stmt::Return Ref-aware path)
    // lets the inner result type-match the outer operator='s rhs.
    let src = "\
        int g_calls = 0;\n\
        class V { public:\n\
          int v;\n\
          V() { v = 0; }\n\
          V& operator=(V& o) { g_calls = g_calls + 1; v = o.v; return *this; }\n\
        };\n\
        int main(void) {\n\
          V x, y, z;\n\
          z.v = 7;\n\
          x = y = z;\n\
          return g_calls + x.v + y.v;\n\
        }\n";
    // 2 (two calls) + 7 (x.v) + 7 (y.v) = 16.
    assert_eq!(code(src), 16);
}

// ---- 14: differential vs cl /MT - user-defined operator= side-effects ----

#[test]
fn differential_cl_op_assign_side_effects() {
    let src = "\
        #include <stdio.h>\n\
        int g = 0;\n\
        class C { public:\n\
          int v;\n\
          C() { v = 0; }\n\
          int operator=(C& o) { g = g + 1; v = o.v + 1; return v; }\n\
        };\n\
        int main(void) {\n\
          C a, b;\n\
          b.v = 10;\n\
          a = b;\n\
          printf(\"%d %d\\n\", g, a.v);\n\
          return a.v;\n\
        }\n";
    let mdbcc_out = out(src);
    let mdbcc_exit = code(src);
    // operator= ran once (g=1), copies+1 (a.v=11).
    assert_eq!(mdbcc_out, "1 11\n");
    assert_eq!(mdbcc_exit, 11);
    differential_against_cl(src, &mdbcc_out, mdbcc_exit);
}

// ===========================================================================
// Mixed / leave-it-green contract
// ===========================================================================

// ---- 15: primitive assignment unaffected by H7 ---------------------------

#[test]
fn primitive_assignment_unaffected_by_h7() {
    // `int a = 5; a = 6;` exercises the assignment-to-primitive path
    // that pre-H7 codegen owned exclusively. H7 must not touch it
    // (the lhs is not a class type ⇒ has_op_method returns false ⇒
    // existing path runs byte-for-byte).
    let src = "\
        int main(void) {\n\
          int a; a = 5;\n\
          a = 6;\n\
          return a;\n\
        }\n";
    assert_eq!(code(src), 6);
}

// ---- 16: built-in subscript on int[] unaffected by H7 --------------------

#[test]
fn builtin_subscript_unaffected_by_h7() {
    // `int arr[10]; arr[3] = 5;` exercises the pointer-arithmetic
    // subscript path. H7 must not touch it (the base is not a class
    // type ⇒ has_op_method returns false ⇒ gen_index_addr runs
    // byte-for-byte).
    let src = "\
        int main(void) {\n\
          int arr[10];\n\
          arr[0] = 100;\n\
          arr[3] = 5;\n\
          arr[9] = 11;\n\
          return arr[0] + arr[3] + arr[9];\n\
        }\n";
    assert_eq!(code(src), 116);
}

// ---- 17: function-pointer call unaffected by H7 --------------------------

#[test]
fn fnptr_call_unaffected_by_h7() {
    // `fp(x)` where fp is a function pointer (not a class) — the
    // Expr::CallPtr indirect-call path. H7 must not touch it.
    let src = "\
        int triple(int x) { return x * 3; }\n\
        int main(void) {\n\
          int (*fp)(int);\n\
          fp = triple;\n\
          return fp(7);\n\
        }\n";
    assert_eq!(code(src), 21);
}

// ===========================================================================
// J-6 (H10 MINOR-4): `(a = b) = c` when operator= returns by value
// ===========================================================================
//
// When `operator=` returns `int` or a record by value (rather than the
// idiomatic `T&`), the H7 `Expr::Assign` arm in `gen_addr` previously
// passed the returned VALUE through as if it were an ADDRESS — a silent
// miscompile in `(a = b) = c` (rare but a real C++ footgun). J-6 rejects
// that combination at codegen with a clear diagnostic; the by-reference
// case is still the happy path; non-chained `a = b` with a by-value
// op= continues to work as before (no regression).

// ---- 18. by-value op= rejected in chained-lvalue position ----------------

#[test]
fn op_assign_returns_by_value_chained_lvalue_rejected() {
    // `int operator=(int)` returns by value; `(a = b) = c` cannot work
    // (the result of `a = b` is a prvalue int, not an lvalue). mdbcc
    // rejects with a diagnostic that names the return-by-value cause.
    let src = "\
        class C { public:\n\
          int v;\n\
          C() { v = 0; }\n\
          int operator=(int x) { v = x; return v; }\n\
        };\n\
        int main(void) {\n\
          C a, b;\n\
          (a = 1) = 2;\n\
          return a.v;\n\
        }\n";
    let err = compile_to_pe(src.as_bytes()).expect_err("must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("'operator=' returns by value"),
        "rejection must mention by-value return cause; got: {msg}"
    );
}

// ---- 19. by-reference op= still accepts chained-lvalue position ----------

#[test]
fn op_assign_returns_by_reference_chained_lvalue_compiles() {
    // `V& operator=(V&)` is the idiomatic form; `(a = b) = c` is well-
    // formed and runs operator= three times (one per `=`): b=c, a=b
    // (the inner of the outer pair), and the outer `(...) = c` doing
    // a third copy of c into a's address. The interesting fact for J-6
    // is that this case COMPILES — only the by-value form is rejected.
    let src = "\
        int g_calls = 0;\n\
        class V { public:\n\
          int v;\n\
          V() { v = 0; }\n\
          V& operator=(V& o) { g_calls = g_calls + 1; v = o.v; return *this; }\n\
        };\n\
        int main(void) {\n\
          V a, b, c;\n\
          c.v = 7;\n\
          (a = b) = c;\n\
          return g_calls + a.v;\n\
        }\n";
    // Three operator= calls (b=c is not in this source; just a=b then (...)=c
    // → a=b first, then the outer's lhs is a's address from that call, then
    // (...)=c does the second op= on a. So g_calls should be 2 and a.v = 7.
    // 2 + 7 = 9.
    assert_eq!(code(src), 9);
}

// ---- 20. non-chained by-value op= still works (regression lock) ----------

#[test]
fn op_assign_returns_by_value_non_chained_unaffected() {
    // `int operator=(int)` used in non-lvalue context (a plain `a = 1;`
    // statement, or as a value `int x = (a = 1);`) must continue to
    // work. J-6's rejection only fires when the by-value result is
    // used as an LVALUE — i.e. only when `gen_addr` is called on an
    // `Expr::Assign` whose op= returns by value.
    let src = "\
        class C { public:\n\
          int v;\n\
          C() { v = 0; }\n\
          int operator=(int x) { v = x; return v; }\n\
        };\n\
        int main(void) {\n\
          C a;\n\
          a = 41;\n\
          return a.v + 1;\n\
        }\n";
    assert_eq!(code(src), 42);
}
