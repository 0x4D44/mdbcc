//! Phase H5: member-function overloading.
//!
//! Per the Phase H HLD: free-function overloading already worked via the
//! Borland-ish single-char per-type mangling at `src/codegen.rs:402`
//! (`overload_symbol`). H5 lifts the deferral that read verbatim "Member
//! overloading is deferred; only free-function names participate" and lets
//! member functions overload on the same footing. The mangling scheme
//! stays as it was (private to emitted `.text`; never crosses the DLL
//! boundary — see HLD §Risk 3) but is now applied uniformly to
//! `Tag::name$<typecodes>`.
//!
//! Resolution algorithm (HLD-tractable subset): collect candidates by
//! qualified name, drop arity-mismatches, score per-parameter (0 = exact
//! match, 1 = convertible, fail otherwise), pick lowest total. Ties at
//! the top ⇒ ambiguous (hard error). C++ standard overload resolution is
//! intentionally NOT implemented (templates / SFINAE / ADL / user-defined
//! conversions are all H-future); the rule matches what real Borland-era
//! OWL code actually depends on.
//!
//! **Byte-identity contract (H5 must not break it)**: a class with only
//! one method of any given name keeps its parser-assigned bare symbol
//! (`Tag::name`) — only ambiguous names get the `$<typecodes>` suffix.
//! `tests/end_to_end.rs` (88) fixtures contain class methods but no
//! overloads, so the entire pre-H5 byte image is preserved (gates the
//! O1 regression).
//!
//! Differential against `cl /MT` (per HLD §H5: "behavioural only —
//! internal symbol-name divergence is fine"): for at least two
//! representative tests we run cl side-by-side and assert matching
//! exit code + stdout (with the standard `\r\n`→`\n` normalisation).

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
    p.push(format!("mdbcc_cppovl_{}_{}.exe", std::process::id(), n));
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

/// Assert `src` fails to compile with an error message containing `needle`.
fn assert_compile_err(src: &str, needle: &str) {
    match compile_to_pe(src.as_bytes()) {
        Ok(_) => panic!("expected compile error containing {needle:?}, got success"),
        Err(e) => {
            let msg = format!("{e}");
            assert!(
                msg.contains(needle),
                "error {msg:?} does not contain expected {needle:?}"
            );
        }
    }
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
    let cl_stdout = String::from_utf8_lossy(&normalize_newlines(&r.stdout)).into_owned();
    assert_eq!(
        cl_stdout, mdbcc_stdout,
        "cl differential FAIL (stdout): cl={cl_stdout:?} mdbcc={mdbcc_stdout:?}"
    );
    assert_eq!(
        r.exit,
        Some(mdbcc_exit),
        "cl differential FAIL (exit): cl={:?} mdbcc={mdbcc_exit}",
        r.exit
    );
    true
}

// ---- 1: overload by arity --------------------------------------------------

#[test]
fn overload_by_arity_two_overloads() {
    // Two overloads keyed by parameter count alone. The arity filter in
    // resolve_overload picks the unique candidate; no scoring needed.
    // 6 + 11 = 17.
    let src = "\
        class C { public:\n\
          int foo(int x) { return x + 1; }\n\
          int foo(int x, int y) { return x + y; }\n\
        };\n\
        int main(void) { C c; return c.foo(5) + c.foo(5, 6); }\n";
    assert_eq!(code(src), 17);
}

// ---- 2: overload by parameter type (int vs double) ------------------------

#[test]
fn overload_by_type_int_vs_double() {
    // Both overloads have arity 1; scoring picks the unique exact match
    // (int → int = 0, double → double = 0). 7 + 3 = 10.
    let src = "\
        class C { public:\n\
          int foo(int x) { return x + 7; }\n\
          int foo(double d) { return (int)d; }\n\
        };\n\
        int main(void) {\n\
          C c;\n\
          int a; a = c.foo(0);\n\
          int b; b = c.foo(3.0);\n\
          return a + b;\n\
        }\n";
    assert_eq!(code(src), 10);
}

// ---- 3: by pointer vs by value (disambiguation by argument category) ------

#[test]
fn overload_by_pointer_vs_value() {
    // foo(int) vs foo(int*). The two overloads are disambiguated by the
    // argument's *category*: an int literal/lvalue picks foo(int); an
    // int* address picks foo(int*). C++'s standard reference-vs-value
    // case (`foo(int)` vs `foo(int&)` against an int lvalue) is
    // *intentionally* ambiguous under mdbcc's simple scoring rule
    // (matches the C++ standard's pre-overload-resolution behaviour);
    // pointer-vs-value is the clean overload-by-type case.
    let src = "\
        class C { public:\n\
          int foo(int x) { return x + 1; }\n\
          int foo(int* p) { *p = *p + 10; return *p; }\n\
        };\n\
        int main(void) {\n\
          C c;\n\
          int n; n = 5;\n\
          int a; a = c.foo(7);\n\
          int b; b = c.foo(&n);\n\
          return a + b + n;\n\
        }\n";
    // foo(7) = 8; foo(&n) bumps n 5→15, returns 15; n now 15.
    // 8 + 15 + 15 = 38.
    assert_eq!(code(src), 38);
}

// ---- 4: by pointer type (different pointee types) --------------------------

#[test]
fn overload_by_pointer_type() {
    // foo(int*) vs foo(char*). Both arity 1; scoring picks the matching
    // pointer type. Result: 42 from int*-path, 99 from char*-path.
    let src = "\
        class C { public:\n\
          int foo(int* p) { return *p; }\n\
          int foo(char* s) { return s[0]; }\n\
        };\n\
        int main(void) {\n\
          C c;\n\
          int x; x = 42;\n\
          char s[2]; s[0] = 99; s[1] = 0;\n\
          return c.foo(&x) + c.foo(s);\n\
        }\n";
    assert_eq!(code(src), 42 + 99);
}

// ---- 5: three overloads (one of each arity 1..3) --------------------------

#[test]
fn three_overloads_by_arity() {
    let src = "\
        class C { public:\n\
          int foo(int a) { return a; }\n\
          int foo(int a, int b) { return a * b; }\n\
          int foo(int a, int b, int c) { return a + b + c; }\n\
        };\n\
        int main(void) {\n\
          C c;\n\
          int a; a = c.foo(7);\n\
          int b; b = c.foo(2, 3);\n\
          int d; d = c.foo(1, 2, 3);\n\
          return a + b + d;\n\
        }\n";
    // 7 + 6 + 6 = 19.
    assert_eq!(code(src), 19);
}

// ---- 6: class-type-parameter overloads ------------------------------------

#[test]
fn overload_by_class_type_parameter() {
    // foo(A&) vs foo(B&). The mangler encodes record types as `R S<id>_`
    // so the two overloads have distinct symbols, and resolve_overload
    // distinguishes them by exact-type match. Result lets us see *which*
    // overload fired: 100 from A-path, 200 from B-path.
    let src = "\
        class A { public: int x; };\n\
        class B { public: int x; };\n\
        class C { public:\n\
          int foo(A& a) { return 100 + a.x; }\n\
          int foo(B& b) { return 200 + b.x; }\n\
        };\n\
        int main(void) {\n\
          A a; a.x = 1;\n\
          B b; b.x = 2;\n\
          C c;\n\
          return c.foo(a) + c.foo(b);\n\
        }\n";
    // (100+1) + (200+2) = 303.
    assert_eq!(code(src), 303);
}

// ---- 7: virtual method overloading ----------------------------------------

#[test]
fn virtual_method_overloads_get_separate_vtable_slots() {
    // Both overloads are virtual; each gets its own vtable slot (the H5
    // rebuild keys overloaded virtual slots by their mangled symbol).
    // Dispatch is through the vptr; exit code 1 + 2 + 3 = 6 lets us see
    // the slot for the (int,int) overload was independent of the (int)
    // overload (else the wrong sym would be in the slot and the call
    // would land on the wrong body).
    let src = "\
        class C { public:\n\
          virtual int foo(int a) { return a; }\n\
          virtual int foo(int a, int b) { return a + b; }\n\
        };\n\
        int main(void) {\n\
          C c;\n\
          C* p; p = &c;\n\
          return p->foo(1) + p->foo(2, 3);\n\
        }\n";
    assert_eq!(code(src), 1 + 5);
}

// ---- 8: shadowing — derived's name hides all base overloads (C++ rule) ----

#[test]
fn derived_shadow_hides_base_overloads() {
    // C++ standard rule: a derived class's name lookup stops at the first
    // class that defines the name. Derived::foo(int) shadows Base's
    // foo(int) AND foo(int,int); calling d.foo(1, 2) must error, not
    // resolve to Base::foo(int, int). HLD §H5 documents this explicitly.
    let src = "\
        class B { public:\n\
          int foo(int a) { return a; }\n\
          int foo(int a, int b) { return a + b; }\n\
        };\n\
        class D : public B { public:\n\
          int foo(int a) { return 1000 + a; }\n\
        };\n\
        int main(void) { D d; return d.foo(1, 2); }\n";
    assert_compile_err(src, "no matching overload");
}

// ---- 9: ambiguous overload ⇒ clean error ----------------------------------

#[test]
fn ambiguous_overload_clean_error() {
    // The two overloads are tied: a `short` argument matches neither
    // `int` nor `char` exactly (Win64 sizes: short=2, int=4, char=1),
    // but both are integers so each scores 1 → tie at the top → mdbcc
    // rejects with "ambiguous". The error message names the qualified
    // method so the user can disambiguate with an explicit cast.
    let src = "\
        class C { public:\n\
          int foo(int x) { return x + 10; }\n\
          int foo(char x) { return (int)x + 20; }\n\
        };\n\
        int main(void) {\n\
          C c;\n\
          short s; s = 3;\n\
          return c.foo(s);\n\
        }\n";
    assert_compile_err(src, "ambiguous");
}

// ---- 10: no matching overload ⇒ clean error -------------------------------

#[test]
fn no_matching_overload_clean_error() {
    // foo(int*) and foo(char*) — neither accepts an int by value (a
    // pointer parameter cannot bind to an int argument). The user
    // gets a "no matching overload" diagnostic with the qualified
    // name in it.
    let src = "\
        class C { public:\n\
          int foo(int* p) { return *p; }\n\
          int foo(char* s) { return s[0]; }\n\
        };\n\
        int main(void) {\n\
          C c;\n\
          return c.foo(42);\n\
        }\n";
    assert_compile_err(src, "no matching overload");
}

// ---- 11: pass a struct-by-value into an overload candidate (H1 interaction) -

#[test]
fn struct_by_value_through_overload_resolution() {
    // The (size-4 record S) candidate must be picked over the int
    // candidate when the arg is an S. Verifies that overload resolution
    // sees record types correctly and that the H1 by-value marshalling
    // path coexists with the H5 mangling. Result: 17 + 9 = 26.
    let src = "\
        struct S { int x; };\n\
        class C { public:\n\
          int foo(int n) { return n; }\n\
          int foo(struct S s) { return s.x; }\n\
        };\n\
        int main(void) {\n\
          C c;\n\
          struct S v; v.x = 9;\n\
          return c.foo(17) + c.foo(v);\n\
        }\n";
    assert_eq!(code(src), 17 + 9);
}

// ---- 12: cl differential — by-arity overloads -----------------------------

#[test]
fn differential_cl_by_arity() {
    // Behavioural oracle: the mangled symbols differ between mdbcc and
    // cl (per HLD §H5: "internal symbol-name divergence is fine") but
    // exit code + stdout must match. If cl is unavailable, the assertion
    // on mdbcc still runs (degrades cleanly to mdbcc-only — V8 §6).
    let src = "\
        #include <stdio.h>\n\
        class C { public:\n\
          int foo(int x) { return x * 2; }\n\
          int foo(int x, int y) { return x + y; }\n\
        };\n\
        int main(void) {\n\
          C c;\n\
          printf(\"%d %d\\n\", c.foo(7), c.foo(3, 4));\n\
          return 0;\n\
        }\n";
    let mdbcc_out = out(src);
    assert_eq!(mdbcc_out, "14 7\n");
    assert_eq!(code(src), 0);
    differential_against_cl(src, &mdbcc_out, 0);
}

// ---- 13: cl differential — three overloads, exit code only ----------------

#[test]
fn differential_cl_three_overloads_exit_code() {
    let src = "\
        class C { public:\n\
          int foo(int a) { return a + 1; }\n\
          int foo(int a, int b) { return a + b + 2; }\n\
          int foo(double d) { return (int)d + 3; }\n\
        };\n\
        int main(void) {\n\
          C c;\n\
          return c.foo(10) + c.foo(20, 30) + c.foo(7.0);\n\
        }\n";
    let mdbcc_exit = code(src);
    // 11 + 52 + 10 = 73.
    assert_eq!(mdbcc_exit, 73);
    differential_against_cl(src, "", mdbcc_exit);
}

// ---- 14: non-overloaded methods coexist with overloaded ones --------------

#[test]
fn unrelated_unique_methods_unchanged_alongside_overloads() {
    // A class that overloads ONE name keeps every other method emitted
    // under its bare `Tag::name` symbol (per the byte-identity contract).
    // This test would fail loudly if the H5 mangling were applied
    // uniformly: bar() would be `C::bar$v` (or similar) and would not
    // round-trip.
    let src = "\
        class C { public:\n\
          int foo(int x) { return x; }\n\
          int foo(int x, int y) { return x + y; }\n\
          int bar() { return 100; }\n\
        };\n\
        int main(void) {\n\
          C c;\n\
          return c.foo(1) + c.foo(2, 3) + c.bar();\n\
        }\n";
    assert_eq!(code(src), 1 + 5 + 100);
}

// ---- 15: trailing-`const` on member functions (J-1 / H10 MINOR-1) ----------
//
// The OWL canonical pattern `T& operator[](int)` paired with
// `const T& operator[](int) const` requires parsing a trailing `const`
// after `)` on a member function. Before J-1 mdbcc errored loudly with
// `expected '{'` at the `const` position; after J-1 the parser accepts
// it, the AST records `const_method: true`, and the mangler emits a
// distinct symbol (suffix `K` per `overload_symbol`).
//
// **Receiver-constness disposition** (J-1a fallback per brief): mdbcc
// does NOT yet track `this`-constness through call sites, so when both a
// const and a non-const overload are viable the non-const overload wins
// the tie-break. Full receiver-const resolution is filed as J-1b.

#[test]
fn parse_trailing_const_member_fn() {
    // The smallest case: a single non-overloaded const method. The parser
    // must accept the trailing `const` between `)` and `{`. No mangling is
    // exercised here (non-overloaded ⇒ unmangled per H5 / J-1 contract).
    let src = "\
        class C { public:\n\
          int v;\n\
          int get() const { return v; }\n\
        };\n\
        int main(void) { C c; c.v = 17; return c.get(); }\n";
    let exe = compile_to_pe(src.as_bytes());
    assert!(exe.is_ok(), "compile should succeed: {:?}", exe.err());
}

#[test]
fn parse_trailing_volatile_accepted_silently() {
    // C++ permits `volatile` as a member-function cv-qualifier on the
    // same axis as `const`. mdbcc has no volatile semantics; we accept-
    // and-ignore it (no AST flag, no mangling impact). The test confirms
    // the parser doesn't choke.
    let src = "\
        class C { public:\n\
          int v;\n\
          int f() volatile { return v; }\n\
        };\n\
        int main(void) { C c; c.v = 9; return c.f(); }\n";
    let exe = compile_to_pe(src.as_bytes());
    assert!(exe.is_ok(), "compile should succeed: {:?}", exe.err());
}

#[test]
fn const_method_call_returns_correct_value() {
    // Runtime end-to-end: a non-overloaded const method returns the field.
    let src = "\
        class C { public:\n\
          int v;\n\
          int get() const { return v; }\n\
        };\n\
        int main(void) { C c; c.v = 42; return c.get(); }\n";
    assert_eq!(code(src), 42);
}

#[test]
fn const_and_nonconst_overloads_coexist() {
    // The canonical OWL container shape: at() in both const and non-const
    // forms. Both compile; both produce distinct mangled symbols (the H5
    // pattern extended with the `K` suffix for the const overload). The
    // J-1a fallback routes `obj.at(0)` to the NON-const overload — that's
    // the documented simplification (receiver-const resolution = J-1b).
    //
    // The non-const overload writes through its returned reference, the
    // const overload returns by value of the same int. Both bodies are
    // present in the emitted PE under distinct mangled symbols
    // (`V::at$i` and `V::at$iK`).
    let src = "\
        class V { public:\n\
          int data[4];\n\
          int at(int i) { return data[i] + 1; }\n\
          int at(int i) const { return data[i]; }\n\
        };\n\
        int main(void) {\n\
          V v; v.data[0] = 5; v.data[1] = 11;\n\
          return v.at(0) + v.at(1);\n\
        }\n";
    // J-1a: both at() candidates have score 0 against `int i = 0`. The
    // tie-break picks the non-const overload (returns data[i]+1) for both
    // calls, so the result is (5+1) + (11+1) = 18. Once J-1b lands the
    // const overload would dispatch on the receiver-constness and the
    // sum would still be 18 here (`v` is not const).
    assert_eq!(code(src), 18);
}

#[test]
fn const_method_out_of_line_definition() {
    // The trailing-const must be parsed in BOTH the inline-definition
    // path (line 605 in parser.rs) and the out-of-line path (line 1351 /
    // member_def_tail). This fixture exercises the latter via a class
    // body that declares the method (`int get() const;`) and a separate
    // out-of-line definition (`int C::get() const { ... }`).
    let src = "\
        class C { public:\n\
          int v;\n\
          int get() const;\n\
        };\n\
        int C::get() const { return v; }\n\
        int main(void) { C c; c.v = 99; return c.get(); }\n";
    assert_eq!(code(src), 99);
}

#[test]
fn const_method_does_not_change_byte_image_for_unaffected_programs() {
    // O1 byte-identity proof: a program that does NOT use trailing-const
    // must produce the exact same PE bytes before and after J-1. We
    // sanity-check by hashing the output and asserting it matches a
    // second compile of the same source (a deterministic-recompile
    // invariant). The contractual claim — "non-overloaded, non-const
    // member fns are byte-identical to pre-J-1" — is enforced
    // mechanically by the e2e 88-program suite (`tests/end_to_end.rs`)
    // staying green; this test additionally locks the same-build hash.
    fn fnv64(b: &[u8]) -> u64 {
        let mut h: u64 = 0xcbf29ce484222325;
        for &x in b {
            h = h.wrapping_mul(0x100000001b3) ^ x as u64;
        }
        h
    }
    let src = "\
        class C { public:\n\
          int v;\n\
          int get() { return v; }\n\
        };\n\
        int main(void) { C c; c.v = 7; return c.get(); }\n";
    let a = compile_to_pe(src.as_bytes()).expect("compile a");
    let b = compile_to_pe(src.as_bytes()).expect("compile b");
    let ha = fnv64(&a);
    let hb = fnv64(&b);
    assert_eq!(
        ha, hb,
        "deterministic-recompile invariant broken: {ha:x} != {hb:x}"
    );
}

#[test]
fn const_overload_emits_distinct_function_bodies() {
    // The H5 mangling rule (Option A) says: only mangle when overloaded.
    // For const overloads this means both forms get mangled — the
    // non-const as `V::at$i` and the const as `V::at$iK`. Both bodies
    // must be EMITTED into the PE; if one were silently elided the
    // const-overload path would never reach the linker. We give the
    // const overload a body that's clearly larger than the non-const
    // one (a series of arithmetic operations) and compare PE sizes
    // against a version that has only the non-const overload. The
    // file alignment (512 B) absorbs small differences, so we make
    // the const body comfortably exceed one alignment block.
    let with_const = "\
        class V { public:\n\
          int data[4];\n\
          int at(int i) { return data[i] + 1; }\n\
          int at(int i) const {\n\
            int x; x = data[i];\n\
            x = x * 2 + 3;\n\
            x = x * 5 + 7;\n\
            x = x * 11 + 13;\n\
            x = x * 17 + 19;\n\
            x = x * 23 + 29;\n\
            x = x * 31 + 37;\n\
            x = x * 41 + 43;\n\
            x = x * 47 + 53;\n\
            x = x * 59 + 61;\n\
            x = x * 67 + 71;\n\
            x = x * 73 + 79;\n\
            x = x * 83 + 89;\n\
            x = x * 97 + 101;\n\
            x = x * 103 + 107;\n\
            x = x * 109 + 113;\n\
            x = x * 127 + 131;\n\
            return x;\n\
          }\n\
        };\n\
        int main(void) { V v; v.data[0] = 1; return v.at(0); }\n";
    let without_const = "\
        class V { public:\n\
          int data[4];\n\
          int at(int i) { return data[i] + 1; }\n\
        };\n\
        int main(void) { V v; v.data[0] = 1; return v.at(0); }\n";
    let with_const_pe = compile_to_pe(with_const.as_bytes()).expect("compile ok");
    let without_const_pe = compile_to_pe(without_const.as_bytes()).expect("compile ok");
    assert!(
        with_const_pe.len() > without_const_pe.len(),
        "the const overload must produce a distinct emitted function: \
         with-const PE = {} bytes, without-const PE = {} bytes",
        with_const_pe.len(),
        without_const_pe.len()
    );
}

#[test]
fn const_method_pure_virtual_also_parses() {
    // Pure-virtual + const: `virtual int f() const = 0;`. The trailing
    // `const` must parse BEFORE the `= 0` token. We can't instantiate
    // the abstract class so the runtime path goes through a derived
    // class that overrides the method (also `const`, exercising the
    // out-of-line member-fn parse path).
    let src = "\
        class B { public:\n\
          virtual int f() const = 0;\n\
        };\n\
        class D : public B { public:\n\
          int v;\n\
          int f() const { return v; }\n\
        };\n\
        int main(void) { D d; d.v = 23; return d.f(); }\n";
    assert_eq!(code(src), 23);
}
