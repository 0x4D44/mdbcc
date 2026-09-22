//! J-10 v1 (tick 58): invoke user-defined copy constructors at by-value
//! pass and by-value return sites.
//!
//! Scope (this tick):
//! - User declares `Tag(const Tag& other) { … }` (or pre-standard `Tag(Tag&
//!   other)` — both accepted). At every by-value-pass site for `Tag`, the
//!   caller invokes the copy ctor on its hidden buffer instead of `memcpy`.
//!   At every by-value-return site, the callee invokes the copy ctor on
//!   the caller's hidden result buffer instead of `memcpy`.
//! - Class with NO copy ctor: existing `memcpy` (`emit_struct_copy`) path
//!   is preserved verbatim (regression-locking — see `*_memcpy_path_is_unchanged`).
//! - InReg-classified classes (size ∈ {1,2,4,8}) with a copy ctor are
//!   rejected loudly (out-of-scope safety net).
//! - Class with a class-typed member whose nested class has a copy ctor
//!   but the outer class has no copy ctor ⇒ tick 66 (J-10b) SYNTHESISES the
//!   missing outer copy ctor memberwise; pre-tick-66 this was a clean
//!   compile-time error pinning the J-10b queue position.
//!
//! Out of scope:
//! - Base-class copy chaining (synthesised ctor with a non-trivial base):
//!   rejected loudly with "synthesized copy ctor with non-trivial base
//!   class is deferred to J-10b-base".
//! - Move ctors (C++11).
//! - Explicit `= delete` / `= default` syntax.
//! - Destructor invocation on by-value-passed params at callee exit (H1
//!   already defers this; same scope here).

#![cfg(windows)]

mod support;

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

fn build(src: &str) -> TempExe {
    let exe = compile_to_pe(src.as_bytes()).expect("mdbcc compile ok");
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("mdbcc_cpyctor_{}_{}.exe", std::process::id(), n));
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

// ===========================================================================
// 1. Copy ctor invoked at by-value pass site.
// ===========================================================================

/// Pass a HiddenPtr-classified class by value; the user copy ctor must fire.
/// Without J-10 v1, the caller `memcpy`s the source into the hidden buffer
/// and the counter stays 0 (silent miscompile).
#[test]
fn class_with_copy_ctor_invoked_on_by_value_pass() {
    let src = r#"
int counter;
class Foo {
public:
  int x;
  int y;
  int z;
  Foo() { x = 0; y = 0; z = 0; }
  Foo(const Foo& o) {
    counter = counter + 1;
    x = o.x;
    y = o.y;
    z = o.z;
  }
};
int f(Foo b) { return b.x + b.y + b.z; }
int main(void) {
  Foo a;
  a.x = 10; a.y = 20; a.z = 30;
  counter = 0;
  int s = f(a);
  // counter must increment exactly once per by-value pass.
  return counter * 100 + s;
}
"#;
    // 1 copy + s=60 ⇒ 160.
    assert_eq!(code(src), 160);
}

// ===========================================================================
// 2. Copy ctor invoked at by-value return site.
// ===========================================================================

/// Return a HiddenPtr-classified class by value; the user copy ctor must
/// fire on the caller's result buffer.
#[test]
fn class_with_copy_ctor_invoked_on_by_value_return() {
    let src = r#"
int counter;
class Foo {
public:
  int x;
  int y;
  int z;
  Foo() { x = 0; y = 0; z = 0; }
  Foo(const Foo& o) {
    counter = counter + 1;
    x = o.x;
    y = o.y;
    z = o.z;
  }
};
Foo make_foo(int v) {
  Foo a;
  a.x = v; a.y = v + 1; a.z = v + 2;
  return a;
}
int main(void) {
  counter = 0;
  Foo r = make_foo(5);
  // by-value RETURN ⇒ exactly one copy ctor invocation on the result.
  return counter * 100 + r.x + r.y + r.z;
}
"#;
    // 1 copy + (5+6+7=18) ⇒ 118.
    assert_eq!(code(src), 118);
}

// ===========================================================================
// 3. Chained pass + return: f(g(x)) where both copies fire.
// ===========================================================================

#[test]
fn class_with_copy_ctor_invoked_in_chained_call() {
    let src = r#"
int counter;
class Foo {
public:
  int x;
  int y;
  int z;
  Foo() { x = 0; y = 0; z = 0; }
  Foo(const Foo& o) {
    counter = counter + 1;
    x = o.x;
    y = o.y;
    z = o.z;
  }
};
Foo make_foo(int v) {
  Foo a;
  a.x = v; a.y = v + 1; a.z = v + 2;
  return a;
}
int consume(Foo b) { return b.x + b.y + b.z; }
int main(void) {
  counter = 0;
  // make_foo(5) ⇒ 1 copy (return). consume(...) ⇒ 1 copy (pass). Total 2.
  int s = consume(make_foo(5));
  return counter * 100 + s;
}
"#;
    // 2 copies + s=18 ⇒ 218.
    assert_eq!(code(src), 218);
}

// ===========================================================================
// 4. Regression lock: class without copy ctor still uses memcpy.
// ===========================================================================

/// A plain class with no copy ctor must hit the existing `emit_struct_copy`
/// path. The fixture exercises the byte-by-byte memcpy of a 12-byte struct
/// across a by-value pass and asserts the data arrives intact.
#[test]
fn class_without_copy_ctor_still_memcpys_byte_identical() {
    let src = r#"
class Bag {
public:
  int x;
  int y;
  int z;
};
int sum(Bag b) { return b.x + b.y + b.z; }
int main(void) {
  Bag a;
  a.x = 11;
  a.y = 22;
  a.z = 33;
  return sum(a);
}
"#;
    assert_eq!(code(src), 66);
}

// ===========================================================================
// 5. InReg-sized class with a copy ctor: now passed by HiddenPtr (S4.2ao).
// ===========================================================================

#[test]
fn inreg_sized_class_with_copy_ctor_passes_via_hiddenptr() {
    // sizeof(Tiny) == 4 ⇒ pure-size classify picks InReg(4). But a class with a
    // non-trivial copy ctor must travel by HIDDEN POINTER per the Win64 ABI (the
    // copy ctor initialises a caller-allocated copy) — a GPR has nowhere for the
    // copy ctor's `this` to point. Pre-S4.2ao this was a hard, Grep-pinned
    // rejection ("InReg-classified class with a copy ctor is not supported");
    // S4.2ao's `effective_struct_abi` now overrides InReg→HiddenPtr for
    // copy-ctor classes, so `f(a)` flows through the existing by-reference path
    // (which invokes the copy ctor). COMPILE-ONLY: a run-assert (== 7) is
    // omitted because Windows Defender deterministically quarantines the
    // generated PE in this env (os error 225, the S7-gating false-positive).
    // Mirrors `class_with_copy_ctor_invoked_on_by_value_pass` (a >8 class that
    // already runs) but with a SIZE-8 class — the exact case S4.2ao reroutes
    // from InReg to HiddenPtr. The copy ctor MUST fire (counter == 1), proving
    // the by-reference path runs, not a silent byte-pack.
    let src = r#"
int counter;
class Eight {
public:
  int x;
  int y;
  Eight() { x = 0; y = 0; }
  Eight(const Eight& o) { counter = counter + 1; x = o.x; y = o.y; }
};
int f(Eight b) { return b.x + b.y; }
int main(void) {
  Eight a;
  a.x = 10; a.y = 20;
  counter = 0;
  int s = f(a);
  return counter * 100 + s;
}
"#;
    // 1 copy + s=30 ⇒ 130 (proves the copy ctor fired via HiddenPtr at size 8).
    assert_eq!(code(src), 130);
}

#[test]
fn inreg_sized_class_with_copy_ctor_returns_via_hiddenptr() {
    // S4.2ao return path: a SIZE-8 copy-ctor class RETURNED by value must use
    // HiddenPtr so the copy ctor fires on the caller's result buffer — mirrors
    // `class_with_copy_ctor_invoked_on_by_value_return` (a >8 class) at size 8.
    // Without the return-site override the class would be classified InReg
    // (returned byte-packed in RAX, copy ctor skipped) ⇒ counter == 0.
    let src = r#"
int counter;
class Eight {
public:
  int x;
  int y;
  Eight() { x = 0; y = 0; }
  Eight(const Eight& o) { counter = counter + 1; x = o.x; y = o.y; }
};
Eight make_eight(int v) {
  Eight a;
  a.x = v; a.y = v + 1;
  return a;
}
int main(void) {
  counter = 0;
  Eight r = make_eight(5);
  return counter * 100 + r.x + r.y;
}
"#;
    // 1 copy + (5+6=11) ⇒ 111 (the return-site copy ctor fired via HiddenPtr).
    assert_eq!(code(src), 111);
}

// ===========================================================================
// 6. Member-with-copy-ctor on a class that has no copy ctor: NO LONGER an
//    error after tick 66 (J-10b) — the outer copy ctor is synthesised. This
//    test just verifies the formerly-defensive program compiles cleanly now;
//    behavioural validation lives in the `t_j10b_*` tests below.
// ===========================================================================

#[test]
fn class_with_inner_copy_ctor_compiles_after_j10b_synthesis() {
    let src = r#"
int counter;
class Inner {
public:
  int x;
  int y;
  int z;
  Inner() { x = 0; y = 0; z = 0; }
  Inner(const Inner& o) {
    counter = counter + 1;
    x = o.x;
    y = o.y;
    z = o.z;
  }
};
class Outer {
public:
  Inner i;
  int tag;
};
int main(void) {
  Outer a;
  return 0;
}
"#;
    // Pre-tick-66 this raised the "memberwise synthesis is deferred to J-10b"
    // defensive CodegenError. Tick 66 closes that gap by synthesising the
    // outer copy ctor; the program now compiles cleanly.
    assert!(compile_to_pe(src.as_bytes()).is_ok());
}

// ===========================================================================
// 7. Pre-standard relaxed (non-const) copy ctor accepted.
// ===========================================================================

/// `Tag(Tag& other)` — pre-standard non-const form, accepted as a copy
/// ctor (the relaxation MSVC and bcc32 5.5.1 both implement).
#[test]
fn pre_standard_relaxed_non_const_copy_ctor_accepted() {
    let src = r#"
int counter;
class Foo {
public:
  int x;
  int y;
  int z;
  Foo() { x = 0; y = 0; z = 0; }
  Foo(Foo& o) {
    counter = counter + 1;
    x = o.x;
    y = o.y;
    z = o.z;
  }
};
int f(Foo b) { return b.x + b.y + b.z; }
int main(void) {
  Foo a;
  a.x = 1; a.y = 2; a.z = 3;
  counter = 0;
  int s = f(a);
  return counter * 100 + s;
}
"#;
    // 1 copy + s=6 ⇒ 106.
    assert_eq!(code(src), 106);
}

// ===========================================================================
// 8. Multiple passes: counter increments per pass.
// ===========================================================================

#[test]
fn copy_ctor_invoked_per_pass_call() {
    let src = r#"
int counter;
class Foo {
public:
  int x;
  int y;
  int z;
  Foo() { x = 0; y = 0; z = 0; }
  Foo(const Foo& o) {
    counter = counter + 1;
    x = o.x;
    y = o.y;
    z = o.z;
  }
};
int f(Foo b) { return b.x + b.y + b.z; }
int main(void) {
  Foo a;
  a.x = 1; a.y = 2; a.z = 3;
  counter = 0;
  int s = f(a) + f(a) + f(a);
  // 3 passes ⇒ 3 copies, s = 6*3 = 18.
  return counter * 100 + s;
}
"#;
    assert_eq!(code(src), 318);
}

// ===========================================================================
// 9. Copy ctor body has visible side effects (mutating an int outside x).
// ===========================================================================

#[test]
fn copy_ctor_body_observable_side_effect() {
    // The copy ctor sets `b.x` to a marker independent of the source — this
    // is non-standard (a real C++ copy ctor would copy the field) but it
    // proves the ctor's body ran, not a `memcpy`.
    let src = r#"
class Marker {
public:
  int x;
  int y;
  int z;
  Marker() { x = 0; y = 0; z = 0; }
  Marker(const Marker& o) { x = 999; y = o.y; z = o.z; }
};
int f(Marker m) { return m.x; }
int main(void) {
  Marker a;
  a.x = 1; a.y = 2; a.z = 3;
  return f(a);
}
"#;
    // If memcpy fired, return would be 1; if copy ctor body ran, 999.
    assert_eq!(code(src), 999);
}

// ===========================================================================
// J-10c (tick 61): copy-init at declaration site — `T x = y;` for class T.
// ===========================================================================
//
// Before tick 61 the Decl path memcpy'd the source bytes into the local
// slot — silent miscompile for any class with a user copy ctor. Tick 61
// invokes the copy ctor on `&local` with `&source` instead, when the
// target class declares one. Plain-data classes (no copy ctor) continue
// to memcpy verbatim. Source expressions that are record-returning calls
// or overloaded-binop record rvalues already deliver a fully copy-
// constructed object in their own result buffer (tick 58 return-site
// path); for those the Decl path keeps memcpying to avoid a redundant
// second copy-ctor invocation per `T x = make_t();`.

/// `T x = y;` where both `T` and `decltype(y)` are the same class with a
/// user copy ctor — the copy ctor must fire on `&x` with `&y` as the
/// source. Without J-10c the Decl-arm memcpy silently bypasses it.
#[test]
fn t_j10c_copy_init_at_declaration_invokes_copy_ctor() {
    let src = r#"
int counter;
class C {
public:
  int v;
  C() { v = 0; }
  C(const C& o) { counter = counter + 1; v = o.v + 1; }
};
int main(void) {
  C a;
  a.v = 10;
  counter = 0;
  C b = a;
  // copy ctor must fire on b with a as source ⇒ counter=1, b.v=11.
  return counter * 100 + b.v;
}
"#;
    // 1 copy + b.v=11 ⇒ 111.
    assert_eq!(code(src), 111);
}

/// Chained copy-init: `C b = a; C c = b;` — each declaration invokes the
/// copy ctor exactly once, and each derived value carries the +1 marker
/// from its own copy ctor invocation.
#[test]
fn t_j10c_chained_copy_init() {
    let src = r#"
int counter;
class C {
public:
  int v;
  C() { v = 0; }
  C(const C& o) { counter = counter + 1; v = o.v + 1; }
};
int main(void) {
  C a;
  a.v = 10;
  counter = 0;
  C b = a;       // 1 copy: b.v = 11
  C c = b;       // 1 copy: c.v = 12
  // counter=2, c.v=12 ⇒ 212.
  return counter * 100 + c.v;
}
"#;
    assert_eq!(code(src), 212);
}

/// Regression lock: a class with NO copy ctor still uses the memcpy path
/// for `T x = y;`. The byte-identical copy must arrive intact.
#[test]
fn t_j10c_plain_pod_class_still_memcpys() {
    let src = r#"
class POD {
public:
  int x;
  int y;
  int z;
};
int main(void) {
  POD a;
  a.x = 7;
  a.y = 11;
  a.z = 13;
  POD b = a;
  return b.x + b.y + b.z;
}
"#;
    // 7 + 11 + 13 = 31. memcpy preserves bytes byte-for-byte.
    assert_eq!(code(src), 31);
}

/// Pre-standard relaxed copy ctor form `C(C&)` (no `const`) is also a
/// copy ctor for J-10c's purposes — `Sigs::copy_ctor_symbol` already
/// recognises both forms via tick 58.
#[test]
fn t_j10c_pre_standard_relaxed_copy_init() {
    let src = r#"
int counter;
class C {
public:
  int v;
  C() { v = 0; }
  C(C& o) { counter = counter + 1; v = o.v + 1; }
};
int main(void) {
  C a;
  a.v = 5;
  counter = 0;
  C b = a;
  return counter * 100 + b.v;
}
"#;
    // 1 copy + b.v=6 ⇒ 106.
    assert_eq!(code(src), 106);
}

// ===========================================================================
// J-10b (tick 66): memberwise copy-ctor synthesis.
// ===========================================================================
//
// Tick 58 introduced a defensive `CodegenError` when an outer class contained
// a class-typed member with its own copy ctor but the outer itself had no
// copy ctor. The fix this tick closes the gap: when that combination occurs,
// the codegen SYNTHESISES the outer copy ctor as a memberwise body — invoking
// each member's copy ctor in declaration order and memcpying any scalar /
// trivial members. The synthesised ctor is registered under the canonical
// `<Tag>::<Tag>` symbol so the existing tick 58 / tick 61 lookup machinery
// finds it transparently.

/// Headline case: outer class has a class-typed member whose inner class has
/// a copy ctor; the outer itself declares NO copy ctor. With J-10b the outer
/// gets a synthesised copy ctor that invokes `Inner::Inner(const Inner&)` on
/// the member field and memcpys the scalar field. `Outer b = a;` ⇒ the
/// inner's copy ctor fires once (counter +1) and `b.m.v` ends up `a.m.v + 1`.
#[test]
fn t_j10b_memberwise_synthesis_invokes_inner_copy_ctor() {
    let src = r#"
class Inner {
public:
  int v;
  Inner() { v = 0; }
  Inner(const Inner& o) { v = o.v + 1; }
};
class Outer {
public:
  Inner m;
  int x;
};
int main(void) {
  Outer a;
  a.m.v = 10;
  a.x = 99;
  Outer b = a;
  // Expected: b.m.v = 10 + 1 = 11 (inner's copy ctor adds 1); b.x = 99
  // (memcpy). Sum 110.
  return b.m.v + b.x;
}
"#;
    assert_eq!(code(src), 110);
}

/// Regression lock: a class WITHOUT any class-typed member with a copy ctor
/// must NOT have a synthesised copy ctor. The whole-object memcpy path stays
/// verbatim ⇒ no behavioural change for plain-data classes (and the O1 byte-
/// identity contract holds for them).
#[test]
fn t_j10b_synthesized_only_when_needed() {
    let src = r#"
class POD {
public:
  int x;
  int y;
  int z;
};
int sum(POD p) { return p.x + p.y + p.z; }
int main(void) {
  POD a;
  a.x = 1;
  a.y = 2;
  a.z = 3;
  POD b = a;
  return sum(b);
}
"#;
    // 1 + 2 + 3 = 6.
    assert_eq!(code(src), 6);
}

/// The synthesised copy ctor must also fire at a by-value pass site (the
/// tick 58 pass-site path: `lower_struct_arg` HiddenPtr branch). Invoking
/// `f(a)` for `f(Outer b)` triggers the synthesised ctor on the hidden
/// buffer; the inner copy ctor's +1 marker must be visible inside `f`.
///
/// `Outer` is padded to >8 bytes so the Win64 classifier picks HiddenPtr
/// (InReg-with-copy-ctor is rejected by tick 58 — a separate ABI-level
/// constraint orthogonal to J-10b).
#[test]
fn t_j10b_synthesized_ctor_invoked_on_by_value_pass() {
    let src = r#"
class Inner {
public:
  int v;
  Inner() { v = 0; }
  Inner(const Inner& o) { v = o.v + 1; }
};
class Outer {
public:
  Inner m;
  int x;
  int y;
  int z;
};
int f(Outer b) { return b.m.v + b.x + b.y + b.z; }
int main(void) {
  Outer a;
  a.m.v = 10;
  a.x = 99;
  a.y = 7;
  a.z = 3;
  // Pass by value: synthesised ctor fires on the hidden buffer; inner ctor
  // adds 1 to v ⇒ 11. b.x = 99, b.y = 7, b.z = 3 (memcpy). Sum 120.
  return f(a);
}
"#;
    assert_eq!(code(src), 120);
}

/// S4.2az (J-10b-base): a synth copy ctor over a TRIVIAL base (no copy ctor)
/// is now SUPPORTED — the base's fields are re-laid into the outer's fields
/// and copied by the field loop. This used to be deferred ("any base disables
/// synthesis"); it now compiles. (The remaining deferral — a base with its OWN
/// copy ctor — is pinned in the test below.)
#[test]
fn t_j10b_trivial_base_class_copy_ctor_now_synthesises() {
    let src = r#"
class Inner {
public:
  int v;
  Inner() { v = 0; }
  Inner(const Inner& o) { v = o.v + 1; }
};
class Base {
public:
  int b;
};
class Outer : public Base {
public:
  Inner m;
  int x;
  int y;
};
int main(void) {
  Outer a;
  return 0;
}
"#;
    compile_to_pe(src.as_bytes())
        .expect("S4.2az: synth copy ctor over a trivial base must now compile");
}

/// Grep-pin the REMAINING deferred surface (S4.2az): a base that has its OWN
/// copy ctor still defers — chaining into the base copy ctor is unverified
/// S4.2b1 (J-10b-base-chain): a synth copy ctor now CHAINS a base class's own
/// copy ctor (was deferred in S4.2az). The class compiles — the synth calls the
/// base copy ctor on the base subobject and the Inner member's copy ctor.
#[test]
fn t_j10b_base_class_with_copy_ctor_now_chains() {
    let src = r#"
class Inner {
public:
  int v;
  Inner() { v = 0; }
  Inner(const Inner& o) { v = o.v + 1; }
};
class Base {
public:
  int b;
  Base() { b = 0; }
  Base(const Base& o) { b = o.b + 1; }
};
class Outer : public Base {
public:
  Inner m;
};
int main(void) {
  Outer a;
  return 0;
}
"#;
    compile_to_pe(src.as_bytes())
        .expect("S4.2b1: synth copy ctor chaining a base copy ctor must now compile");
}

/// S3/RailC: a declaration-only private copy ctor marks the type non-copyable,
/// but it must not be dragged into the image when no copy actually occurs.
/// OWL uses this pattern heavily; emitting an unused synthesized outer copy ctor
/// produces unresolved references to private copy ctors that no library defines.
#[test]
fn unused_synth_copy_ctor_does_not_reference_private_member_copy_ctor() {
    let src = r#"
class NonCopy {
public:
  int x;
  NonCopy() { x = 7; }
private:
  NonCopy(const NonCopy&);
};
class Holder {
public:
  NonCopy n;
  Holder() {}
  int value() { return n.x; }
};
int main(void) {
  Holder h;
  return h.value();
}
"#;
    assert_eq!(code(src), 7);
}

/// Headline copy-init case (the J-10c declaration-init path): `Outer b = a;`
/// must use the synthesised copy ctor, not the silent memcpy.
#[test]
fn t_j10b_synthesized_ctor_invoked_on_copy_init() {
    let src = r#"
int counter;
class Inner {
public:
  int v;
  Inner() { v = 0; }
  Inner(const Inner& o) { counter = counter + 1; v = o.v + 1; }
};
class Outer {
public:
  Inner m;
  int x;
};
int main(void) {
  Outer a;
  a.m.v = 10;
  a.x = 99;
  counter = 0;
  Outer b = a;
  // Exactly one copy-ctor invocation (on the inner member); outer is
  // memberwise. counter=1, b.m.v=11, b.x=99 ⇒ 100 + 11 + 99 = 210.
  return counter * 100 + b.m.v + b.x;
}
"#;
    assert_eq!(code(src), 210);
}
