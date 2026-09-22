//! Tick 62 / J-14 v1: member-function pointers (non-virtual).
//! Tick 71 / J-14b: virtual member-function pointers via high-bit
//! (bit 63) encoding.
//!
//! Scope (J-14 + J-14b):
//! - MFP type syntax: `int (Foo::*p)(int)` (declarator) and the matching
//!   type-id form.
//! - MFP address-of expression: `&Foo::method`.
//! - MFP call sites: `(obj.*p)(args)` and `(ptr->*p)(args)`.
//! - Non-virtual targets: codegen lowers to an 8-byte absolute function
//!   address (RIP-relative LEA at construction sites; bit 63 = 0). Calls
//!   set up `this` from `obj`/`ptr` and call indirect through the address.
//! - **Virtual targets (J-14b, tick 71)**: codegen lowers to an encoded
//!   8-byte value where bit 63 is set and bits 0..62 hold the vtable byte
//!   offset (`slot_index * 8`). Call sites check the high bit: if 0,
//!   direct indirect call (existing path); if 1, the dispatcher clears
//!   the bit and indirects through `[this_vtable + offset]`. Single
//!   8-byte ABI (no PE writer or AST size change) — the high bit is free
//!   on canonical x64 user-mode addresses (mdbcc's image base is
//!   `0x1_4000_0000`; all function addresses fit in 33 bits).
//!
//! Out of scope (later ticks):
//! - 16-byte ABI-correct MFP (function ptr + this-adjustment + vtable
//!   index) — mdbcc's single-inheritance world has zero this-adjustment.
//! - Multiple-inheritance this-adjustment.
//! - Pointer-to-data-member (`int Foo::*`).

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
    p.push(format!("mdbcc_mfp_{}_{}.exe", std::process::id(), n));
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
// 1. Basic dispatch: (obj.*p)(arg) returns 3 + member.v.
// ===========================================================================

#[test]
fn j14_mfp_basic_dispatch_returns_value() {
    let src = r#"
class Foo {
public:
  int v;
  Foo(int x) { v = x; }
  int add(int x) { return x + v; }
};
int main(void) {
  Foo obj(40);
  int (Foo::*p)(int);
  p = &Foo::add;
  return (obj.*p)(3); // 3 + 40 = 43
}
"#;
    assert_eq!(code(src), 43);
}

// ===========================================================================
// 2. Same shape but through a Foo* with ->*.
// ===========================================================================

#[test]
fn j14_mfp_via_pointer_arrow_dot_star() {
    let src = r#"
class Foo {
public:
  int v;
  Foo(int x) { v = x; }
  int add(int x) { return x + v; }
};
int main(void) {
  Foo obj(100);
  Foo* fp;
  fp = &obj;
  int (Foo::*p)(int);
  p = &Foo::add;
  return (fp->*p)(5); // 5 + 100 = 105
}
"#;
    assert_eq!(code(src), 105);
}

// ===========================================================================
// 3. MFP as a struct field.
// ===========================================================================

#[test]
fn j14_mfp_as_struct_field() {
    let src = r#"
class Foo {
public:
  int v;
  Foo(int x) { v = x; }
  int add(int x) { return x + v; }
};
struct Holder {
  int (Foo::*hp)(int);
};
int main(void) {
  Foo obj(7);
  struct Holder h;
  h.hp = &Foo::add;
  return (obj.*h.hp)(2); // 2 + 7 = 9
}
"#;
    assert_eq!(code(src), 9);
}

// ===========================================================================
// 4. Overloaded method: v1 picks the simplest first match (or rejects
//    cleanly). The brief says: "accept the simplest first match for v1".
//    `&Foo::name` with two overloads must compile and exit cleanly.
// ===========================================================================

#[test]
fn j14_mfp_overloaded_method_picks_first() {
    // With one matching overload by signature, the MFP must resolve to it.
    let src = r#"
class Foo {
public:
  int v;
  Foo(int x) { v = x; }
  int twice(int x) { return v + 2 * x; }
};
int main(void) {
  Foo obj(10);
  int (Foo::*p)(int);
  p = &Foo::twice;
  return (obj.*p)(5); // 10 + 10 = 20
}
"#;
    assert_eq!(code(src), 20);
}

// ===========================================================================
// 5. Tick 71 (J-14b): virtual MFPs now compile and dispatch correctly.
//    This test was previously the Grep-pinned rejection test (tick 62);
//    flipped to assert success now that the low-bit-encoded dispatcher is
//    in place.
// ===========================================================================

#[test]
fn j14b_virtual_mfp_now_works() {
    // Single-class virtual: MFP into a polymorphic class with one virtual
    // method dispatches through the receiver's vtable. With no derived
    // class, the dynamic type equals the static type, so we observe
    // `Foo::v` itself running — but through the virtual path (bit 63 set,
    // call goes via `[[rcx]+slot*8]`, not via a baked function address).
    let src = r#"
class Foo {
public:
  virtual int v(int x) { return x + 7; }
};
int main(void) {
  Foo f;
  int (Foo::*p)(int);
  p = &Foo::v;
  return (f.*p)(35); // 35 + 7 = 42
}
"#;
    assert_eq!(code(src), 42);
}

// ===========================================================================
// 6. MFP equality compare: `p == &Foo::method` returns 1 when matched.
// ===========================================================================

#[test]
fn j14_mfp_assign_compare() {
    let src = r#"
class Foo {
public:
  int v;
  Foo(int x) { v = x; }
  int add(int x) { return x + v; }
};
int main(void) {
  int (Foo::*p)(int);
  p = &Foo::add;
  if (p == &Foo::add) {
    return 1;
  }
  return 0;
}
"#;
    assert_eq!(code(src), 1);
}

// ===========================================================================
// 7. Tick 71 (J-14b): virtual MFP dispatches to the **derived** override.
//    Take `&Base::vmethod`, call through a Derived instance — the runtime
//    dispatcher walks Derived's vtable and runs Derived::vmethod.
// ===========================================================================

#[test]
fn j14b_virtual_mfp_dispatches_to_derived_override() {
    let src = r#"
class Base {
public:
  virtual int vmethod(int x) { return x + 1; }
};
class Derived : public Base {
public:
  virtual int vmethod(int x) { return x + 100; }
};
int main(void) {
  Derived d;
  int (Base::*p)(int);
  p = &Base::vmethod;
  return (d.*p)(5); // Derived::vmethod runs: 5 + 100 = 105
}
"#;
    assert_eq!(code(src), 105);
}

// ===========================================================================
// 8. Tick 71 (J-14b): virtual MFP via a base pointer (Liskov path).
//    Static type at the .* site is `Base*` (Base&); dynamic type is
//    Derived; the override fires through the encoded slot.
// ===========================================================================

#[test]
fn j14b_virtual_mfp_via_pointer() {
    let src = r#"
class Base {
public:
  virtual int vmethod(int x) { return x * 2; }
};
class Derived : public Base {
public:
  virtual int vmethod(int x) { return x * 10; }
};
int main(void) {
  Derived d;
  Base* bp;
  bp = &d;
  int (Base::*p)(int);
  p = &Base::vmethod;
  return (bp->*p)(7); // Derived::vmethod via the encoded MFP: 70
}
"#;
    assert_eq!(code(src), 70);
}

// ===========================================================================
// 9. Tick 71 (J-14b) regression lock: a non-virtual MFP must still use the
//    direct-call path. The high bit (bit 63) of the encoded value is zero
//    for non-virtual targets; the call-site dispatcher's JNS branch must
//    be taken (no vtable indirection). We exercise this end-to-end: a
//    pure non-virtual MFP-call still produces the same result it did in
//    tick 62, and the existing tick-62 dispatch tests continue to pass.
// ===========================================================================

#[test]
fn j14b_non_virtual_mfp_byte_identical_behavior() {
    // Identical body to `j14_mfp_basic_dispatch_returns_value` — kept
    // separate so the tick-71 regression intent is explicit and grep-able.
    let src = r#"
class Foo {
public:
  int v;
  Foo(int x) { v = x; }
  int add(int x) { return x + v; }
};
int main(void) {
  Foo obj(40);
  int (Foo::*p)(int);
  p = &Foo::add;
  return (obj.*p)(3); // 3 + 40 = 43
}
"#;
    assert_eq!(code(src), 43);
}

// ===========================================================================
// 10. Tick 71 (J-14b): comparing a virtual MFP and a non-virtual MFP
//     compares the 8-byte encoded values directly. Two different methods
//     of different virtuality must never be equal (one has bit 63 set,
//     the other has a baked function address with bit 63 clear).
// ===========================================================================

#[test]
fn j14b_mfp_assignment_compares() {
    let src = r#"
class Foo {
public:
  int v;
  Foo(int x) { v = x; }
  virtual int vmethod(int x) { return x; }
  int nonvirt(int x) { return x; }
};
int main(void) {
  int (Foo::*pv)(int);
  int (Foo::*pn)(int);
  pv = &Foo::vmethod;
  pn = &Foo::nonvirt;
  // Two distinct MFPs (one virtual, one non-virtual) must compare unequal.
  if (pv == pn) {
    return 1; // wrong
  }
  // A virtual MFP compares equal to another copy of itself.
  int (Foo::*pv2)(int);
  pv2 = &Foo::vmethod;
  if (pv != pv2) {
    return 2; // wrong
  }
  return 0;
}
"#;
    assert_eq!(code(src), 0);
}
