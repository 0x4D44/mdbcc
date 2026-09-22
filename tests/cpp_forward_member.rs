//! S4.2: forward member references in inline member functions.
//!
//! A C++ inline member function body is a *complete-class context*: it may name
//! data members declared LATER in the same class. Borland's RTL/classlib relies
//! on this everywhere — e.g. REF.H:
//!
//! ```cpp
//! class TReference {
//! public:
//!     void AddReference() { Refs++; }   // Refs used here ...
//! private:
//!     unsigned short Refs;              // ... but declared here
//! };
//! ```
//!
//! mdbcc parses inline bodies eagerly (before later members are seen), so such a
//! name lowers to a bare `Var`. Codegen's `this_member_fallback` resolves it:
//! when a `Var` is otherwise undeclared (locals, globals, and functions are all
//! resolved first — and codegen's symbol tables are whole-TU complete) and a
//! `this` pointer to a record is in scope, it is treated as `this->name`.
//!
//! These tests compile + run on the real OS loader (Win64) and assert the exit
//! code, proving the member access actually reads/writes the right field — not
//! merely that it parses.

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

fn code(src: &str) -> i32 {
    let exe = compile_to_pe(src.as_bytes()).expect("mdbcc compile ok");
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("mdbcc_fwdmem_{}_{}.exe", std::process::id(), n));
    let t = TempExe(p);
    std::fs::write(&t.0, &exe).expect("write exe");
    Command::new(&t.0)
        .status()
        .expect("launch")
        .code()
        .expect("exit code")
}

/// A read of a data member declared after the inline method that reads it.
#[test]
fn read_member_declared_later() {
    let src = "struct S { int get() { return x; } int x; };\n\
               int main(){ S s; s.x = 42; return s.get(); }";
    assert_eq!(code(src), 42);
}

/// A write (`++`) to a member declared after the inline method — REF.H's
/// `AddReference() { Refs++; }` pattern exactly.
#[test]
fn mutate_member_declared_later() {
    let src = "struct S { void inc() { n++; } int n; };\n\
               int main(){ S s; s.n = 5; s.inc(); s.inc(); return s.n; }";
    assert_eq!(code(src), 7);
}

/// Two members declared after, used together in one expression.
#[test]
fn two_members_declared_later() {
    let src = "struct S { int sum() { return a + b; } int a; int b; };\n\
               int main(){ S s; s.a = 3; s.b = 4; return s.sum(); }";
    assert_eq!(code(src), 7);
}

/// Regression guard: a member function referencing a file-scope GLOBAL must
/// still bind to the global (resolved before the member fallback), NOT be
/// hijacked into `this->g`. If the fallback were too eager this would become a
/// "no member named g" error or read the wrong storage.
#[test]
fn method_still_reads_global_not_this_member() {
    let src = "int g = 10;\n\
               struct S { int f() { return g; } int x; };\n\
               int main(){ S s; s.x = 99; return s.f(); }";
    assert_eq!(code(src), 10);
}
