//! B-04: Win64 reference-argument binding must upcast derived lvalues to the
//! requested base subobject before marshalling the pointer.
//!
//! The i386 marshaller already routed `D&` -> `B&` binding through pointer
//! conversion. Win64's `marshal_args` took the source address and passed it
//! unchanged, which is wrong when a polymorphic derived class shifts its
//! non-polymorphic base behind the vptr.

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
        p.push(format!(
            "mdbcc_win64_refbase_{}_{}.exe",
            std::process::id(),
            n
        ));
        TempExe(p)
    }
}

impl Drop for TempExe {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn run(src: &str) -> i32 {
    let exe = compile_to_pe(src.as_bytes()).expect("compile ok");
    let tmp = TempExe::new();
    std::fs::write(&tmp.0, &exe).expect("write exe");
    let status = Command::new(&tmp.0)
        .status()
        .unwrap_or_else(|e| panic!("failed to launch generated exe: {e}"));
    status.code().expect("process returned an exit code")
}

#[test]
fn direct_ref_arg_binds_shifted_base_subobject() {
    let src = "\
        struct M { int v; M(int k) : v(k) {} };\n\
        struct D : M { D() : M(40) {} virtual int f() { return 1; } };\n\
        int take(M& m) { return m.v + 2; }\n\
        int main(void) { D d; return take(d); }\n";
    assert_eq!(run(src), 42);
}

#[test]
fn this_deref_ref_arg_binds_shifted_base_subobject() {
    let src = "\
        struct M { int v; M(int k) : v(k) {} };\n\
        int take(M& m) { return m.v + 2; }\n\
        struct D : M { D() : M(40) {} virtual int f() { return take(*this); } };\n\
        int main(void) { D d; return d.f(); }\n";
    assert_eq!(run(src), 42);
}

#[test]
fn virtual_ref_arg_binds_shifted_base_subobject() {
    let src = "\
        struct M { int v; M(int k) : v(k) {} };\n\
        struct App { virtual int take(M& m) { return m.v + 2; } };\n\
        struct D : M { D() : M(40) {} virtual int f(App* app) { return app->take(*this); } };\n\
        int main(void) { App app; D d; return d.f(&app); }\n";
    assert_eq!(run(src), 42);
}

#[test]
fn function_pointer_ref_arg_binds_shifted_base_subobject() {
    let src = "\
        struct M { int v; M(int k) : v(k) {} };\n\
        struct D : M { D() : M(40) {} virtual int f() { return 1; } };\n\
        int take(M& m) { return m.v + 2; }\n\
        int main(void) { int (*fp)(M&); D d; fp = take; return fp(d); }\n";
    assert_eq!(run(src), 42);
}
