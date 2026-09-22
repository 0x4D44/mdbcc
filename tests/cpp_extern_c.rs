//! S3: `extern "C"` linkage-specifications (C++ §7.5) — end-to-end.
//!
//! The parser-level behaviour (block / single form, `c_linkage` flagging,
//! nesting, the undisturbed plain-`extern` path) is unit-tested in
//! `parser.rs`'s `#[cfg(test)] mod tests`. This suite closes the loop on the
//! REAL pipeline: compile a program whose function is declared AND defined
//! inside an `extern "C" { ... }` block, link it to a PE, run it, and assert
//! the exit code — proving the C-linkage symbol the mangler emits for the
//! definition matches the one emitted for the call site.
//!
//! x64 (`compile_to_pe`) — the same path the O1 byte-identity corpus uses;
//! these are NEW fixtures (the 88 SipHash fixtures use no `extern "C"`), so
//! the suite is purely additive.

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

fn build(src: &str) -> TempExe {
    let exe = compile_to_pe(src.as_bytes()).expect("mdbcc compile ok");
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("mdbcc_externc_{}_{}.exe", std::process::id(), n));
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

#[test]
fn extern_c_block_define_and_call() {
    // `addc` is declared+defined inside an `extern "C"` block; `main` (also
    // in the block) calls it. Both sides must agree on the C-linkage symbol.
    let src = "\
        extern \"C\" {\n\
          int addc(int a, int b) { return a + b; }\n\
          int main(void) { return addc(40, 2); }\n\
        }\n";
    assert_eq!(code(src), 42);
}

#[test]
fn extern_c_proto_in_block_def_outside() {
    // Common header shape: prototype inside `extern \"C\" { ... }`, the
    // definition (and the caller) outside. The proto's C-linkage symbol must
    // line up with the definition's emitted symbol.
    let src = "\
        extern \"C\" { int mulc(int, int); }\n\
        int mulc(int a, int b) { return a * b; }\n\
        int main(void) { return mulc(6, 7); }\n";
    assert_eq!(code(src), 42);
}

#[test]
fn extern_c_single_form_define_and_call() {
    // No-braces single-declaration form applied to a definition.
    let src = "\
        extern \"C\" int subc(int a, int b) { return a - b; }\n\
        int main(void) { return subc(50, 8); }\n";
    assert_eq!(code(src), 42);
}
