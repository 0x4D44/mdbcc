//! B-01: Win64 pointer comparisons must use the full 64-bit pointer value.
//!
//! The bug was not pointer arithmetic; it was the generic binary-op width gate:
//! `Type::Ptr` operands fell through to the 32-bit integer compare path, so two
//! pointers whose low dwords matched compared equal.

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
            "mdbcc_win64_ptrcmp_{}_{}.exe",
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
fn pointer_comparisons_observe_high_32_bits() {
    let src = "\
        int main(void) {\n\
            char* a = (char*)0x100000001ULL;\n\
            char* b = (char*)0x200000001ULL;\n\
            char* c = (char*)0x100000000ULL;\n\
            char* d = (char*)0x200000000ULL;\n\
            if (a == b) return 10;\n\
            if (!(a != b)) return 11;\n\
            if (!(c < d)) return 12;\n\
            if (d < c) return 13;\n\
            return 42;\n\
        }\n";
    assert_eq!(run(src), 42);
}
