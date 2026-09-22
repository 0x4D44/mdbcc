//! Phase C / C3 oracle: the intrinsic `<windows.h>` Win64 **LLP64 ABI lock**.
//!
//! C3's intrinsic `<windows.h>` body (`src/pp.rs::WINDOWS_H`) typedefs the
//! Win32 scalar/handle types. Under the Win64 **LLP64** data model the trap is
//! `long` (and `unsigned long`) is **32-bit**, so `WPARAM`/`LPARAM`/`LRESULT`
//! MUST be sourced from `__int64` (8 bytes), never `long`, and the opaque
//! handles MUST be `void*` (8 bytes). The types are correct *by construction*
//! today, but nothing executable pins the contract: a careless future
//! `WINDOWS_H` edit changing `__int64`->`long` would still parse and compile,
//! silently making `LPARAM` 32-bit. This file is that regression TRIPWIRE
//! (the HLD's C3 TDD plan / risk #4 mitigation explicitly called for it).
//!
//! It compiles & runs a tiny `#include <windows.h>` console program that
//! returns, via its process exit code, a *weighted* sum of the intrinsic
//! `sizeof`s. Each type gets a distinct odd weight, so ANY single wrong size
//! shifts the total by a unique, non-cancelling amount — the failure names
//! which type slipped (see the assertion's diagnostic). `sizeof(TYPE)` works
//! directly on these names because they are `typedef`s the parser already
//! recognises as type-names (`peek_is_type_after_lparen` -> `typedefs`).
//!
//! This is the run-and-assert-exit-code oracle style of `tests/winmain.rs` /
//! `tests/end_to_end.rs` (NOT the structural-only `tests/win32_msgbox.rs`):
//! it is about *type sizes*, so it is headless (plain `int main`, sizeof
//! arithmetic only — no `MessageBox`, no GUI, fully deterministic).

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
        p.push(format!("mdbcc_abi_{}_{}.exe", std::process::id(), n));
        TempExe(p)
    }
}

impl Drop for TempExe {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// The Win64/LLP64 size every intrinsic 8-byte type MUST have.
const P8: i32 = 8;
/// The Win64 size every intrinsic 4-byte type MUST have.
const P4: i32 = 4;

/// The ten `(type, weight, expected-size)` rows this oracle locks. Weights are
/// distinct odd integers so the weighted sum `Σ wᵢ·sizeof(Tᵢ)` changes by a
/// **unique, non-cancelling** delta for any single wrong size (an `__int64`->
/// `long` LLP64 slip turns an 8 into a 4: that type contributes `-4·wᵢ`, a
/// value no other single deviation can produce — the failure is unambiguous).
const ROWS: &[(&str, i32, i32)] = &[
    // The seven 8-byte types. WPARAM/LPARAM/LRESULT are the LLP64 trap
    // (must be `__int64`, not `long`); the four handles + LPSTR/LPCSTR are
    // pointers (`void*`/`char*`).
    ("WPARAM", 3, P8),
    ("LPARAM", 5, P8),
    ("LRESULT", 7, P8),
    ("HWND", 9, P8),
    ("HINSTANCE", 11, P8),
    ("LPSTR", 13, P8),
    ("LPCSTR", 15, P8),
    // The three 4-byte types.
    ("UINT", 17, P4),
    ("DWORD", 19, P4),
    ("BOOL", 21, P4),
];

/// The single exact value the program must return: `Σ wᵢ·expectedᵢ`.
/// Derivable from `ROWS`; computed here so the test fails loudly (with the
/// per-type diagnostic) on ANY size drift rather than hiding a hand-typed
/// magic number. With the table above this is
/// `(3+5+7+9+11+13+15)·8 + (17+19+21)·4 = 63·8 + 57·4 = 504 + 228 = 732`.
fn expected_total() -> i32 {
    ROWS.iter().map(|&(_, w, sz)| w * sz).sum()
}

/// Build `int main(void){ return W0*sizeof(T0)+W1*sizeof(T1)+...; }` over a
/// `#include <windows.h>` so the intrinsic typedefs are in scope.
fn abi_program() -> String {
    let terms = ROWS
        .iter()
        .map(|&(ty, w, _)| format!("{w} * (int)sizeof({ty})"))
        .collect::<Vec<_>>()
        .join(" + ");
    format!("#include <windows.h>\nint main(void) {{ return {terms}; }}\n")
}

#[test]
fn intrinsic_windows_h_types_have_exact_win64_llp64_sizes() {
    let src = abi_program();
    let exe = compile_to_pe(src.as_bytes()).expect("a <windows.h> sizeof program must compile");
    let tmp = TempExe::new();
    std::fs::write(&tmp.0, &exe).expect("write exe");
    let code = Command::new(&tmp.0)
        .status()
        .unwrap_or_else(|e| panic!("failed to launch generated exe: {e}"))
        .code()
        .expect("process returned an exit code");

    let want = expected_total();
    if code != want {
        // Pinpoint the slipped type(s): the only single-size deviations that
        // can occur are an 8-byte type collapsing to 4 (the `__int64`->`long`
        // LLP64 trap) or a 4-byte type growing to 8. Report the unique
        // weighted residual so the regression is unambiguous, not just "!=".
        let diag = ROWS
            .iter()
            .map(|&(ty, w, sz)| format!("{ty}=(w{w}*expect{sz})"))
            .collect::<Vec<_>>()
            .join(", ");
        panic!(
            "Win64/LLP64 ABI lock FAILED: <windows.h> intrinsic type sizes \
             drifted. Weighted sizeof sum = {code}, expected {want} \
             (residual {}). A common cause is a `WINDOWS_H` edit changing \
             `__int64`->`long` (LLP64: `long` is 32-bit), silently making \
             WPARAM/LPARAM/LRESULT 4 bytes, or a handle no longer `void*`. \
             Locked rows: [{diag}]. Required: WPARAM/LPARAM/LRESULT/HWND/\
             HINSTANCE/LPSTR/LPCSTR == 8; UINT/DWORD/BOOL == 4.",
            code - want
        );
    }
}
