//! Phase C / C2 oracle: subsystem selection + the `WinMain` GUI entry stub.
//!
//! C2 makes the PE writer emit a **GUI** (subsystem 2) image entered through
//! a `WinMain`-calling stub when the translation unit defines `WinMain`
//! instead of `main`, while the console (`main`, subsystem 3) path stays
//! **byte-identical** (locked separately by `tests/pe_imports.rs`).
//!
//! Three things are proven here:
//!  1. *End-to-end on the real OS loader* — a GUI PE whose `WinMain` just
//!     returns a constant (and calls **no** USER32/GUI API, so it runs
//!     headless in CI) launches and its process exit code equals that
//!     constant. This validates subsystem-2 + the GUI stub's argument
//!     marshalling, Win64 stack alignment and `ExitProcess` exit path.
//!  2. *Ambiguity is a hard error* — a TU defining **both** `main` and
//!     `WinMain` is a clean `CompileError`, never a silent guess.
//!  3. *Cheap structural lock* — a `WinMain` program's PE Subsystem byte is
//!     `2` (GUI); a `main` program's is `3` (CUI). Reads the produced
//!     image's own optional header (cannot be fooled by an optimizer).

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
        p.push(format!("mdbcc_wm_{}_{}.exe", std::process::id(), n));
        TempExe(p)
    }
}

impl Drop for TempExe {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

const PE_OFF: usize = 0x80;

/// The PE optional header's `Subsystem` field (`u16`). Layout is identical to
/// `src/pe.rs`: `PE\0\0` (4) + COFF header (20) + optional header, with
/// `Subsystem` at optional-header offset 68.
fn subsystem(pe: &[u8]) -> u16 {
    let opt = PE_OFF + 4 + 20;
    let off = opt + 68;
    u16::from_le_bytes([pe[off], pe[off + 1]])
}

/// A GUI program that calls **no** GUI/USER32 API, so it runs headless in CI.
/// Its `WinMain` (no `<windows.h>` types yet — that is C3; use plain `int`/
/// `void*`/`char*` so this parses on the C2-only tree) simply returns 7. The
/// process exit code must therefore be exactly 7, proving subsystem-2 + the
/// GUI stub's arg marshalling / stack alignment / `ExitProcess` exit path.
const PROG_WINMAIN: &str = r#"
int WinMain(void *hInstance, void *hPrevInstance, char *lpCmdLine,
            int nCmdShow) {
    return 7;
}
"#;

/// A normal console program (unchanged path).
const PROG_MAIN: &str = "int main(void){ return 0; }";

/// Ambiguous: defines BOTH entry points. Must be a hard compile error.
const PROG_BOTH: &str = r#"
int main(void){ return 0; }
int WinMain(void *a, void *b, char *c, int d){ return 1; }
"#;

#[test]
fn winmain_program_runs_and_returns_its_constant() {
    let exe = compile_to_pe(PROG_WINMAIN.as_bytes()).expect("compile WinMain");
    let tmp = TempExe::new();
    std::fs::write(&tmp.0, &exe).expect("write exe");
    let status = Command::new(&tmp.0)
        .status()
        .unwrap_or_else(|e| panic!("failed to launch generated GUI exe: {e}"));
    assert_eq!(
        status.code().expect("process returned an exit code"),
        7,
        "the GUI WinMain stub did not call WinMain / return its value / \
         exit cleanly (subsystem-2 PE + WinMain stub end-to-end)"
    );
}

#[test]
fn winmain_program_is_subsystem_gui() {
    let exe = compile_to_pe(PROG_WINMAIN.as_bytes()).expect("compile WinMain");
    assert_eq!(
        subsystem(&exe),
        2,
        "a WinMain program must have PE Subsystem == 2 (WINDOWS_GUI)"
    );
}

#[test]
fn console_program_is_subsystem_cui() {
    let exe = compile_to_pe(PROG_MAIN.as_bytes()).expect("compile main");
    assert_eq!(
        subsystem(&exe),
        3,
        "a console (main) program must stay PE Subsystem == 3 (WINDOWS_CUI)"
    );
}

#[test]
fn both_main_and_winmain_is_a_clean_error() {
    let err = compile_to_pe(PROG_BOTH.as_bytes())
        .expect_err("a TU defining both main and WinMain must not compile");
    let msg = err.to_string();
    assert!(
        msg.contains("main") && msg.contains("WinMain"),
        "the both-entries error must name both `main` and `WinMain`, got: {msg}"
    );
}
