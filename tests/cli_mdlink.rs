//! S1c.5 — CLI integration tests for `mdlink`.
//!
//! Covers:
//! 1. Single-input round-trip: `bcc -c hello.c && mdlink hello.obj` produces
//!    a runnable PE.
//! 2. Two-input link: a normal mdbcc-compiled foo.obj plus a hand-rolled
//!    bar.obj (mirroring `tests/two_file_link.rs::build_bar_object`,
//!    because mdbcc's codegen demands a TU define `main` — see Q-Mangling-
//!    Reach in the HLD) link to a single PE; the linked binary runs end-
//!    to-end via the CLI.
//! 3. Unknown option → exit non-zero with `unknown option` in stderr.
//! 4. Zero inputs → exit non-zero with `no input files` in stderr.
//! 5. MSVC-style aliases (`/OUT:`, `/SUBSYSTEM:CONSOLE`) are accepted in
//!    place of `--out` and `--subsystem` (Q-Cli ratified design).
//!
//! These mirror the discipline of `tests/cli_dash_c.rs`: each test owns a
//! fresh tempdir; the binary is located via Cargo-set
//! `CARGO_BIN_EXE_<bin>` env vars; std-only; no `tests/support` coupling.

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use mdbcc::coff::{
    self, AuxRecord, Object, Section, SectionRef, StorageClass, SymKind, SymName, Symbol,
};

// ---------------------------------------------------------------------------
// Test-harness helpers
// ---------------------------------------------------------------------------

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// The compiled `mdlink` binary. Cargo sets `CARGO_BIN_EXE_<bin-name>` for
/// every binary in the crate during integration-test builds.
fn mdlink_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mdlink"))
}

/// The compiled `bcc` binary (needed to produce `.obj` inputs for tests
/// that exercise the full bcc → mdlink → exe pipeline).
fn bcc_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bcc"))
}

/// Allocate a fresh per-test temp directory. One directory per test makes
/// cleanup a single `remove_dir_all` and avoids parallel-test contention.
fn fresh_temp_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!(
        "mdbcc_cli_mdlink_{}_{}_{}",
        std::process::id(),
        n,
        tag
    ));
    std::fs::create_dir_all(&p).expect("mkdir temp");
    p
}

/// Run a command to completion under a wall-clock timeout. Returns
/// `(exit_code, stdout, stderr)`. Duplicated from `tests/cli_dash_c.rs`
/// to keep this file self-contained (`tests/support/mod.rs` is off-limits
/// per the test-suite rules).
fn run_with_timeout(cmd: &mut Command, timeout: Duration) -> (Option<i32>, Vec<u8>, Vec<u8>) {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return (None, Vec::new(), format!("spawn failed: {e}").into_bytes()),
    };
    let mut so = child.stdout.take().expect("piped stdout");
    let mut se = child.stderr.take().expect("piped stderr");
    let h_out = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = std::io::Read::read_to_end(&mut so, &mut v);
        v
    });
    let h_err = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = std::io::Read::read_to_end(&mut se, &mut v);
        v
    });
    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break None,
        }
    };
    let stdout = h_out.join().unwrap_or_default();
    let stderr = h_err.join().unwrap_or_default();
    let exit = status.and_then(|s| s.code());
    (exit, stdout, stderr)
}

/// Invoke `bcc <args>` with `cwd = work_dir`.
fn run_bcc(work_dir: &Path, args: &[&str]) -> (Option<i32>, Vec<u8>, Vec<u8>) {
    let mut cmd = Command::new(bcc_exe());
    cmd.current_dir(work_dir).args(args);
    run_with_timeout(&mut cmd, Duration::from_secs(30))
}

/// Invoke `mdlink <args>` with `cwd = work_dir`.
fn run_mdlink(work_dir: &Path, args: &[&str]) -> (Option<i32>, Vec<u8>, Vec<u8>) {
    let mut cmd = Command::new(mdlink_exe());
    cmd.current_dir(work_dir).args(args);
    run_with_timeout(&mut cmd, Duration::from_secs(30))
}

/// Write a small source file inside `dir`.
fn write_source(dir: &Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, body).expect("write source");
    p
}

/// Hand-craft a coff::Object that defines `_bar` as `int bar(int x) {
/// return x + 1; }` and serialise it to a `.obj` on disk. Mirrors
/// `tests/two_file_link.rs::build_bar_object` (the rationale for hand-
/// crafting rather than `compile_to_object`-ing a `bar.c` is documented
/// there: mdbcc's codegen demands every TU define `main`, which is HLD
/// §10 Q-Mangling-Reach work deferred past S1c).
fn write_bar_obj(dir: &Path) -> PathBuf {
    // bar: `mov eax, ecx; inc eax; ret` — Win64 ABI, first int arg in
    // ECX/RCX, return in EAX/RAX. 5 bytes total.
    let bar_code: Vec<u8> = vec![0x89, 0xC8, 0xFF, 0xC0, 0xC3];

    let mut obj = Object {
        machine: coff::Machine::Amd64,
        ..Default::default()
    };

    // .text section carrying just _bar's body.
    obj.sections.push(Section {
        data: bar_code.clone(),
        ..Section::text()
    });

    // Symbols: [0] the .text section symbol (STATIC + SectionDef aux);
    // [1] the _bar function symbol (EXTERNAL, defined at offset 0).
    let mut section_name_arr = [0u8; 8];
    section_name_arr[..5].copy_from_slice(b".text");
    obj.symbols.push(Symbol {
        name: SymName::Short(section_name_arr),
        value: 0,
        section: SectionRef::Section(1),
        kind: SymKind::Notype,
        storage: StorageClass::Static,
        aux: vec![AuxRecord::SectionDef {
            length: bar_code.len() as u32,
            num_relocs: 0,
            checksum: 0,
            number: 0,
            selection: None,
        }],
    });
    // S4.2b8: plain `bar` (was `_bar`) — the mdbcc-compiled caller now
    // references a primitive-param free function by its plain source name.
    let mut bar_name_arr = [0u8; 8];
    bar_name_arr[..3].copy_from_slice(b"bar");
    obj.symbols.push(Symbol {
        name: SymName::Short(bar_name_arr),
        value: 0,
        section: SectionRef::Section(1),
        kind: SymKind::Function,
        storage: StorageClass::External,
        aux: Vec::new(),
    });
    obj.symbol_source_locs = vec![None; obj.symbols.len()];

    let bytes = obj.write();
    let path = dir.join("bar.obj");
    std::fs::write(&path, &bytes).expect("write bar.obj");
    path
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Simplest end-to-end: `bcc -c hello.c && mdlink hello.obj --out hello.exe
/// && hello.exe`. Exit code must match the source `return` statement.
#[test]
fn mdlink_single_obj_file_runs() {
    let dir = fresh_temp_dir("single_obj");
    write_source(&dir, "hello.c", "int main(void) { return 23; }\n");

    let (exit, _stdout, stderr) = run_bcc(&dir, &["-c", "hello.c"]);
    assert_eq!(
        exit,
        Some(0),
        "bcc -c failed: exit={exit:?} stderr={}",
        String::from_utf8_lossy(&stderr)
    );

    let (exit, _stdout, stderr) = run_mdlink(&dir, &["hello.obj", "--out", "hello.exe"]);
    assert_eq!(
        exit,
        Some(0),
        "mdlink failed: exit={exit:?} stderr={}",
        String::from_utf8_lossy(&stderr)
    );

    let exe = dir.join("hello.exe");
    assert!(exe.exists(), "mdlink produced no exe at {}", exe.display());

    let (run_exit, run_stdout, run_stderr) =
        run_with_timeout(&mut Command::new(&exe), Duration::from_secs(5));
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        run_exit,
        Some(23),
        "linked hello.exe exited with {:?}, expected 23\nstdout:\n{}\nstderr:\n{}",
        run_exit,
        String::from_utf8_lossy(&run_stdout),
        String::from_utf8_lossy(&run_stderr)
    );
}

/// Multi-input link via CLI. foo.c calls bar(); bar.obj is hand-rolled
/// (see `write_bar_obj` rationale). Main computes 1 + bar(10) + bar(20)
/// = 1 + 11 + 21 = 33; the assertion mirrors `two_file_link.rs::
/// two_objects_link_and_run` but exercises the CLI path end-to-end.
#[test]
fn mdlink_links_two_obj_files() {
    let dir = fresh_temp_dir("two_obj");
    write_source(
        &dir,
        "foo.c",
        "int bar(int x);\n\
         int main(void) {\n\
             int v;\n\
             v = 1;\n\
             v = v + bar(10);\n\
             v = v + bar(20);\n\
             return v;\n\
         }\n",
    );

    // Compile foo.c with bcc.
    let (exit, _stdout, stderr) = run_bcc(&dir, &["-c", "foo.c"]);
    assert_eq!(
        exit,
        Some(0),
        "bcc -c foo.c failed: exit={exit:?} stderr={}",
        String::from_utf8_lossy(&stderr)
    );

    // Hand-rolled bar.obj sits alongside foo.obj.
    let _bar_path = write_bar_obj(&dir);

    let (exit, _stdout, stderr) = run_mdlink(&dir, &["foo.obj", "bar.obj", "--out", "hello.exe"]);
    assert_eq!(
        exit,
        Some(0),
        "mdlink foo.obj bar.obj failed: exit={exit:?} stderr={}",
        String::from_utf8_lossy(&stderr)
    );

    let exe = dir.join("hello.exe");
    assert!(exe.exists(), "mdlink produced no exe at {}", exe.display());

    let (run_exit, run_stdout, run_stderr) =
        run_with_timeout(&mut Command::new(&exe), Duration::from_secs(5));
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        run_exit,
        Some(33),
        "linked hello.exe exited with {:?}, expected 33 (1 + bar(10) + bar(20))\
         \nstdout:\n{}\nstderr:\n{}",
        run_exit,
        String::from_utf8_lossy(&run_stdout),
        String::from_utf8_lossy(&run_stderr)
    );
}

/// Unknown options must error (not be silently treated as inputs). The
/// stderr text must mention "unknown option" so users can see what went
/// wrong without consulting --help.
#[test]
fn mdlink_unknown_option_errors() {
    let dir = fresh_temp_dir("unknown_opt");

    let (exit, _stdout, stderr) = run_mdlink(&dir, &["--bogus", "foo.obj"]);
    assert_ne!(
        exit,
        Some(0),
        "mdlink --bogus expected non-zero exit; stderr={}",
        String::from_utf8_lossy(&stderr)
    );
    let stderr_s = String::from_utf8_lossy(&stderr);
    assert!(
        stderr_s.contains("unknown option"),
        "expected 'unknown option' in stderr; got:\n{stderr_s}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// No positional inputs at all. Must exit non-zero (a linker call with
/// no inputs makes no sense) and explain why.
#[test]
fn mdlink_no_inputs_errors() {
    let dir = fresh_temp_dir("no_inputs");

    let (exit, _stdout, stderr) = run_mdlink(&dir, &["--out", "foo.exe"]);
    assert_ne!(
        exit,
        Some(0),
        "mdlink --out foo.exe (no inputs) expected non-zero exit; stderr={}",
        String::from_utf8_lossy(&stderr)
    );
    let stderr_s = String::from_utf8_lossy(&stderr);
    assert!(
        stderr_s.contains("no input"),
        "expected 'no input' in stderr; got:\n{stderr_s}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// MSVC-style aliases for the common options are accepted. The Q-Cli
/// design says `/OUT:`, `/SUBSYSTEM:`, `/ENTRY:`, `/BASE:`, and `/STACK:`
/// must work as drop-in substitutes for their GNU long-form equivalents.
/// This test exercises `/OUT:` and `/SUBSYSTEM:CONSOLE`.
#[test]
fn mdlink_msvc_style_options_accepted() {
    let dir = fresh_temp_dir("msvc_style");
    write_source(&dir, "hello.c", "int main(void) { return 5; }\n");

    let (exit, _stdout, stderr) = run_bcc(&dir, &["-c", "hello.c"]);
    assert_eq!(
        exit,
        Some(0),
        "bcc -c failed: exit={exit:?} stderr={}",
        String::from_utf8_lossy(&stderr)
    );

    let (exit, _stdout, stderr) =
        run_mdlink(&dir, &["hello.obj", "/OUT:hello.exe", "/SUBSYSTEM:CONSOLE"]);
    assert_eq!(
        exit,
        Some(0),
        "mdlink /OUT: /SUBSYSTEM: failed: exit={exit:?} stderr={}",
        String::from_utf8_lossy(&stderr)
    );

    let exe = dir.join("hello.exe");
    assert!(
        exe.exists(),
        "mdlink with MSVC options produced no exe at {}",
        exe.display()
    );

    let (run_exit, _so, _se) = run_with_timeout(&mut Command::new(&exe), Duration::from_secs(5));
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        run_exit,
        Some(5),
        "MSVC-style linked hello.exe exited with {run_exit:?}, expected 5"
    );
}
