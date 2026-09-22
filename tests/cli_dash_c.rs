//! S1b.5 — CLI integration tests for `bcc -c` (HLD §1.4, §5 row S1b.5).
//!
//! The `-c` flag stops the compile pipeline at the COFF `.obj` boundary
//! instead of producing an in-process PE `.exe`. These tests cover:
//!
//! 1. Default output path (`<basename>.obj`).
//! 2. Explicit output path via `-o`.
//! 3. Round-trip through `lld-link` to a runnable `.exe` (format gate;
//!    self-skips if `lld-link` or the Windows SDK kernel32.Lib is absent).
//! 4. `.cpp` source auto-detection (the parser today treats `.c` / `.cpp`
//!    identically; this test just pins that the CLI accepts both).
//! 5. Compile errors exit non-zero and do NOT leave a stale `.obj` behind.
//!
//! All tests use the binary built by Cargo for this crate; the path is
//! injected via the `CARGO_BIN_EXE_bcc` env var, set automatically by
//! `cargo test`. Std-only; no new crate dependencies.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Test-harness helpers (self-contained — no `tests/support/mod.rs` coupling)
// ---------------------------------------------------------------------------

/// The compiled `bcc` binary. Cargo sets `CARGO_BIN_EXE_<bin-name>` for
/// every binary in the crate when building integration tests.
fn bcc_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bcc"))
}

/// Allocate a fresh per-test temp directory. We use one directory per
/// test so test cleanup is trivial (one `remove_dir_all`) and tests
/// running in parallel don't trample each other's output files.
fn fresh_temp_dir(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "mdbcc_cli_dash_c_{}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
        tag
    ));
    std::fs::create_dir_all(&p).expect("mkdir temp");
    p
}

/// Run a command to completion under a wall-clock timeout, capturing
/// stdout / stderr. Mirrors the helper in `tests/coff_object_format.rs`;
/// duplicated here to keep `cli_dash_c.rs` self-contained (the harness
/// constraint is "no `tests/support` edits" — see test-suite rules).
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

/// Invoke `bcc <args>` with `cwd = work_dir`. Returns (exit, stdout, stderr).
fn run_bcc(work_dir: &Path, args: &[&str]) -> (Option<i32>, Vec<u8>, Vec<u8>) {
    let mut cmd = Command::new(bcc_exe());
    cmd.current_dir(work_dir).args(args);
    run_with_timeout(&mut cmd, Duration::from_secs(30))
}

/// Write a small source file inside `dir`.
fn write_source(dir: &Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, body).expect("write source");
    p
}

/// Self-skip helper. Returns `None` if `lld-link` is unavailable. The
/// candidates mirror `tests/coff_object_format.rs::discover_lld_link`;
/// any change in install conventions wants to be made in both places.
fn discover_lld_link() -> Option<PathBuf> {
    for cand in [
        PathBuf::from("lld-link.exe"),
        PathBuf::from("lld-link"),
        PathBuf::from(r"C:\Program Files\LLVM\bin\lld-link.exe"),
        PathBuf::from(r"C:\Program Files (x86)\LLVM\bin\lld-link.exe"),
    ] {
        let mut probe = Command::new(&cand);
        probe.arg("--version");
        probe
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Ok(mut child) = probe.spawn() {
            let _ = child.wait();
            return Some(cand);
        }
    }
    None
}

/// Locate the x64 `kernel32.Lib` shipped with the Windows 10/11 SDK.
/// Walks the SDK lib root sorted descending so newer SDKs win. Mirrors
/// `tests/coff_object_format.rs::discover_kernel32_lib` (intentionally
/// duplicated — see `run_with_timeout` rationale above).
fn discover_kernel32_lib() -> Option<PathBuf> {
    let lib_root = PathBuf::from(r"C:\Program Files (x86)\Windows Kits\10\Lib");
    if !lib_root.exists() {
        return None;
    }
    let mut versions: Vec<PathBuf> = match std::fs::read_dir(&lib_root) {
        Ok(rd) => rd.filter_map(|e| e.ok().map(|e| e.path())).collect(),
        Err(_) => return None,
    };
    versions.sort();
    versions.reverse();
    for v in versions {
        let candidate = v.join("um").join("x64").join("kernel32.Lib");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// `bcc -c hello.c` writes `hello.obj` next to the source with a non-
/// trivial body and the COFF AMD64 magic in the first two bytes
/// (`64 86` little-endian for `IMAGE_FILE_MACHINE_AMD64 = 0x8664`).
#[test]
fn bcc_dash_c_produces_obj() {
    let dir = fresh_temp_dir("produces_obj");
    write_source(&dir, "hello.c", "int main(void) { return 42; }\n");

    let (exit, _stdout, stderr) = run_bcc(&dir, &["-c", "hello.c"]);
    assert_eq!(
        exit,
        Some(0),
        "bcc -c failed: exit={exit:?} stderr={}",
        String::from_utf8_lossy(&stderr)
    );

    let obj_path = dir.join("hello.obj");
    let bytes = std::fs::read(&obj_path)
        .unwrap_or_else(|e| panic!("expected hello.obj at {}: {e}", obj_path.display()));
    assert!(
        bytes.len() > 100,
        "hello.obj is suspiciously small: {} bytes",
        bytes.len()
    );
    assert_eq!(
        &bytes[..2],
        &[0x64, 0x86],
        "expected IMAGE_FILE_MACHINE_AMD64 magic (0x8664 LE = 64 86); got {:02x} {:02x}",
        bytes[0],
        bytes[1]
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `bcc -c -o customname.obj hello.c` writes the `.obj` to the
/// specified path, not the default `<basename>.obj`.
#[test]
fn bcc_dash_c_with_dash_o() {
    let dir = fresh_temp_dir("with_dash_o");
    write_source(&dir, "hello.c", "int main(void) { return 1; }\n");

    let (exit, _stdout, stderr) = run_bcc(&dir, &["-c", "-o", "customname.obj", "hello.c"]);
    assert_eq!(
        exit,
        Some(0),
        "bcc -c -o failed: exit={exit:?} stderr={}",
        String::from_utf8_lossy(&stderr)
    );

    let custom = dir.join("customname.obj");
    assert!(
        custom.exists(),
        "expected customname.obj at {}",
        custom.display()
    );
    let default = dir.join("hello.obj");
    assert!(
        !default.exists(),
        "did NOT expect default hello.obj at {}",
        default.display()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Format-conformance gate (HLD §5 S1b.5 row, §4.2 Half B): compile
/// `int main(void) { return 17; }` with `bcc -c`, link with `lld-link`,
/// run the resulting `.exe`, assert it exits with 17. Self-skips if
/// `lld-link` or the SDK's kernel32.Lib is absent.
///
/// This is the headline test: it proves our `.obj` round-trips through
/// a real Microsoft-COFF linker AND the resulting program executes with
/// the right semantics.
#[test]
fn bcc_dash_c_then_lld_link_runs() {
    let lld = match discover_lld_link() {
        Some(p) => p,
        None => {
            eprintln!("[cli_dash_c] skipped: lld-link not on PATH or LLVM install");
            return;
        }
    };
    let kernel32 = match discover_kernel32_lib() {
        Some(p) => p,
        None => {
            eprintln!("[cli_dash_c] skipped: kernel32.Lib not found in Win10 SDK");
            return;
        }
    };

    let dir = fresh_temp_dir("lld_link_runs");
    write_source(&dir, "hello.c", "int main(void) { return 17; }\n");

    // Stage 1 — produce hello.obj.
    let (exit, _stdout, stderr) = run_bcc(&dir, &["-c", "hello.c"]);
    assert_eq!(
        exit,
        Some(0),
        "bcc -c failed: exit={exit:?} stderr={}",
        String::from_utf8_lossy(&stderr)
    );
    let obj_path = dir.join("hello.obj");
    assert!(obj_path.exists(), "expected {}", obj_path.display());

    // Stage 2 — link to hello.exe via lld-link.
    let exe_path = dir.join("hello.exe");
    let mut link_cmd = Command::new(&lld);
    link_cmd
        .arg("/subsystem:console")
        .arg("/entry:main")
        .arg(format!("/out:{}", exe_path.display()))
        .arg(&obj_path)
        .arg(&kernel32);
    let (link_exit, link_stdout, link_stderr) =
        run_with_timeout(&mut link_cmd, Duration::from_secs(30));
    if link_exit != Some(0) {
        let _ = std::fs::remove_dir_all(&dir);
        panic!(
            "lld-link failed: exit={link_exit:?}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&link_stdout),
            String::from_utf8_lossy(&link_stderr)
        );
    }
    assert!(exe_path.exists(), "expected {}", exe_path.display());

    // Stage 3 — run hello.exe; expect exit 17.
    let mut run_cmd = Command::new(&exe_path);
    let (run_exit, run_stdout, run_stderr) = run_with_timeout(&mut run_cmd, Duration::from_secs(5));
    let cleanup = std::fs::remove_dir_all(&dir);
    let _ = cleanup;
    match run_exit {
        Some(17) => { /* success — full COFF → lld-link → PE → exec round-trip */ }
        other => panic!(
            "hello.exe exited with {:?}, expected 17\nstdout:\n{}\nstderr:\n{}",
            other,
            String::from_utf8_lossy(&run_stdout),
            String::from_utf8_lossy(&run_stderr)
        ),
    }
}

/// `.cpp` source extension works identically. The mdbcc parser today
/// treats `.c` and `.cpp` the same (see `ast::Function::c_linkage`
/// docstring); the CLI just has to accept the extension. We assert the
/// `.obj` is produced and carries COFF AMD64 magic.
#[test]
fn bcc_dash_c_cpp_source() {
    let dir = fresh_temp_dir("cpp_source");
    write_source(&dir, "hello.cpp", "int main(void) { return 7; }\n");

    let (exit, _stdout, stderr) = run_bcc(&dir, &["-c", "hello.cpp"]);
    assert_eq!(
        exit,
        Some(0),
        "bcc -c hello.cpp failed: exit={exit:?} stderr={}",
        String::from_utf8_lossy(&stderr)
    );

    let obj_path = dir.join("hello.obj");
    let bytes = std::fs::read(&obj_path)
        .unwrap_or_else(|e| panic!("expected hello.obj at {}: {e}", obj_path.display()));
    assert!(
        bytes.len() > 100,
        "hello.obj too small: {} bytes",
        bytes.len()
    );
    assert_eq!(
        &bytes[..2],
        &[0x64, 0x86],
        "expected COFF AMD64 magic; got {:02x} {:02x}",
        bytes[0],
        bytes[1]
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Syntactically-broken source: `bcc -c` exits non-zero and does NOT
/// leave a stale `.obj` behind. (We don't want a previous error to
/// poison a subsequent `lld-link` invocation that re-uses the path.)
#[test]
fn bcc_dash_c_compile_error_exits_nonzero() {
    let dir = fresh_temp_dir("compile_error");
    // Missing closing `)` in the parameter list — guaranteed parse error.
    write_source(&dir, "broken.c", "int main(void { return 42; }\n");

    let (exit, _stdout, stderr) = run_bcc(&dir, &["-c", "broken.c"]);
    assert_ne!(
        exit,
        Some(0),
        "expected non-zero exit on syntax error; stderr={}",
        String::from_utf8_lossy(&stderr)
    );

    let obj_path = dir.join("broken.obj");
    assert!(
        !obj_path.exists(),
        "syntax error must not leave a stale .obj at {}",
        obj_path.display()
    );

    let _ = std::fs::remove_dir_all(&dir);
}
