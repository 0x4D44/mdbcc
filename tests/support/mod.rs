//! Shared support for the differential oracles (O2 = MSVC `cl`, O3 = Borland
//! `bcc32 5.5.1`). See `wrk_docs/2026.05.17 - HLD - Test Oracles.md` (V8).
//!
//! Design notes:
//! - mdbcc is exercised **in-process** via `mdbcc::compile_to_pe`, exactly
//!   like O1 (`tests/end_to_end.rs`). This sidesteps the V8 §6 PATH hazard
//!   entirely (no `bcc` binary lookup, no stale `c:\apps\bcc.exe`).
//! - Std-only; no new crate dependencies.
//! - The §4.4/§4.6 equivalence relation (`normalize_newlines`,
//!   `is_crash_code`, `compare`, `parse_skip`) is pure and unit-tested — it
//!   is the oracle that encodes "correct", so it must itself be checked.

#![allow(dead_code)]

// S0.4 — BCC 4.52 toolchain oracle. Accessed via `support::bcc_oracle::*`
// from tests that exercise the CD tools. Kept as a sibling module rather
// than re-exporting names at this level to avoid colliding with the
// in-process `Lang` enum below.
pub mod bcc_oracle;

// S1b.6 — minimal OMF reader used by the O13 oracle to decode bcc32's
// .obj output so it can be compared against mdbcc's COFF output. Lives
// next to bcc_oracle because it has the same "test-side, std-only" shape;
// no production code path consumes it.
pub mod omf_walker;

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Core types + pure equivalence relation (V8 §4.4 / §4.6)
// ---------------------------------------------------------------------------

/// Observable outcome of running a built program.
#[derive(Debug, Clone)]
pub struct RunOutcome {
    /// Did a runnable artefact exist and the process start? `false` also
    /// encodes "reference build failed" (the build/launch-fail bucket).
    pub launched: bool,
    /// `ExitStatus::code()`; `None` = killed / no code.
    pub exit: Option<i32>,
    /// Raw stdout bytes, bounded (no string decode).
    pub stdout: Vec<u8>,
    /// stdout exceeded the capture cap (⇒ EXCLUDE, likely miscurated).
    pub stdout_overflow: bool,
    /// Killed by the wall-clock timeout.
    pub timed_out: bool,
    /// stderr (diagnostics only — never in the pass/fail tuple).
    pub stderr: Vec<u8>,
}

impl RunOutcome {
    fn not_launched() -> Self {
        RunOutcome {
            launched: false,
            exit: None,
            stdout: Vec::new(),
            stdout_overflow: false,
            timed_out: false,
            stderr: Vec::new(),
        }
    }
}

/// The verdict for one corpus program under one reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    /// A real, actionable mdbcc red.
    Fail(String),
    /// Not comparable (reference-side problem, UB-adjacent, miscurated) —
    /// never counted as agreement, never an mdbcc red.
    Exclude(String),
}

/// V8 §4.4.3: strip a `\r` immediately preceding each `\n`, on both streams.
/// MSVC and Borland CRTs both emit `\r\n`; mdbcc emits raw `\n`. This single
/// normalisation is necessary (else 100% false-FAIL) and — proven by the
/// 2026-05-17 spike across mdbcc/cl/bcc32 — sufficient.
pub fn normalize_newlines(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let cr_before_lf = b[i] == b'\r' && i + 1 < b.len() && b[i + 1] == b'\n';
        if !cr_before_lf {
            out.push(b[i]);
        }
        i += 1;
    }
    out
}

/// V8 §4.4.2: a Windows crash exit code (`STATUS_*`: high byte `0xC0`/`0x80`).
/// Two crashes are *not* agreement.
pub fn is_crash_code(code: i32) -> bool {
    let hi = ((code as u32) >> 24) & 0xff;
    hi == 0xC0 || hi == 0x80
}

/// The §4.4/§4.6 equivalence relation. `md` = mdbcc, `rf` = reference.
pub fn compare(md: &RunOutcome, rf: &RunOutcome) -> Verdict {
    // Reference build/launch failure: not comparable, not an mdbcc verdict
    // (counted in the build/launch-fail health bucket by the caller).
    if !rf.launched {
        return Verdict::Exclude("reference build/launch failed".into());
    }
    // mdbcc produced no runnable exe on code the reference accepted ⇒ red.
    if !md.launched {
        return Verdict::Fail("mdbcc produced no runnable exe".into());
    }
    if md.stdout_overflow || rf.stdout_overflow {
        return Verdict::Exclude("output-overflow — likely miscurated".into());
    }
    match (md.timed_out, rf.timed_out) {
        (true, true) => return Verdict::Exclude("both timed out".into()),
        (true, false) => return Verdict::Fail("mdbcc timed out".into()),
        (false, true) => return Verdict::Exclude("reference timed out".into()),
        (false, false) => {}
    }
    let (mc, rc) = match (md.exit, rf.exit) {
        (None, None) => return Verdict::Exclude("both killed (no exit code)".into()),
        (None, Some(_)) => return Verdict::Fail("mdbcc killed (no exit code)".into()),
        (Some(_), None) => {
            return Verdict::Exclude("reference killed (no exit code)".into());
        }
        (Some(mc), Some(rc)) => (mc, rc),
    };
    match (is_crash_code(mc), is_crash_code(rc)) {
        (true, true) => {
            return Verdict::Exclude(format!("both crashed (mdbcc={mc:#x}, ref={rc:#x})"));
        }
        (true, false) => return Verdict::Fail(format!("mdbcc crashed: {mc:#x}")),
        (false, true) => return Verdict::Exclude(format!("reference crashed: {rc:#x}")),
        (false, false) => {}
    }
    if mc != rc {
        return Verdict::Fail(format!("exit code differs: mdbcc={mc} ref={rc}"));
    }
    let mo = normalize_newlines(&md.stdout);
    let ro = normalize_newlines(&rf.stdout);
    if mo != ro {
        return Verdict::Fail(format!(
            "stdout differs (normalised): mdbcc={:?} ref={:?}",
            String::from_utf8_lossy(&mo),
            String::from_utf8_lossy(&ro)
        ));
    }
    Verdict::Pass
}

/// Corpus skip directive (V8 §4.5). The more specific form is matched first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Skip {
    None,
    /// `// oracle: skip <reason>` — excluded from *all* differential arms.
    Full(String),
    /// `// oracle: skip-bcc32-behaviour <reason>` — excluded from the bcc32
    /// *behavioural* arm only (Win32 ptr=4 vs our Win64 ptr=8); still gets
    /// O2 and O3 acceptance.
    Bcc32Behaviour(String),
}

pub fn parse_skip(src: &str) -> Skip {
    for line in src.lines().take(15) {
        let t = line.trim();
        if let Some(r) = t.strip_prefix("// oracle: skip-bcc32-behaviour") {
            return Skip::Bcc32Behaviour(r.trim().to_string());
        }
        if let Some(r) = t.strip_prefix("// oracle: skip") {
            return Skip::Full(r.trim().to_string());
        }
    }
    Skip::None
}

/// Reference-compiler source language for a corpus file (B-4 / Phase C C5).
/// mdbcc is language-agnostic in-process; this only selects how the O2/O3
/// reference toolchains are invoked. Default (no directive) is `C`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    C,
    Cpp,
}

/// `// oracle: lang cpp` ⇒ compile the reference build as C++ (cl `/TP` +
/// `t.cpp`; bcc32 `-P` + `t.cpp`). Same first-15-lines scan as `parse_skip`;
/// orthogonal to it (a file may be both `lang cpp` and `skip-bcc32-behaviour`).
/// Anything other than the exact `cpp` token is C (no silent surprises).
pub fn parse_lang(src: &str) -> Lang {
    for line in src.lines().take(15) {
        if let Some(r) = line.trim().strip_prefix("// oracle: lang") {
            return if r.trim() == "cpp" {
                Lang::Cpp
            } else {
                Lang::C
            };
        }
    }
    Lang::C
}

// ---------------------------------------------------------------------------
// Child execution (std-only, bounded, timed)
// ---------------------------------------------------------------------------

fn read_capped<R: Read>(mut r: R, cap: usize) -> (Vec<u8>, bool) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let mut overflow = false;
    loop {
        match r.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                if buf.len() < cap {
                    let take = n.min(cap - buf.len());
                    buf.extend_from_slice(&tmp[..take]);
                    if take < n {
                        overflow = true;
                    }
                } else {
                    overflow = true;
                }
            }
            Err(_) => break,
        }
    }
    (buf, overflow)
}

/// Run `cmd` with a wall-clock `timeout`, capturing stdout (bounded to `cap`)
/// and stderr concurrently (reader threads avoid pipe-buffer deadlock).
pub fn run_with_timeout(cmd: &mut Command, timeout: Duration, cap: usize) -> RunOutcome {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(_) => return RunOutcome::not_launched(),
    };
    let mut so = child.stdout.take().expect("piped stdout");
    let mut se = child.stderr.take().expect("piped stderr");
    let ho = std::thread::spawn(move || read_capped(&mut so, cap));
    let he = std::thread::spawn(move || read_capped(&mut se, 64 * 1024).0);

    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break None;
                }
                std::thread::sleep(Duration::from_millis(15));
            }
            Err(_) => break None,
        }
    };
    let (stdout, stdout_overflow) = ho.join().unwrap_or((Vec::new(), false));
    let stderr = he.join().unwrap_or_default();
    let exit = status.and_then(|s| s.code());
    RunOutcome {
        launched: true,
        exit,
        stdout,
        stdout_overflow,
        timed_out,
        stderr,
    }
}

// ---------------------------------------------------------------------------
// Per-invocation work dir + repo paths
// ---------------------------------------------------------------------------

static DIR_N: AtomicU32 = AtomicU32::new(0);

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Fresh `target/oracle/<pid>_<n>/` (git-ignored) — avoids `*.obj`
/// collisions under parallel `cargo test`.
pub fn work_dir() -> PathBuf {
    let n = DIR_N.fetch_add(1, Ordering::Relaxed);
    let d = repo_root()
        .join("target/oracle")
        .join(format!("{}_{}", std::process::id(), n));
    let _ = fs::create_dir_all(&d);
    d
}

// ---------------------------------------------------------------------------
// mdbcc (in-process, like O1)
// ---------------------------------------------------------------------------

/// Compile a TU with mdbcc. A *panic* in mdbcc is converted to `Err` (a red,
/// not a harness crash). Returns the PE bytes on success.
pub fn mdbcc_compile(src: &str) -> Result<Vec<u8>, String> {
    let bytes = src.as_bytes().to_vec();
    // Map the error to String *inside* the closure so the return type is
    // unconditionally `UnwindSafe`.
    let r = std::panic::catch_unwind(|| mdbcc::compile_to_pe(&bytes).map_err(|e| e.to_string()));
    match r {
        Ok(Ok(pe)) => Ok(pe),
        Ok(Err(e)) => Err(format!("mdbcc compile error: {e}")),
        Err(_) => Err("mdbcc panicked during compile".to_string()),
    }
}

/// Build with mdbcc and run, under the §4.6 robustness rules. An mdbcc
/// compile failure ⇒ `launched=false` (compare() turns that into a red).
pub fn mdbcc_run(src: &str) -> RunOutcome {
    let pe = match mdbcc_compile(src) {
        Ok(pe) => pe,
        Err(_) => return RunOutcome::not_launched(),
    };
    let dir = work_dir();
    let exe = dir.join("mdbcc.exe");
    if fs::write(&exe, &pe).is_err() {
        return RunOutcome::not_launched();
    }
    let mut c = Command::new(&exe);
    c.current_dir(&dir);
    run_with_timeout(&mut c, Duration::from_secs(10), 8 << 20)
}

// ---------------------------------------------------------------------------
// O2 — MSVC `cl` discovery + known-answer probe + reference build
// ---------------------------------------------------------------------------

struct ClEnv {
    cl_exe: PathBuf,
    env: Vec<(String, String)>,
}

static CL: OnceLock<Option<ClEnv>> = OnceLock::new();

fn discover_cl() -> Option<ClEnv> {
    let pf = std::env::var("ProgramFiles(x86)")
        .unwrap_or_else(|_| r"C:\Program Files (x86)".to_string());
    let vswhere = Path::new(&pf)
        .join("Microsoft Visual Studio")
        .join("Installer")
        .join("vswhere.exe");
    if !vswhere.exists() {
        return None;
    }
    let out = Command::new(&vswhere)
        .args([
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property",
            "installationPath",
        ])
        .output()
        .ok()?;
    let install = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()?
        .trim()
        .to_string();
    if install.is_empty() {
        return None;
    }
    let vcvars = Path::new(&install).join("VC/Auxiliary/Build/vcvars64.bat");
    if !vcvars.exists() {
        return None;
    }
    // Rust's Windows arg-quoting + cmd.exe quote-stripping mangle a complex
    // `cmd /c "...&&..."` line. Write a batch wrapper to a space-free dir
    // (target/oracle) and run that instead — robust, dependency-free.
    let dir = work_dir();
    let bat = dir.join("dumpenv.bat");
    fs::write(
        &bat,
        format!(
            "@echo off\r\ncall \"{}\" >nul 2>&1\r\nset\r\n",
            vcvars.display()
        ),
    )
    .ok()?;
    let setout = Command::new("cmd").arg("/c").arg(&bat).output().ok()?;
    let text = String::from_utf8_lossy(&setout.stdout);
    let mut env = Vec::new();
    for line in text.lines() {
        let Some(eq) = line.find('=') else { continue };
        let k = &line[..eq];
        let valid = !k.is_empty()
            && k.chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && k.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '(' || c == ')');
        if valid {
            env.push((k.to_string(), line[eq + 1..].to_string()));
        }
    }
    let path = env
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("PATH"))
        .map(|(_, v)| v.clone())?;
    let cl_exe = path
        .split(';')
        .map(|d| Path::new(d).join("cl.exe"))
        .find(|p| p.exists())?;
    Some(ClEnv { cl_exe, env })
}

fn cl_env() -> Option<&'static ClEnv> {
    CL.get_or_init(discover_cl).as_ref()
}

/// Build `src` with the exact O2 command line (`cl /nologo /MT … /Fe:`) in a
/// fresh work dir, then run it. Build failure ⇒ `launched=false`.
pub fn msvc_ref(src: &str, lang: Lang) -> RunOutcome {
    let Some(cl) = cl_env() else {
        return RunOutcome::not_launched();
    };
    msvc_build_run(cl, src, false, lang)
}

fn msvc_build_run(cl: &ClEnv, src: &str, with_o2: bool, lang: Lang) -> RunOutcome {
    let dir = work_dir();
    // C path (default) is byte-for-byte unchanged: `t.c`, no language flag —
    // `cl` infers C from `.c`. C++ corpus opts in to `t.cpp` + `/TP`.
    let src_name = match lang {
        Lang::C => "t.c",
        Lang::Cpp => "t.cpp",
    };
    let c = dir.join(src_name);
    let exe = dir.join("ref.exe");
    if fs::write(&c, src).is_err() {
        return RunOutcome::not_launched();
    }
    let mut b = Command::new(&cl.cl_exe);
    b.current_dir(&dir).env_clear();
    for (k, v) in &cl.env {
        b.env(k, v);
    }
    b.args(["/nologo", "/MT"]);
    if with_o2 {
        b.arg("/O2");
    }
    if lang == Lang::Cpp {
        b.arg("/TP");
    }
    b.arg(&c).arg(format!("/Fe:{}", exe.display()));
    let _ = run_with_timeout(&mut b, Duration::from_secs(30), 1 << 20);
    if !exe.exists() {
        return RunOutcome::not_launched();
    }
    let mut r = Command::new(&exe);
    r.current_dir(&dir);
    run_with_timeout(&mut r, Duration::from_secs(10), 8 << 20)
}

static O2: OnceLock<bool> = OnceLock::new();

/// V8 §4.3 known-answer probe: gates O2 ACTIVE. Asserts Rust-computed bytes
/// (post-normalisation) **and** exit 7 from the exact O2 build.
pub fn o2_active() -> bool {
    *O2.get_or_init(|| {
        if cl_env().is_none() {
            return false;
        }
        let probe = "#include <stdio.h>\n\
                     int main(void){ printf(\"%d %u %lld\\n\", -7, 4294967295u, 4294967295LL); return 7; }\n";
        let r = msvc_ref(probe, Lang::C);
        r.launched
            && r.exit == Some(7)
            && normalize_newlines(&r.stdout) == b"-7 4294967295 4294967295\n"
    })
}

/// V8 §4.5 advisory: rebuild with `/O2`; disagreement ⇒ reference-unstable
/// WARN (never excludes, never exonerates mdbcc).
pub fn msvc_ref_o2_unstable(src: &str, lang: Lang) -> bool {
    let Some(cl) = cl_env() else {
        return false;
    };
    let a = msvc_build_run(cl, src, false, lang);
    let b = msvc_build_run(cl, src, true, lang);
    if !a.launched || !b.launched {
        return false;
    }
    a.exit != b.exit || normalize_newlines(&a.stdout) != normalize_newlines(&b.stdout)
}

// ---------------------------------------------------------------------------
// O3 — Borland bcc32 5.5.1 (acceptance + Win32 behavioural)
// ---------------------------------------------------------------------------

struct Bcc {
    exe: PathBuf,
    inc: PathBuf,
    lib: PathBuf,
    bin: PathBuf,
}

fn bcc() -> Option<Bcc> {
    let r = repo_root().join("wrk_tools/BCC55");
    let exe = r.join("Bin/bcc32.exe");
    if !exe.exists() {
        return None;
    }
    Some(Bcc {
        exe,
        inc: r.join("Include"),
        lib: r.join("Lib"),
        bin: r.join("Bin"),
    })
}

fn child_path_with_bin(bin: &Path) -> String {
    let cur = std::env::var("PATH").unwrap_or_default();
    format!("{};{}", bin.display(), cur)
}

/// O3 acceptance arm (V8 §3/§4.2): `bcc32 -q -c -I<inc> <src>`.
/// Pass iff exit 0 and an `.obj` is produced.
pub fn bcc32_accept(src: &str, lang: Lang) -> Result<(), String> {
    let Some(b) = bcc() else {
        return Err("bcc32 not present".into());
    };
    let dir = work_dir();
    // C path unchanged: `t.c`, no `-P` (bcc32 infers C from `.c`).
    let c = dir.join(match lang {
        Lang::C => "t.c",
        Lang::Cpp => "t.cpp",
    });
    let obj = dir.join("t.obj");
    fs::write(&c, src).map_err(|e| e.to_string())?;
    let mut cmd = Command::new(&b.exe);
    cmd.current_dir(&dir)
        .env("PATH", child_path_with_bin(&b.bin))
        .arg("-q")
        .arg("-c");
    if lang == Lang::Cpp {
        cmd.arg("-P");
    }
    cmd.arg(format!("-I{}", b.inc.display()))
        .arg(format!("-o{}", obj.display()))
        .arg(&c);
    let o = run_with_timeout(&mut cmd, Duration::from_secs(30), 1 << 20);
    if o.exit == Some(0) && obj.exists() {
        Ok(())
    } else {
        Err(format!(
            "bcc32 -c exit={:?}: {}",
            o.exit,
            String::from_utf8_lossy(&o.stdout)
        ))
    }
}

/// O3 behavioural arm (V8 §4.2): `bcc32 -q -I -L -e<exe> <src>`, then run.
/// Build failure ⇒ `launched=false`.
pub fn bcc32_ref(src: &str, lang: Lang) -> RunOutcome {
    let Some(b) = bcc() else {
        return RunOutcome::not_launched();
    };
    let dir = work_dir();
    // C path unchanged: `t.c`, no `-P` (bcc32 infers C from `.c`).
    let c = dir.join(match lang {
        Lang::C => "t.c",
        Lang::Cpp => "t.cpp",
    });
    let exe = dir.join("ref_bc.exe");
    if fs::write(&c, src).is_err() {
        return RunOutcome::not_launched();
    }
    let path = child_path_with_bin(&b.bin);
    let mut cmd = Command::new(&b.exe);
    cmd.current_dir(&dir).env("PATH", &path).arg("-q");
    if lang == Lang::Cpp {
        cmd.arg("-P");
    }
    cmd.arg(format!("-I{}", b.inc.display()))
        .arg(format!("-L{}", b.lib.display()))
        .arg(format!("-e{}", exe.display()))
        .arg(&c);
    let _ = run_with_timeout(&mut cmd, Duration::from_secs(30), 1 << 20);
    if !exe.exists() {
        return RunOutcome::not_launched();
    }
    let mut r = Command::new(&exe);
    r.current_dir(&dir).env("PATH", &path);
    run_with_timeout(&mut r, Duration::from_secs(10), 8 << 20)
}

static O3: OnceLock<bool> = OnceLock::new();

/// O3 liveness (V8 §4.3): bcc32 present and accepts the probe (minus `%lld`
/// — bcc32 5.5.1 predates `long long`).
pub fn o3_active() -> bool {
    *O3.get_or_init(|| {
        if bcc().is_none() {
            return false;
        }
        let probe = "#include <stdio.h>\n\
                     int main(void){ printf(\"%d %u\\n\", -7, 4294967295u); return 7; }\n";
        bcc32_accept(probe, Lang::C).is_ok()
    })
}

// ---------------------------------------------------------------------------
// Corpus discovery
// ---------------------------------------------------------------------------

/// `(path, source)` for every `*.c` in `tests/corpus/<sub>/`, sorted.
pub fn corpus_files(sub: &str) -> Vec<(PathBuf, String)> {
    let d = repo_root().join("tests/corpus").join(sub);
    let mut v = Vec::new();
    if let Ok(rd) = fs::read_dir(&d) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().is_some_and(|x| x == "c")
                && let Ok(s) = fs::read_to_string(&p)
            {
                v.push((p, s));
            }
        }
    }
    v.sort_by(|a, b| a.0.cmp(&b.0));
    v
}

/// Short file label for diagnostics.
pub fn label(p: &Path) -> String {
    p.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}

// ---------------------------------------------------------------------------
// Unit tests for the pure equivalence relation (TDD — the oracle's oracle)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod unit {
    use super::*;

    fn ran(exit: Option<i32>, stdout: &[u8]) -> RunOutcome {
        RunOutcome {
            launched: true,
            exit,
            stdout: stdout.to_vec(),
            stdout_overflow: false,
            timed_out: false,
            stderr: Vec::new(),
        }
    }

    #[test]
    fn normalize_strips_only_cr_before_lf() {
        assert_eq!(normalize_newlines(b"a\r\n"), b"a\n");
        assert_eq!(normalize_newlines(b"a\nb"), b"a\nb");
        assert_eq!(normalize_newlines(b"\r\r\n"), b"\r\n");
        assert_eq!(normalize_newlines(b"end\r"), b"end\r");
        assert_eq!(normalize_newlines(b"x\ry"), b"x\ry");
        assert_eq!(normalize_newlines(b"1\r\n2\r\n"), b"1\n2\n");
    }

    #[test]
    fn crash_codes_detected() {
        assert!(is_crash_code(0xC0000005u32 as i32)); // access violation
        assert!(is_crash_code(0x80000003u32 as i32)); // breakpoint
        assert!(!is_crash_code(0));
        assert!(!is_crash_code(7));
        assert!(!is_crash_code(88));
        assert!(!is_crash_code(-1)); // 0xFFFFFFFF — not a STATUS crash
    }

    #[test]
    fn pass_when_equal_post_normalisation() {
        // mdbcc bare \n vs reference CRT \r\n — the spike's real case.
        let md = ran(Some(88), b"88\n");
        let rf = ran(Some(88), b"88\r\n");
        assert_eq!(compare(&md, &rf), Verdict::Pass);
    }

    #[test]
    fn fail_on_stdout_or_exit_divergence() {
        assert!(matches!(
            compare(&ran(Some(0), b"7\n"), &ran(Some(0), b"8\r\n")),
            Verdict::Fail(_)
        ));
        assert!(matches!(
            compare(&ran(Some(1), b"x\n"), &ran(Some(0), b"x\r\n")),
            Verdict::Fail(_)
        ));
    }

    #[test]
    fn crash_and_kill_rules() {
        let clean = ran(Some(0), b"ok\r\n");
        let crash = ran(Some(0xC0000005u32 as i32), b"");
        // mdbcc-only crash ⇒ FAIL; both crash ⇒ EXCLUDE (not agreement).
        assert!(matches!(compare(&crash, &clean), Verdict::Fail(_)));
        assert!(matches!(compare(&crash, &crash), Verdict::Exclude(_)));
        // None handling.
        let none = ran(None, b"");
        assert!(matches!(compare(&none, &clean), Verdict::Fail(_)));
        assert!(matches!(compare(&none, &none), Verdict::Exclude(_)));
    }

    #[test]
    fn reference_side_problems_exclude_not_fail() {
        let md_ok = ran(Some(0), b"r\n");
        assert_eq!(
            compare(&md_ok, &RunOutcome::not_launched()),
            Verdict::Exclude("reference build/launch failed".into())
        );
        let mut rf_to = ran(None, b"");
        rf_to.timed_out = true;
        assert!(matches!(compare(&md_ok, &rf_to), Verdict::Exclude(_)));
    }

    #[test]
    fn mdbcc_no_exe_is_a_fail() {
        let rf_ok = ran(Some(0), b"r\r\n");
        assert!(matches!(
            compare(&RunOutcome::not_launched(), &rf_ok),
            Verdict::Fail(_)
        ));
    }

    #[test]
    fn overflow_excludes() {
        let mut md = ran(Some(0), b"x\n");
        md.stdout_overflow = true;
        assert!(matches!(
            compare(&md, &ran(Some(0), b"x\r\n")),
            Verdict::Exclude(_)
        ));
    }

    #[test]
    fn skip_directive_parsing() {
        assert_eq!(parse_skip("int main(){}"), Skip::None);
        assert_eq!(
            parse_skip("// oracle: skip uses float\nint main(){}"),
            Skip::Full("uses float".into())
        );
        assert_eq!(
            parse_skip("// oracle: skip-bcc32-behaviour prints a pointer\nx"),
            Skip::Bcc32Behaviour("prints a pointer".into())
        );
        // Specific form must win over the generic prefix.
        match parse_skip("// oracle: skip-bcc32-behaviour ptr\n") {
            Skip::Bcc32Behaviour(_) => {}
            other => panic!("expected Bcc32Behaviour, got {other:?}"),
        }
    }

    #[test]
    fn lang_directive_parsing() {
        // Default (no directive) and unrelated content ⇒ C.
        assert_eq!(parse_lang("int main(){}"), Lang::C);
        assert_eq!(parse_lang("// oracle: skip foo\nint main(){}"), Lang::C);
        // The exact opt-in token ⇒ C++.
        assert_eq!(parse_lang("// oracle: lang cpp\nclass S{};"), Lang::Cpp);
        // Only within the first 15 lines (same scan window as parse_skip).
        let late = format!("{}// oracle: lang cpp\n", "x\n".repeat(20));
        assert_eq!(parse_lang(&late), Lang::C);
        // Unknown language token is C, not a surprise.
        assert_eq!(parse_lang("// oracle: lang rust\n"), Lang::C);
        // Orthogonal to parse_skip: both directives coexist.
        let both = "// oracle: lang cpp\n// oracle: skip-bcc32-behaviour p\n";
        assert_eq!(parse_lang(both), Lang::Cpp);
        assert_eq!(parse_skip(both), Skip::Bcc32Behaviour("p".into()));
    }
}
