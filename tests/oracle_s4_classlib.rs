//! S4 EXIT ORACLE — differential vs bcc32 for both PLAN S4 exit clauses:
//! (1) ClassLib `TArrayAsVector` instantiate + RUN; (2) a single
//! multiple-inheritance + RTTI (`dynamic_cast`) fixture.
//!
//! The PLAN's S4 exit criterion (clause 1): a program that instantiates the
//! real `<classlib/arrays.h>` `TArrayAsVector`, `Add`s two elements, and
//! returns their sum must **compile, link, RUN, and return the correct value**
//! through the mdbcc toolchain (`bcc.exe -c` → `mdlink.exe`), matching a
//! bcc32-built reference. This is the headline running-evidence test for S4.
//!
//! Clause 2 ("Single MI+RTTI fixture green") is still not complete:
//! `s4_mi_plus_rtti_secondary_base_dynamic_cast_known_gap` documents the
//! remaining secondary-vtable RTTI gap. Construction and secondary virtual
//! dispatch are supported, but `dynamic_cast` through the secondary base still
//! returns null under mdbcc while bcc32 returns 20.
//!
//! ## Why the element type is `long`, not `int`
//!
//! bcc32 4.52 **itself cannot compile `TArrayAsVector<int>`**: Borland's own
//! classlib (ARRAYS.H:185-202) declares both `int Detach(const T& t)` and
//! `int Detach(int loc)`, and `int Destroy(const T&)` calls `Detach(t)`. When
//! `T == int` the two `Detach` overloads collapse into an ambiguous pair and
//! bcc32 errors ("Ambiguity between … Detach(const int &) and … Detach(int)").
//! The classlib was written for object/pointer element types where the two are
//! distinguishable. `<long>` avoids the collapse (the 2nd overload is literally
//! `Detach(int)`), preserves the integer-arithmetic semantics, and is built
//! identically by *both* toolchains — so it is the faithful, bcc32-matchable
//! oracle. `bcc32_rejects_tarrayasvector_int_ambiguity` pins the `<int>`
//! rejection so the finding cannot be silently lost.
//!
//! ## Architecture note
//!
//! bcc32 4.52 only emits i386; mdbcc here targets **win64** (the mission
//! target — "runs natively on Win11 x64"). The differential is therefore
//! mdbcc-win64-exit vs bcc32-i386-exit — both 18, an architecture-independent
//! *behaviour* match (exit code), which is exactly what "behaviour matching the
//! bcc32-built reference" means.
//!
//! Self-skips loudly when the repo's `wrk_oracle/bc452/BC45/INCLUDE` tree (and,
//! for the diff arm, the bcc32 BIN) is absent — mirrors the
//! `oracle_real_headers` / `oracle_bcc452` self-skip idiom.

#![cfg(windows)]

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use support::bcc_oracle::{BccOracle, BuildOpts, Lang};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The real `\BC45\INCLUDE\` tree shipped in-repo — the `-I` root for mdbcc.
/// (bcc32 reads the SAME tree via `BccOracle`, which discovers it next to BIN.)
fn include_dir() -> PathBuf {
    repo_root().join("wrk_oracle\\bc452\\BC45\\INCLUDE")
}

/// The Cargo-built compiler / linker binaries (`CARGO_BIN_EXE_<name>` is set by
/// `cargo test` for every `[[bin]]` in the crate).
fn bcc_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bcc"))
}
fn mdlink_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mdlink"))
}

/// Fresh per-test temp dir (one per test → trivial cleanup, no parallel clash).
fn fresh_temp_dir(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "mdbcc_s4oracle_{}_{}_{}",
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
/// stdout/stderr. (Self-contained per the test-suite "no `support` edits for
/// small helpers" convention — same helper as `cli_dash_c.rs`.)
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
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) => {
                if Instant::now() >= deadline {
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
    (status.and_then(|s| s.code()), stdout, stderr)
}

/// The S4 oracle source, parameterised by element type. `(int)`-casts the sum
/// so a wider element type still yields an `int` process exit code.
fn oracle_src(elem: &str) -> String {
    format!(
        "#include <classlib/arrays.h>\n\
         int main() {{ TArrayAsVector<{elem}> a(10, 0, 5); a.Add(7); a.Add(11); \
         return (int)(a[0] + a[1]); }}\n"
    )
}

/// Build the oracle through the real mdbcc CLI — `bcc.exe -c` (win64, default
/// target) then `mdlink.exe` — and run the resulting exe. Returns its exit
/// code. Asserts the compile and link both succeed (a regression there is a
/// hard failure, not a skip).
fn mdbcc_build_and_run_win64(work: &Path, src: &str, tag: &str) -> i32 {
    let src_path = work.join("o.cpp");
    std::fs::write(&src_path, src).expect("write oracle src");
    let obj = work.join("o.o");
    let exe = work.join("o.exe");

    let mut compile = Command::new(bcc_exe());
    compile.current_dir(work).arg("-c").arg("-o").arg(&obj);
    // The classlib oracle needs the real headers; the MI+RTTI fixture is
    // self-contained. Add `-I` only when the tree is present (harmless either
    // way — a self-contained source references nothing under it).
    if include_dir().is_dir() {
        compile.arg("-I").arg(include_dir());
    }
    compile.arg(&src_path);
    let (ec, _o, ee) = run_with_timeout(&mut compile, Duration::from_secs(60));
    assert_eq!(
        ec,
        Some(0),
        "[{tag}] mdbcc compile failed (exit={ec:?}):\n{}",
        String::from_utf8_lossy(&ee)
    );
    assert!(obj.is_file(), "[{tag}] mdbcc produced no object");

    let mut link = Command::new(mdlink_exe());
    link.arg(&obj).arg("-o").arg(&exe);
    let (lc, _lo, le) = run_with_timeout(&mut link, Duration::from_secs(60));
    assert_eq!(
        lc,
        Some(0),
        "[{tag}] mdlink failed (exit={lc:?}):\n{}",
        String::from_utf8_lossy(&le)
    );
    assert!(exe.is_file(), "[{tag}] mdlink produced no exe");

    let mut runc = Command::new(&exe);
    let (rc, _ro, _re) = run_with_timeout(&mut runc, Duration::from_secs(10));
    rc.unwrap_or_else(|| panic!("[{tag}] oracle exe did not exit cleanly (timeout/crash)"))
}

/// THE S4 EXIT ORACLE. mdbcc (win64) compiles `TArrayAsVector<long>` against
/// the real `<classlib/arrays.h>`, links, runs → 18 (= a[0]+a[1] = 7+11), and
/// — when the bcc32 oracle is present — matches the bcc32-built reference exe.
#[test]
fn s4_classlib_tarrayasvector_long_runs_18_and_matches_bcc32() {
    let inc = include_dir();
    if !inc.is_dir() {
        eprintln!(
            "[s4long] SKIP: {} absent (BC45 INCLUDE tree not on this machine).",
            inc.display()
        );
        return;
    }
    let work = fresh_temp_dir("s4long");
    let src = oracle_src("long");

    let md_exit = mdbcc_build_and_run_win64(&work, &src, "s4long");
    assert_eq!(
        md_exit, 18,
        "[s4long] mdbcc win64 oracle exit (a[0]+a[1] = 7+11 = 18)"
    );

    if let Some(oracle) = BccOracle::discover() {
        // bcc32 reads the SAME real headers (its own -I <INCLUDE> next to BIN).
        let r = oracle.build(
            &src,
            &BuildOpts {
                lang: Lang::Cpp,
                ..BuildOpts::default()
            },
        );
        let bcc_exe = r.exe.unwrap_or_else(|| {
            panic!(
                "[s4long] bcc32 reference build failed: exit={:?}\nstdout={}\nstderr={}",
                r.output.exit,
                String::from_utf8_lossy(&r.output.stdout),
                String::from_utf8_lossy(&r.output.stderr)
            )
        });
        let bcc_run = oracle.run(&bcc_exe, &[]);
        assert_eq!(
            bcc_run.output.exit,
            Some(18),
            "[s4long] bcc32 reference exit must be 18"
        );
        assert_eq!(
            bcc_run.output.exit,
            Some(md_exit),
            "[s4long] mdbcc win64 exit ({md_exit}) must match the bcc32 reference"
        );
    } else {
        eprintln!("NOTE [s4long]: bcc32 oracle absent — verified mdbcc-only (exit 18).");
    }
    let _ = std::fs::remove_dir_all(&work);
}

/// Pins the finding that motivates `<long>`: bcc32 4.52 REJECTS
/// `TArrayAsVector<int>` with a Detach-overload ambiguity inside the classlib
/// itself (ARRAYS.H:197). Skips when the bcc32 oracle is absent. If a future
/// toolchain swap ever *accepts* `<int>`, this fails loudly so the oracle's
/// element-type choice gets revisited.
#[test]
fn bcc32_rejects_tarrayasvector_int_ambiguity() {
    let Some(oracle) = BccOracle::discover() else {
        eprintln!("[s4int] SKIP: bcc32 oracle absent.");
        return;
    };
    let r = oracle.build(
        &oracle_src("int"),
        &BuildOpts {
            lang: Lang::Cpp,
            ..BuildOpts::default()
        },
    );
    assert!(
        r.exe.is_none(),
        "[s4int] expected bcc32 to REJECT TArrayAsVector<int> (classlib Detach ambiguity), \
         but it produced an exe — the oracle's <long> element type may no longer be necessary."
    );
    let mut diag = String::from_utf8_lossy(&r.output.stdout).into_owned();
    diag.push_str(&String::from_utf8_lossy(&r.output.stderr));
    assert!(
        diag.contains("Ambiguity") || diag.contains("Detach"),
        "[s4int] expected a Detach-ambiguity diagnostic from bcc32, got:\n{diag}"
    );
}

/// S4 exit clause 2 — the MULTIPLE-INHERITANCE + RTTI fixture: `D : B1, B2`
/// with BOTH bases polymorphic; `dynamic_cast<D*>(b2)` down-casts through the
/// SECONDARY base subobject and `dynamic_cast<B1*>(b2)` side-casts via D.
///
/// B-09: construction and virtual dispatch for a polymorphic NON-PRIMARY base
/// use a secondary vtable plus a this-adjusting thunk. RTTI through that
/// secondary vtable must still recover the complete object so a
/// `dynamic_cast<D*>(B2*)` downcast and `dynamic_cast<B1*>(B2*)` sidecast both
/// match bcc32.
#[test]
fn s4_mi_plus_rtti_secondary_base_dynamic_cast() {
    let src = "struct B1 { virtual ~B1(){} virtual int f(){return 1;} };\n\
               struct B2 { virtual ~B2(){} virtual int g(){return 2;} };\n\
               struct D : B1, B2 { int f(){return 10;} int g(){return 20;} };\n\
               int main() {\n\
                 D d; B2* b2 = &d;\n\
                 D*  p  = dynamic_cast<D*>(b2);  if (!p)  return 99;\n\
                 B1* b1 = dynamic_cast<B1*>(b2); if (!b1) return 98;\n\
                 return p->f() + b1->f();\n\
               }\n";
    let work = fresh_temp_dir("s4mirtti");

    let md_exit = mdbcc_build_and_run_win64(&work, src, "s4mirtti");
    assert_eq!(
        md_exit, 20,
        "[s4mirtti] secondary-base dynamic_cast should match bcc32"
    );

    if let Some(oracle) = BccOracle::discover() {
        let r = oracle.build(
            src,
            &BuildOpts {
                lang: Lang::Cpp,
                ..BuildOpts::default()
            },
        );
        let bcc_exe = r.exe.unwrap_or_else(|| {
            panic!(
                "[s4mirtti] bcc32 reference build failed: exit={:?}\nstdout={}\nstderr={}",
                r.output.exit,
                String::from_utf8_lossy(&r.output.stdout),
                String::from_utf8_lossy(&r.output.stderr)
            )
        });
        let bcc_run = oracle.run(&bcc_exe, &[]);
        assert_eq!(
            bcc_run.output.exit,
            Some(20),
            "[s4mirtti] bcc32 reference exit must be 20"
        );
    } else {
        eprintln!("NOTE [s4mirtti]: bcc32 oracle absent — verified mdbcc runtime result only.");
    }
    let _ = std::fs::remove_dir_all(&work);
}

/// S5 regression — overload resolution must not be defeated by a STALE record
/// layout on a method-call rvalue. CLASSLIB/TIME.CPP:95
/// (`endMarch.Previous(SUNDAY) + 7`) binds the result of the OVERLOADED,
/// record-returning `TDate::Previous(DayTy)` to the friend
/// `operator+(const TDate&, int)`. `Previous` is declared inside the still-
/// incomplete `TDate` body, so its return type was captured as a `size:0`
/// stub; for an *overloaded* method `expr_type` returns that stub verbatim
/// (`ov.ret`), and `arg_compat`'s full-equality record compare (id+size+align)
/// then matched it against NO completed `const TDate&` parameter ⇒ a spurious
/// "no matching overload for operator+". Completing the record layout in
/// `resolve_overload`'s argtys (re-reading `records[id].size`) fixes it.
///
/// Compile-only: `TDate::Previous` is defined out-of-line in DATE.CPP (absent
/// from this TU), so the snippet cannot be RUN without the full library link
/// (#48). The bug was a COMPILE failure, so compile-success against the real
/// `<classlib/date.h>` is the correct oracle. The 88 byte-identity baselines
/// guard codegen; this guards resolution.
#[test]
fn s5_operator_plus_on_overloaded_record_returning_method_rvalue_compiles() {
    let inc = include_dir();
    if !inc.is_dir() {
        eprintln!(
            "[s5datep] SKIP: {} absent (BC45 INCLUDE tree not on this machine).",
            inc.display()
        );
        return;
    }
    let work = fresh_temp_dir("s5datep");
    let src = "#include <classlib/date.h>\n\
               TDate f(unsigned year) {\n\
                 TDate endMarch(31, 3, year);\n\
                 return endMarch.Previous((DayTy)0) + 7;\n\
               }\n";
    let src_path = work.join("d.cpp");
    std::fs::write(&src_path, src).expect("write date src");
    let obj = work.join("d.o");

    let mut compile = Command::new(bcc_exe());
    compile
        .current_dir(&work)
        .arg("-c")
        .arg("-o")
        .arg(&obj)
        .arg("-I")
        .arg(&inc)
        .arg(&src_path);
    let (ec, _o, ee) = run_with_timeout(&mut compile, Duration::from_secs(60));
    assert_eq!(
        ec,
        Some(0),
        "[s5datep] mdbcc must compile `operator+` on an OVERLOADED record-returning \
         method rvalue (the TIME.CPP:95 pattern) — exit={ec:?}:\n{}",
        String::from_utf8_lossy(&ee)
    );
    assert!(obj.is_file(), "[s5datep] mdbcc produced no object");
    let _ = std::fs::remove_dir_all(&work);
}
