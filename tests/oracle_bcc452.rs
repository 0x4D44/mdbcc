//! S0.4 — smoke tests for the BCC 4.52 oracle harness (`support::bcc_oracle`).
//!
//! Every test self-skips loudly when the CD is not present, mirroring the
//! O2/O3 self-skip idiom in `tests/differential.rs`. The harness is a
//! pre-S1 piece of test infrastructure — these tests exercise it, they do
//! NOT exercise mdbcc itself.

#![cfg(windows)]

mod support;

use std::time::Instant;
use support::bcc_oracle::{BccOracle, BuildOpts, CacheStatus, CompileOpts, Lang, LinkOpts};

/// Try to acquire the oracle; print a loud SKIP line and return `None` if
/// the CD is absent so individual tests can early-return cleanly.
fn try_oracle() -> Option<BccOracle> {
    match BccOracle::discover() {
        Some(o) => Some(o),
        None => {
            println!(
                "[oracle_bcc452] SKIP: wrk_oracle/bc452/BC45/BIN/BCC32.EXE \
                 not present (self-skip)."
            );
            None
        }
    }
}

const HELLO_C: &str = "\
#include <stdio.h>
int main(void) {
    printf(\"Hello from BCC32 4.52\\n\");
    return 42;
}
";

const HELLO_CPP_CLASS: &str = "\
#include <stdio.h>
class Foo { public: int v; int get() { return v; } };
int main(void) {
    Foo f;
    f.v = 17;
    printf(\"class get=%d\\n\", f.get());
    return f.get();
}
";

#[test]
fn bcc32_compiles_hello_c() {
    let Some(oracle) = try_oracle() else { return };
    let opts = CompileOpts::default();
    let r = oracle.compile(HELLO_C, &opts);
    assert!(
        r.output.ok(),
        "bcc32 -c hello.c failed: exit={:?}\nstdout={}\nstderr={}",
        r.output.exit,
        String::from_utf8_lossy(&r.output.stdout),
        String::from_utf8_lossy(&r.output.stderr),
    );
    let obj = r.obj.expect("compile produced no .obj");
    assert!(obj.exists(), "obj path {:?} missing", obj);
    let bytes = std::fs::read(&obj).expect("read obj");
    assert!(!bytes.is_empty(), "obj is empty");
    // Surprise: BCC32 4.52 emits **OMF** .obj files (not COFF) by default —
    // the format the bundled TLINK32 consumes. The first byte is 0x80
    // (THEADR record marker, MS OMF spec). The May-26 plan's "COFF only"
    // policy applies to mdbcc's own emission; the CD tools predate COFF.
    assert_eq!(
        bytes[0], 0x80,
        "obj does not look like Borland OMF (first byte {:#x} != 0x80)",
        bytes[0]
    );
    // No "Error" diagnostics in stderr/stdout for clean source. BCC32
    // prints the source file name to stdout as a progress line ("t.c:"),
    // so we just check for the absence of the literal "Error".
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&r.output.stdout),
        String::from_utf8_lossy(&r.output.stderr),
    );
    assert!(
        !combined.contains("Error"),
        "BCC32 reported an Error for clean hello.c:\n{combined}"
    );
}

#[test]
fn bcc32_builds_and_runs_hello_c() {
    let Some(oracle) = try_oracle() else { return };
    let opts = BuildOpts::default();
    let r = oracle.build(HELLO_C, &opts);
    assert!(
        r.output.ok(),
        "bcc32 build hello.c failed: exit={:?}\nstdout={}\nstderr={}",
        r.output.exit,
        String::from_utf8_lossy(&r.output.stdout),
        String::from_utf8_lossy(&r.output.stderr),
    );
    let exe = r.exe.expect("build produced no .exe");
    assert!(exe.exists(), "exe path {:?} missing", exe);

    let run = oracle.run(&exe, &[]);
    assert_eq!(run.output.exit, Some(42), "exit was {:?}", run.output.exit);
    let stdout = String::from_utf8_lossy(&run.output.stdout);
    assert!(
        stdout.contains("Hello from BCC32 4.52"),
        "stdout did not contain the expected greeting:\n{stdout}"
    );
}

#[test]
fn bcc32_compiles_cpp_class_with_method() {
    let Some(oracle) = try_oracle() else { return };
    let opts = BuildOpts {
        lang: Lang::Cpp,
        ..BuildOpts::default()
    };
    let r = oracle.build(HELLO_CPP_CLASS, &opts);
    assert!(
        r.output.ok(),
        "bcc32 build hello.cpp failed: exit={:?}\nstdout={}\nstderr={}",
        r.output.exit,
        String::from_utf8_lossy(&r.output.stdout),
        String::from_utf8_lossy(&r.output.stderr),
    );
    let exe = r.exe.expect("build produced no .exe");
    let run = oracle.run(&exe, &[]);
    assert_eq!(run.output.exit, Some(17), "exit was {:?}", run.output.exit);
    let stdout = String::from_utf8_lossy(&run.output.stdout);
    assert!(
        stdout.contains("class get=17"),
        "stdout did not contain expected output:\n{stdout}"
    );
}

#[test]
fn oracle_cache_hits_on_second_compile() {
    let Some(oracle) = try_oracle() else { return };
    // Use a source unique to this test so prior runs don't poison the
    // miss/hit assertion. The variation is keyed off `file!()+line!()` so
    // it's stable across runs (deterministic warm-up) but distinct from
    // other tests' sources.
    let src = format!(
        "#include <stdio.h>\nint main(void){{return 11; /* {}:{} */}}\n",
        file!(),
        line!(),
    );
    let opts = CompileOpts::default();

    // Cold compile — should report Miss. If the cache directory already
    // contains this entry from a prior run we accept either status here:
    // the point of this test is that the *second* call is a Hit, not that
    // a CI machine that has run before is forced to invalidate.
    let cold = oracle.compile(&src, &opts);
    assert!(cold.output.ok(), "cold compile failed: {:?}", cold.output);
    let cold_obj_bytes = cold
        .obj
        .as_ref()
        .map(|p| std::fs::read(p).unwrap_or_default())
        .unwrap_or_default();
    assert!(!cold_obj_bytes.is_empty(), "cold obj is empty");

    // Warm compile — must be a Hit AND must be much faster than a real
    // compile (which on this CD is ~200-400 ms even for trivial sources).
    let t0 = Instant::now();
    let warm = oracle.compile(&src, &opts);
    let warm_elapsed = t0.elapsed();
    assert_eq!(
        warm.cache,
        CacheStatus::Hit,
        "second compile was not a cache hit (status={:?})",
        warm.cache,
    );
    assert!(
        warm.output.ok(),
        "warm compile loaded a non-ok result: {:?}",
        warm.output
    );
    // Hits should never be slow. 50ms is generous (the on-disk read +
    // copy is microseconds; the budget allows for noisy CI machines).
    assert!(
        warm_elapsed.as_millis() < 50,
        "warm compile took {}ms — cache hit should be near-free",
        warm_elapsed.as_millis()
    );
    // The cached .obj must be byte-identical to the cold one.
    let warm_obj_bytes = warm
        .obj
        .as_ref()
        .map(|p| std::fs::read(p).unwrap_or_default())
        .unwrap_or_default();
    assert_eq!(
        cold_obj_bytes, warm_obj_bytes,
        "warm obj bytes differ from cold obj bytes"
    );
}

#[test]
fn explicit_tlink32_link_path_works() {
    // Sanity-check the explicit `link()` path (separate `compile()` +
    // explicit TLINK32). Exercises the full TLINK32 command-line form
    // (c0x32.obj + cw32.lib + import32.lib) — distinct from `build()`'s
    // BCC32-drives-TLINK path.
    let Some(oracle) = try_oracle() else { return };
    let c = oracle.compile(HELLO_C, &CompileOpts::default());
    assert!(c.output.ok(), "compile leg failed: {:?}", c.output);
    let obj = c.obj.expect("no obj from compile leg");
    let l = oracle.link(&[&obj], &LinkOpts::default());
    assert!(
        l.output.ok(),
        "tlink32 failed: exit={:?}\nstdout={}\nstderr={}",
        l.output.exit,
        String::from_utf8_lossy(&l.output.stdout),
        String::from_utf8_lossy(&l.output.stderr),
    );
    let exe = l.exe.expect("link produced no .exe");
    let run = oracle.run(&exe, &[]);
    assert_eq!(run.output.exit, Some(42));
    let stdout = String::from_utf8_lossy(&run.output.stdout);
    assert!(
        stdout.contains("Hello from BCC32 4.52"),
        "explicit-link stdout: {stdout}"
    );
}
